#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import shutil
import socket
import sqlite3
import threading
import time
import urllib.parse
import webbrowser

mimetypes.add_type("application/manifest+json", ".webmanifest")
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("CONTEO_DATA_DIR", BASE_DIR / "data"))
BACKUP_DIR = Path(os.environ.get("CONTEO_BACKUP_DIR", BASE_DIR / "backups"))
DB_PATH = DATA_DIR / "conteo_ciego.db"
HTML_PATH = BASE_DIR / "ABRIR_CONTEO_CIEGO.html"

HOST = os.environ.get("CONTEO_HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", os.environ.get("CONTEO_PORT", "8765")))
SESSION_HOURS = int(os.environ.get("CONTEO_SESSION_HOURS", "24"))
OPEN_BROWSER = os.environ.get("CONTEO_OPEN_BROWSER", "1") != "0"

ALLOWED_STORES = {
    "sessions": "id",
    "items": "id",
    "counts": "key",
    "results": "key",
    "analysis": "key",
    "partMaster": "partNo",
    "stockMemory": "key",
}
AUTO_STORES = {"sessions", "items"}
ROLE_MANAGER = "MANAGER"
ROLE_COUNTER = "COUNTER"
PBKDF2_ITERATIONS = 210_000
MAX_BODY_BYTES = 120 * 1024 * 1024

DATA_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

DB_LOCK = threading.RLock()
CONN = sqlite3.connect(DB_PATH, check_same_thread=False)
CONN.row_factory = sqlite3.Row


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


def public_user(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "username": row["username"],
        "displayName": row["display_name"],
        "role": row["role"],
        "active": bool(row["active"]),
        "createdAt": row["created_at"],
        "createdBy": row["created_by"],
        "lastLoginAt": row["last_login_at"],
        "passwordChangedAt": row["password_changed_at"],
        "updatedAt": row["updated_at"],
    }


def normalize_username(value: Any) -> str:
    username = str(value or "").strip().lower()

    if not (3 <= len(username) <= 60):
        raise ValueError(
            "El usuario debe tener entre 3 y 60 caracteres."
        )

    allowed = set(
        "abcdefghijklmnopqrstuvwxyz0123456789@._-"
    )

    if any(char not in allowed for char in username):
        raise ValueError(
            "El usuario solo puede contener letras sin espacios, "
            "números, @, punto, guion o guion bajo."
        )

    return username


def validate_password(password: Any) -> str:
    clean = str(password or "")

    if len(clean) < 8:
        raise ValueError(
            "La contraseña debe contener por lo menos 8 caracteres."
        )

    return clean


def password_hash(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    ).hex()


def create_password(password: str) -> tuple[str, str]:
    clean = validate_password(password)
    salt = secrets.token_bytes(24)
    return salt.hex(), password_hash(clean, salt)


def verify_password(
    password: str,
    salt_hex: str,
    expected_hash: str,
) -> bool:
    try:
        calculated = password_hash(
            str(password),
            bytes.fromhex(salt_hex),
        )
    except Exception:
        return False

    return hmac.compare_digest(
        calculated,
        expected_hash,
    )


def init_database() -> None:
    with DB_LOCK:
        CONN.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;

            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                password_changed_at TEXT NOT NULL,
                last_login_at TEXT,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS auth_sessions (
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(username)
                    REFERENCES users(username)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS records (
                store TEXT NOT NULL,
                record_key TEXT NOT NULL,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(store, record_key)
            );

            CREATE TABLE IF NOT EXISTS sequences (
                store TEXT PRIMARY KEY,
                next_id INTEGER NOT NULL
            );
            """
        )

        for store in AUTO_STORES:
            CONN.execute(
                """
                INSERT INTO sequences(store, next_id)
                VALUES(?, 1)
                ON CONFLICT(store) DO NOTHING
                """,
                (store,),
            )

        CONN.commit()


def cleanup_sessions() -> None:
    with DB_LOCK:
        CONN.execute(
            "DELETE FROM auth_sessions WHERE expires_at <= ?",
            (utc_now(),),
        )
        CONN.commit()


def issue_token(username: str) -> str:
    cleanup_sessions()
    token = secrets.token_urlsafe(42)
    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()
    created_at = utc_now()
    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(hours=SESSION_HOURS)
    ).isoformat()

    with DB_LOCK:
        CONN.execute(
            """
            INSERT INTO auth_sessions(
                token_hash,
                username,
                created_at,
                expires_at
            )
            VALUES(?, ?, ?, ?)
            """,
            (
                token_hash,
                username,
                created_at,
                expires_at,
            ),
        )
        CONN.commit()

    return token


def revoke_token(token: str) -> None:
    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    with DB_LOCK:
        CONN.execute(
            "DELETE FROM auth_sessions WHERE token_hash = ?",
            (token_hash,),
        )
        CONN.commit()


def revoke_user_sessions(username: str) -> None:
    with DB_LOCK:
        CONN.execute(
            "DELETE FROM auth_sessions WHERE username = ?",
            (username,),
        )
        CONN.commit()


def user_from_token(token: str) -> sqlite3.Row | None:
    cleanup_sessions()
    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    with DB_LOCK:
        row = CONN.execute(
            """
            SELECT users.*
            FROM auth_sessions
            JOIN users
              ON users.username = auth_sessions.username
            WHERE auth_sessions.token_hash = ?
              AND auth_sessions.expires_at > ?
              AND users.active = 1
            """,
            (token_hash, utc_now()),
        ).fetchone()

    return row


def get_user(username: str) -> sqlite3.Row | None:
    with DB_LOCK:
        return CONN.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()


def create_user(
    *,
    display_name: Any,
    username: Any,
    password: Any,
    role: str,
    created_by: str,
) -> sqlite3.Row:
    clean_name = str(display_name or "").strip()

    if len(clean_name) < 3:
        raise ValueError(
            "Capture el nombre completo del usuario."
        )

    clean_username = normalize_username(username)
    salt, hashed = create_password(str(password))
    stamp = utc_now()
    user_id = f"USR-{secrets.token_hex(10)}"

    with DB_LOCK:
        try:
            CONN.execute(
                """
                INSERT INTO users(
                    id,
                    username,
                    display_name,
                    role,
                    active,
                    salt,
                    password_hash,
                    created_at,
                    created_by,
                    password_changed_at,
                    updated_at
                )
                VALUES(?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    clean_username,
                    clean_name,
                    role,
                    salt,
                    hashed,
                    stamp,
                    created_by,
                    stamp,
                    stamp,
                ),
            )
            CONN.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                "Ese nombre de usuario ya está registrado."
            ) from exc

    user = get_user(clean_username)

    if user is None:
        raise RuntimeError(
            "No fue posible crear el usuario."
        )

    return user


def require_store(store: str) -> str:
    if store not in ALLOWED_STORES:
        raise ValueError(
            f"Almacén de datos no permitido: {store}."
        )

    return store


def next_auto_id(store: str) -> int:
    with DB_LOCK:
        row = CONN.execute(
            "SELECT next_id FROM sequences WHERE store = ?",
            (store,),
        ).fetchone()

        next_id = int(row["next_id"]) if row else 1

        CONN.execute(
            """
            INSERT INTO sequences(store, next_id)
            VALUES(?, ?)
            ON CONFLICT(store)
            DO UPDATE SET next_id = excluded.next_id
            """,
            (store, next_id + 1),
        )
        CONN.commit()

    return next_id


def advance_sequence(store: str, used_id: int) -> None:
    with DB_LOCK:
        row = CONN.execute(
            "SELECT next_id FROM sequences WHERE store = ?",
            (store,),
        ).fetchone()
        current = int(row["next_id"]) if row else 1
        desired = max(current, int(used_id) + 1)

        CONN.execute(
            """
            INSERT INTO sequences(store, next_id)
            VALUES(?, ?)
            ON CONFLICT(store)
            DO UPDATE SET next_id = MAX(
                sequences.next_id,
                excluded.next_id
            )
            """,
            (store, desired),
        )
        CONN.commit()


def determine_record_key(
    store: str,
    value: dict[str, Any],
    *,
    allow_auto: bool,
) -> tuple[str, Any]:
    key_field = ALLOWED_STORES[store]
    key = value.get(key_field)

    if store in AUTO_STORES and (
        key is None or key == ""
    ):
        if not allow_auto:
            raise ValueError(
                f"El registro requiere el campo {key_field}."
            )

        key = next_auto_id(store)
        value[key_field] = key

    if key is None or key == "":
        raise ValueError(
            f"El registro requiere el campo {key_field}."
        )

    if store in AUTO_STORES:
        try:
            numeric_key = int(key)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"El campo {key_field} debe ser numérico."
            ) from exc

        value[key_field] = numeric_key
        advance_sequence(store, numeric_key)
        return str(numeric_key), numeric_key

    value[key_field] = str(key)
    return str(key), str(key)


def save_record(
    store: str,
    value: Any,
    *,
    allow_auto: bool,
) -> Any:
    require_store(store)

    if not isinstance(value, dict):
        raise ValueError(
            "El registro debe ser un objeto JSON."
        )

    value_copy = json.loads(
        json.dumps(value, ensure_ascii=False)
    )
    key_text, response_key = determine_record_key(
        store,
        value_copy,
        allow_auto=allow_auto,
    )

    with DB_LOCK:
        CONN.execute(
            """
            INSERT INTO records(
                store,
                record_key,
                value_json,
                updated_at
            )
            VALUES(?, ?, ?, ?)
            ON CONFLICT(store, record_key)
            DO UPDATE SET
                value_json = excluded.value_json,
                updated_at = excluded.updated_at
            """,
            (
                store,
                key_text,
                json.dumps(
                    value_copy,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
                utc_now(),
            ),
        )
        CONN.commit()

    return response_key


def list_records(store: str) -> list[dict[str, Any]]:
    require_store(store)
    order_sql = (
        "ORDER BY CAST(record_key AS INTEGER)"
        if store in AUTO_STORES
        else "ORDER BY record_key"
    )

    with DB_LOCK:
        rows = CONN.execute(
            f"""
            SELECT value_json
            FROM records
            WHERE store = ?
            {order_sql}
            """,
            (store,),
        ).fetchall()

    return [
        json.loads(row["value_json"])
        for row in rows
    ]


def read_record(
    store: str,
    key: str,
) -> dict[str, Any] | None:
    require_store(store)

    with DB_LOCK:
        row = CONN.execute(
            """
            SELECT value_json
            FROM records
            WHERE store = ?
              AND record_key = ?
            """,
            (store, str(key)),
        ).fetchone()

    return (
        json.loads(row["value_json"])
        if row
        else None
    )


def delete_record(store: str, key: str) -> None:
    require_store(store)

    with DB_LOCK:
        CONN.execute(
            """
            DELETE FROM records
            WHERE store = ?
              AND record_key = ?
            """,
            (store, str(key)),
        )
        CONN.commit()


def clear_store(store: str) -> None:
    require_store(store)

    with DB_LOCK:
        CONN.execute(
            "DELETE FROM records WHERE store = ?",
            (store,),
        )

        if store in AUTO_STORES:
            CONN.execute(
                """
                INSERT INTO sequences(store, next_id)
                VALUES(?, 1)
                ON CONFLICT(store)
                DO UPDATE SET next_id = 1
                """,
                (store,),
            )

        CONN.commit()


def create_backup(
    *,
    prefix: str = "conteo_ciego",
) -> Path:
    stamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )
    destination = (
        BACKUP_DIR
        / f"{prefix}_{stamp}.db"
    )

    with DB_LOCK:
        backup_conn = sqlite3.connect(destination)
        try:
            CONN.backup(backup_conn)
        finally:
            backup_conn.close()

    backups = sorted(
        BACKUP_DIR.glob("*.db"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )

    for old in backups[30:]:
        old.unlink(missing_ok=True)

    return destination


def automatic_startup_backup() -> None:
    try:
        if DB_PATH.exists() and DB_PATH.stat().st_size:
            create_backup(prefix="automatico")
    except Exception as exc:
        print(
            f"No se pudo crear respaldo automático: {exc}"
        )


class ApiError(Exception):
    def __init__(
        self,
        status: int,
        message: str,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class Handler(BaseHTTPRequestHandler):
    server_version = "ConteoCiegoPWA/1.35"

    def log_message(
        self,
        fmt: str,
        *args: object,
    ) -> None:
        print(
            f"[{self.log_date_time_string()}] "
            f"{self.client_address[0]} "
            f"{fmt % args}"
        )

    def end_headers(self) -> None:
        self.send_header(
            "Cache-Control",
            "no-store, no-cache, must-revalidate",
        )
        self.send_header("Pragma", "no-cache")
        self.send_header(
            "X-Content-Type-Options",
            "nosniff",
        )
        self.send_header(
            "X-Frame-Options",
            "SAMEORIGIN",
        )
        super().end_headers()

    def send_json(
        self,
        payload: Any,
        status: int = 200,
    ) -> None:
        data = json.dumps(
            payload,
            ensure_ascii=False,
        ).encode("utf-8")
        self.send_response(status)
        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8",
        )
        self.send_header(
            "Content-Length",
            str(len(data)),
        )
        self.end_headers()
        self.wfile.write(data)

    def send_bytes(
        self,
        data: bytes,
        *,
        content_type: str,
        filename: str | None = None,
    ) -> None:
        self.send_response(200)
        self.send_header(
            "Content-Type",
            content_type,
        )
        self.send_header(
            "Content-Length",
            str(len(data)),
        )

        if filename:
            self.send_header(
                "Content-Disposition",
                f'attachment; filename="{filename}"',
            )

        self.end_headers()
        self.wfile.write(data)

    def read_json(self) -> dict[str, Any]:
        length_text = self.headers.get(
            "Content-Length",
            "0",
        )

        try:
            length = int(length_text)
        except ValueError as exc:
            raise ApiError(
                400,
                "Longitud de solicitud inválida.",
            ) from exc

        if length > MAX_BODY_BYTES:
            raise ApiError(
                413,
                "La solicitud es demasiado grande.",
            )

        raw = self.rfile.read(length) if length else b"{}"

        try:
            payload = json.loads(
                raw.decode("utf-8")
            )
        except Exception as exc:
            raise ApiError(
                400,
                "El cuerpo JSON no es válido.",
            ) from exc

        if not isinstance(payload, dict):
            raise ApiError(
                400,
                "El cuerpo debe ser un objeto JSON.",
            )

        return payload

    def bearer_token(self) -> str:
        header = self.headers.get(
            "Authorization",
            "",
        )

        if not header.startswith("Bearer "):
            raise ApiError(
                401,
                "Inicie sesión para continuar.",
            )

        token = header[7:].strip()

        if not token:
            raise ApiError(
                401,
                "La sesión no es válida.",
            )

        return token

    def authenticated_user(self) -> sqlite3.Row:
        user = user_from_token(
            self.bearer_token()
        )

        if user is None:
            raise ApiError(
                401,
                "La sesión terminó o la cuenta fue dada de baja.",
            )

        return user

    def manager_user(self) -> sqlite3.Row:
        user = self.authenticated_user()

        if user["role"] != ROLE_MANAGER:
            raise ApiError(
                403,
                "Esta función es exclusiva del gerente.",
            )

        return user

    def path_parts(self) -> list[str]:
        path = urllib.parse.urlparse(
            self.path
        ).path
        return [
            urllib.parse.unquote(part)
            for part in path.split("/")
            if part
        ]

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.end_headers()

    def do_GET(self) -> None:
        try:
            parts = self.path_parts()

            if parts and parts[0] == "api":
                self.handle_api_get(parts[1:])
            else:
                self.serve_static(parts)
        except ApiError as exc:
            self.send_json(
                {"error": exc.message},
                exc.status,
            )
        except Exception as exc:
            print(f"Error GET: {exc}")
            self.send_json(
                {"error": "Error interno del servidor."},
                500,
            )

    def do_POST(self) -> None:
        try:
            parts = self.path_parts()

            if not parts or parts[0] != "api":
                raise ApiError(
                    404,
                    "Ruta no encontrada.",
                )

            self.handle_api_post(parts[1:])
        except ApiError as exc:
            self.send_json(
                {"error": exc.message},
                exc.status,
            )
        except ValueError as exc:
            self.send_json(
                {"error": str(exc)},
                400,
            )
        except Exception as exc:
            print(f"Error POST: {exc}")
            self.send_json(
                {"error": "Error interno del servidor."},
                500,
            )

    def do_DELETE(self) -> None:
        try:
            parts = self.path_parts()

            if not parts or parts[0] != "api":
                raise ApiError(
                    404,
                    "Ruta no encontrada.",
                )

            self.handle_api_delete(parts[1:])
        except ApiError as exc:
            self.send_json(
                {"error": exc.message},
                exc.status,
            )
        except ValueError as exc:
            self.send_json(
                {"error": str(exc)},
                400,
            )
        except Exception as exc:
            print(f"Error DELETE: {exc}")
            self.send_json(
                {"error": "Error interno del servidor."},
                500,
            )

    def serve_static(
        self,
        parts: list[str],
    ) -> None:
        if not parts:
            path = HTML_PATH
        else:
            requested = (
                BASE_DIR / Path(*parts)
            ).resolve()

            try:
                requested.relative_to(
                    BASE_DIR.resolve()
                )
            except ValueError as exc:
                raise ApiError(
                    403,
                    "Acceso no permitido.",
                ) from exc

            path = requested

        if path.is_dir():
            path = path / "ABRIR_CONTEO_CIEGO.html"

        if not path.exists() or not path.is_file():
            raise ApiError(
                404,
                "Archivo no encontrado.",
            )

        content_type = (
            mimetypes.guess_type(path.name)[0]
            or "application/octet-stream"
        )
        self.send_bytes(
            path.read_bytes(),
            content_type=content_type,
        )

    def handle_api_get(
        self,
        parts: list[str],
    ) -> None:
        if parts == ["health"]:
            self.send_json(
                {
                    "ok": True,
                    "mode": "central",
                    "version": "1.36",
                }
            )
            return

        if parts == ["auth", "status"]:
            with DB_LOCK:
                count = CONN.execute(
                    "SELECT COUNT(*) AS total FROM users"
                ).fetchone()["total"]

            self.send_json(
                {"initialized": bool(count)}
            )
            return

        if parts == ["me"]:
            user = self.authenticated_user()
            self.send_json(
                {"user": public_user(user)}
            )
            return

        if parts == ["users"]:
            self.manager_user()

            with DB_LOCK:
                rows = CONN.execute(
                    """
                    SELECT *
                    FROM users
                    ORDER BY
                      CASE role
                        WHEN 'MANAGER' THEN 0
                        ELSE 1
                      END,
                      display_name
                    """
                ).fetchall()

            self.send_json(
                {
                    "users": [
                        public_user(row)
                        for row in rows
                    ]
                }
            )
            return

        if parts == ["backup"]:
            self.manager_user()
            backup = create_backup(
                prefix="manual"
            )
            self.send_bytes(
                backup.read_bytes(),
                content_type=(
                    "application/octet-stream"
                ),
                filename=backup.name,
            )
            return

        if (
            len(parts) == 2
            and parts[0] == "store"
        ):
            self.authenticated_user()
            self.send_json(
                list_records(parts[1])
            )
            return

        if (
            len(parts) == 3
            and parts[0] == "store"
        ):
            self.authenticated_user()
            value = read_record(
                parts[1],
                parts[2],
            )
            self.send_json(
                {
                    "found": value is not None,
                    "value": value,
                }
            )
            return

        raise ApiError(
            404,
            "Ruta no encontrada.",
        )

    def handle_api_post(
        self,
        parts: list[str],
    ) -> None:
        if parts == ["setup-manager"]:
            payload = self.read_json()

            with DB_LOCK:
                count = CONN.execute(
                    "SELECT COUNT(*) AS total FROM users"
                ).fetchone()["total"]

            if count:
                raise ApiError(
                    409,
                    "La cuenta principal ya fue creada.",
                )

            user = create_user(
                display_name=payload.get(
                    "displayName"
                ),
                username=payload.get(
                    "username"
                ),
                password=payload.get(
                    "password"
                ),
                role=ROLE_MANAGER,
                created_by="PRIMER_INICIO",
            )
            token = issue_token(
                user["username"]
            )
            self.send_json(
                {
                    "user": public_user(user),
                    "token": token,
                },
                201,
            )
            return

        if parts == ["login"]:
            payload = self.read_json()
            username = normalize_username(
                payload.get("username")
            )
            user = get_user(username)

            if (
                user is None
                or not bool(user["active"])
                or not verify_password(
                    str(payload.get("password") or ""),
                    user["salt"],
                    user["password_hash"],
                )
            ):
                raise ApiError(
                    401,
                    "Usuario o contraseña incorrectos.",
                )

            stamp = utc_now()

            with DB_LOCK:
                CONN.execute(
                    """
                    UPDATE users
                    SET last_login_at = ?,
                        updated_at = ?
                    WHERE username = ?
                    """,
                    (
                        stamp,
                        stamp,
                        username,
                    ),
                )
                CONN.commit()

            user = get_user(username)
            token = issue_token(username)
            self.send_json(
                {
                    "user": public_user(user),
                    "token": token,
                }
            )
            return

        if parts == ["logout"]:
            token = self.bearer_token()
            revoke_token(token)
            self.send_json({"ok": True})
            return

        if parts == ["change-password"]:
            user = self.authenticated_user()
            payload = self.read_json()

            if not verify_password(
                str(
                    payload.get(
                        "currentPassword"
                    )
                    or ""
                ),
                user["salt"],
                user["password_hash"],
            ):
                raise ApiError(
                    400,
                    "La contraseña actual no es correcta.",
                )

            salt, hashed = create_password(
                str(
                    payload.get(
                        "newPassword"
                    )
                    or ""
                )
            )
            stamp = utc_now()

            with DB_LOCK:
                CONN.execute(
                    """
                    UPDATE users
                    SET salt = ?,
                        password_hash = ?,
                        password_changed_at = ?,
                        updated_at = ?
                    WHERE username = ?
                    """,
                    (
                        salt,
                        hashed,
                        stamp,
                        stamp,
                        user["username"],
                    ),
                )
                CONN.commit()

            revoke_user_sessions(
                user["username"]
            )
            token = issue_token(
                user["username"]
            )
            self.send_json(
                {
                    "ok": True,
                    "token": token,
                }
            )
            return

        if parts == ["users"]:
            manager = self.manager_user()
            payload = self.read_json()
            user = create_user(
                display_name=payload.get(
                    "displayName"
                ),
                username=payload.get(
                    "username"
                ),
                password=payload.get(
                    "password"
                ),
                role=ROLE_COUNTER,
                created_by=manager["username"],
            )
            self.send_json(
                {"user": public_user(user)},
                201,
            )
            return

        if (
            len(parts) == 3
            and parts[0] == "users"
        ):
            manager = self.manager_user()
            username = normalize_username(
                parts[1]
            )
            action = parts[2]
            user = get_user(username)

            if user is None:
                raise ApiError(
                    404,
                    "No se encontró el usuario.",
                )

            if user["role"] != ROLE_COUNTER:
                raise ApiError(
                    400,
                    "La cuenta principal del gerente no puede darse de baja desde esta opción.",
                )

            if action == "reset-password":
                payload = self.read_json()
                salt, hashed = create_password(
                    str(
                        payload.get(
                            "password"
                        )
                        or ""
                    )
                )
                stamp = utc_now()

                with DB_LOCK:
                    CONN.execute(
                        """
                        UPDATE users
                        SET salt = ?,
                            password_hash = ?,
                            password_changed_at = ?,
                            updated_at = ?
                        WHERE username = ?
                        """,
                        (
                            salt,
                            hashed,
                            stamp,
                            stamp,
                            username,
                        ),
                    )
                    CONN.commit()

                revoke_user_sessions(username)
                self.send_json({"ok": True})
                return

            if action in {
                "deactivate",
                "reactivate",
            }:
                active = (
                    0
                    if action == "deactivate"
                    else 1
                )
                stamp = utc_now()

                with DB_LOCK:
                    CONN.execute(
                        """
                        UPDATE users
                        SET active = ?,
                            updated_at = ?
                        WHERE username = ?
                        """,
                        (
                            active,
                            stamp,
                            username,
                        ),
                    )
                    CONN.commit()

                if not active:
                    revoke_user_sessions(
                        username
                    )

                updated = get_user(username)
                self.send_json(
                    {
                        "user": public_user(
                            updated
                        ),
                        "changedBy": manager[
                            "username"
                        ],
                    }
                )
                return

        if (
            len(parts) == 3
            and parts[0] == "store"
            and parts[2] in {
                "put",
                "add",
            }
        ):
            self.authenticated_user()
            payload = self.read_json()
            key = save_record(
                parts[1],
                payload.get("value"),
                allow_auto=(
                    parts[2] == "add"
                    or parts[1] in AUTO_STORES
                ),
            )
            self.send_json({"key": key})
            return

        if parts == ["migrate"]:
            self.manager_user()
            payload = self.read_json()
            stores = payload.get("stores")

            if not isinstance(stores, dict):
                raise ValueError(
                    "La migración no contiene almacenes válidos."
                )

            create_backup(
                prefix="antes_migracion"
            )
            imported = 0
            imported_by_store: dict[str, int] = {}

            for store, records in stores.items():
                require_store(store)

                if not isinstance(records, list):
                    continue

                count = 0

                for value in records:
                    if not isinstance(value, dict):
                        continue

                    if (
                        store == "analysis"
                        and value.get(
                            "recordType"
                        )
                        == "AUTH_USER"
                    ):
                        continue

                    save_record(
                        store,
                        value,
                        allow_auto=True,
                    )
                    count += 1
                    imported += 1

                imported_by_store[store] = count

            self.send_json(
                {
                    "imported": imported,
                    "stores": imported_by_store,
                }
            )
            return

        raise ApiError(
            404,
            "Ruta no encontrada.",
        )

    def handle_api_delete(
        self,
        parts: list[str],
    ) -> None:
        self.authenticated_user()

        if (
            len(parts) == 3
            and parts[0] == "store"
            and parts[2] == "clear"
        ):
            clear_store(parts[1])
            self.send_json({"ok": True})
            return

        if (
            len(parts) == 3
            and parts[0] == "store"
        ):
            delete_record(
                parts[1],
                parts[2],
            )
            self.send_json({"ok": True})
            return

        raise ApiError(
            404,
            "Ruta no encontrada.",
        )


def network_ip() -> str:
    try:
        addresses = socket.gethostbyname_ex(
            socket.gethostname()
        )[2]
        private_addresses = [
            address
            for address in addresses
            if not address.startswith("127.")
        ]

        return (
            private_addresses[0]
            if private_addresses
            else "127.0.0.1"
        )
    except Exception:
        return "127.0.0.1"


def open_browser() -> None:
    time.sleep(1)
    webbrowser.open(
        f"http://127.0.0.1:{PORT}/"
    )


def main() -> None:
    if not HTML_PATH.exists():
        raise SystemExit(
            "No se encontró ABRIR_CONTEO_CIEGO.html"
        )

    init_database()
    automatic_startup_backup()

    server = ThreadingHTTPServer(
        (HOST, PORT),
        Handler,
    )

    local_url = (
        f"http://127.0.0.1:{PORT}/"
    )
    lan_url = (
        f"http://{network_ip()}:{PORT}/"
    )

    print("=" * 62)
    print("CONTEO CIEGO PWA CLOUD v1.36")
    print("=" * 62)
    print(f"En esta computadora: {local_url}")
    print(f"En la red local:      {lan_url}")
    print(f"Base de datos:        {DB_PATH}")
    print("Mantenga esta ventana abierta mientras se utilice el sistema.")
    print("Para detener el servidor presione Ctrl+C.")
    print("=" * 62)

    if OPEN_BROWSER:
        threading.Thread(
            target=open_browser,
            daemon=True,
        ).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nCerrando servidor...")
    finally:
        server.server_close()
        with DB_LOCK:
            CONN.close()


if __name__ == "__main__":
    main()
