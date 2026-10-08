"""
SecureNotes API  —  Week 13 Security Lab (STUDENT VERSION)
Web Systems and Technologies

A tiny notes service: users register, log in, and keep private notes.
It works... but it is NOT secure. Somewhere in this file are SECURITY BUGS
that map to the OWASP Top 10 (2025). Your job is to find them and fix them.

Run it:
    uvicorn app.main:app --reload
Open the interactive docs at:
    http://127.0.0.1:8000/docs

Do NOT change the behaviour students rely on (register, login, notes still work).
Only make it secure. See the lab handout for the task list and rubric.
"""

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# --- app + config ----------------------------------------------------------
app = FastAPI(title="SecureNotes API", version="1.0")

logger = logging.getLogger(__name__)
SECRET_KEY = os.environ.get("SECURENOTES_SECRET_KEY") or secrets.token_urlsafe(32)
TOKEN_TTL_SECONDS = 3600
PBKDF2_ITERATIONS = 600_000
DEFAULT_CORS_ORIGINS = [
    origin.strip()
    for origin in os.environ.get(
        "SECURENOTES_CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=DEFAULT_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


# --- database (SQLite, created fresh on startup) ---------------------------
db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, PBKDF2_ITERATIONS
    )
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_password: str) -> bool:
    try:
        salt_hex, digest_hex = stored_password.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected_digest = bytes.fromhex(digest_hex)
    except (ValueError, TypeError):
        return False
    actual_digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, PBKDF2_ITERATIONS
    )
    return hmac.compare_digest(actual_digest, expected_digest)


def _encode_token_payload(payload: str) -> str:
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def _decode_token_payload(encoded_payload: str) -> str:
    padding = "=" * (-len(encoded_payload) % 4)
    return base64.urlsafe_b64decode(encoded_payload + padding).decode()


def create_token(user_id: int) -> str:
    payload = _encode_token_payload(f"{user_id}:{int(time.time()) + TOKEN_TTL_SECONDS}")
    signature = hmac.new(
        SECRET_KEY.encode(), payload.encode(), hashlib.sha256
    ).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{payload}.{encoded_signature}"


def get_user_id_from_token(token: str) -> int:
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
        expected_signature = hmac.new(
            SECRET_KEY.encode(), encoded_payload.encode(), hashlib.sha256
        ).digest()
        padding = "=" * (-len(encoded_signature) % 4)
        actual_signature = base64.urlsafe_b64decode(encoded_signature + padding)
        if not hmac.compare_digest(actual_signature, expected_signature):
            raise ValueError
        user_id_text, expiry_text = _decode_token_payload(encoded_payload).split(":", 1)
        user_id = int(user_id_text)
        if int(expiry_text) < int(time.time()):
            raise ValueError
        return user_id
    except (ValueError, TypeError, UnicodeDecodeError, binascii.Error):
        raise HTTPException(status_code=401, detail="Invalid or expired credentials")


def init_db():
    db.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        );
        """
    )
    # seed: one admin, two normal users, a few notes
    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)",
        ("admin", hash_password("admin123")),
    )
    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
        ("alice", hash_password("alicepass")),
    )
    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
        ("bob", hash_password("bobpass")),
    )
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (2,'Alice diary','Alice secret note')")
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (3,'Bob plans','Bob secret note')")
    db.commit()


init_db()


# --- request models --------------------------------------------------------
class Credentials(BaseModel):
    username: str
    password: str


class NewNote(BaseModel):
    title: str
    body: str


# --- auth helper -----------------------------------------------------------
def current_user(authorization: str = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    token = authorization[7:].strip()
    user_id = get_user_id_from_token(token)
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Invalid or expired credentials")
    return row


# --- error handling --------------------------------------------------------
@app.exception_handler(Exception)
async def handle_everything(request, exc):
    logger.exception("Unhandled application error", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"},
    )


# --- routes ----------------------------------------------------------------
@app.post("/register")
def register(creds: Credentials):
    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
        (creds.username, hash_password(creds.password)),
    )
    db.commit()
    return {"message": f"user {creds.username} created"}


@app.post("/login")
def login(creds: Credentials):
    row = db.execute(
        "SELECT id, password FROM users WHERE username = ?",
        (creds.username,),
    ).fetchone()
    if row is None or not verify_password(creds.password, row["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"token": create_token(row["id"])}


@app.get("/notes")
def list_my_notes(authorization: str = Header(default=None)):
    user = current_user(authorization)
    rows = db.execute("SELECT * FROM notes WHERE owner_id = ?", (user["id"],)).fetchall()
    return [dict(r) for r in rows]


@app.get("/notes/{note_id}")
def get_note(note_id: int, authorization: str = Header(default=None)):
    user = current_user(authorization)
    row = db.execute(
        "SELECT * FROM notes WHERE id = ? AND owner_id = ?",
        (note_id, user["id"]),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Note not found")
    return dict(row)


@app.post("/notes")
def create_note(note: NewNote, authorization: str = Header(default=None)):
    user = current_user(authorization)
    cur = db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (user["id"], note.title, note.body),
    )
    db.commit()
    return {"id": cur.lastrowid, "title": note.title}


@app.get("/admin/users")
def list_all_users(authorization: str = Header(default=None)):
    user = current_user(authorization)
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    rows = db.execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]


@app.get("/")
def home():
    return {"service": "SecureNotes API", "docs": "/docs"}
