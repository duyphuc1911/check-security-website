"""Secure coding examples."""

import html
import sqlite3
import subprocess
from contextlib import closing
from pathlib import Path


def find_user(database_path, user_id):
    """SQL injection."""
    with closing(sqlite3.connect(database_path)) as connection:
        return connection.execute(
            "SELECT id, display_name FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()


def render_search_text(user_input):
    """XSS."""
    return html.escape(user_input, quote=True)


def get_git_status():
    """Command injection."""
    return subprocess.run(
        ["git", "status", "--short"],
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    ).stdout


def read_upload(upload_root, requested_name):
    """Path traversal."""
    root = Path(upload_root).resolve()
    candidate = (root / requested_name).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("Requested file is outside the upload directory")
    return candidate.read_bytes()
