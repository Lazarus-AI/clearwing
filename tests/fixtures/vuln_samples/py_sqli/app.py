"""Tiny SQL-injection sample for sourcehunt fixture tests.

The file mixes a clean parameterised query (login_safe) with a vulnerable
f-string concatenation (search_books). The hunter should flag search_books.
"""
import sqlite3


def login_safe(username: str, password: str) -> bool:
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM users WHERE username = ? AND password = ?",
        (username, password),
    )
    return cursor.fetchone() is not None


def search_books(title: str) -> list:
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # VULN: f-string SQL — sql_injection finding expected
    cursor.execute(f"SELECT id, title FROM books WHERE title LIKE '%{title}%'")
    return cursor.fetchall()
