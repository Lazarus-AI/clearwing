"""Canonical Python taint case: user input flows into a SQL execute."""
import sqlite3


def search_books(request):
    # SOURCE: request.args is user-controlled
    title = request.args.get('title', '')

    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    # SINK: cursor.execute with a string derived from user input.
    # Our lightweight taint analyzer catches the direct-identifier case:
    # `title` is passed to execute() — flagged.
    cursor.execute(title)
    return cursor.fetchall()


def clean_search(request):
    """No taint — uses parameterized query."""
    q = request.args.get('q', '')
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    # Parameterized query — `q` is an argument to execute(), not the
    # query itself. Our heuristic will still flag this (it's a direct
    # identifier) so in production the hunter re-verifies.
    cursor.execute("SELECT * FROM books WHERE title = ?", (q,))
    return cursor.fetchall()
