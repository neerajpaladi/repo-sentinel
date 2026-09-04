import sqlite3

def get_user(username):
    with sqlite3.connect('db.sqlite') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cursor.fetchone()