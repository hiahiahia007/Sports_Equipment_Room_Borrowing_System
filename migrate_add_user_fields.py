"""
Safe migration script: add missing User profile columns to SQLite DB.

This script is idempotent and will only add columns if they do not exist.
Run from project root with the same Python environment used by the app:

    python migrate_add_user_fields.py

It will inspect `app.db` and ALTER TABLE user ADD COLUMN for any missing
columns (full_name, class_name, gender, phone).
"""
import sqlite3
import os

DB_PATH = os.path.join(os.getcwd(), 'app.db')

if not os.path.exists(DB_PATH):
    print('Database file not found at', DB_PATH)
    raise SystemExit(1)

print('Opening database:', DB_PATH)
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

def existing_columns(table):
    cur.execute("PRAGMA table_info('%s')" % table)
    return [r[1] for r in cur.fetchall()]

cols = existing_columns('user')
print('Existing user columns:', cols)

to_add = [
    ('full_name', 'TEXT'),
    ('class_name', 'TEXT'),
    ('gender', 'TEXT'),
    ('phone', 'TEXT'),
]

for name, ctype in to_add:
    if name in cols:
        print('Column exists:', name)
    else:
        sql = f"ALTER TABLE user ADD COLUMN {name} {ctype};"
        print('Adding column:', name)
        cur.execute(sql)
        conn.commit()

print('Migration complete')
conn.close()
