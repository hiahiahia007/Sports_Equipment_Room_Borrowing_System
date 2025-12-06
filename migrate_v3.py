import sqlite3
import os

DB_PATH = 'app.db'

def migrate():
    if not os.path.exists(DB_PATH):
        print("Database not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        # Add image_file to equipment
        try:
            cursor.execute("ALTER TABLE equipment ADD COLUMN image_file VARCHAR(120) DEFAULT 'default.jpg'")
            print("Added image_file to equipment.")
        except sqlite3.OperationalError as e:
            print(f"Skipping equipment.image_file: {e}")

        conn.commit()
        print("Migration v3 completed successfully.")

    except Exception as e:
        print(f"Migration failed: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    migrate()
