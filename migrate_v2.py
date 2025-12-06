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
        # Add price to equipment
        try:
            cursor.execute("ALTER TABLE equipment ADD COLUMN price FLOAT DEFAULT 0.0")
            print("Added price to equipment.")
        except sqlite3.OperationalError as e:
            print(f"Skipping equipment.price: {e}")

        # Add columns to borrow_record
        columns = [
            ("status", "VARCHAR(20) DEFAULT 'borrowed'"),
            ("due_date", "DATETIME"),
            ("fine", "FLOAT DEFAULT 0.0"),
            ("damage_cost", "FLOAT DEFAULT 0.0"),
            ("is_damaged", "BOOLEAN DEFAULT 0")
        ]

        for col_name, col_type in columns:
            try:
                cursor.execute(f"ALTER TABLE borrow_record ADD COLUMN {col_name} {col_type}")
                print(f"Added {col_name} to borrow_record.")
            except sqlite3.OperationalError as e:
                print(f"Skipping borrow_record.{col_name}: {e}")

        # Update status for existing records
        cursor.execute("UPDATE borrow_record SET status = 'returned' WHERE return_date IS NOT NULL")
        cursor.execute("UPDATE borrow_record SET status = 'borrowed' WHERE return_date IS NULL")
        print("Updated existing borrow_record statuses.")

        conn.commit()
        print("Migration completed successfully.")

    except Exception as e:
        print(f"Migration failed: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    migrate()
