import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'farm_data.db')
print(f"Connecting to database at: {DATABASE}")

try:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    print("Creating 'daily_closures' table...")
    
    # This table stores a record of every closed day
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS daily_closures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        closure_date TEXT NOT NULL UNIQUE,
        closed_at TEXT NOT NULL,
        closed_by_user_id INTEGER NOT NULL,
        FOREIGN KEY (closed_by_user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    print("\nSUCCESS: The 'daily_closures' table was created successfully.")
    print("You should also add a new 'close_day' permission to your 'permissions' table.")

except Exception as e:
    print(f"\nERROR: An unexpected error occurred: {e}")
finally:
    if conn:
        conn.close()