import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'farm_data.db')
print(f"Connecting to database at: {DATABASE}")

try:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    print("Attempting to add 'created_by_user_id' to the 'inventory_log' table...")
    
    # This is the command that adds the new column.
    # It links to the 'users' table, which is good practice.
    cursor.execute("ALTER TABLE inventory_log ADD COLUMN created_by_user_id INTEGER REFERENCES users(id)")

    conn.commit()
    
    print("\nSUCCESS: The 'created_by_user_id' column was added successfully.")
    print("You can now restart your Flask application.")

except sqlite3.OperationalError as e:
    # This error will likely show if the column ALREADY exists.
    print(f"\nINFO: An error occurred, which might be okay. Error: {e}")
    print("This usually means the column already exists. The schema should be correct.")
except Exception as e:
    print(f"\nERROR: An unexpected error occurred: {e}")
finally:
    if 'conn' in locals() and conn:
        conn.close()