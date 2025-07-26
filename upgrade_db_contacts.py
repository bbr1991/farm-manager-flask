# Create a temporary file named upgrade_db_contacts.py and run it

import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'farm_data.db')
print(f"Connecting to database at: {DATABASE}")
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()

try:
    print("Upgrading 'contacts' table...")
    cursor.execute("ALTER TABLE contacts ADD COLUMN account_id INTEGER REFERENCES accounts(id)")
    print("'contacts' table upgraded successfully with 'account_id'.")
    
    conn.commit()

except sqlite3.OperationalError as e:
    print(f"\nINFO: Error might be okay. It usually means the column already exists. Error: {e}")
finally:
    conn.close()