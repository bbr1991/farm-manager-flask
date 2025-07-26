# Create a temporary file named upgrade_db_flocks.py and run it once

import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'farm_data.db')
print(f"Connecting to database at: {DATABASE}")
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()

try:
    print("Upgrading 'poultry_flocks' table...")
    cursor.execute("ALTER TABLE poultry_flocks ADD COLUMN cost_per_bird REAL DEFAULT 0")
    print("'poultry_flocks' table upgraded successfully with 'cost_per_bird'.")
    
    conn.commit()

except sqlite3.OperationalError as e:
    print(f"\nINFO: Error might be okay. It usually means the column already exists. Error: {e}")
finally:
    conn.close()