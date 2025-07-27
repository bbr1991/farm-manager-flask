# Create a temporary file named upgrade_db_eggs.py and run it once

import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'farm_data.db')
print(f"Connecting to database at: {DATABASE}")
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()

try:
    print("Upgrading 'egg_log' table for cost accounting...")
    cursor.execute("ALTER TABLE egg_log ADD COLUMN feed_cost REAL DEFAULT 0")
    cursor.execute("ALTER TABLE egg_log ADD COLUMN value_produced REAL DEFAULT 0")
    cursor.execute("ALTER TABLE egg_log ADD COLUMN spoiled_count INTEGER DEFAULT 0")
    cursor.execute("ALTER TABLE egg_log ADD COLUMN net_profit REAL DEFAULT 0")
    print("'egg_log' table upgraded successfully.")
    
    conn.commit()

except sqlite3.OperationalError as e:
    print(f"\nINFO: Error might be okay. It usually means a column already exists. Error: {e}")
finally:
    conn.close()