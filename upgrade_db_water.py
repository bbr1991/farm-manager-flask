import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'farm_data.db')
print(f"Connecting to database at: {DATABASE}")
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()

try:
    print("Upgrading 'water_production_log' table...")
    # Add columns to store the final calculated cost for each production run
    cursor.execute("ALTER TABLE water_production_log ADD COLUMN total_cost REAL DEFAULT 0")
    cursor.execute("ALTER TABLE water_production_log ADD COLUMN cost_per_unit REAL DEFAULT 0")
    print("'water_production_log' table upgraded successfully.")

    conn.commit()
    print("\nDATABASE UPGRADE COMPLETE.")

except sqlite3.OperationalError as e:
    print(f"\nINFO: A potential error occurred. This is often okay and means a column may already exist. Error: {e}")
finally:
    conn.close()