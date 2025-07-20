import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'farm_data.db')
print(f"Connecting to database at: {DATABASE}")
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()

try:
    print("Upgrading 'inventory_log' table...")
    # Add a column to track the cost of the items used in each log entry
    cursor.execute("ALTER TABLE inventory_log ADD COLUMN cost_of_usage REAL DEFAULT 0")
    # Add a column to link usage directly to a poultry flock
    cursor.execute("ALTER TABLE inventory_log ADD COLUMN flock_id INTEGER REFERENCES poultry_flocks(id)")
    # Add a column to link usage directly to a water production run
    cursor.execute("ALTER TABLE inventory_log ADD COLUMN water_production_log_id INTEGER REFERENCES water_production_log(id)")
    print("'inventory_log' table upgraded successfully.")

    print("\nUpgrading 'poultry_flocks' table...")
    # Add columns to store the final financial outcome of a flock
    cursor.execute("ALTER TABLE poultry_flocks ADD COLUMN final_sale_price REAL DEFAULT 0")
    cursor.execute("ALTER TABLE poultry_flocks ADD COLUMN total_cost REAL DEFAULT 0")
    cursor.execute("ALTER TABLE poultry_flocks ADD COLUMN net_profit REAL DEFAULT 0")
    print("'poultry_flocks' table upgraded successfully.")

    conn.commit()
    print("\nDATABASE UPGRADE COMPLETE.")

except sqlite3.OperationalError as e:
    print(f"\nINFO: A potential error occurred. This is often okay and means a column may already exist. Error: {e}")
finally:
    conn.close()