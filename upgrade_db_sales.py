import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'farm_data.db')
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()

try:
    print("Creating 'sales_packages' table...")
    # This table defines the different ways you can sell an item.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sales_packages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_name TEXT NOT NULL UNIQUE,
        base_inventory_item_id INTEGER NOT NULL,
        quantity_per_package INTEGER NOT NULL,
        sale_price REAL NOT NULL,
        FOREIGN KEY (base_inventory_item_id) REFERENCES inventory(id)
    )
    """)
    print("'sales_packages' table created successfully.")
    
    conn.commit()

except Exception as e:
    print(f"An error occurred: {e}")
finally:
    conn.close()