import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'farm_data.db')
print(f"Connecting to database at: {DATABASE}")
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()

try:
    print("Creating 'brooding_batches' table...")
    # This new table will track each batch of chicks separately.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS brooding_batches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        batch_name TEXT NOT NULL,
        breed TEXT,
        arrival_date TEXT NOT NULL,
        initial_chick_count INTEGER NOT NULL,
        initial_cost REAL NOT NULL,
        current_chick_count INTEGER,
        status TEXT NOT NULL DEFAULT 'Brooding', -- Brooding, Transferred, Completed
        transfer_date TEXT,
        final_cost_per_bird REAL
    )
    """)
    print("'brooding_batches' table created successfully.")

    print("\nCreating 'brooding_log' table...")
    # This table will record daily mortality for each batch.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS brooding_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        log_date TEXT NOT NULL,
        batch_id INTEGER NOT NULL,
        mortality_count INTEGER NOT NULL DEFAULT 0,
        notes TEXT,
        FOREIGN KEY (batch_id) REFERENCES brooding_batches(id)
    )
    """)
    print("'brooding_log' table created successfully.")

    print("\nUpgrading 'inventory_log' table for brooding...")
    # Add a column to link inventory usage (feed, medicine) to a specific brooding batch
    cursor.execute("ALTER TABLE inventory_log ADD COLUMN brooding_batch_id INTEGER REFERENCES brooding_batches(id)")
    print("'inventory_log' table upgraded successfully.")
    
    conn.commit()
    print("\nDATABASE UPGRADE FOR BROODING SECTION IS COMPLETE.")

except sqlite3.OperationalError as e:
    print(f"\nINFO: A potential error occurred. This is often okay and means a column may already exist. Error: {e}")
finally:
    conn.close()