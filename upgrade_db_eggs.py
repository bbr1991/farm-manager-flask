import sqlite3

def upgrade():
    # This script will connect to your database and add the new columns.
    db = sqlite3.connect('farm_data.db')
    cursor = db.cursor()
    print("Connecting to farm_data.db to upgrade 'egg_log' table...")

    try:
        # Add the new 'crates' column
        print("Adding 'crates' column...")
        cursor.execute("ALTER TABLE egg_log ADD COLUMN crates INTEGER NOT NULL DEFAULT 0")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("Column 'crates' already exists, skipping.")
        else:
            raise e

    try:
        # Add the new 'pieces' column
        print("Adding 'pieces' column...")
        cursor.execute("ALTER TABLE egg_log ADD COLUMN pieces INTEGER NOT NULL DEFAULT 0")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("Column 'pieces' already exists, skipping.")
        else:
            raise e
    
    # This part is a one-time data migration. It is safe to run multiple times.
    print("Migrating existing 'quantity' data to new columns (if needed)...")
    # Assuming 30 eggs per crate
    cursor.execute("""
        UPDATE egg_log 
        SET 
            crates = quantity / 30, 
            pieces = quantity % 30
        WHERE crates = 0 AND pieces = 0 AND quantity > 0
    """)
    
    db.commit()
    db.close()
    print("\nSUCCESS: Database upgrade for egg log is complete.")

if __name__ == '__main__':
    upgrade()