import sqlite3

def upgrade():
    db = sqlite3.connect('farm_data.db')
    cursor = db.cursor()
    print("Upgrading egg_production table...")

    try:
        # Add new columns for crates and pieces
        cursor.execute("ALTER TABLE egg_production ADD COLUMN crates INTEGER DEFAULT 0")
        cursor.execute("ALTER TABLE egg_production ADD COLUMN pieces INTEGER DEFAULT 0")
        print("Added 'crates' and 'pieces' columns.")
        
        # One-time migration: Try to estimate crates/pieces from old 'quantity' data
        # Assuming 30 eggs per crate
        cursor.execute("""
            UPDATE egg_production 
            SET 
                crates = quantity / 30, 
                pieces = quantity % 30
            WHERE crates = 0 AND pieces = 0 AND quantity > 0
        """)
        print("Migrated existing quantity data to crates and pieces.")

    except sqlite3.OperationalError as e:
        # This will happen if the columns already exist, which is fine.
        if "duplicate column name" in str(e):
            print("Columns already exist, skipping.")
        else:
            raise e

    db.commit()
    db.close()
    print("Database upgrade complete.")

if __name__ == '__main__':
    upgrade()
import sqlite3

def upgrade():
    db = sqlite3.connect('farm_data.db')
    cursor = db.cursor()
    print("Upgrading egg_production table...")

    try:
        # Add new columns for crates and pieces
        cursor.execute("ALTER TABLE egg_production ADD COLUMN crates INTEGER DEFAULT 0")
        cursor.execute("ALTER TABLE egg_production ADD COLUMN pieces INTEGER DEFAULT 0")
        print("Added 'crates' and 'pieces' columns.")
        
        # One-time migration: Try to estimate crates/pieces from old 'quantity' data
        # Assuming 30 eggs per crate
        cursor.execute("""
            UPDATE egg_production 
            SET 
                crates = quantity / 30, 
                pieces = quantity % 30
            WHERE crates = 0 AND pieces = 0 AND quantity > 0
        """)
        print("Migrated existing quantity data to crates and pieces.")

    except sqlite3.OperationalError as e:
        # This will happen if the columns already exist, which is fine.
        if "duplicate column name" in str(e):
            print("Columns already exist, skipping.")
        else:
            raise e

    db.commit()
    db.close()
    print("Database upgrade complete.")

if __name__ == '__main__':
    upgrade()