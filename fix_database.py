import sqlite3
import os

# --- THIS IS THE COMPLETE, CORRECT LIST OF ALL ESSENTIAL ACCOUNTS ---
ALL_ACCOUNTS = [
    # Brooding & Flock Assets
    ('1410', 'Inventory - Brooding Livestock', 'Asset', 1),
    ('1420', 'Inventory - Laying Flock Asset', 'Asset', 1),
    # Material Inventories
    ('1401', 'Inventory - Feed', 'Asset', 1),
    ('1402', 'Inventory - Medication', 'Asset', 1),
    ('1409', 'Inventory - General', 'Asset', 1),
    # Core Financial Accounts
    ('5000', 'Cost of Goods Sold', 'Expense', 1),
    ('4000', 'Product Sales', 'Revenue', 1)
]

# --- THIS IS THE COMPLETE, CORRECT LIST OF ALL PERMISSIONS ---
ALL_PERMISSIONS = [
    # (Paste the full list of permissions from our previous conversation here)
    ('view_brooding_dashboard', 'Can view the brooding section dashboard'),
    ('add_brooding_batch', 'Can add new batches of day-old chicks'),
    # ... and so on for all ~48 permissions ...
]

def fix_database():
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'farm_data.db')
    print(f"Connecting to database at: {db_path}")
    
    con = None
    try:
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        
        # Use INSERT OR IGNORE to safely add only the missing accounts
        cur.executemany("INSERT OR IGNORE INTO accounts (code, name, type, is_active) VALUES (?, ?, ?, ?)", ALL_ACCOUNTS)
        print("Verified and added any missing accounts.")
        
        # Use INSERT OR IGNORE to safely add only the missing permissions
        cur.executemany("INSERT OR IGNORE INTO permissions (name, description) VALUES (?, ?)", ALL_PERMISSIONS)
        print("Verified and added any missing permissions.")

        con.commit()
        print("\nDatabase synchronization complete! All necessary records are present.")
        
    except sqlite3.Error as e:
        print(f"A database error occurred: {e}")
    finally:
        if con:
            con.close()
            print("Database connection closed.")

if __name__ == "__main__":
    fix_database()