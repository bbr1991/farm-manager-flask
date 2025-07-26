import sqlite3
import os
import sys

# --- CONFIGURATION ---
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'farm_data.db')

# List of tables that hold PURELY transactional data.
# These can be safely and completely cleared.
# Order is important for tables with relationships.
TABLES_TO_DELETE_FROM = [
    'journal_entries',
    'egg_log',
    'inventory_log',
    'water_production_log',
    'brooding_log',
    'daily_closures',
    'brooding_batches', # A batch is a transaction, not setup
    'poultry_flocks'    # A flock is a transaction, not setup
]

# List of tables that contain SETUP data but also have transactional columns
# that need to be reset to zero.
TABLES_TO_UPDATE = {
    'inventory': 'quantity = 0',      # Reset stock count to 0
    'water_products': 'quantity = 0'  # Reset water stock to 0
}


def reset_database_transactions():
    """
    Connects to the database and clears all transactional data.
    Leaves setup data (Users, Accounts, Contacts, Inventory Items) intact.
    USE WITH EXTREME CAUTION.
    """
    print("--- DATABASE TRANSACTION RESET SCRIPT ---")
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        print("\nThis script will PERMANENTLY delete all transactional data including:")
        print("- All journal entries, sales, and expenses")
        print("- All brooding batches, poultry flocks, and their logs")
        print("- It will also RESET all inventory stock counts to ZERO.")
        print("\nSetup data like users, chart of accounts, and contacts will NOT be affected.")
        
        # --- CRITICAL CONFIRMATION STEP ---
        confirm = input("This action cannot be undone. Are you sure you want to proceed? Type 'YES' to confirm: ")
        if confirm != "YES":
            print("\nOperation cancelled by user.")
            sys.exit()
            
        print("\nUser confirmed. Proceeding with data deletion...")

        # 1. DELETE all records from the purely transactional tables.
        for table in TABLES_TO_DELETE_FROM:
            cursor.execute(f"DELETE FROM {table};")
            # We also reset the autoincrement counter for these tables
            cursor.execute(f"DELETE FROM sqlite_sequence WHERE name='{table}';")
            print(f"  - Cleared all records from '{table}' table.")

        # 2. UPDATE setup tables to reset their transactional columns (e.g., stock counts).
        for table, update_statement in TABLES_TO_UPDATE.items():
            cursor.execute(f"UPDATE {table} SET {update_statement};")
            print(f"  - Reset stock counts in '{table}' table.")
            
        conn.commit()
        
        print("\n--- SCRIPT COMPLETED SUCCESSFULLY ---")
        print("All transactional data has been cleared.")
        print("Your database is now in a clean state, ready for deployment.")

    except sqlite3.Error as e:
        print(f"\n--- DATABASE ERROR ---")
        print(f"An error occurred: {e}")
        if 'conn' in locals() and conn:
            conn.rollback()
            
    finally:
        if 'conn' in locals() and conn:
            conn.close()


if __name__ == '__main__':
    reset_database_transactions()