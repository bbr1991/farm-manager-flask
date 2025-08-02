import sqlite3
import os
import sys
import shutil

# --- CONFIGURATION ---
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'farm_data.db')
BACKUP_DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'farm_data_BACKUP.db')

# List of tables that hold PURELY transactional data.
# These can be safely and completely cleared.
TABLES_TO_DELETE_FROM = [
    'journal_entries',
    'egg_log',
    'inventory_log',
    'water_production_log',
    'brooding_log',
    'daily_closures',
    'brooding_batches',
    'poultry_flocks',
    'sales_packages'
]

# List of tables that contain SETUP data but also have transactional columns
# that need to be reset.
TABLES_TO_UPDATE = {
    'inventory': 'quantity = 0',      # Reset stock count to 0
    'water_products': 'quantity = 0'  # Reset water product stock to 0
}


def reset_database_transactions():
    """
    Connects to the database and clears all transactional data.
    Leaves setup data (Users, Accounts, Contacts, Inventory Items) intact.
    Automatically creates a backup before running.
    """
    print("--- DATABASE TRANSACTION RESET SCRIPT ---")
    
    # --- AUTOMATIC BACKUP ---
    try:
        print(f"\nCreating a safety backup at: {BACKUP_DATABASE}")
        shutil.copyfile(DATABASE, BACKUP_DATABASE)
        print("Backup created successfully.")
    except Exception as e:
        print(f"!!! WARNING: Could not create backup file. Error: {e}")
        confirm_no_backup = input("Do you want to continue without a backup? This is risky. Type 'CONTINUE' to proceed: ")
        if confirm_no_backup != "CONTINUE":
            print("Operation cancelled by user.")
            sys.exit()

    # --- MAIN SCRIPT ---
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        print("\nThis script will PERMANENTLY delete all transactional data including:")
        print("- All journal entries, sales, and expenses")
        print("- All brooding batches, poultry flocks, and their logs")
        print("- It will also RESET all inventory stock counts to ZERO.")
        print("\nSetup data like users, accounts, contacts, and package definitions will NOT be affected.")
        
        # --- CRITICAL CONFIRMATION STEP ---
        confirm = input("This action cannot be undone. Are you sure you want to proceed? Type 'YES' to confirm: ")
        if confirm != "YES":
            print("\nOperation cancelled by user.")
            sys.exit()
            
        print("\nUser confirmed. Proceeding with data deletion...")

        # 1. DELETE all records from the purely transactional tables.
        for table in TABLES_TO_DELETE_FROM:
            cursor.execute(f"DELETE FROM {table};")
            # Reset the autoincrement counter for these tables for a truly clean start
            cursor.execute(f"DELETE FROM sqlite_sequence WHERE name='{table}';")
            print(f"  - Cleared all records from '{table}'.")

        # 2. UPDATE setup tables to reset their transactional columns.
        for table, update_statement in TABLES_TO_UPDATE.items():
            cursor.execute(f"UPDATE {table} SET {update_statement};")
            print(f"  - Reset stock counts in '{table}'.")
            
        conn.commit()
        
        print("\n--- SCRIPT COMPLETED SUCCESSFULLY ---")
        print("All transactional data has been cleared.")
        print("Your database is now clean and ready for live data.")

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