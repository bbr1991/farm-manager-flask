import sqlite3
import os
import sys

# --- CONFIGURATION ---
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'farm_data.db')

# List of tables that hold transactional data. 
# The order is important! We delete from "child" tables before "parent" tables.
# For example, we must delete inventory_log before we can reset inventory quantities.
TRANSACTION_TABLES = [
    'journal_entries',
    'sales',
    'egg_log',
    'inventory_log',
    'water_production_log',
    'brooding_log',
    'daily_closures'
]

# List of tables that are a mix of setup and transactional data,
# so we UPDATE them instead of deleting from them.
TABLES_TO_UPDATE = {
    'inventory': 'quantity = 0',
    'brooding_batches': "status = 'Completed', current_chick_count = 0",
    'poultry_flocks': "status = 'Archived'",
    'contacts': "account_id = NULL" # This is optional, but cleans up links
}


def reset_database_transactions():
    """
    Connects to the database and clears all data from transactional tables.
    USE WITH EXTREME CAUTION.
    """
    print("--- DATABASE TRANSACTION RESET SCRIPT ---")
    print(f"Connecting to database: {DATABASE}")
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        print("\nThis script will permanently delete all transactional data.")
        print("Setup data like users, chart of accounts, and permissions will NOT be affected.")
        
        # --- CRITICAL CONFIRMATION STEP ---
        # We force the user to type 'YES' to prevent accidental execution.
        confirm = input("Are you absolutely sure you want to proceed? Type 'YES' to confirm: ")
        if confirm != "YES":
            print("\nOperation cancelled by user.")
            sys.exit() # Exit the script
            
        print("\nUser confirmed. Proceeding with data deletion...")

        # 1. Delete all records from the transaction tables.
        for table in TRANSACTION_TABLES:
            cursor.execute(f"DELETE FROM {table};")
            print(f"  - Cleared all records from '{table}' table.")

        # 2. Update records in the setup tables to reset their state.
        for table, update_statement in TABLES_TO_UPDATE.items():
            cursor.execute(f"UPDATE {table} SET {update_statement};")
            print(f"  - Reset records in '{table}' table.")
            
        # 3. Special case: We want to delete brooding batches, not just update them.
        cursor.execute("DELETE FROM brooding_batches;")
        print(f"  - Cleared all records from 'brooding_batches' table.")

        # Commit all changes to the database
        conn.commit()
        
        print("\n--- SCRIPT COMPLETED SUCCESSFULLY ---")
        print("All transactional data has been cleared.")
        print("Your application is now in a clean state, ready for live data.")

    except sqlite3.Error as e:
        print(f"\n--- DATABASE ERROR ---")
        print(f"An error occurred: {e}")
        if 'conn' in locals() and conn:
            conn.rollback() # Roll back any partial changes
            
    finally:
        if 'conn' in locals() and conn:
            conn.close()
            print("\nDatabase connection closed.")


# This makes the script runnable from the command line
if __name__ == '__main__':
    reset_database_transactions()