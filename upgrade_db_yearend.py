import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'farm_data.db')
print(f"Connecting to database at: {DATABASE}")
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()

try:
    print("Upgrading 'journal_entries' table...")
    # Add a column to lock transactions from closed periods
    cursor.execute("ALTER TABLE journal_entries ADD COLUMN is_closed INTEGER DEFAULT 0")
    print("'journal_entries' table upgraded successfully.")

    print("\nEnsuring 'Retained Earnings' account exists...")
    # Check if the account already exists
    retained_earnings = cursor.execute("SELECT id FROM accounts WHERE name = 'Retained Earnings'").fetchone()
    
    if not retained_earnings:
        # If it doesn't exist, create it with a standard equity code
        cursor.execute("INSERT INTO accounts (code, name, type) VALUES ('3900', 'Retained Earnings', 'Equity')")
        print("'Retained Earnings' account created.")
    else:
        print("'Retained Earnings' account already exists.")
        
    conn.commit()
    print("\nDATABASE UPGRADE FOR YEAR-END CLOSE IS COMPLETE.")

except sqlite3.OperationalError as e:
    print(f"\nINFO: A potential error occurred. This is often okay and means a column may already exist. Error: {e}")
finally:
    conn.close()