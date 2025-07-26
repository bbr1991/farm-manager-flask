import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'farm_data.db')
print(f"Connecting to database at: {DATABASE}")

def fix_customer_accounts():
    conn = sqlite3.connect(DATABASE)
    # --- THIS IS THE CORRECTED LINE ---
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        print("Finding existing customers who are missing a linked ledger account...")
        
        # 1. Find all customers where account_id is NULL
        customers_to_fix = cursor.execute(
            "SELECT * FROM contacts WHERE type = 'Customer' AND account_id IS NULL"
        ).fetchall()

        if not customers_to_fix:
            print("No customers found to fix. All customers are correctly linked.")
            return

        print(f"Found {len(customers_to_fix)} customer(s) to update.")

        # 2. Get the parent "Accounts Receivable" account details
        parent_ar_acc = cursor.execute("SELECT code FROM accounts WHERE name = 'Accounts Receivable'").fetchone()
        if not parent_ar_acc:
            print("\nCRITICAL ERROR: Could not find a parent account named 'Accounts Receivable'.")
            print("Please create one in your Chart of Accounts with type 'Asset' and run this script again.")
            return
        parent_code = parent_ar_acc['code']

        # 3. Find the last sub-account code to start numbering from
        last_sub_acc_row = cursor.execute("SELECT MAX(code) FROM accounts WHERE code LIKE ?", (f"{parent_code}.%",)).fetchone()
        next_sub_account_number = 1
        if last_sub_acc_row and last_sub_acc_row[0]:
            parts = last_sub_acc_row[0].split('.')
            next_sub_account_number = int(parts[1]) + 1
        
        # 4. Loop through each customer, create their account, and link it
        for customer in customers_to_fix:
            print(f"  -> Processing customer: {customer['name']} (ID: {customer['id']})")
            
            # Create the new account code and name
            new_code = f"{parent_code}.{next_sub_account_number:02d}"
            account_name = f"A/R - {customer['name']}"
            
            # Insert the new account into the chart of accounts
            cursor.execute("INSERT INTO accounts (code, name, type) VALUES (?, ?, 'Asset')", (new_code, account_name))
            new_account_id = cursor.lastrowid
            print(f"     - Created new account '{account_name}' with ID: {new_account_id}")

            # Update the customer's record to link to this new account
            cursor.execute("UPDATE contacts SET account_id = ? WHERE id = ?", (new_account_id, customer['id']))
            print(f"     - Linked new account to customer.")

            next_sub_account_number += 1

        conn.commit()
        print("\nSUCCESS: All existing customers have been updated with linked ledger accounts.")

    except Exception as e:
        print(f"\nAN ERROR OCCURRED: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    fix_customer_accounts()