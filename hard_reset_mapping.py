import sqlite3

def hard_reset_accounts():
    db_path = 'farm_data.db'
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print("🚀 Starting Hard Reset of Account Mappings...")
    print("This will move all transaction history from P&L/Liabilities to Equity.")
    
    # 1. Get/Create Opening Balance Equity Account
    equity_row = cursor.execute("SELECT id FROM accounts WHERE name = 'Opening Balance Equity'").fetchone()
    if not equity_row:
        cursor.execute("INSERT INTO accounts (code, name, type) VALUES ('3000', 'Opening Balance Equity', 'Equity')")
        equity_id = cursor.lastrowid
    else:
        equity_id = equity_row[0]

    print(f"Target Equity Account ID: {equity_id}")

    # 2. Identify Accounts to Clear (Everything EXCEPT Assets)
    # We keep Assets (which includes Contacts/Cash/Inventory). 
    # We clear Revenue, Expense, Liability, Equity (except the target).
    
    accounts_to_clear = cursor.execute("""
        SELECT id, name, type FROM accounts 
        WHERE type IN ('Revenue', 'Expense', 'Liability', 'Equity')
        AND id != ?
    """, (equity_id,)).fetchall()

    count_moved = 0

    for acc in accounts_to_clear:
        acc_id = acc[0]
        acc_name = acc[1]
        
        # Move Debits
        cursor.execute("""
            UPDATE journal_entries 
            SET debit_account_id = ? 
            WHERE debit_account_id = ?
        """, (equity_id, acc_id))
        debits_moved = cursor.rowcount

        # Move Credits
        cursor.execute("""
            UPDATE journal_entries 
            SET credit_account_id = ? 
            WHERE credit_account_id = ?
        """, (equity_id, acc_id))
        credits_moved = cursor.rowcount
        
        if debits_moved > 0 or credits_moved > 0:
            print(f"Moved history from '{acc_name}' to Equity ({debits_moved + credits_moved} entries)")
            count_moved += debits_moved + credits_moved

    # 3. Clean up the "Fix" entries we made earlier 
    cursor.execute("DELETE FROM journal_entries WHERE description LIKE '%Force Retained Earnings%'")
    cursor.execute("DELETE FROM journal_entries WHERE description LIKE '%System Reset:%'")
    
    # 4. Zero out Operational Cost tracking (Since financials are reset)
    cursor.execute("UPDATE poultry_flocks SET initial_cost = 0, total_cost = 0")
    cursor.execute("UPDATE fish_batches SET initial_cost = 0")
    cursor.execute("UPDATE brooding_batches SET initial_cost = 0")
    
    # 5. Ensure Inventory Value is 0 (Since we moved the financial value to Equity)
    cursor.execute("UPDATE inventory SET unit_cost = 0")

    conn.commit()
    conn.close()
    
    print("-" * 30)
    print(f"✅ COMPLETE. {count_moved} transactions re-mapped.")
    print("Your Retained Earnings should now be exactly 0.00.")
    print("Your Balance Sheet will show: Contact Assets = Opening Balance Equity.")

if __name__ == "__main__":
    hard_reset_accounts()