import sqlite3
from datetime import datetime

def reset_financials_keep_contacts():
    db_path = 'farm_data.db'
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    print("⚠️  WARNING: This will reset all Financial Balances and Inventory Quantities to ZERO.")
    print("ℹ️  EXCEPTION: Customer/Supplier (A/R) balances will be preserved.")
    print("ℹ️  History will NOT be deleted. A reversal entry will be created.")
    
    confirm = input("Type 'RESET' to proceed: ")
    if confirm != 'RESET':
        print("Aborted.")
        return

    today = datetime.now().strftime('%Y-%m-%d')
    
    # 1. IDENTIFY ACCOUNTS TO RESET
    # We select ALL accounts, but we will filter out the ones starting with 'A/R' or 'A/P'
    all_accounts = cursor.execute("SELECT id, name, type FROM accounts").fetchall()
    
    reset_entries = []
    total_debit_correction = 0
    total_credit_correction = 0

    print("\n--- Calculating Reversals ---")

    for acc in all_accounts:
        # SKIP Contacts (Accounts Receivable / Payable)
        if "A/R" in acc['name'] or "A/P" in acc['name']:
            print(f"Skipping Contact: {acc['name']} (Keeping Balance)")
            continue
        
        # Calculate Current Balance
        # Debit - Credit for Asset/Expense
        # Credit - Debit for Liability/Equity/Revenue
        
        row = cursor.execute("""
            SELECT 
                (SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE debit_account_id = ?) as debits,
                (SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE credit_account_id = ?) as credits
        """, (acc['id'], acc['id'])).fetchone()
        
        debits = row['debits']
        credits = row['credits']
        net_balance = debits - credits # Positive means Debit balance
        
        if abs(net_balance) < 0.01:
            continue # Already zero

        # CREATE REVERSAL
        # If Balance is Debit (Positive), we must CREDIT it to zero it out.
        # If Balance is Credit (Negative), we must DEBIT it to zero it out.
        
        if net_balance > 0:
            # It has a Debit balance. We need to Credit it.
            reset_entries.append({
                'debit_id': None, # To be determined (Equity)
                'credit_id': acc['id'],
                'amount': net_balance,
                'name': acc['name']
            })
            total_credit_correction += net_balance
            print(f"Zeroing {acc['name']}: Crediting {net_balance:,.2f}")
            
        else:
            # It has a Credit balance. We need to Debit it.
            amount = abs(net_balance)
            reset_entries.append({
                'debit_id': acc['id'],
                'credit_id': None, # To be determined (Equity)
                'amount': amount,
                'name': acc['name']
            })
            total_debit_correction += amount
            print(f"Zeroing {acc['name']}: Debiting {amount:,.2f}")

    # 2. HANDLE THE DIFFERENCE (PLUG TO EQUITY)
    # The difference between what we zeroed out must go to "Opening Balance Equity"
    # This forces Assets (Contacts) = Equity.
    
    equity_acc = cursor.execute("SELECT id FROM accounts WHERE name = 'Opening Balance Equity'").fetchone()
    if not equity_acc:
        # Create if missing
        cursor.execute("INSERT INTO accounts (code, name, type) VALUES ('3000', 'Opening Balance Equity', 'Equity')")
        equity_id = cursor.lastrowid
    else:
        equity_id = equity_acc['id']

    # 3. POST THE MASSIVE JOURNAL ENTRY
    print("\n--- Posting Reversal Journal Entry ---")
    
    # We create one massive transaction or individual lines. Individual lines are safer for debugging.
    
    for entry in reset_entries:
        debit = entry['debit_id']
        credit = entry['credit_id']
        amount = entry['amount']
        
        # Fill the missing side with Equity
        if debit is None: 
            debit = equity_id # We credited the account, so we debit Equity
        if credit is None: 
            credit = equity_id # We debited the account, so we credit Equity
            
        cursor.execute("""
            INSERT INTO journal_entries 
            (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id)
            VALUES (?, ?, ?, ?, ?, 1)
        """, (today, f"System Reset: Zeroing {entry['name']}", debit, credit, amount))

    # 4. RESET OPERATIONAL QUANTITIES
    # Since we zeroed the financial value of Inventory, we must zero the physical count too.
    print("\n--- Resetting Inventory Quantities ---")
    cursor.execute("UPDATE inventory SET quantity = 0, unit_cost = 0")
    
    # Reset Fish/Poultry Batches current cost tracking (Optional, but recommended)
    cursor.execute("UPDATE poultry_flocks SET initial_cost = 0, total_cost = 0")
    cursor.execute("UPDATE brooding_batches SET initial_cost = 0")
    cursor.execute("UPDATE fish_batches SET initial_cost = 0")

    conn.commit()
    conn.close()
    
    print("\n✅ SUCCESS! System Reset Complete.")
    print("1. All Accounts (except Contacts) are now 0.00")
    print("2. Inventory Quantity is 0.")
    print("3. Contact Balances are preserved.")
    print("4. Total Contact Value now equals Opening Balance Equity.")

if __name__ == "__main__":
    reset_financials_keep_contacts()