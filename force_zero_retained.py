import sqlite3
from datetime import datetime

def zero_retained_earnings():
    db_path = 'farm_data.db'
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    today = datetime.now().strftime('%Y-%m-%d')

    print("🧹 Zeroing Revenue, Expenses, and Retained Earnings...")

    # 1. Get Opening Balance Equity ID (The Dump Account)
    equity_row = cursor.execute("SELECT id FROM accounts WHERE name = 'Opening Balance Equity'").fetchone()
    equity_id = equity_row['id']

    # 2. Find ALL Accounts that affect Retained Earnings
    # (Revenue, Expense, and the Retained Earnings account itself)
    targets = cursor.execute("""
        SELECT id, name, type FROM accounts 
        WHERE type IN ('Revenue', 'Expense') OR name = 'Retained Earnings'
    """).fetchall()

    for acc in targets:
        # Calculate Balance
        bal_row = cursor.execute("""
            SELECT 
                (SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE debit_account_id = ?) -
                (SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE credit_account_id = ?) as net
        """, (acc['id'], acc['id'])).fetchone()
        
        balance = bal_row['net']
        
        if abs(balance) < 0.01: continue # Skip if zero

        # REVERSE IT
        # If Debit Balance (Positive), Credit it.
        # If Credit Balance (Negative), Debit it.
        
        if balance > 0:
            # Credit the Account, Debit Equity
            cursor.execute("""
                INSERT INTO journal_entries 
                (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id)
                VALUES (?, ?, ?, ?, ?, 1)
            """, (today, f"Reset {acc['name']}", equity_id, acc['id'], balance))
            print(f"Zeroed {acc['name']} (Credit {balance:,.2f})")
        else:
            # Debit the Account, Credit Equity
            amount = abs(balance)
            cursor.execute("""
                INSERT INTO journal_entries 
                (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id)
                VALUES (?, ?, ?, ?, ?, 1)
            """, (today, f"Reset {acc['name']}", acc['id'], equity_id, amount))
            print(f"Zeroed {acc['name']} (Debit {amount:,.2f})")

    conn.commit()
    conn.close()
    print("✅ Retained Earnings and P&L successfully cleared.")

if __name__ == "__main__":
    zero_retained_earnings()