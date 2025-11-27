import sqlite3
from datetime import datetime

def fix_date_mismatch():
    conn = sqlite3.connect('farm_data.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    today = datetime.now().strftime('%Y-%m-%d')

    print(f"📅 Today is: {today}")
    print("---------------------------------------------------")

    # 1. CHECK FOR FUTURE TRANSACTIONS
    future_tx = cursor.execute("SELECT count(*) as count, SUM(amount) as total FROM journal_entries WHERE transaction_date > ?", (today,)).fetchone()
    
    if future_tx['count'] > 0:
        print(f"⚠️ FOUND {future_tx['count']} TRANSACTIONS IN THE FUTURE!")
        print(f"   Total Value: ₦{future_tx['total']:,.2f}")
        print("   These are causing your Balance Sheet mismatch.")
        print("   (The script balanced 'Everything', but your report only looks at 'Today'.)")
        
        confirm = input("Type 'FIX' to move all future dates to Today: ")
        if confirm == 'FIX':
            cursor.execute("UPDATE journal_entries SET transaction_date = ? WHERE transaction_date > ?", (today, today))
            conn.commit()
            print("✅ All future dates moved to today.")
        else:
            print("Skipped date fix.")
    else:
        print("✅ No future transactions found. Dates look okay.")

    print("---------------------------------------------------")

    # 2. RE-CALCULATE NET PROFIT (Strictly <= Today)
    # We delete the previous 'System Adjustment' entries first to get a clean slate
    print("🧹 Removing previous adjustment entries...")
    cursor.execute("DELETE FROM journal_entries WHERE description = 'Force Retained Earnings to Zero'")
    cursor.execute("DELETE FROM journal_entries WHERE description = 'System Integrity Fix'")