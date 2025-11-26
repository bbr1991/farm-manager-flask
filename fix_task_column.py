import sqlite3

conn = sqlite3.connect('farm_data.db')
cursor = conn.cursor()

print("🔧 Fixing Scheduled Tasks Table...")

# Your app expects 'brooding_batch_id', but the table has 'batch_id'
# Let's add the correct column.
try:
    cursor.execute("ALTER TABLE scheduled_tasks ADD COLUMN brooding_batch_id INTEGER DEFAULT 0")
    print("✅ Successfully added column 'brooding_batch_id'")
except sqlite3.OperationalError:
    print("ℹ️ Column 'brooding_batch_id' already exists.")

conn.commit()
conn.close()