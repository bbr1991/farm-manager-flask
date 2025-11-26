import sqlite3

conn = sqlite3.connect('farm_data.db')
cursor = conn.cursor()

print("📅 Creating Scheduled Tasks Table...")

cursor.execute("""
CREATE TABLE IF NOT EXISTS scheduled_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_name TEXT NOT NULL,
    description TEXT,
    due_date DATE NOT NULL,
    status TEXT DEFAULT 'Pending', -- Pending, Completed, Skipped
    batch_id INTEGER, -- Links to a specific batch (optional)
    category TEXT -- e.g., Vaccination, Medication, Cleaning
);
""")

conn.commit()
conn.close()
print("✅ Scheduled Tasks Table Created Successfully!")