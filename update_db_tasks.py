import sqlite3

conn = sqlite3.connect('farm_data.db')
cursor = conn.cursor()

print("Creating Tasks Table...")

# Create table for scheduled tasks (Vaccinations, Debeaking, etc.)
cursor.execute("""
CREATE TABLE IF NOT EXISTS scheduled_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_name TEXT NOT NULL,
    task_type TEXT, -- 'Vaccination', 'Medication', 'Other'
    due_date DATE NOT NULL,
    status TEXT DEFAULT 'Pending', -- 'Pending', 'Completed', 'Missed'
    brooding_batch_id INTEGER,
    flock_id INTEGER,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")

conn.commit()
conn.close()
print("Tasks Table Created Successfully.")