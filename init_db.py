# Correct and Final init_db.py

import sqlite3

# Define the name of your database file
DATABASE_NAME = 'farm_data.db'

def initialize_database():
    """Connects to the database and creates all necessary tables if they don't exist."""
    
    # Connect to the SQLite database.
    # If the file doesn't exist, it will be created.
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor() # Create a cursor object to execute SQL commands

    print(f"Database '{DATABASE_NAME}' opened/created successfully.")

    # --- Create Expenses Table ---
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        expense_date TEXT NOT NULL,
        category TEXT NOT NULL,
        description TEXT NOT NULL,
        amount REAL NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    print("Table 'expenses' created or already exists.")

    # --- Create Income Table ---
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS income (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        income_date TEXT NOT NULL,
        source TEXT NOT NULL,
        description TEXT NOT NULL,
        amount REAL NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    print("Table 'income' created or already exists.")

    # --- Create Inventory Table ---
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        quantity REAL NOT NULL,
        unit TEXT NOT NULL,
        expiry_date TEXT,
        supplier TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    print("Table 'inventory' created or already exists.")
        # --- Create Poultry Flocks Table ---
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS poultry_flocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        flock_name TEXT NOT NULL,
        breed TEXT NOT NULL,
        acquisition_date TEXT NOT NULL,
        initial_quantity INTEGER NOT NULL,
        status TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    print("Table 'poultry_flocks' created or already exists.")
# --- Create Egg Log Table ---
    # This table will store daily egg collection records.
    # 'flock_id' is a FOREIGN KEY that links this record to a specific flock.
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS egg_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        log_date TEXT NOT NULL,
        quantity INTEGER NOT NULL,
        flock_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (flock_id) REFERENCES poultry_flocks (id)
    )
    ''')
    print("Table 'egg_log' created or already exists.")


    # Commit the changes (important!)
    conn.commit()
    print("Changes committed to the database.")

    # Close the connection
    conn.close()
    print("Database connection closed.")

# This part allows you to run the script directly from the command line
if __name__ == '__main__':
    initialize_database()
    print("\nDatabase initialization process complete.")