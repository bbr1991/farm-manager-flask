# ==============================================================================
# Babura Farm Manager - Database Initialization Script (init_db.py)
# Version 3.0 - Professional Refactor
# ==============================================================================

import sqlite3
from flask_bcrypt import Bcrypt
from flask import Flask

# --- Configuration ---
DATABASE_NAME = 'farm_data.db'
app = Flask(__name__)
bcrypt = Bcrypt(app)
import sqlite3
DATABASE = 'farm_data.db'
conn = sqlite3.connect(DATABASE)
conn.execute("ALTER TABLE users ADD COLUMN cash_account_id INTEGER REFERENCES accounts(id)")
conn.commit()
conn.close()
print("'users' table updated successfully with 'cash_account_id'.")
def initialize_database():
    """
    Connects to the database, drops old tables if they exist,
    creates the new professional schema, and populates it with default data.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    print(f"Database '{DATABASE_NAME}' opened/created successfully.")

    # --- Drop Old Tables (for a clean slate during development) ---
    print("\n--- Dropping old tables (if they exist)... ---")
    # Drop tables that depend on others first
    cursor.execute("DROP TABLE IF EXISTS user_permissions")
    cursor.execute("DROP TABLE IF EXISTS journal_entries")
    cursor.execute("DROP TABLE IF EXISTS sale_items")
    cursor.execute("DROP TABLE IF EXISTS sales")
    cursor.execute("DROP TABLE IF EXISTS inventory_log")
    cursor.execute("DROP TABLE IF EXISTS egg_log")
    cursor.execute("DROP TABLE IF EXISTS water_production_log")
    # Drop base tables
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("DROP TABLE IF EXISTS permissions")
    cursor.execute("DROP TABLE IF EXISTS contacts")
    cursor.execute("DROP TABLE IF EXISTS inventory")
    cursor.execute("DROP TABLE IF EXISTS poultry_flocks")
    cursor.execute("DROP TABLE IF EXISTS water_products")
    cursor.execute("DROP TABLE IF EXISTS accounts")
    # Drop old, redundant tables
    cursor.execute("DROP TABLE IF EXISTS income")
    cursor.execute("DROP TABLE IF EXISTS expenses")
    print("Old tables dropped.")


    # --- 1. User, Permissions, and Roles Structure ---
    print("\n--- 1. Setting up User and Permission tables... ---")
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            farm_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user', -- 'user' or 'admin'
            is_active BOOLEAN NOT NULL DEFAULT 1,f
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE permissions (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE user_permissions (
            user_id INTEGER NOT NULL,
            permission_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, permission_id),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
        )
    ''')
    print("User and Permission tables created.")


    # --- 2. Core Bookkeeping Structure ---
    print("\n--- 2. Setting up Bookkeeping tables... ---")
    cursor.execute('''
        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY,
            code TEXT UNIQUE,
            name TEXT NOT NULL UNIQUE,
            type TEXT NOT NULL, -- Asset, Liability, Equity, Revenue, Expense
            is_active BOOLEAN NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE contacts (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            type TEXT NOT NULL, -- Customer, Supplier, Other
            phone TEXT,
            email TEXT,
            account_id INTEGER, -- Links to a sub-account in Accounts (A/R or A/P)
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE SET NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE journal_entries (
            id INTEGER PRIMARY KEY,
            transaction_date TEXT NOT NULL,
            description TEXT NOT NULL,
            debit_account_id INTEGER NOT NULL,
            credit_account_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            created_by_user_id INTEGER NOT NULL,
            related_contact_id INTEGER,
            related_sale_id INTEGER, -- Links back to a specific sale
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (debit_account_id) REFERENCES accounts (id),
            FOREIGN KEY (credit_account_id) REFERENCES accounts (id),
            FOREIGN KEY (created_by_user_id) REFERENCES users (id),
            FOREIGN KEY (related_contact_id) REFERENCES contacts (id),
            FOREIGN KEY (related_sale_id) REFERENCES sales (id)
        )
    ''')
    print("Bookkeeping tables created.")


    # --- 3. Farm Operations Structure ---
    print("\n--- 3. Setting up Farm Operations tables... ---")
    cursor.execute('''
        CREATE TABLE inventory (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            quantity REAL NOT NULL,
            unit TEXT NOT NULL,
            unit_cost REAL NOT NULL DEFAULT 0,
            sale_price REAL NOT NULL DEFAULT 0,
            low_stock_threshold REAL,
            expiry_date TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS inventory_log (
            id INTEGER PRIMARY KEY,
            log_date TEXT NOT NULL,
            inventory_item_id INTEGER NOT NULL,
            quantity_used REAL NOT NULL,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (inventory_item_id) REFERENCES inventory (id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS water_production_log (
        id INTEGER PRIMARY KEY,
        production_date TEXT NOT NULL,
        quantity_produced INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        notes TEXT, -- This column is now guaranteed to exist
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (product_id) REFERENCES water_products (id) ON DELETE CASCADE
    )
    ''')
    print("Table 'water_production_log' created or already exists.")
    cursor.execute('''
        CREATE TABLE sales (
            id INTEGER PRIMARY KEY,
            sale_date TEXT NOT NULL,
            total_amount REAL NOT NULL,
            contact_id INTEGER,
            created_by_user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (contact_id) REFERENCES contacts (id),
            FOREIGN KEY (created_by_user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE sale_items (
            id INTEGER PRIMARY KEY,
            sale_id INTEGER NOT NULL,
            inventory_item_id INTEGER NOT NULL,
            quantity_sold REAL NOT NULL,
            price_at_sale REAL NOT NULL,
            FOREIGN KEY (sale_id) REFERENCES sales (id) ON DELETE CASCADE,
            FOREIGN KEY (inventory_item_id) REFERENCES inventory (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE poultry_flocks (
            id INTEGER PRIMARY KEY,
            flock_name TEXT NOT NULL,
            breed TEXT NOT NULL,
            acquisition_date TEXT NOT NULL,
            bird_count INTEGER NOT NULL,
            status TEXT NOT NULL, -- Active, Sold, Archived
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE egg_log (
            id INTEGER PRIMARY KEY,
            log_date TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            flock_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (flock_id) REFERENCES poultry_flocks (id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('''
        CREATE TABLE water_products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            quantity INTEGER NOT NULL DEFAULT 0,
            price REAL NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # --- 4. Populate Default Data ---
    print("\n--- 4. Populating with default data... ---")
    # Default Permissions
    all_permissions = [
        ('view_dashboard', 'Can view the main dashboard'),
        ('view_poultry', 'Can view the poultry dashboard'), ('edit_poultry', 'Can add/edit flocks and log eggs'),
        ('view_water', 'Can view the water dashboard'), ('edit_water', 'Can add/edit water products and log production'),
        ('view_inventory', 'Can view inventory'), ('edit_inventory', 'Can add/edit inventory items'),
        ('view_contacts', 'Can view contacts'), ('edit_contacts', 'Can add/edit contacts'),
        ('view_bookkeeping', 'Can view financial center, journal, and ledgers'),
        ('add_sale', 'Can use the POS to make a sale'), ('add_expense', 'Can record an expense'),
        ('add_manual_journal', 'Can create manual journal entries'),
        ('view_reports', 'Can generate and view all reports'),
        ('view_admin_panel', 'Can view the admin dashboard'), ('add_users', 'Can create new users'),
        ('edit_permissions', 'Can edit user permissions')
    ]
    if cursor.execute("SELECT COUNT(id) FROM permissions").fetchone()[0] == 0:
        cursor.executemany("INSERT INTO permissions (name, description) VALUES (?, ?)", all_permissions)
        print("Default permissions populated.")
    print(f"{len(all_permissions)} default permissions inserted.")
    
    # Default Chart of Accounts
    default_accounts = [
        ('1010', 'Cash on Hand', 'Asset'), ('1020', 'Bank Account', 'Asset'),
        ('1200', 'Accounts Receivable', 'Asset'), ('1300', 'Inventory', 'Asset'),
        ('2010', 'Accounts Payable', 'Liability'), ('2100', 'Farm Loan', 'Liability'),
        ('3010', "Owner's Capital", 'Equity'), ('3020', 'Retained Earnings', 'Equity'),
        ('4010', 'Product Sales', 'Revenue'), ('4020', 'Service Revenue', 'Revenue'),
        ('5010', 'Cost of Goods Sold', 'Expense'), ('5020', 'Feed Expense', 'Expense'),
        ('5030', 'Veterinary Expense', 'Expense'), ('5040', 'Utilities Expense', 'Expense'),
        ('5050', 'Salaries Expense', 'Expense'), ('5060', 'Bank Fees', 'Expense'),
        ('3998', 'Opening Balance Equity', 'Equity'),
    ]
    cursor.executemany("INSERT INTO accounts (code, name, type) VALUES (?, ?, ?)", default_accounts)
    print(f"{len(default_accounts)} default accounts inserted.")

    # Default Contact
    cursor.execute("INSERT INTO contacts (name, type) VALUES (?, ?)", ('Walk-in Customer', 'Customer'))
    print("Default 'Walk-in Customer' inserted.")

    # Create First Admin User
    print("Creating initial admin user...")
    admin_password = 'admin' # Change this in a real scenario
    hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')
    cursor.execute("INSERT INTO users (username, email, password_hash, farm_name, role) VALUES (?, ?, ?, ?, ?)",
                   ('admin', 'admin@example.com', hashed_password, 'My Farm', 'admin'))
    print(f"Admin user 'admin' with password '{admin_password}' created.")


    # --- Finalize ---
    conn.commit()
    print("\nChanges committed to the database.")
    conn.close()
    print("Database connection closed.")


if __name__ == '__main__':
    initialize_database()
    print("\nDatabase initialization process complete.")