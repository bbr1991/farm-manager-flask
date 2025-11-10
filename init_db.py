# ==============================================================================
# Babura Farm Manager - Database Initialization Script (init_db.py)
# Version 4.0 - Comprehensive Schema & Data Population + PHONE CHARGING SERVICE
# ==============================================================================

import sqlite3
import os
from datetime import datetime
from flask import Flask
from flask_bcrypt import Bcrypt

# --- Configuration ---

# Initialize Flask app and Bcrypt for password hashing
# This is a minimal Flask app setup just to allow Bcrypt to work outside the main app.py
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_placeholder_secret_key_for_db_init' # Not used for live sessions, but needed by Bcrypt
bcrypt = Bcrypt(app)

def initialize_database():
    """
    Connects to the database, drops old tables if they exist,
    creates the new professional schema (V4.0), and populates it with default data.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    print(f"Database '{DATABASE_NAME}' opened/created successfully.")

    # --- Drop Old Tables (for a clean slate during development) ---
    print("\n--- Dropping old tables (if they exist)... ---")
    # Drop tables that depend on others first to avoid foreign key errors
    cursor.execute("DROP TABLE IF EXISTS user_permissions")
    cursor.execute("DROP TABLE IF EXISTS journal_entries")
    cursor.execute("DROP TABLE IF EXISTS sales")
    cursor.execute("DROP TABLE IF EXISTS sales_packages")
    cursor.execute("DROP TABLE IF EXISTS inventory_log")
    cursor.execute("DROP TABLE IF EXISTS egg_log")
    cursor.execute("DROP TABLE IF EXISTS water_production_log")
    cursor.execute("DROP TABLE IF EXISTS brooding_log")
    cursor.execute("DROP TABLE IF EXISTS daily_closures")
    
    # NEW: Drop charging-related tables
    cursor.execute("DROP TABLE IF EXISTS charging_transactions")
    cursor.execute("DROP TABLE IF EXISTS charging_cards")
    cursor.execute("DROP TABLE IF EXISTS clients")

    # Drop base tables
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("DROP TABLE IF EXISTS permissions")
    cursor.execute("DROP TABLE IF EXISTS contacts")
    cursor.execute("DROP TABLE IF EXISTS poultry_flocks")
    cursor.execute("DROP TABLE IF EXISTS brooding_batches")
    cursor.execute("DROP TABLE IF EXISTS water_products")
    cursor.execute("DROP TABLE IF EXISTS inventory")
    cursor.execute("DROP TABLE IF EXISTS accounts")
    
    print("Old tables dropped.")


    # --- 1. Core Financial and User Structure ---
    print("\n--- 1. Setting up Core Financial and User tables... ---")
    
    cursor.execute('''
        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL UNIQUE,
            type TEXT NOT NULL, -- Asset, Liability, Equity, Revenue, Expense
            is_active INTEGER DEFAULT 1, -- 1 for active, 0 for inactive
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            farm_name TEXT NOT NULL,
            role TEXT DEFAULT 'user', -- 'admin', 'user'
            cash_account_id INTEGER, -- Links to an account in the accounts table
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (cash_account_id) REFERENCES accounts(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT
        )
    ''')

    print("Accounts, Users, and Permissions tables created.")


    # --- 2. Operational Base Tables ---
    print("\n--- 2. Setting up Operational Base tables... ---")

    cursor.execute('''
        CREATE TABLE poultry_flocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flock_name TEXT NOT NULL UNIQUE,
            breed TEXT NOT NULL,
            acquisition_date TEXT NOT NULL, -- YYYY-MM-DD
            initial_chick_count INTEGER NOT NULL,
            current_chick_count INTEGER NOT NULL, -- Decreases with mortality, increases with transfers
            initial_cost REAL DEFAULT 0, -- Initial purchase cost of the chicks
            cost_per_bird REAL DEFAULT 0, -- Average cost per bird in the flock
            status TEXT NOT NULL DEFAULT 'Active', -- 'Active', 'Inactive', 'Transferred'
            transfer_date TEXT, -- YYYY-MM-DD, if transferred from brooding
            final_chick_count INTEGER, -- Count at transfer/deactivation
            final_total_cost REAL, -- Total accumulated cost when deactivated/transferred
            final_sale_price REAL, -- If sold
            net_profit REAL, -- If sold
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE brooding_batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_name TEXT NOT NULL UNIQUE,
            breed TEXT NOT NULL,
            arrival_date TEXT NOT NULL,
            initial_chick_count INTEGER NOT NULL,
            initial_cost REAL DEFAULT 0,
            current_chick_count INTEGER NOT NULL,
            status TEXT DEFAULT 'Brooding', -- 'Brooding', 'Transferred', 'Completed'
            transfer_date TEXT,
            final_chick_count INTEGER,
            final_total_cost REAL,
            final_cost_per_bird REAL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE water_products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            price REAL NOT NULL, -- Sale price per unit
            quantity REAL NOT NULL DEFAULT 0, -- Stock level of finished water products
            inventory_item_id INTEGER UNIQUE, -- Links to inventory item for sales, nullable for initial creation
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (inventory_item_id) REFERENCES inventory(id) ON DELETE SET NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            category TEXT NOT NULL, -- e.g., 'Feed', 'Medication', 'Produce', 'Water Production', 'Equipment', 'Other', 'Finished Goods'
            quantity REAL NOT NULL DEFAULT 0,
            unit TEXT NOT NULL, -- e.g., 'kg', 'bags', 'pieces', 'litres'
            low_stock_threshold REAL DEFAULT 0,
            unit_cost REAL DEFAULT 0, -- Average cost for costing purposes
            sale_price REAL DEFAULT 0,
            expiry_date TEXT, -- YYYY-MM-DD, nullable
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # NEW TABLES FOR PHONE CHARGING SERVICE
    cursor.execute('''
        CREATE TABLE clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone_number TEXT UNIQUE, -- Allow NULL if not always provided, but unique if present
            email TEXT, -- Optional
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE charging_cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE, -- Human-readable code or barcode value
            is_available INTEGER DEFAULT 1, -- 1 if available, 0 if issued to a client
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    print("Poultry Flocks, Brooding Batches, Water Products, Inventory, Clients, and Charging Cards tables created.")


    # --- 3. Linked Tables ---
    print("\n--- 3. Setting up Linked tables... ---")

    cursor.execute('''
        CREATE TABLE contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            type TEXT NOT NULL, -- Customer, Supplier, Other
            phone TEXT,
            email TEXT,
            account_id INTEGER, -- Links to a sub-account in Accounts (A/R or A/P)
            assigned_user_id INTEGER, -- User responsible for this contact
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE SET NULL,
            FOREIGN KEY (assigned_user_id) REFERENCES users (id) ON DELETE SET NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE sales_packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL UNIQUE,
            base_inventory_item_id INTEGER NOT NULL,
            quantity_per_package REAL NOT NULL, -- e.g., 30 eggs in a crate
            sale_price REAL NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (base_inventory_item_id) REFERENCES inventory(id) ON DELETE CASCADE
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sale_date TEXT NOT NULL,
            total_amount REAL NOT NULL,
            contact_id INTEGER,
            created_by_user_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (contact_id) REFERENCES contacts (id),
            FOREIGN KEY (created_by_user_id) REFERENCES users (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE daily_closures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            closure_date TEXT NOT NULL UNIQUE, -- YYYY-MM-DD
            closed_at TEXT DEFAULT CURRENT_TIMESTAMP,
            closed_by_user_id INTEGER NOT NULL,
            FOREIGN KEY (closed_by_user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE brooding_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_date TEXT NOT NULL,
            batch_id INTEGER NOT NULL,
            mortality_count INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (batch_id) REFERENCES brooding_batches(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE water_production_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            production_date TEXT NOT NULL,
            product_id INTEGER NOT NULL,
            quantity_produced REAL NOT NULL,
            notes TEXT,
            production_labor_cost REAL DEFAULT 0,
            sales_commission REAL DEFAULT 0,
            total_cost REAL,
            cost_per_unit REAL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES water_products(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE egg_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_date TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            flock_id INTEGER NOT NULL,
            crates INTEGER NOT NULL DEFAULT 0,
            pieces INTEGER NOT NULL DEFAULT 0,
            spoiled_count INTEGER NOT NULL DEFAULT 0,
            feed_cost REAL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (flock_id) REFERENCES poultry_flocks(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE inventory_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_date TEXT NOT NULL,
            inventory_item_id INTEGER NOT NULL,
            quantity_used REAL NOT NULL,
            cost_of_usage REAL NOT NULL,
            flock_id INTEGER,
            water_production_log_id INTEGER,
            brooding_batch_id INTEGER,
            created_by_user_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (inventory_item_id) REFERENCES inventory(id) ON DELETE CASCADE,
            FOREIGN KEY (flock_id) REFERENCES poultry_flocks(id) ON DELETE SET NULL,
            FOREIGN KEY (water_production_log_id) REFERENCES water_production_log(id) ON DELETE SET NULL,
            FOREIGN KEY (brooding_batch_id) REFERENCES brooding_batches(id) ON DELETE SET NULL,
            FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # NEW: Charging Transactions table
    cursor.execute('''
        CREATE TABLE charging_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_id INTEGER NOT NULL,
            client_id INTEGER,
            client_name TEXT NOT NULL,
            client_phone TEXT,
            phone_description TEXT NOT NULL,
            imei_number TEXT,
            check_in_time TEXT DEFAULT CURRENT_TIMESTAMP,
            check_out_time TEXT,
            status TEXT NOT NULL DEFAULT 'charging', -- 'charging', 'ready', 'collected', 'overdue'
            fee REAL DEFAULT 0,
            fee_account_id INTEGER,
            collected_by_user_id INTEGER,
            created_by_user_id INTEGER NOT NULL,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (card_id) REFERENCES charging_cards(id) ON DELETE RESTRICT, -- Card must exist
            FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL,
            FOREIGN KEY (fee_account_id) REFERENCES accounts(id) ON DELETE SET NULL,
            FOREIGN KEY (collected_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE journal_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_date TEXT NOT NULL, -- YYYY-MM-DD
            description TEXT NOT NULL,
            debit_account_id INTEGER NOT NULL,
            credit_account_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            created_by_user_id INTEGER NOT NULL,
            related_contact_id INTEGER, -- Optional: Link to a supplier/customer
            related_flock_id INTEGER, -- Optional: Link to a poultry flock
            created_at TEXT DEFAULT CURRENT_TIMESTAMP, -- For internal tracking
            is_closed INTEGER DEFAULT 0, -- 1 if day/period is closed, 0 otherwise
            FOREIGN KEY (debit_account_id) REFERENCES accounts(id),
            FOREIGN KEY (credit_account_id) REFERENCES accounts(id),
            FOREIGN KEY (created_by_user_id) REFERENCES users(id),
            FOREIGN KEY (related_contact_id) REFERENCES contacts(id),
            FOREIGN KEY (related_flock_id) REFERENCES poultry_flocks(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE user_permissions (
            user_id INTEGER NOT NULL,
            permission_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP, -- Moved to valid column definition position
            PRIMARY KEY (user_id, permission_id),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
        )
    ''')
    
    print("Contacts, Sales Packages, Sales, Daily Closures, Brooding Log, Water Production Log, Egg Log, Inventory Log, Charging Transactions, Journal Entries, and User Permissions tables created.")


    # --- 4. Populate Default Data ---
    print("\n--- 4. Populating with default data... ---")

    all_permissions = [
        ('view_dashboard', 'Can view the main dashboard'),
        ('view_poultry_dashboard', 'Can view the poultry laying flocks dashboard'),
        ('add_poultry_flock', 'Can add new poultry flocks'),
        ('log_poultry_eggs', 'Can log daily egg production for flocks'),
        ('log_poultry_mortality', 'Can log mortality for laying flocks'),
        ('deactivate_poultry_flock', 'Can deactivate/sell a laying flock and finalize its profit/loss'),
        ('view_brooding_dashboard', 'Can view the brooding section dashboard'),
        ('add_brooding_batch', 'Can add new brooding batches'),
        ('log_brooding_mortality', 'Can log mortality for brooding batches'),
        ('log_inventory_usage', 'Can log the usage of any inventory item (e.g., feed, medication)'),
        ('transfer_brooding_batch', 'Can transfer chicks from a brooding batch to a laying flock'),
        ('view_water_dashboard', 'Can view the water production dashboard'),
        ('add_water_product', 'Can add new water products'),
        ('log_water_production', 'Can log daily water production runs'),
        ('edit_water_product', 'Can edit water product details'),
        ('edit_production_log', 'Can edit/delete water production logs and associated costs'),
        ('calculate_water_cost', 'Can calculate and finalize costs for water production runs'),
        ('view_inventory_dashboard', 'Can view the inventory dashboard'),
        ('add_inventory_item', 'Can add new types of inventory items'),
        ('add_inventory_stock', 'Can add stock to existing inventory items'),
        ('edit_inventory_item', 'Can edit existing inventory item details'),
        ('delete_inventory_item', 'Can delete inventory items (if no usage history)'),
        ('view_sales_packages', 'Can view and manage sales packages'),
        ('add_contact', 'Can add new customer or supplier contacts'),
        ('edit_contact', 'Can edit existing contact details'),
        ('delete_contact', 'Can delete contacts (if no related transactions)'),
        ('assign_contact_user', 'Can assign users to manage specific contacts'),
        ('view_contacts_dashboard', 'Can view the contacts dashboard and individual ledgers'),
        ('view_financial_center', 'Can view the main financial center dashboard'),
        ('view_chart_of_accounts', 'Can view the Chart of Accounts'),
        ('add_chart_of_accounts', 'Can add new accounts to the Chart of Accounts'),
        ('view_general_journal', 'Can view the General Journal'),
        ('add_manual_journal_entry', 'Can create manual journal entries'),
        ('reverse_journal_entry', 'Can reverse existing journal entries'),
        ('record_new_sale', 'Can record new Point of Sale transactions'),
        ('record_customer_transaction', 'Can record customer deposits and credit sales'),
        ('record_batch_deposit', 'Can record multiple customer deposits at once'),
        ('record_new_expense', 'Can record general expenses and purchases (including inventory stock updates)'),
        ('record_batch_expense', 'Can record multiple expenses in a single batch'),
        ('view_reports_dashboard', 'Can view the reports center and access all reports'),
        ('run_financial_reports', 'Can run Profit & Loss, Balance Sheet, Trial Balance reports'),
        ('run_operational_reports', 'Can run inventory, egg, water, flock, brooding reports'),
        ('run_brooding_report', 'Can view detailed brooding reports'),
        ('run_mortality_report', 'Can view detailed mortality reports'),
        ('view_admin_panel', 'Can view the admin dashboard'),
        ('add_users', 'Can create new users'),
        ('manage_users', 'Can edit user permissions and delete users'),
        ('close_day', 'Can close a financial day (admin function)'),
        ('manage_phone_charging', 'Can manage the phone charging service (check-in/out)'), # NEW PERMISSION
    ]
    # Check if permissions table is empty before inserting
    if cursor.execute("SELECT COUNT(*) FROM permissions").fetchone()[0] == 0:
        cursor.executemany("INSERT INTO permissions (name, description) VALUES (?, ?)", all_permissions)
        print(f"{len(all_permissions)} default permissions inserted.")
    else:
        print("Permissions table not empty, skipping default permission insertion.")
    
    default_accounts = [
        ('1010', 'Cash on Hand', 'Asset'), ('1020', 'Bank Account', 'Asset'),
        ('1030', 'Moniepoint MFB Account', 'Asset'),
        ('1200', 'Accounts Receivable', 'Asset'), 
        ('1201', 'Inventory - Feed', 'Asset'), ('1202', 'Inventory - Medication', 'Asset'),
        ('1203', 'Inventory - Eggs', 'Asset'), ('1204', 'Inventory - Water Production', 'Asset'),
        ('1205', 'Inventory - Equipment', 'Asset'), ('1206', 'Inventory - Produce', 'Asset'),
        ('1207', 'Inventory - Other', 'Asset'), ('1208', 'Inventory - Finished Goods', 'Asset'),
        ('1301', 'Inventory - Laying Flock Asset', 'Asset'),
        ('1302', 'Inventory - Brooding Livestock', 'Asset'),
        ('2010', 'Accounts Payable', 'Liability'), ('2100', 'Farm Loan', 'Liability'),
        ('3010', "Owner's Capital", 'Equity'), ('3020', 'Retained Earnings', 'Equity'),
        ('3998', 'Opening Balance Equity', 'Equity'),
        ('4010', 'Product Sales', 'Revenue'), ('4020', 'Service Revenue', 'Revenue'),
        ('4030', 'Phone Charging Revenue', 'Revenue'), # NEW ACCOUNT
        ('4101', 'Poultry Production Income', 'Revenue'),
        ('5010', 'Cost of Goods Sold', 'Expense'), 
        ('5020', 'Utilities Expense', 'Expense'),
        ('5030', 'Salaries Expense', 'Expense'),
        ('5040', 'Bank Fees', 'Expense'),
        ('6101', 'Poultry Feed Expense', 'Expense'),
        ('6102', 'Poultry Medication Expense', 'Expense'),
        ('6103', 'Poultry Labor Expense', 'Expense'),
        ('6104', 'Poultry Consultancy Expense', 'Expense'),
        ('6105', 'Poultry Other Expense', 'Expense'),
        ('6201', 'Livestock Loss Expense', 'Expense'),
        ('6301', 'Water Production Expenses', 'Expense'),
        ('6999', 'General Farm Expenses', 'Expense'),
    ]
    # Check if accounts table is empty before inserting
    if cursor.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0:
        cursor.executemany("INSERT INTO accounts (code, name, type) VALUES (?, ?, ?)", default_accounts)
        print(f"{len(default_accounts)} default accounts inserted.")
    else:
        print("Accounts table not empty, skipping default account insertion.")

    # Default Contact (If accounts were inserted, A/R should exist for auto-creation)
    if cursor.execute("SELECT COUNT(*) FROM contacts WHERE name = 'Walk-in Customer'").fetchone()[0] == 0:
        cursor.execute("INSERT INTO contacts (name, type) VALUES (?, ?)", ('Walk-in Customer', 'Customer'))
        print("Default 'Walk-in Customer' inserted.")
    else:
        print("'Walk-in Customer' already exists.")

    # Create First Admin User
    print("Creating initial admin user...")
    admin_password = 'admin'
    hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')

    cash_on_hand_id = cursor.execute("SELECT id FROM accounts WHERE name = 'Cash on Hand'").fetchone()
    admin_cash_account_id = cash_on_hand_id[0] if cash_on_hand_id else None

    if cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'").fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, email, password_hash, farm_name, role, cash_account_id) VALUES (?, ?, ?, ?, ?, ?)",
                       ('admin', 'admin@example.com', hashed_password, 'My Farm', 'admin', admin_cash_account_id))
        admin_user_id = cursor.lastrowid
        print(f"Admin user 'admin' with password '{admin_password}' created.")

        # Assign all permissions to the admin user
        all_permission_ids = cursor.execute("SELECT id FROM permissions").fetchall()
        user_perms_to_insert = [(admin_user_id, pid[0]) for pid in all_permission_ids]
        cursor.executemany("INSERT INTO user_permissions (user_id, permission_id) VALUES (?, ?)", user_perms_to_insert)
        print("All default permissions assigned to admin user.")
    else:
        print("Admin user 'admin' already exists, skipping creation.")


    # --- Finalize ---
    conn.commit()
    print("\nChanges committed to the database.")
    conn.close()
    print("Database connection closed.")


if __name__ == '__main__':
    # Uncomment this line if you want to completely wipe the existing database and start fresh
    # os.remove(DATABASE_NAME) 
    
    initialize_database()
    print("\nDatabase initialization process complete.")