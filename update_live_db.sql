-- update_live_db.sql (ULTIMATE VERSION: Tailored to your PythonAnywhere poultry_flocks schema)
-- This script updates your existing farm_data.db schema on PythonAnywhere.
-- Run this locally first for testing: `python run_sql_updates.py`

PRAGMA foreign_keys = OFF; -- Temporarily disable FK checks for alterations

-- #############################################
-- SECTION A: CREATE NEW TABLES (IF THEY DON'T EXIST) - All new tables first, respecting FK order
-- #############################################

-- New table: clients
CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone_number TEXT UNIQUE,
    email TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- New table: charging_cards
CREATE TABLE IF NOT EXISTS charging_cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    is_available INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- New table: brooding_batches
CREATE TABLE IF NOT EXISTS brooding_batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_name TEXT NOT NULL UNIQUE,
    breed TEXT NOT NULL,
    arrival_date TEXT NOT NULL,
    initial_chick_count INTEGER NOT NULL,
    initial_cost REAL DEFAULT 0,
    current_chick_count INTEGER NOT NULL,
    status TEXT DEFAULT 'Brooding',
    transfer_date TEXT,
    final_chick_count INTEGER,
    final_total_cost REAL,
    final_cost_per_bird REAL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- New table: daily_closures
CREATE TABLE IF NOT EXISTS daily_closures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    closure_date TEXT NOT NULL UNIQUE,
    closed_at TEXT DEFAULT CURRENT_TIMESTAMP,
    closed_by_user_id INTEGER NOT NULL,
    FOREIGN KEY (closed_by_user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- New table: brooding_log (depends on brooding_batches)
CREATE TABLE IF NOT EXISTS brooding_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_date TEXT NOT NULL,
    batch_id INTEGER NOT NULL,
    mortality_count INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (batch_id) REFERENCES brooding_batches(id) ON DELETE CASCADE
);

-- New table: water_products (if not already existing from earlier updates, necessary before water_production_log)
CREATE TABLE IF NOT EXISTS water_products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    price REAL NOT NULL, -- Sale price per unit
    quantity REAL NOT NULL DEFAULT 0, -- Stock level of finished water products
    inventory_item_id INTEGER UNIQUE, -- Links to inventory item for sales, nullable for initial creation
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (inventory_item_id) REFERENCES inventory(id) ON DELETE SET NULL
);

-- New table: water_production_log (depends on water_products)
CREATE TABLE IF NOT EXISTS water_production_log (
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
);

-- New table: sales_packages (if missing)
-- This assumes 'inventory' table exists (it's an existing table, covered in ALTERs or already existed)
CREATE TABLE IF NOT EXISTS sales_packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT NOT NULL UNIQUE,
    base_inventory_item_id INTEGER NOT NULL,
    quantity_per_package REAL NOT NULL,
    sale_price REAL NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (base_inventory_item_id) REFERENCES inventory(id) ON DELETE CASCADE
);

-- New table: sales (if missing)
-- This assumes 'contacts' and 'users' tables exist (they are existing tables)
CREATE TABLE IF NOT EXISTS sales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sale_date TEXT NOT NULL,
    total_amount REAL NOT NULL,
    contact_id INTEGER,
    created_by_user_id INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (contact_id) REFERENCES contacts (id),
    FOREIGN KEY (created_by_user_id) REFERENCES users (id)
);

-- New table: charging_transactions (depends on charging_cards, clients, accounts, users)
CREATE TABLE IF NOT EXISTS charging_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id INTEGER NOT NULL,
    client_id INTEGER,
    client_name TEXT NOT NULL,
    client_phone TEXT,
    phone_description TEXT NOT NULL,
    imei_number TEXT,
    check_in_time TEXT DEFAULT CURRENT_TIMESTAMP,
    check_out_time TEXT,
    status TEXT NOT NULL DEFAULT 'charging',
    fee REAL DEFAULT 0,
    fee_account_id INTEGER,
    collected_by_user_id INTEGER,
    created_by_user_id INTEGER NOT NULL,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (card_id) REFERENCES charging_cards(id) ON DELETE RESTRICT,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL,
    FOREIGN KEY (fee_account_id) REFERENCES accounts(id) ON DELETE SET NULL,
    FOREIGN KEY (collected_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE CASCADE
);


-- #############################################
-- SECTION B: ADD MISSING COLUMNS TO EXISTING TABLES (based on YOUR .schema output)
-- This MUST run after new tables are created (Section A).
-- For each column, check if it's truly missing using `.schema <table_name>`.
-- If an ALTER TABLE ADD COLUMN succeeds, its corresponding UPDATE will follow.
-- #############################################

-- --- poultry_flocks table ---
-- Based on YOUR `.schema poultry_flocks` output:
-- bird_count, status, created_at, final_sale_price, total_cost, net_profit, cost_per_bird all EXIST.
-- The following need to be ADDED:
ALTER TABLE poultry_flocks ADD COLUMN initial_chick_count INTEGER;
ALTER TABLE poultry_flocks ADD COLUMN current_chick_count INTEGER;
ALTER TABLE poultry_flocks ADD COLUMN initial_cost REAL;
ALTER TABLE poultry_flocks ADD COLUMN transfer_date TEXT;
ALTER TABLE poultry_flocks ADD COLUMN final_chick_count INTEGER;
ALTER TABLE poultry_flocks ADD COLUMN final_total_cost REAL; -- This was missing
-- UPDATE statements to backfill/default (run after ALTERs)
UPDATE poultry_flocks SET initial_chick_count = bird_count WHERE initial_chick_count IS NULL; -- Use existing bird_count
UPDATE poultry_flocks SET current_chick_count = bird_count WHERE current_chick_count IS NULL; -- Use existing bird_count
UPDATE poultry_flocks SET initial_cost = 0 WHERE initial_cost IS NULL;
UPDATE poultry_flocks SET transfer_date = NULL WHERE transfer_date IS NULL;
UPDATE poultry_flocks SET final_chick_count = 0 WHERE final_chick_count IS NULL;
UPDATE poultry_flocks SET final_total_cost = 0 WHERE final_total_cost IS NULL;

-- --- accounts table ---
-- Based on your history, 'created_at' probably exists. If not, re-add ALTER TABLE here.
-- Assuming created_at exists.


-- --- users table ---
-- Based on your history, 'cash_account_id' and 'created_at' probably exist.
-- Assuming cash_account_id and created_at exist.
-- If 'created_at' for users was missing:
-- ALTER TABLE users ADD COLUMN created_at TEXT;
-- UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL;


-- --- contacts table ---
-- 'assigned_user_id' might be missing. Add if you confirm. 'created_at' probably exists.
ALTER TABLE contacts ADD COLUMN assigned_user_id INTEGER;
UPDATE contacts SET assigned_user_id = NULL WHERE assigned_user_id IS NULL;
-- If 'created_at' for contacts was missing:
-- ALTER TABLE contacts ADD COLUMN created_at TEXT;
-- UPDATE contacts SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL;


-- --- journal_entries table ---
-- 'related_flock_id', 'created_at', 'is_closed' might be missing. Add if you confirm.
ALTER TABLE journal_entries ADD COLUMN related_flock_id INTEGER;
UPDATE journal_entries SET related_flock_id = NULL WHERE related_flock_id IS NULL;
ALTER TABLE journal_entries ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP; -- Re-adding with default
UPDATE journal_entries SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL;
ALTER TABLE journal_entries ADD COLUMN is_closed INTEGER DEFAULT 0;
UPDATE journal_entries SET is_closed = 0 WHERE is_closed IS NULL;


-- --- egg_log table ---
-- 'crates', 'pieces', 'spoiled_count', 'feed_cost' might be missing. Add if you confirm.
ALTER TABLE egg_log ADD COLUMN crates INTEGER DEFAULT 0;
UPDATE egg_log SET crates = 0 WHERE crates IS NULL;
ALTER TABLE egg_log ADD COLUMN pieces INTEGER DEFAULT 0;
UPDATE egg_log SET pieces = 0 WHERE pieces IS NULL;
ALTER TABLE egg_log ADD COLUMN spoiled_count INTEGER DEFAULT 0;
UPDATE egg_log SET spoiled_count = 0 WHERE spoiled_count IS NULL;
ALTER TABLE egg_log ADD COLUMN feed_cost REAL DEFAULT 0;
UPDATE egg_log SET feed_cost = 0 WHERE feed_cost IS NULL;
-- Backfill crates/pieces from existing quantity if quantity is known:
-- UPDATE egg_log SET crates = quantity / 30, pieces = quantity % 30 WHERE crates = 0 AND pieces = 0 AND quantity IS NOT NULL;


-- --- water_products table ---
-- 'inventory_item_id' might be missing. 'created_at' probably exists.
ALTER TABLE water_products ADD COLUMN inventory_item_id INTEGER UNIQUE;
UPDATE water_products SET inventory_item_id = NULL WHERE inventory_item_id IS NULL;
-- If 'created_at' for water_products was missing:
-- ALTER TABLE water_products ADD COLUMN created_at TEXT;
-- UPDATE water_products SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL;


-- --- permissions table ---
-- 'description' might be missing. 'created_at' probably exists.
ALTER TABLE permissions ADD COLUMN description TEXT;
UPDATE permissions SET description = '' WHERE description IS NULL;
-- If 'created_at' for permissions was missing:
-- ALTER TABLE permissions ADD COLUMN created_at TEXT;
-- UPDATE permissions SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL;


-- --- user_permissions table ---
-- 'created_at' might be missing.
ALTER TABLE user_permissions ADD COLUMN created_at TEXT;
UPDATE user_permissions SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL;


-- --- inventory table ---
-- 'created_at' might be missing.
ALTER TABLE inventory ADD COLUMN created_at TEXT;
UPDATE inventory SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL;


-- #############################################
-- SECTION C: INSERT NEW DEFAULT DATA (IF NOT EXISTS)
-- #############################################

-- Insert new default permissions
INSERT OR IGNORE INTO permissions (name, description) VALUES ('manage_phone_charging', 'Can manage the phone charging service (check-in/out)');
-- Add any other new permissions from init_db.py here with INSERT OR IGNORE
INSERT OR IGNORE INTO permissions (name, description) VALUES ('view_poultry_dashboard', 'Can view the poultry laying flocks dashboard');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('add_poultry_flock', 'Can add new poultry flocks');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('log_poultry_eggs', 'Can log daily egg production for flocks');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('log_poultry_mortality', 'Can log mortality for laying flocks');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('deactivate_poultry_flock', 'Can deactivate/sell a laying flock and finalize its profit/loss');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('view_brooding_dashboard', 'Can view the brooding section dashboard');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('add_brooding_batch', 'Can add new brooding batches');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('log_brooding_mortality', 'Can log mortality for brooding batches');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('log_inventory_usage', 'Can log the usage of any inventory item (e.g., feed, medication)');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('transfer_brooding_batch', 'Can transfer chicks from a brooding batch to a laying flock');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('view_water_dashboard', 'Can view the water production dashboard');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('add_water_product', 'Can add new water products');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('log_water_production', 'Can log daily water production runs');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('edit_water_product', 'Can edit water product details');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('edit_production_log', 'Can edit/delete water production logs and associated costs');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('calculate_water_cost', 'Can calculate and finalize costs for water production runs');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('view_inventory_dashboard', 'Can view the inventory dashboard');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('add_inventory_item', 'Can add new types of inventory items');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('add_inventory_stock', 'Can add stock to existing inventory items');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('edit_inventory_item', 'Can edit existing inventory item details');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('delete_inventory_item', 'Can delete inventory items (if no usage history)');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('view_sales_packages', 'Can view and manage sales packages');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('add_contact', 'Can add new customer or supplier contacts');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('edit_contact', 'Can edit existing contact details');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('delete_contact', 'Can delete contacts (if no related transactions)');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('assign_contact_user', 'Can assign users to manage specific contacts');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('view_contacts_dashboard', 'Can view the contacts dashboard and individual ledgers');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('view_financial_center', 'Can view the main financial center dashboard');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('view_chart_of_accounts', 'Can view the Chart of Accounts');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('add_chart_of_accounts', 'Can add new accounts to the Chart of Accounts');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('view_general_journal', 'Can view the General Journal');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('add_manual_journal_entry', 'Can create manual journal entries');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('reverse_journal_entry', 'Can reverse existing journal entries');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('record_new_sale', 'Can record new Point of Sale transactions');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('record_customer_transaction', 'Can record customer deposits and credit sales');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('record_batch_deposit', 'Can record multiple customer deposits at once');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('record_new_expense', 'Can record general expenses and purchases (including inventory stock updates)');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('record_batch_expense', 'Can record multiple expenses in a single batch');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('view_reports_dashboard', 'Can view the reports center and access all reports');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('run_financial_reports', 'Can run Profit & Loss, Balance Sheet, Trial Balance reports');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('run_operational_reports', 'Can run inventory, egg, water, flock, brooding reports');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('run_brooding_report', 'Can view detailed brooding reports');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('run_mortality_report', 'Can view detailed mortality reports');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('view_admin_panel', 'Can view the admin dashboard');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('add_users', 'Can create new users');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('manage_users', 'Can edit user permissions and delete users');
INSERT OR IGNORE INTO permissions (name, description) VALUES ('close_day', 'Can close a financial day (admin function)');


-- Insert new default accounts
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('4030', 'Phone Charging Revenue', 'Revenue', 1, CURRENT_TIMESTAMP);
-- Add other new accounts (e.g., from init_db.py) here with INSERT OR IGNORE
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('1030', 'Moniepoint MFB Account', 'Asset', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('1201', 'Inventory - Feed', 'Asset', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('1202', 'Inventory - Medication', 'Asset', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('1203', 'Inventory - Eggs', 'Asset', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('1204', 'Inventory - Water Production', 'Asset', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('1205', 'Inventory - Equipment', 'Asset', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('1206', 'Inventory - Produce', 'Asset', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('1207', 'Inventory - Other', 'Asset', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('1208', 'Inventory - Finished Goods', 'Asset', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('1301', 'Inventory - Laying Flock Asset', 'Asset', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('1302', 'Inventory - Brooding Livestock', 'Asset', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('4101', 'Poultry Production Income', 'Revenue', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('5010', 'Cost of Goods Sold', 'Expense', 1, CURRENT_TIMESTAMP); -- This was in old default_accounts
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('5020', 'Utilities Expense', 'Expense', 1, CURRENT_TIMESTAMP); -- This was in old default_accounts
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('5030', 'Salaries Expense', 'Expense', 1, CURRENT_TIMESTAMP); -- This was in old default_accounts
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('5040', 'Bank Fees', 'Expense', 1, CURRENT_TIMESTAMP); -- This was in old default_accounts
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('6101', 'Poultry Feed Expense', 'Expense', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('6102', 'Poultry Medication Expense', 'Expense', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('6103', 'Poultry Labor Expense', 'Expense', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('6104', 'Poultry Consultancy Expense', 'Expense', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('6105', 'Poultry Other Expense', 'Expense', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('6201', 'Livestock Loss Expense', 'Expense', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('6301', 'Water Production Expenses', 'Expense', 1, CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('6999', 'General Farm Expenses', 'Expense', 1, CURRENT_TIMESTAMP);


PRAGMA foreign_keys = ON; -- Re-enable FK checks