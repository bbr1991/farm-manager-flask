-- update_live_db.sql (RESTRUCTURED FOR DEPENDENCIES)
-- This script updates your existing farm_data.db schema to the latest version.
-- Run this against your downloaded farm_data.db locally using `sqlite3 farm_data.db < update_live_db.sql`

PRAGMA foreign_keys = OFF; -- Temporarily disable FK checks for alterations

-- #############################################
-- 1. CREATE NEW TABLES (IF THEY DON'T EXIST) - All new tables first, respecting FK order
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
-- 2. ADD MISSING COLUMNS TO EXISTING TABLES (only columns not defined by CREATE TABLE IF NOT EXISTS)
-- #############################################

-- --- poultry_flocks table ---
-- These UPDATE statements should be done AFTER all relevant columns are added.
-- Only keep ALTER TABLE ADD COLUMN for columns you've confirmed are MISSING.
-- Assuming initial_chick_count, current_chick_count, initial_cost, status, transfer_date, final_chick_count, final_total_cost, final_sale_price, net_profit
-- are *already existing* from your previous debugging, so their ALTERs are removed.
-- IF any are still missing, add their ALTER TABLE here.

-- Backfill initial_chick_count (assuming existing 'bird_count' represents the initial count)
-- This requires 'bird_count' to still exist in poultry_flocks.
-- If 'bird_count' was already dropped, you need to decide how to initialize these.
-- For now, commenting out complex UPDATEs to avoid errors if bird_count doesn't exist.
-- If bird_count exists and you want to use it:
-- UPDATE poultry_flocks SET initial_chick_count = bird_count WHERE initial_chick_count IS NULL AND EXISTS (SELECT 1 FROM pragma_table_info('poultry_flocks') WHERE name='bird_count');
-- UPDATE poultry_flocks SET current_chick_count = bird_count WHERE current_chick_count IS NULL AND EXISTS (SELECT 1 FROM pragma_table_info('poultry_flocks') WHERE name='bird_count');
-- And then DROP COLUMN bird_count if it's no longer needed:
-- ALTER TABLE poultry_flocks DROP COLUMN bird_count; -- BE CAREFUL WITH DROP COLUMN


-- Set default to 0 if no bird_count to backfill (for current_chick_count etc.)
UPDATE poultry_flocks SET current_chick_count = 0 WHERE current_chick_count IS NULL;
UPDATE poultry_flocks SET initial_chick_count = 0 WHERE initial_chick_count IS NULL;
UPDATE poultry_flocks SET initial_cost = 0 WHERE initial_cost IS NULL;
UPDATE poultry_flocks SET cost_per_bird = 0 WHERE cost_per_bird IS NULL;
UPDATE poultry_flocks SET status = 'Active' WHERE status IS NULL;
UPDATE poultry_flocks SET final_total_cost = 0 WHERE final_total_cost IS NULL;
UPDATE poultry_flocks SET final_sale_price = 0 WHERE final_sale_price IS NULL;
UPDATE poultry_flocks SET net_profit = 0 WHERE net_profit IS NULL;



-- #############################################
-- 3. INSERT NEW DEFAULT DATA (IF NOT EXISTS)
-- #############################################

-- Insert new default permissions
INSERT OR IGNORE INTO permissions (name, description) VALUES ('manage_phone_charging', 'Can manage the phone charging service (check-in/out)');
-- Add any other new permissions (e.g., from init_db.py) here with INSERT OR IGNORE

-- Insert new default accounts
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('4030', 'Phone Charging Revenue', 'Revenue', 1, CURRENT_TIMESTAMP);
-- Add any other new accounts (e.g., from init_db.py) here with INSERT OR IGNORE
-- Ensure you have all Inventory - [Category] accounts (e.g., Inventory - Feed, Inventory - Medication, Inventory - Eggs, Inventory - Water Production, Inventory - Equipment, Inventory - Produce, Inventory - Other, Inventory - Finished Goods)
-- Ensure you have all Poultry/Water Expense accounts (e.g., Poultry Feed Expense, Poultry Medication Expense, Poultry Labor Expense, Poultry Consultancy Expense, Poultry Other Expense, Livestock Loss Expense, Water Production Expenses, General Farm Expenses)
-- Ensure you have Poultry Production Income

PRAGMA foreign_keys = ON; -- Re-enable FK checks