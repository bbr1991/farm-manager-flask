-- master_schema_updates.sql

-- IMPORTANT: Run these CREATE TABLE IF NOT EXISTS first for new tables
-- (Order matters due to foreign keys)

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

-- New table: water_production_log (depends on water_products - if water_products is new, it needs a CREATE TABLE IF NOT EXISTS too)
-- Assuming water_products is defined in init_db.py, if not, add its CREATE TABLE IF NOT EXISTS here too.
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


-- ALTER TABLE statements for existing tables
-- (Only add columns that are MISSING from your *live* PythonAnywhere DB)

-- For poultry_flocks (this is the one causing the current error: no such column: current_chick_count)
-- If your live DB's poultry_flocks table has 'bird_count', you need to add ALL the new columns.
-- Check your live DB's poultry_flocks schema first!
-- ASSUMPTION: Your live DB's poultry_flocks is missing most of these, based on your errors.
-- If 'bird_count' exists but 'initial_chick_count' does not, you might need to add it and initialize it.
-- It's safer to add all expected new columns and provide a default.
ALTER TABLE poultry_flocks ADD COLUMN initial_chick_count INTEGER DEFAULT 0;
UPDATE poultry_flocks SET initial_chick_count = bird_count WHERE initial_chick_count = 0; -- Assuming 'bird_count' was the initial count
ALTER TABLE poultry_flocks ADD COLUMN current_chick_count INTEGER DEFAULT 0;
UPDATE poultry_flocks SET current_chick_count = bird_count WHERE current_chick_count = 0; -- Initialize with existing bird_count
ALTER TABLE poultry_flocks ADD COLUMN initial_cost REAL DEFAULT 0;
ALTER TABLE poultry_flocks ADD COLUMN cost_per_bird REAL DEFAULT 0;
ALTER TABLE poultry_flocks ADD COLUMN transfer_date TEXT;
ALTER TABLE poultry_flocks ADD COLUMN final_chick_count INTEGER;
ALTER TABLE poultry_flocks ADD COLUMN final_total_cost REAL;
ALTER TABLE poultry_flocks ADD COLUMN final_sale_price REAL;
ALTER TABLE poultry_flocks ADD COLUMN net_profit REAL;
ALTER TABLE poultry_flocks ADD COLUMN status TEXT DEFAULT 'Active'; -- Or update existing status if it's different
UPDATE poultry_flocks SET status = 'Active' WHERE status IS NULL; -- Ensure existing flocks get a default status

-- For accounts (if created_at is missing)
-- ALTER TABLE accounts ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP; -- Only if truly missing

-- For users (if cash_account_id is missing)
ALTER TABLE users ADD COLUMN cash_account_id INTEGER;
-- Note: Cannot add FOREIGN KEY constraint directly with ALTER TABLE in SQLite easily without recreating table.
-- It's often handled by application logic.

-- For contacts (if assigned_user_id is missing)
ALTER TABLE contacts ADD COLUMN assigned_user_id INTEGER;
-- Note: Same as above for FK.

-- For journal_entries (if related_flock_id, created_at, is_closed are missing)
ALTER TABLE journal_entries ADD COLUMN related_flock_id INTEGER;
ALTER TABLE journal_entries ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE journal_entries ADD COLUMN is_closed INTEGER DEFAULT 0;

-- For egg_log (if crates, pieces, spoiled_count, feed_cost are missing)
-- WARNING: If your current egg_log only has 'quantity', adding 'crates', 'pieces', 'spoiled_count' will make them NULL.
-- You might need a more complex migration script to backfill these from 'quantity' if possible.
ALTER TABLE egg_log ADD COLUMN crates INTEGER DEFAULT 0;
ALTER TABLE egg_log ADD COLUMN pieces INTEGER DEFAULT 0;
ALTER TABLE egg_log ADD COLUMN spoiled_count INTEGER DEFAULT 0;
ALTER TABLE egg_log ADD COLUMN feed_cost REAL DEFAULT 0;
-- If you want to guess initial crates/pieces from existing quantity:
-- UPDATE egg_log SET crates = quantity / 30, pieces = quantity % 30 WHERE crates = 0 AND pieces = 0;

-- For water_products (if inventory_item_id is missing)
ALTER TABLE water_products ADD COLUMN inventory_item_id INTEGER UNIQUE;
-- You'll need to manually link these in the app later if data exists already.

-- For permissions (add new descriptions if existing table lacked it)
ALTER TABLE permissions ADD COLUMN description TEXT;
-- UPDATE permissions SET description = '...' WHERE name = '...'; for existing ones

-- For user_permissions (if created_at is missing)
ALTER TABLE user_permissions ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP;


-- Insert new default permissions (if they don't exist)
-- These are safer to run with "INSERT OR IGNORE" to avoid errors if some already exist.
-- You'll need to manually manage the permissions for your existing admin user.
INSERT OR IGNORE INTO permissions (name, description) VALUES ('manage_phone_charging', 'Can manage the phone charging service (check-in/out)');
-- Add all other new permissions from init_db.py here with INSERT OR IGNORE

-- Insert new default accounts (if they don't exist)
INSERT OR IGNORE INTO accounts (code, name, type, is_active, created_at) VALUES ('4030', 'Phone Charging Revenue', 'Revenue', 1, CURRENT_TIMESTAMP);
-- Add all other new accounts from init_db.py here with INSERT OR IGNORE

-- Final update: Ensure old 'bird_count' data is copied to 'initial_chick_count' and 'current_chick_count' IF 'bird_count' existed
-- This relies on the column existing temporarily. Only run if you haven't dropped bird_count
-- If 'bird_count' column already removed, skip this.
-- ALTER TABLE poultry_flocks ADD COLUMN IF NOT EXISTS old_bird_count INTEGER; -- Temporary column if needed
-- UPDATE poultry_flocks SET old_bird_count = bird_count; -- Copy existing data
-- ALTER TABLE poultry_flocks DROP COLUMN bird_count; -- Remove old column
-- This is complex, better to just update new columns with sensible defaults and then query current_chick_count.