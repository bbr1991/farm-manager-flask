import sqlite3

def setup_fishery():
    conn = sqlite3.connect('farm_data.db')
    cursor = conn.cursor()
    print("🐟 Setting up Fishery Database...")

    # 1. Create Ponds Table (Where the fish live)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS fish_ponds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL, -- e.g., "Earthen Pond 1", "Tank A"
        type TEXT, -- Concrete, Earthen, Tarpaulin, Plastic
        capacity_liters REAL,
        status TEXT DEFAULT 'Empty' -- Empty, Stocked, Maintenance
    );
    """)

    # 2. Create Fish Batches Table (The specific group of fish)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS fish_batches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        batch_name TEXT NOT NULL, -- e.g., "Catfish Batch Jan 2025"
        pond_id INTEGER,
        species TEXT DEFAULT 'African Catfish',
        stocking_date DATE,
        initial_quantity INTEGER,
        current_quantity INTEGER,
        initial_avg_weight_g REAL, -- Weight of fingerlings in grams
        initial_cost REAL, -- Cost of purchasing fingerlings
        status TEXT DEFAULT 'Active', -- Active, Harvested
        
        -- Harvest Data
        harvest_date DATE,
        total_harvest_weight_kg REAL,
        total_sales_amount REAL,
        total_expenses REAL,
        net_profit REAL,
        cost_per_kg REAL,
        
        FOREIGN KEY(pond_id) REFERENCES fish_ponds(id)
    );
    """)

    # 3. Create Daily Fish Log (Feeding, Mortality, Water Change)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS fish_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        log_date DATE,
        batch_id INTEGER,
        activity_type TEXT, -- 'Feeding', 'Mortality', 'Water Change', 'Sampling'
        
        -- Details
        inventory_item_id INTEGER, -- If feeding
        quantity_used REAL, -- Kg of feed
        cost_of_activity REAL, -- Cost of feed or labor
        
        mortality_count INTEGER,
        sampled_avg_weight_g REAL, -- To track growth
        notes TEXT,
        
        FOREIGN KEY(batch_id) REFERENCES fish_batches(id)
    );
    """)

    # 4. Create Financial Accounts for Fishery
    accounts_to_create = [
        ('Inventory - Fish Stock', 'Asset'),      # Value of live fish
        ('Fish Sales Income', 'Revenue'),         # Money from selling fish
        ('Fish Feed Expense', 'Expense'),         # Cost of floating/sinking feed
        ('Fish Medication Expense', 'Expense'),   # Antibiotics, salt, etc.
        ('Fish Labor/Ops Expense', 'Expense')     # Pumping water, labor
    ]

    for name, acc_type in accounts_to_create:
        # Check if exists
        exists = cursor.execute("SELECT id FROM accounts WHERE name = ?", (name,)).fetchone()
        if not exists:
            # Generate code logic (simplified)
            prefix = '1' if acc_type == 'Asset' else ('4' if acc_type == 'Revenue' else '6')
            cursor.execute("INSERT INTO accounts (code, name, type, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", 
                           (f"{prefix}99{len(name)}", name, acc_type))
            print(f"Created Account: {name}")

    conn.commit()
    conn.close()
    print("✅ Fishery Module Ready!")

if __name__ == "__main__":
    setup_fishery()