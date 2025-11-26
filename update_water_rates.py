import sqlite3

def update_water_rates():
    conn = sqlite3.connect('farm_data.db')
    cursor = conn.cursor()
    print("💧 Updating Water Database for Piece-Rate Logic...")

    # 1. Create a Settings table for Water Rates
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS water_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        production_manager_rate REAL DEFAULT 0, -- Per 100 Sachets
        selling_manager_rate REAL DEFAULT 0,    -- Per 100 Sachets
        carriage_labor_rate REAL DEFAULT 0,     -- Per Sachet/Bundle
        leather_yield_per_kg REAL DEFAULT 0     -- How many bundles does 1kg of leather produce? (Approx)
    );
    """)

    # Initialize default settings if empty
    cursor.execute("SELECT count(*) FROM water_settings")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO water_settings (production_manager_rate, selling_manager_rate, carriage_labor_rate, leather_yield_per_kg) VALUES (0, 0, 0, 0)")

    # 2. Update Production Log to store broken-down costs
    try:
        cursor.execute("ALTER TABLE water_production_log ADD COLUMN production_manager_cost REAL DEFAULT 0")
        cursor.execute("ALTER TABLE water_production_log ADD COLUMN selling_manager_cost REAL DEFAULT 0")
        cursor.execute("ALTER TABLE water_production_log ADD COLUMN carriage_cost REAL DEFAULT 0")
        cursor.execute("ALTER TABLE water_production_log ADD COLUMN bundles_produced REAL DEFAULT 0")
    except sqlite3.OperationalError:
        pass # Columns might already exist

    conn.commit()
    conn.close()
    print("✅ Water Module Updated!")

if __name__ == "__main__":
    update_water_rates()