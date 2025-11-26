import sqlite3

def update_water_v2():
    conn = sqlite3.connect('farm_data.db')
    cursor = conn.cursor()
    print("💧 Updating Water Module for Material Costing & Promos...")

    # 1. Add Material Cost column to Production Log
    try:
        cursor.execute("ALTER TABLE water_production_log ADD COLUMN material_cost REAL DEFAULT 0")
        print("Added 'material_cost' to production log.")
    except:
        pass

    # 2. Add Promo Rate to Settings (How many promo sachets per 100 sold?)
    try:
        cursor.execute("ALTER TABLE water_settings ADD COLUMN promo_sachets_rate INTEGER DEFAULT 0")
        print("Added 'promo_sachets_rate' to settings.")
    except:
        pass

    conn.commit()
    conn.close()
    print("✅ Database Updated Successfully!")

if __name__ == "__main__":
    update_water_v2()