import sqlite3

def setup_fish_ingredients():
    conn = sqlite3.connect('farm_data.db')
    cursor = conn.cursor()
    print("🐟 Setting up Fish Feed Ingredients...")

    # 1. Add 'category' column to ingredients table if it doesn't exist
    try:
        cursor.execute("ALTER TABLE feed_ingredients ADD COLUMN category TEXT DEFAULT 'General'")
        print("Added 'category' column to feed_ingredients.")
    except sqlite3.OperationalError:
        print("'category' column already exists.")

    # 2. Specific African Catfish Ingredients (High Protein + Floating Agents)
    # Name, CP%, ME (Energy), Price/kg, Category
    fish_ingredients = [
        ('Fish Meal (72%)', 72.0, 2800, 1500, 'Fish'),
        ('Imported Fish Meal (65%)', 65.0, 2900, 1800, 'Fish'),
        ('Soya Bean Meal (Toasted)', 44.0, 2230, 1100, 'Fish'),
        ('Groundnut Cake (GNC)', 45.0, 2600, 950, 'Fish'),
        ('Maize', 9.0, 3350, 600, 'Fish'),
        ('Cassava Flour (Binder/Floating)', 2.0, 3000, 400, 'Fish'),
        ('Wheat Offal', 15.0, 1900, 300, 'Fish'),
        ('Fish Premix (Grower)', 0, 0, 3500, 'Fish'),
        ('Fish Premix (Finisher)', 0, 0, 3500, 'Fish'),
        ('Methionine', 99, 0, 8000, 'Fish'),
        ('Lysine', 99, 0, 6000, 'Fish'),
        ('Bone Meal', 0, 0, 200, 'Fish'),
        ('Salt', 0, 0, 200, 'Fish'),
        ('Vitamin C (Anti-stress)', 0, 0, 12000, 'Fish')
    ]

    for name, cp, me, price, cat in fish_ingredients:
        # Check if ingredient exists, if so, update category, else insert
        exists = cursor.execute("SELECT id FROM feed_ingredients WHERE name = ?", (name,)).fetchone()
        if exists:
            cursor.execute("UPDATE feed_ingredients SET category = ? WHERE id = ?", (cat, exists[0]))
        else:
            cursor.execute("""
                INSERT INTO feed_ingredients (name, cp_percent, me_value, price_per_kg, category)
                VALUES (?, ?, ?, ?, ?)
            """, (name, cp, me, price, cat))

    conn.commit()
    conn.close()
    print("✅ Fish Ingredients Loaded Successfully!")

if __name__ == "__main__":
    setup_fish_ingredients()