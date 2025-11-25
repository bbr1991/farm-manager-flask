import sqlite3

conn = sqlite3.connect('farm_data.db')
cursor = conn.cursor()

print("Setting up Feed Formulation Tables...")

# 1. Ingredients Table (Stores nutritional info)
cursor.execute("""
CREATE TABLE IF NOT EXISTS feed_ingredients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,
    cp_percent REAL, -- Crude Protein %
    me_value REAL,   -- Energy (Kcal/kg)
    price_per_kg REAL
);
""")

# 2. Saved Formulas (To save your recipes)
cursor.execute("""
CREATE TABLE IF NOT EXISTS feed_formulas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    batch_size_kg REAL,
    final_cp_percent REAL,
    final_me_value REAL,
    cost_per_kg REAL,
    ingredients_json TEXT, -- Stores the mix details
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")

# 3. Seed Data (Standard Nigerian Poultry Ingredients)
# Name, Protein%, Energy(ME), Approx Price/kg
ingredients = [
    ('Maize', 8.5, 3350, 600),
    ('Soya Bean Meal', 44.0, 2230, 1100),
    ('Groundnut Cake (GNC)', 45.0, 2600, 900),
    ('Wheat Offal', 15.0, 1900, 300),
    ('Fish Meal (72%)', 72.0, 2800, 1800),
    ('Bone Meal', 0, 0, 200),
    ('Limestone/Oyster Shell', 0, 0, 150),
    ('Broiler Premix', 0, 0, 2500),
    ('Layer Premix', 0, 0, 2500),
    ('Methionine', 99, 0, 8000),
    ('Lysine', 99, 0, 6000),
    ('Salt', 0, 0, 200)
]

for ing in ingredients:
    try:
        cursor.execute("INSERT INTO feed_ingredients (name, cp_percent, me_value, price_per_kg) VALUES (?, ?, ?, ?)", ing)
    except sqlite3.IntegrityError:
        pass # Skip if exists

conn.commit()
conn.close()
print("Feed Formulation Database Ready!")