import sqlite3

def setup_fish_vet():
    conn = sqlite3.connect('farm_data.db')
    cursor = conn.cursor()
    print("🩺 Upgrading Vet Database for Fishery...")

    # 1. Add 'category' column to existing tables if missing
    # This allows us to separate Chicken symptoms from Fish symptoms
    tables = ['vet_symptoms', 'vet_diseases']
    for table in tables:
        try:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN category TEXT DEFAULT 'Poultry'")
            print(f"Added 'category' column to {table}")
        except sqlite3.OperationalError:
            print(f"'category' column already exists in {table}")

    # 2. Define Catfish Symptoms
    fish_symptoms = [
        "Fish hanging vertically at surface",
        "Gasping for air / Rapid gill movement",
        "White patches on skin/fins",
        "Red sores / Ulcers on body",
        "Eroded / Rotting fins (Fin Rot)",
        "Swollen belly (Dropsy)",
        "Pop-eye (Bulging eyes)",
        "Rubbing body against pond walls (Flashing)",
        "Erratic swimming / Whirling",
        "Skin peeling off",
        "Yellowish fluid in belly",
        "Curved spine / Deformity"
    ]

    symptom_map = {}
    for sym in fish_symptoms:
        # Insert if not exists
        cursor.execute("SELECT id FROM vet_symptoms WHERE name = ?", (sym,))
        row = cursor.fetchone()
        if row:
            symptom_map[sym] = row[0]
            # Ensure it is marked as Fish
            cursor.execute("UPDATE vet_symptoms SET category = 'Fish' WHERE id = ?", (row[0],))
        else:
            cursor.execute("INSERT INTO vet_symptoms (name, category) VALUES (?, 'Fish')", (sym,))
            symptom_map[sym] = cursor.lastrowid

    # 3. Define Catfish Diseases
    fish_diseases = [
        {
            "name": "Ammonia Poisoning",
            "desc": "Caused by high waste levels/uneaten feed. Burns gills and darkens skin.",
            "treat": "Stop feeding immediately. Change 50% water daily. Reduce stocking density.",
            "prev": "Regular water changes. Don't overfeed.",
            "symptoms": ["Gasping for air / Rapid gill movement", "Red sores / Ulcers on body", "Erratic swimming / Whirling"]
        },
        {
            "name": "Columnaris (Fin Rot)",
            "desc": "Bacterial infection usually following stress or rough handling.",
            "treat": "Potassium Permanganate bath or Oxytetracycline in feed.",
            "prev": "Avoid handling fish roughly. Maintain good water quality.",
            "symptoms": ["White patches on skin/fins", "Eroded / Rotting fins (Fin Rot)", "Skin peeling off"]
        },
        {
            "name": "Aeromonas (Red Pest)",
            "desc": "Bacterial hemorrhagic septicemia.",
            "treat": "Antibiotics (Oxytetracycline or Erythromycin) in feed for 7-10 days.",
            "prev": "Prevent overcrowding and high organic load.",
            "symptoms": ["Red sores / Ulcers on body", "Swollen belly (Dropsy)", "Pop-eye (Bulging eyes)"]
        },
        {
            "name": "Saprolegnia (Fungal)",
            "desc": "Cotton-wool like growth on skin, usually secondary to injury.",
            "treat": "Salt bath (3-5ppt) or Formalin treatment.",
            "prev": "Remove dead fish immediately. Handle with care.",
            "symptoms": ["White patches on skin/fins", "Rubbing body against pond walls (Flashing)"]
        },
        {
            "name": "Cracked Skull Disease",
            "desc": "Nutritional deficiency (Vitamin C) or water pollution.",
            "treat": "Add Vitamin C to feed. Improve water quality.",
            "prev": "Use high-quality feed rich in Vitamin C.",
            "symptoms": ["Red sores / Ulcers on body", "Curved spine / Deformity", "Fish hanging vertically at surface"]
        },
        {
            "name": "Dropsy (Bloat)",
            "desc": "Internal bacterial infection causing fluid accumulation.",
            "treat": "Difficult to cure. Isolate sick fish. Antibiotics may help early.",
            "prev": "Maintain clean water.",
            "symptoms": ["Swollen belly (Dropsy)", "Yellowish fluid in belly", "Pop-eye (Bulging eyes)"]
        }
    ]

    # 4. Link Diseases to Symptoms
    for disease in fish_diseases:
        # Check if disease exists
        cursor.execute("SELECT id FROM vet_diseases WHERE name = ?", (disease["name"],))
        row = cursor.fetchone()
        
        if row:
            disease_id = row[0]
            cursor.execute("UPDATE vet_diseases SET category = 'Fish' WHERE id = ?", (disease_id,))
        else:
            cursor.execute("""
                INSERT INTO vet_diseases (name, description, treatment_plan, prevention_plan, category) 
                VALUES (?, ?, ?, ?, 'Fish')
            """, (disease["name"], disease["desc"], disease["treat"], disease["prev"]))
            disease_id = cursor.lastrowid

        # Link symptoms
        for sym_name in disease["symptoms"]:
            if sym_name in symptom_map:
                sym_id = symptom_map[sym_name]
                # Avoid duplicates
                cursor.execute("SELECT * FROM vet_disease_symptoms WHERE disease_id=? AND symptom_id=?", (disease_id, sym_id))
                if not cursor.fetchone():
                    cursor.execute("INSERT INTO vet_disease_symptoms (disease_id, symptom_id) VALUES (?, ?)", (disease_id, sym_id))

    conn.commit()
    conn.close()
    print("✅ Fish Vet Data Loaded Successfully!")

if __name__ == "__main__":
    setup_fish_vet()