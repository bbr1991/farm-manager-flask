import sqlite3

conn = sqlite3.connect('farm_data.db')
cursor = conn.cursor()

print("Creating Veterinary Tables...")

# 1. Diseases Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS vet_diseases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    treatment_plan TEXT
);
""")

# 2. Symptoms Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS vet_symptoms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL
);
""")

# 3. Link Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS vet_disease_symptoms (
    disease_id INTEGER,
    symptom_id INTEGER,
    FOREIGN KEY(disease_id) REFERENCES vet_diseases(id),
    FOREIGN KEY(symptom_id) REFERENCES vet_symptoms(id)
);
""")

# Seed Data
symptoms = [
    ('Blood in stool',), ('Diarrhea (White)',), ('Diarrhea (Green)',), 
    ('Droopy wings',), ('Coughing/Sneezing',), ('Swollen head',), 
    ('Paralysis',), ('Reduced egg production',), ('Sudden death',)
]
cursor.executemany("INSERT OR IGNORE INTO vet_symptoms (name) VALUES (?)", symptoms)

diseases = [
    ('Coccidiosis', 'Parasitic disease.', 'Amprolium or Toltrazuril.'),
    ('Newcastle Disease', 'Viral disease.', 'Quarantine. No cure.'),
    ('CRD', 'Respiratory infection.', 'Tylosin or Doxycycline.'),
    ('Gumboro', 'Viral immune disease.', 'Supportive care.')
]
cursor.executemany("INSERT OR IGNORE INTO vet_diseases (name, description, treatment_plan) VALUES (?, ?, ?)", diseases)

conn.commit()
conn.close()
print("Vet Database Created!")