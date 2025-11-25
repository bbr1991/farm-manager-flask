import sqlite3

conn = sqlite3.connect('farm_data.db')
cursor = conn.cursor()

print("Upgrading Veterinary Knowledge Base to Professional Standard...")

# 1. Reset Tables (Clean Slate to avoid duplicates)
cursor.execute("DROP TABLE IF EXISTS vet_disease_symptoms")
cursor.execute("DROP TABLE IF EXISTS vet_diseases")
cursor.execute("DROP TABLE IF EXISTS vet_symptoms")

# 2. Re-Create Tables with "Prevention" column
cursor.execute("""
CREATE TABLE vet_diseases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    treatment_plan TEXT,
    prevention_plan TEXT
);
""")

cursor.execute("CREATE TABLE vet_symptoms (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL);")

cursor.execute("""
CREATE TABLE vet_disease_symptoms (
    disease_id INTEGER,
    symptom_id INTEGER,
    FOREIGN KEY(disease_id) REFERENCES vet_diseases(id),
    FOREIGN KEY(symptom_id) REFERENCES vet_symptoms(id)
);
""")

# 3. PROFESSIONAL DATA INSERTION

# A. SYMPTOMS LIST
symptoms_list = [
    "Bloody Droppings", "White Diarrhea (Chalky)", "Greenish Diarrhea", "Yellowish Diarrhea", 
    "Coughing / Sneezing", "Gasping for Air / Rales", "Swollen Head / Eyes", "Nasal Discharge",
    "Droopy Wings", "Paralysis (Legs/Wings)", "Twisted Neck (Torticollis)", "Tremors / Shaking",
    "Sudden Death", "Purple Comb/Wattles", "Warts/Scabs on Comb", "Pale Comb",
    "Ruffled Feathers", "Huddling Together", "Drop in Egg Production", "Soft-shelled Eggs"
]

symptom_map = {} # To store ID references
for sym in symptoms_list:
    cursor.execute("INSERT INTO vet_symptoms (name) VALUES (?)", (sym,))
    symptom_map[sym] = cursor.lastrowid

# B. DISEASE DATA
diseases_data = [
    {
        "name": "Coccidiosis",
        "desc": "A parasitic disease that damages the intestinal tract.",
        "treat": "Administer Amprolium, Toltrazuril, or Sulfa-drugs in water. Add Vitamin K.",
        "prev": "Keep litter dry. Avoid overcrowding. Use medicated starter feed.",
        "symptoms": ["Bloody Droppings", "Ruffled Feathers", "Huddling Together", "Pale Comb", "Droopy Wings"]
    },
    {
        "name": "Newcastle Disease",
        "desc": "A highly contagious viral disease affecting respiratory, nervous, and digestive systems.",
        "treat": "No cure (Viral). Isolate sick birds. Give antibiotics to prevent secondary infection.",
        "prev": "Strict Vaccination (LaSota/Komorov). Biosecurity.",
        "symptoms": ["Greenish Diarrhea", "Twisted Neck (Torticollis)", "Paralysis (Legs/Wings)", "Gasping for Air / Rales", "Drop in Egg Production", "Sudden Death"]
    },
    {
        "name": "Chronic Respiratory Disease (CRD)",
        "desc": "A bacterial infection (Mycoplasma) affecting the respiratory system.",
        "treat": "Antibiotics: Tylosin, Doxycycline, or Enrofloxacin.",
        "prev": "Good ventilation. Reduce ammonia levels. Buying Mycoplasma-free chicks.",
        "symptoms": ["Coughing / Sneezing", "Nasal Discharge", "Swollen Head / Eyes", "Gasping for Air / Rales"]
    },
    {
        "name": "Infectious Bursal Disease (Gumboro)",
        "desc": "Viral disease attacking the immune system (Bursa of Fabricius).",
        "treat": "No specific cure. Give Electrolytes, Multivitamins, and Sugar water. Reduce protein in feed.",
        "prev": "Vaccination (Gumboro I & II) is mandatory.",
        "symptoms": ["White Diarrhea (Chalky)", "Ruffled Feathers", "Tremors / Shaking", "Sudden Death", "Prostrated (Lying down)"]
    },
    {
        "name": "Fowl Pox",
        "desc": "Viral infection causing painful lesions/warts on skin or mouth.",
        "treat": "No cure. Apply Iodine/Glycerine to scabs. Prevent secondary infections.",
        "prev": "Vaccination (Wing web stab). Control mosquitoes.",
        "symptoms": ["Warts/Scabs on Comb", "Drop in Egg Production", "Difficulty Eating"]
    },
    {
        "name": "Fowl Cholera",
        "desc": " Bacterial infection causing septicemia.",
        "treat": "Sulfa antibiotics, Tetracyclines, or Penicillin.",
        "prev": "Rodent control. Sanitation.",
        "symptoms": ["Yellowish Diarrhea", "Purple Comb/Wattles", "Swollen Head / Eyes", "Sudden Death"]
    },
    {
        "name": "Mareks Disease",
        "desc": "Viral tumor-causing disease causing paralysis.",
        "treat": "No cure. Cull affected birds.",
        "prev": "Hatchery vaccination (HVT) is the only prevention.",
        "symptoms": ["Paralysis (Legs/Wings)", "Grey Eye (Blindness)", "Weight Loss"]
    }
]

# C. LINKING LOGIC
for disease in diseases_data:
    cursor.execute("INSERT INTO vet_diseases (name, description, treatment_plan, prevention_plan) VALUES (?, ?, ?, ?)", 
                   (disease["name"], disease["desc"], disease["treat"], disease["prev"]))
    disease_id = cursor.lastrowid
    
    for sym_name in disease["symptoms"]:
        if sym_name in symptom_map:
            sym_id = symptom_map[sym_name]
            cursor.execute("INSERT INTO vet_disease_symptoms (disease_id, symptom_id) VALUES (?, ?)", (disease_id, sym_id))

conn.commit()
conn.close()
print("Professional Vet Database Loaded Successfully!")