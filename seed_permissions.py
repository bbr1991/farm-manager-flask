import sqlite3

def seed_permissions():
    print("🚀 Starting Permission Seeding Process...")
    
    conn = sqlite3.connect('farm_data.db')
    cursor = conn.cursor()

    # 1. Ensure the permissions table exists
    print("🔧 Verifying table structure...")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        description TEXT
    );
    """)
    
    # 2. Ensure user_permissions table exists
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_permissions (
        user_id INTEGER,
        permission_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(permission_id) REFERENCES permissions(id)
    );
    """)

    # 3. List of ALL permissions
    all_permissions = [
        # --- ADMIN & USERS ---
        ('view_admin_panel', 'Access Admin Dashboard'),
        ('add_users', 'Create New User Accounts'),
        ('manage_users', 'Edit User Permissions & Delete Users'),
        ('close_day', 'Perform End-of-Day and Year-End Closing'),

        # --- FINANCIALS ---
        ('view_financial_center', 'View Financial Dashboard'),
        ('view_chart_of_accounts', 'View Chart of Accounts'),
        ('add_chart_of_accounts', 'Add New Accounts (GL)'),
        ('view_general_journal', 'View General Journal & Ledgers'),
        ('view_bookkeeping', 'View Contact Ledgers'),
        ('add_manual_journal_entry', 'Post Manual Journal Entries'),
        ('reverse_journal_entry', 'Reverse Journal Entries'),

        # --- TRANSACTIONS ---
        ('record_new_expense', 'Record New Expenses'),
        ('record_batch_expense', 'Record Batch Expenses'),
        ('record_new_sale', 'Record POS Sales & Receipts'),
        ('record_customer_transaction', 'Record Customer Deposits/Credit Sales'),
        ('record_batch_deposit', 'Record Batch Customer Deposits'),
        ('view_sales_packages', 'View Sales Packages'),

        # --- INVENTORY ---
        ('view_inventory_dashboard', 'View Inventory Dashboard'),
        ('add_inventory_item', 'Create New Inventory Items'),
        ('add_inventory_stock', 'Add Stock to Existing Items'),
        ('edit_inventory', 'Edit Sales Packages'),
        ('edit_inventory_item', 'Edit Inventory Item Details'),
        ('delete_inventory_item', 'Delete Inventory Items'),
        ('log_inventory_usage', 'Log Internal Inventory Usage'),

        # --- POULTRY ---
        ('view_poultry_dashboard', 'View Poultry/Layers Dashboard'),
        ('add_poultry_flock', 'Add New Poultry Flock'),
        ('deactivate_poultry_flock', 'Deactivate/Sell Off Flock'),
        ('log_poultry_eggs', 'Log Daily Egg Collection'),
        ('log_poultry_mortality', 'Log Flock Mortality'),

        # --- BROODING ---
        ('view_brooding_dashboard', 'View Brooding Dashboard'),
        ('add_brooding_batch', 'Add/Edit/Delete Brooding Batches'),
        ('log_brooding_mortality', 'Log Brooding Mortality'),
        ('transfer_brooding_batch', 'Transfer Birds from Brooding to Layers'),
        ('run_brooding_report', 'View Brooding Specific Reports'),

        # --- WATER PRODUCTION ---
        ('view_water_dashboard', 'View Water Production Dashboard'),
        ('add_water_product', 'Add New Water Products'),
        ('edit_water_product', 'Edit Water Products'),
        ('log_water_production', 'Log Daily Water Production'),
        ('calculate_water_cost', 'Calculate/Finalize Water Costs'),
        ('edit_production_log', 'Edit/Delete Water Logs & Schedule Tasks'),

        # --- CONTACTS ---
        ('view_contacts_dashboard', 'View Contacts List'),
        ('add_contact', 'Add New Contact'),
        ('edit_contact', 'Edit Contact Details'),
        ('delete_contact', 'Delete Contact'),
        ('assign_contact_user', 'Assign Contacts to Specific Staff'),

        # --- PHONE CHARGING ---
        ('manage_phone_charging', 'Manage Phone Charging (Check-in/out, Cards)'),

        # --- REPORTS ---
        ('view_reports_dashboard', 'Access Reports Menu'),
        ('run_financial_reports', 'Run P&L, Balance Sheet, Trial Balance'),
        ('run_operational_reports', 'Run Operational Reports (Eggs, Feed, Flock)'),
        ('run_mortality_report', 'Run Mortality Reports'),
        ('view_reports', 'View General Reports'),
        # ... inside all_permissions list ...
        ('view_fishery_dashboard', 'View Fish Farming Dashboard'),
        ('manage_fishery', 'Add Ponds, Stock Batches, Log Feeding'),
    ]
    added_count = 0
    skipped_count = 0

    for code, desc in all_permissions:
        try:
            # Check if exists
            exists = cursor.execute("SELECT id FROM permissions WHERE name = ?", (code,)).fetchone()
            
            if exists:
                cursor.execute("UPDATE permissions SET description = ? WHERE name = ?", (desc, code))
                skipped_count += 1
            else:
                cursor.execute("INSERT INTO permissions (name, description) VALUES (?, ?)", (code, desc))
                added_count += 1
                
        except Exception as e:
            print(f"Error processing {code}: {e}")

    conn.commit()
    conn.close()
    
    print("-" * 30)
    print(f"✅ Successfully Added: {added_count}")
    print(f"🔄 Updated/Skipped:   {skipped_count}")
    print("-" * 30)

if __name__ == "__main__":
    seed_permissions()