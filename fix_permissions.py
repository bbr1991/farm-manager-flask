import sqlite3
import os

# --- THIS IS THE COMPLETE, CORRECT LIST OF ALL PERMISSIONS ---
ALL_PERMISSIONS = [
    # Brooding & Poultry
    ('view_brooding_dashboard', 'Can view the brooding section dashboard'),
    ('add_brooding_batch', 'Can add new batches of day-old chicks'),
    ('log_brooding_mortality', 'Can log daily mortality for brooding batches'),
    ('transfer_brooding_batch', 'Can transfer a completed brooding batch to a laying flock'),
    ('view_poultry_dashboard', 'Can view the laying flocks dashboard'),
    ('add_poultry_flock', 'Can create new laying flocks'),
    ('log_poultry_eggs', 'Can log daily egg collection and feed usage for flocks'),
    ('log_poultry_mortality', 'Can log mortality for laying flocks'),
    ('deactivate_poultry_flock', 'Can deactivate a flock and record its final sale price'),
    # Operations
    ('view_inventory_dashboard', 'Can view the main inventory dashboard and stock levels'),
    ('add_inventory_item', 'Can add a completely new type of item to the inventory list'),
    ('add_inventory_stock', 'Can add quantity to an existing inventory item'),
    ('log_inventory_usage', 'Can log the usage of an inventory item (e.g., feed, meds)'),
    ('edit_inventory_item', 'Can edit an item''s details like name, category, and cost'),
    ('delete_inventory_item', 'Can delete an inventory item if it has no history'),
    ('view_sales_packages', 'Can view the list of sales packages'),
    ('edit_inventory', 'Can add, edit, or delete Sales Packages'),
    ('view_water_dashboard', 'Can view the water production dashboard'),
    ('add_water_product', 'Can define a new water product type'),
    ('log_water_production', 'Can log a new water production run'),
    ('edit_water_product', 'Can edit a water product''s details'),
    ('calculate_water_cost', 'Can run the cost calculation for a production run'),
    ('edit_production_log', 'Can edit or delete historical production logs'),
    ('view_contacts_dashboard', 'Can view the list of customers and suppliers'),
    ('add_contact', 'Can add a new customer or supplier'),
    ('edit_contact', 'Can edit an existing contact''s details'),
    ('delete_contact', 'Can delete a contact'),
    ('assign_contact_user', 'Can assign a sales user to a specific contact (Admin task)'),
    # Finance & Admin
    ('view_financial_center', 'Can view the main Financial Center dashboard'),
    ('view_chart_of_accounts', 'Can view the Chart of Accounts'),
    ('add_chart_of_accounts', 'Can add a new account to the Chart of Accounts'),
    ('view_general_journal', 'Can view the General Journal history'),
    ('add_manual_journal_entry', 'Can create a new manual journal entry'),
    ('reverse_journal_entry', 'Can reverse an existing journal entry'),
    ('record_new_sale', 'Can record a new cash or credit sale (POS)'),
    ('record_new_expense', 'Can record a new expense'),
    ('record_customer_transaction', 'Can record customer payments or credit sales'),
    ('view_reports_dashboard', 'Can access the main Reports Center'),
    ('run_financial_reports', 'Can generate P&L, Balance Sheet, Trial Balance reports'),
    ('run_operational_reports', 'Can generate sales, inventory, and production reports'),
    ('close_day', 'Can perform the daily close procedure'),
    ('close_year', 'Can perform the year-end close procedure'),
    # Core User/Admin Permissions
    ('view_admin_panel', 'Can view the admin dashboard'),
    ('add_users', 'Can create new users'),
    ('manage_users', 'Can manage users'),
    ('edit_permissions', 'Can edit user permissions'),
]

def fix_permissions():
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'farm_data.db')
    print(f"Connecting to database at: {db_path}")
    
    try:
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        
        # Use INSERT OR IGNORE to safely add only the missing permissions
        cur.executemany("INSERT OR IGNORE INTO permissions (name, description) VALUES (?, ?)", ALL_PERMISSIONS)
        con.commit()
        
        # Verification step
        count_after = cur.execute("SELECT COUNT(*) FROM permissions").fetchone()[0]
        print(f"Success! The 'permissions' table now contains {count_after} total rows.")
        
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        if con:
            con.close()
            print("Database connection closed.")

if __name__ == "__main__":
    fix_permissions()