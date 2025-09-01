-- First, DELETE the old, broad Operations permissions
DELETE FROM permissions WHERE name IN (
    'view_inventory', 'edit_inventory',
    'view_water', 'edit_water',
    'view_contacts', 'edit_contacts'
);

-- Now, INSERT the new, granular permissions for each Operations section
-- Note: We re-use 'edit_inventory' for sales packages as they are closely related.

-- Inventory Permissions
INSERT INTO permissions (name, description) VALUES
('view_inventory_dashboard', 'Can view the main inventory dashboard and stock levels'),
('add_inventory_item', 'Can add a completely new type of item to the inventory list'),
('add_inventory_stock', 'Can add quantity to an existing inventory item'),
('log_inventory_usage', 'Can log the usage of an inventory item (e.g., feed, meds)'),
('edit_inventory_item', 'Can edit an item''s details like name, category, and cost'),
('delete_inventory_item', 'Can delete an inventory item if it has no history');

-- Sales Packages Permissions (re-uses 'edit_inventory' for simplicity)
INSERT INTO permissions (name, description) VALUES
('view_sales_packages', 'Can view the list of sales packages');

-- Water Management Permissions
INSERT INTO permissions (name, description) VALUES
('view_water_dashboard', 'Can view the water production dashboard'),
('add_water_product', 'Can define a new water product type (e.g., Sachet, Bottle)'),
('log_water_production', 'Can log a new water production run'),
('edit_water_product', 'Can edit a water product''s details (name, price)'),
('calculate_water_cost', 'Can run the cost calculation for a production run');

-- Contacts Permissions
INSERT INTO permissions (name, description) VALUES
('view_contacts_dashboard', 'Can view the list of customers and suppliers'),
('add_contact', 'Can add a new customer or supplier'),
('edit_contact', 'Can edit an existing contact''s details'),
('delete_contact', 'Can delete a contact'),
('assign_contact_user', 'Can assign a sales user to a specific contact (Admin task)');