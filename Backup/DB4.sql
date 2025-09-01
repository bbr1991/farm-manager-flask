-- First, DELETE the old, broad financial permissions
DELETE FROM permissions WHERE name IN ('view_bookkeeping', 'edit_bookkeeping', 'add_manual_journal', 'add_expense', 'add_sale');

-- Now, INSERT the new, granular permissions for Finance & Admin

-- Core Bookkeeping & Financial Center Permissions
INSERT INTO permissions (name, description) VALUES
('view_financial_center', 'Can view the main Financial Center dashboard'),
('view_chart_of_accounts', 'Can view the Chart of Accounts'),
('add_chart_of_accounts', 'Can add a new account to the Chart of Accounts'),
('view_general_journal', 'Can view the General Journal history'),
('add_manual_journal_entry', 'Can create a new manual journal entry'),
('reverse_journal_entry', 'Can reverse an existing journal entry');

-- Data Entry Permissions
INSERT INTO permissions (name, description) VALUES
('record_new_sale', 'Can record a new cash or credit sale (POS)'),
('record_new_expense', 'Can record a new expense'),
('record_customer_transaction', 'Can record customer payments or credit sales');

-- Reporting Permissions
INSERT INTO permissions (name, description) VALUES
('view_reports_dashboard', 'Can access the main Reports Center'),
('run_financial_reports', 'Can generate P&L, Balance Sheet, Trial Balance reports'),
('run_operational_reports', 'Can generate sales, inventory, and production reports');

-- High-Level Admin Permissions (These likely exist, but ensure they are there)
INSERT INTO permissions (name, description) VALUES
('close_day', 'Can perform the daily close procedure'),
('close_year', 'Can perform the year-end close procedure');