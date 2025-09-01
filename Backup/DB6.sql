-- First, DELETE the old, broad poultry permissions
DELETE FROM permissions WHERE name = 'view_poultry';
DELETE FROM permissions WHERE name = 'edit_poultry';

-- Now, INSERT the new, granular permissions for Livestock
INSERT INTO permissions (name, description) VALUES
    -- Brooding Section Permissions
    ('view_brooding_dashboard', 'Can view the brooding section dashboard'),
    ('add_brooding_batch', 'Can add new batches of day-old chicks'),
    ('log_brooding_mortality', 'Can log daily mortality for brooding batches'),
    ('transfer_brooding_batch', 'Can transfer a completed brooding batch to a laying flock'),

    -- Laying Flock Section Permissions
    ('view_poultry_dashboard', 'Can view the laying flocks dashboard'),
    ('add_poultry_flock', 'Can create new laying flocks'),
    ('log_poultry_eggs', 'Can log daily egg collection and feed usage for flocks'),
    ('log_poultry_mortality', 'Can log mortality for laying flocks'),
    ('deactivate_poultry_flock', 'Can deactivate a flock and record its final sale price');