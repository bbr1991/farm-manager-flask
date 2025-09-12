INSERT INTO sales_packages (package_name, base_inventory_item_id, quantity_per_package, sale_price)
SELECT name, id, 1, sale_price
FROM inventory
WHERE category = 'Finished Goods' AND name NOT IN (SELECT package_name FROM sales_packages);