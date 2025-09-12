INSERT INTO water_products (name, price, quantity)
SELECT name, sale_price, quantity
FROM inventory
WHERE
    name = '50cl 20 in 1 sachet' AND
    name NOT IN (SELECT name FROM water_products);