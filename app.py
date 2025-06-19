# Final, Correct, and Fully Refactored app.py

print("--- app.py is starting to load ---")
from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3

# Initialize the Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_good_and_long_dev_secret_key_!@#$'

# --- Configuration and Models (OOP Approach) ---

DATABASE = 'farm_data.db'

# 1. User Class
class User:
    def __init__(self, farm_name):
        self.farm_name = farm_name

# 2. InventoryItem Class
class InventoryItem:
    def __init__(self, name, category, quantity, unit, expiry_date=None, item_id=None):
        self.id = item_id
        self.name = name
        self.category = category
        self.quantity = quantity
        self.unit = unit
        self.expiry_date = expiry_date

    def save(self):
        conn = get_db_connection()
        if self.id:
            sql = "UPDATE inventory SET name = ?, category = ?, quantity = ?, unit = ?, expiry_date = ? WHERE id = ?"
            conn.execute(sql, (self.name, self.category, self.quantity, self.unit, self.expiry_date, self.id))
        else:
            sql = "INSERT INTO inventory (name, category, quantity, unit, expiry_date) VALUES (?, ?, ?, ?, ?)"
            conn.execute(sql, (self.name, self.category, self.quantity, self.unit, self.expiry_date))
        conn.commit()
        conn.close()

    @staticmethod
    def get_all():
        conn = get_db_connection()
        items_from_db = conn.execute("SELECT * FROM inventory ORDER BY name ASC").fetchall()
        conn.close()
        return items_from_db

    @staticmethod
    def get_by_id(item_id):
        conn = get_db_connection()
        item_row = conn.execute("SELECT * FROM inventory WHERE id = ?", (item_id,)).fetchone()
        conn.close()
        if item_row:
            return InventoryItem(item_row['name'], item_row['category'], item_row['quantity'], item_row['unit'], item_row['expiry_date'], item_row['id'])
        return None

    @staticmethod
    def delete_by_id(item_id):
        conn = get_db_connection()
        conn.execute("DELETE FROM inventory WHERE id = ?", (item_id,))
        conn.commit()
        conn.close()

# In app.py, after the InventoryItem class

# 3. Define the IncomeRecord "Blueprint" (Class)
class IncomeRecord:
    def __init__(self, date, source, description, amount, record_id=None):
        self.id = record_id
        self.date = date
        self.source = source
        self.description = description
        self.amount = amount

    def save(self):
        conn = get_db_connection()
        if self.id:
            # Update existing record
            sql = "UPDATE income SET income_date = ?, source = ?, description = ?, amount = ? WHERE id = ?"
            conn.execute(sql, (self.date, self.source, self.description, self.amount, self.id))
        else:
            # Insert new record
            sql = "INSERT INTO income (income_date, source, description, amount) VALUES (?, ?, ?, ?)"
            conn.execute(sql, (self.date, self.source, self.description, self.amount))
        conn.commit()
        conn.close()

    @staticmethod
    def get_all():
        conn = get_db_connection()
        records = conn.execute("SELECT * FROM income ORDER BY income_date DESC").fetchall()
        conn.close()
        return records

    @staticmethod
    def get_by_id(record_id):
        conn = get_db_connection()
        record = conn.execute("SELECT * FROM income WHERE id = ?", (record_id,)).fetchone()
        conn.close()
        if record:
            return IncomeRecord(record['income_date'], record['source'], record['description'], record['amount'], record['id'])
        return None

    @staticmethod
    def delete_by_id(record_id):
        conn = get_db_connection()
        conn.execute("DELETE FROM income WHERE id = ?", (record_id,))
        conn.commit()
        conn.close()

# In app.py, after the IncomeRecord class

# 4. Define the ExpenseRecord "Blueprint" (Class)
class ExpenseRecord:
    def __init__(self, date, category, description, amount, record_id=None):
        self.id = record_id
        self.date = date
        self.category = category
        self.description = description
        self.amount = amount

    def save(self):
        conn = get_db_connection()
        if self.id:
            # Update existing record
            sql = "UPDATE expenses SET expense_date = ?, category = ?, description = ?, amount = ? WHERE id = ?"
            conn.execute(sql, (self.date, self.category, self.description, self.amount, self.id))
        else:
            # Insert new record
            sql = "INSERT INTO expenses (expense_date, category, description, amount) VALUES (?, ?, ?, ?)"
            conn.execute(sql, (self.date, self.category, self.description, self.amount))
        conn.commit()
        conn.close()

    @staticmethod
    def get_all():
        conn = get_db_connection()
        records = conn.execute("SELECT * FROM expenses ORDER BY expense_date DESC").fetchall()
        conn.close()
        return records

    @staticmethod
    def get_by_id(record_id):
        conn = get_db_connection()
        record = conn.execute("SELECT * FROM expenses WHERE id = ?", (record_id,)).fetchone()
        conn.close()
        if record:
            return ExpenseRecord(record['expense_date'], record['category'], record['description'], record['amount'], record['id'])
        return None

    @staticmethod
    def delete_by_id(record_id):
        conn = get_db_connection()
        conn.execute("DELETE FROM expenses WHERE id = ?", (record_id,))
        conn.commit()
        conn.close()
# 3. Create the single user instance
# In app.py, after the ExpenseRecord class

# 5. Define the PoultryFlock "Blueprint" (Class)
class PoultryFlock:
    def __init__(self, name, breed, acq_date, quantity, status, flock_id=None):
        self.id = flock_id
        self.name = name
        self.breed = breed
        self.acq_date = acq_date
        self.quantity = quantity
        self.status = status

    def save(self):
        conn = get_db_connection()
        if self.id:
            # Update existing flock
            sql = "UPDATE poultry_flocks SET flock_name = ?, breed = ?, acquisition_date = ?, initial_quantity = ?, status = ? WHERE id = ?"
            conn.execute(sql, (self.name, self.breed, self.acq_date, self.quantity, self.status, self.id))
        else:
            # Insert new flock
            sql = "INSERT INTO poultry_flocks (flock_name, breed, acquisition_date, initial_quantity, status) VALUES (?, ?, ?, ?, ?)"
            conn.execute(sql, (self.name, self.breed, self.acq_date, self.quantity, self.status))
        conn.commit()
        conn.close()

    @staticmethod
    def get_all():
        conn = get_db_connection()
        flocks = conn.execute("SELECT * FROM poultry_flocks ORDER BY acquisition_date DESC").fetchall()
        conn.close()
        return flocks

    @staticmethod
    def get_by_id(flock_id):
        conn = get_db_connection()
        flock = conn.execute("SELECT * FROM poultry_flocks WHERE id = ?", (flock_id,)).fetchone()
        conn.close()
        if flock:
            return PoultryFlock(flock['flock_name'], flock['breed'], flock['acquisition_date'], flock['initial_quantity'], flock['status'], flock['id'])
        return None

    @staticmethod
    def delete_by_id(flock_id):
        conn = get_db_connection()
        # Important: You might want to also delete related egg logs in a real app
        conn.execute("DELETE FROM poultry_flocks WHERE id = ?", (flock_id,))
        conn.commit()
        conn.close()
current_user = User(farm_name="Babura Multi-Links Venture Farms")


# --- Database Helper Function ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# --- Main Routes ---

@app.route('/')
@app.route('/dashboard')
def dashboard():
    conn = get_db_connection()
    total_income = conn.execute("SELECT SUM(amount) FROM income").fetchone()[0] or 0
    total_expenses = conn.execute("SELECT SUM(amount) FROM expenses").fetchone()[0] or 0
    total_active_birds = conn.execute("SELECT SUM(initial_quantity) FROM poultry_flocks WHERE status = 'Active'").fetchone()[0] or 0
    eggs_today = conn.execute("SELECT SUM(quantity) FROM egg_log WHERE log_date = date('now', 'localtime')").fetchone()[0] or 0
    eggs_last_7_days = conn.execute("SELECT SUM(quantity) FROM egg_log WHERE log_date >= date('now', '-6 days')").fetchone()[0] or 0
    conn.close()
    
    stats = {
        "total_income": total_income, "total_expenses": total_expenses, "net_profit": total_income - total_expenses,
        "total_active_birds": total_active_birds, "eggs_today": eggs_today, "eggs_last_7_days": eggs_last_7_days
    }
    return render_template('dashboard.html', user=current_user, stats=stats, current_page_title="Farm Dashboard", page_title_tag="Dashboard")

@app.route('/financials')
def financials():
    return render_template('financials.html', user=current_user, current_page_title="Financial Overview", page_title_tag="Financials")

# --- Income Routes (Not yet refactored, still works) ---


# --- Income Routes (OOP Refactored) ---

@app.route('/financials/income')
def income():
    income_records = IncomeRecord.get_all()
    return render_template('income.html', 
                           user=current_user, 
                           income_list=income_records,
                           current_page_title="Farm Income Records",
                           page_title_tag="Income")

@app.route('/add_income', methods=['POST'])
def add_income():
    new_record = IncomeRecord(
        date=request.form.get('income_date'),
        source=request.form.get('income_source'),
        description=request.form.get('income_description'),
        amount=float(request.form.get('income_amount', 0))
    )
    new_record.save()
    flash('Income successfully added!', 'success')
    return redirect(url_for('income'))

@app.route('/income/edit/<int:income_id>')
def edit_income(income_id):
    record_to_edit = IncomeRecord.get_by_id(income_id)
    if record_to_edit is None:
        flash("Income record not found.", "danger")
        return redirect(url_for('income'))
    
    return render_template('edit_income.html', 
                           user=current_user, 
                           income=record_to_edit,
                           current_page_title="Edit Income",
                           page_title_tag="Edit Income")

@app.route('/income/update/<int:income_id>', methods=['POST'])
def update_income(income_id):
    updated_record = IncomeRecord(
        date=request.form.get('income_date'),
        source=request.form.get('income_source'),
        description=request.form.get('income_description'),
        amount=float(request.form.get('income_amount', 0)),
        record_id=income_id  # Pass the ID to ensure an UPDATE
    )
    updated_record.save()
    flash('Income record successfully updated!', 'success')
    return redirect(url_for('income'))

@app.route('/income/delete/<int:income_id>', methods=['POST'])
def delete_income(income_id):
    IncomeRecord.delete_by_id(income_id)
    flash('Income record successfully deleted!', 'success')
    return redirect(url_for('income'))

# --- Expense Routes (Not yet refactored, still works) ---


# --- Expense Routes (OOP Refactored) ---

@app.route('/financials/expenses')
def expenses():
    expense_records = ExpenseRecord.get_all()
    return render_template('expenses.html', 
                           user=current_user, 
                           expenses_list=expense_records,
                           current_page_title="Farm Expense Records",
                           page_title_tag="Expenses")

@app.route('/add_expense', methods=['POST'])
def add_expense():
    new_record = ExpenseRecord(
        date=request.form.get('expense_date'),
        category=request.form.get('expense_category'),
        description=request.form.get('expense_description'),
        amount=float(request.form.get('expense_amount', 0))
    )
    new_record.save()
    flash('Expense successfully added!', 'success')
    return redirect(url_for('expenses'))

@app.route('/expense/edit/<int:expense_id>')
def edit_expense(expense_id):
    record_to_edit = ExpenseRecord.get_by_id(expense_id)
    if record_to_edit is None:
        flash("Expense record not found.", "danger")
        return redirect(url_for('expenses'))
    
    return render_template('edit_expense.html', 
                           user=current_user, 
                           expense=record_to_edit,
                           current_page_title="Edit Expense",
                           page_title_tag="Edit Expense")

@app.route('/expense/update/<int:expense_id>', methods=['POST'])
def update_expense(expense_id):
    updated_record = ExpenseRecord(
        date=request.form.get('expense_date'),
        category=request.form.get('expense_category'),
        description=request.form.get('expense_description'),
        amount=float(request.form.get('expense_amount', 0)),
        record_id=expense_id  # Pass the ID to ensure an UPDATE
    )
    updated_record.save()
    flash('Expense successfully updated!', 'success')
    return redirect(url_for('expenses'))

@app.route('/expense/delete/<int:expense_id>', methods=['POST'])
def delete_expense(expense_id):
    ExpenseRecord.delete_by_id(expense_id)
    flash('Expense successfully deleted!', 'success')
    return redirect(url_for('expenses'))

# --- Inventory Routes (OOP Refactored) ---

@app.route('/inventory')
def inventory():
    inventory_records = InventoryItem.get_all()
    return render_template('inventory.html', user=current_user, inventory_list=inventory_records, current_page_title="Inventory Management", page_title_tag="Inventory")

@app.route('/inventory/add', methods=['POST'])
def add_inventory_item():
    new_item = InventoryItem(
        name=request.form.get('name'), category=request.form.get('category'),
        quantity=float(request.form.get('quantity', 0)), unit=request.form.get('unit'),
        expiry_date=request.form.get('expiry_date') or None
    )
    new_item.save()
    flash('Inventory item successfully added!', 'success')
    return redirect(url_for('inventory'))

@app.route('/inventory/edit/<int:item_id>')
def edit_inventory_item(item_id):
    item_to_edit = InventoryItem.get_by_id(item_id)
    if item_to_edit is None:
        flash("Inventory item not found.", "danger")
        return redirect(url_for('inventory'))
    return render_template('edit_inventory.html', user=current_user, item=item_to_edit, current_page_title="Edit Inventory Item", page_title_tag="Edit Item")

@app.route('/inventory/update/<int:item_id>', methods=['POST'])
def update_inventory_item(item_id):
    updated_item = InventoryItem(
        name=request.form.get('name'), category=request.form.get('category'),
        quantity=float(request.form.get('quantity', 0)), unit=request.form.get('unit'),
        expiry_date=request.form.get('expiry_date') or None, item_id=item_id
    )
    updated_item.save()
    flash('Inventory item successfully updated!', 'success')
    return redirect(url_for('inventory'))

@app.route('/inventory/delete/<int:item_id>', methods=['POST'])
def delete_inventory_item(item_id):
    InventoryItem.delete_by_id(item_id)
    flash('Inventory item successfully deleted!', 'success')
    return redirect(url_for('inventory'))

# --- Poultry Routes (Not yet refactored, still works) ---

# --- Poultry Routes (OOP Refactored) ---

@app.route('/poultry')
def poultry():
    flocks = PoultryFlock.get_all()
    conn = get_db_connection()
    egg_logs = conn.execute("""
        SELECT egg_log.log_date, egg_log.quantity, poultry_flocks.flock_name
        FROM egg_log JOIN poultry_flocks ON poultry_flocks.id = egg_log.flock_id
        ORDER BY egg_log.log_date DESC, egg_log.id DESC LIMIT 10
    """).fetchall()
    conn.close()
    
    return render_template('poultry.html', 
                           user=current_user, 
                           flocks_list=flocks, 
                           egg_logs=egg_logs,
                           current_page_title="Poultry Flock Management",
                           page_title_tag="Poultry")

@app.route('/poultry/add', methods=['POST'])
def add_flock():
    new_flock = PoultryFlock(
        name=request.form.get('flock_name'),
        breed=request.form.get('breed'),
        acq_date=request.form.get('acquisition_date'),
        quantity=int(request.form.get('initial_quantity', 0)),
        status=request.form.get('status')
    )
    new_flock.save()
    flash('New flock successfully added!', 'success')
    return redirect(url_for('poultry'))

@app.route('/poultry/edit/<int:flock_id>')
def edit_flock(flock_id):
    flock_to_edit = PoultryFlock.get_by_id(flock_id)
    if flock_to_edit is None:
        flash("Flock not found.", "danger")
        return redirect(url_for('poultry'))
    
    return render_template('edit_flock.html', 
                           user=current_user, 
                           flock=flock_to_edit,
                           current_page_title="Edit Flock",
                           page_title_tag="Edit Flock")

@app.route('/poultry/update/<int:flock_id>', methods=['POST'])
def update_flock(flock_id):
    updated_flock = PoultryFlock(
        name=request.form.get('flock_name'),
        breed=request.form.get('breed'),
        acq_date=request.form.get('acquisition_date'),
        quantity=int(request.form.get('initial_quantity', 0)),
        status=request.form.get('status'),
        flock_id=flock_id
    )
    updated_flock.save()
    flash('Flock successfully updated!', 'success')
    return redirect(url_for('poultry'))

@app.route('/poultry/delete/<int:flock_id>', methods=['POST'])
def delete_flock(flock_id):
    PoultryFlock.delete_by_id(flock_id)
    flash('Flock successfully deleted!', 'success')
    return redirect(url_for('poultry'))

# The egg log route can remain as it is for now, as it's a simple INSERT
@app.route('/poultry/eggs/add', methods=['POST'])
def add_egg_log():
    if request.method == 'POST':
        log_date = request.form.get('log_date')
        flock_id = request.form.get('flock_id')
        try:
            quantity = int(request.form.get('quantity'))
        except (ValueError, TypeError):
            quantity = 0
        if not all([log_date, flock_id, quantity > 0]):
            flash("Please fill all required fields and enter a valid quantity.", "warning")
            return redirect(url_for('poultry'))
        conn = get_db_connection()
        conn.execute("INSERT INTO egg_log (log_date, quantity, flock_id) VALUES (?, ?, ?)",
                     (log_date, quantity, flock_id))
        conn.commit()
        conn.close()
        flash('Egg collection successfully logged!', 'success')
    return redirect(url_for('poultry'))


# --- Main Execution ---
if __name__ == '__main__':
    print("--- __name__ is __main__, starting app.run ---")
    app.run(debug=True)