# ==============================================================================
# Babura Farm Manager - app.py (Version 4.0 - Final Cleaned Structure + Egg Costing)
# ==============================================================================

# --- Core Imports ---
import os
import sqlite3
from datetime import date, timedelta, datetime
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for, flash,
                   session, g, jsonify, send_from_directory)

from flask_bcrypt import Bcrypt

# ==============================================================================
# 1. FLASK APP INITIALIZATION & CONFIGURATION
# ==============================================================================
app = Flask(__name__, static_url_path='/static', static_folder='static')
app.config['SECRET_KEY'] = 'a_very_good_and_long_production_secret_key_!@#$%'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
bcrypt = Bcrypt(app)
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'farm_data.db')

# ==============================================================================
# 2. DATABASE CONNECTION HANDLING
# ==============================================================================
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.route('/sw.js')
def serve_sw():
    return send_from_directory(os.path.join(app.root_path, ''), 'sw.js')

# ==============================================================================
# 2B. HELPER FUNCTIONS (e.g., for getting Account IDs)
# ==============================================================================
def get_account_id(name, acc_type=None, create_if_not_found=False):
    """
    Helper to fetch an account ID by name, with optional creation.
    This helps in centralizing account lookup and handling missing accounts gracefully.
    """
    db = get_db()
    account = db.execute("SELECT id FROM accounts WHERE name = ?", (name,)).fetchone()
    if not account:
        if create_if_not_found and acc_type:
            print(f"Warning: Account '{name}' not found. Attempting to create (Type: {acc_type}).")
            try:
                cursor = db.cursor()
                # Simple code generation: find max code for type and add 1
                highest_code_row = db.execute("SELECT MAX(CAST(code AS INTEGER)) FROM accounts WHERE type = ?", (acc_type,)).fetchone()
                highest_code = highest_code_row[0] if highest_code_row[0] is not None else (6000 if acc_type == 'Expense' else (4000 if acc_type == 'Revenue' else 1000)) # Default codes
                new_code = str(highest_code + 1)
                
                # Check for code collision
                code_exists = db.execute("SELECT id FROM accounts WHERE code = ?", (new_code,)).fetchone()
                if code_exists: # If generated code exists, try a generic high code
                    new_code = str(highest_code + 100) # Jump further
                    
                cursor.execute("INSERT INTO accounts (code, name, type, is_active, created_at) VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)", (new_code, name, acc_type))
                new_id = cursor.lastrowid
                db.commit() # Commit the new account
                print(f"Account '{name}' created with ID: {new_id} and Code: {new_code}")
                return new_id
            except sqlite3.IntegrityError:
                print(f"Account '{name}' already exists (IntegrityError) or code conflict. Retrying lookup.")
                account_recheck = db.execute("SELECT id FROM accounts WHERE name = ?", (name,)).fetchone()
                if account_recheck: 
                    db.rollback() # Rollback potentially failed insert
                    return account_recheck['id']
                raise Exception(f"CRITICAL SETUP ERROR: Account '{name}' not found and could not be created/found after retry.")
            except Exception as e:
                db.rollback() # Rollback on other errors
                print(f"Error creating fallback account '{name}': {e}")
                raise Exception(f"CRITICAL SETUP ERROR: Account '{name}' not found and could not create fallback. Error: {e}")
        else:
            raise Exception(f"CRITICAL SETUP ERROR: Account '{name}' not found. Please create it in your Chart of Accounts.")
    return account['id']


# ==============================================================================
# 3. USER MODEL
# ==============================================================================
class User:
    def __init__(self, **kwargs):
        self.id = kwargs.get('id')
        self.username = kwargs.get('username')
        self.email = kwargs.get('email')
        self.password_hash = kwargs.get('password_hash')
        self.farm_name = kwargs.get('farm_name')
        self.role = kwargs.get('role', 'user')
        self.cash_account_id = kwargs.get('cash_account_id')
        self._permissions = None
        
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def has_permission(self, required_permission):
        if self.role == 'admin':
            return True
        
        if self._permissions is None:
            db = get_db()
            perms_rows = db.execute("SELECT p.name FROM permissions p JOIN user_permissions up ON p.id = up.permission_id WHERE up.user_id = ?", (self.id,)).fetchall()
            self._permissions = {row['name'] for row in perms_rows}
        
        return required_permission in self._permissions
    
    def reload_permissions(self):
        db = get_db()
        perms_rows = db.execute("SELECT p.name FROM permissions p JOIN user_permissions up ON p.id = up.permission_id WHERE up.user_id = ?", (self.id,)).fetchall()
        self._permissions = {row['name'] for row in perms_rows}
    
    @staticmethod
    def get_by_id(user_id):
        user_row = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return User(**user_row) if user_row else None
    
    @staticmethod
    def get_by_username(username):
        user_row = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return User(**user_row) if user_row else None

    @staticmethod
    def get_by_email(email):
        user_row = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        return User(**user_row) if user_row else None

# ==============================================================================
# 4. DECORATORS
# ==============================================================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        g.user = User.get_by_id(session['user_id'])
        if not g.user:
            session.clear()
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def permission_required(permission_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'user') or not g.user.has_permission(permission_name):
                flash('You do not have the required permission.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def check_day_closed(date_field_name='date'):
    """
    Decorator to check if a transaction date falls on a day that has been closed.
    Admins are always allowed to post.
    The 'date_field_name' argument specifies the name of the form field for the date.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # --- Admin Override: Admins can post to any date ---
            if g.user.role == 'admin':
                return f(*args, **kwargs)

            # Get the transaction date from the submitted form
            transaction_date_str = request.form.get(date_field_name)

            if transaction_date_str:
                db = get_db()
                # Check if this date exists in the closures table
                is_closed = db.execute(
                    "SELECT id FROM daily_closures WHERE closure_date = ?", 
                    (transaction_date_str,)
                ).fetchone()

                if is_closed:
                    # If the day is closed, block the transaction
                    flash(f"Transactions for {transaction_date_str} are closed. No new entries are allowed.", 'danger')
                    # Redirect back to the dashboard or the previous page
                    return redirect(request.referrer or url_for('dashboard'))
            
            # If the day is not closed, or no date was found, proceed
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==============================================================================
# 5. AUTHENTICATION & ADMIN ROUTES
# ==============================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.get_by_username(request.form['username'])
        if user and user.check_password(request.form['password']):
            session.permanent = True
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been successfully logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
@permission_required('view_admin_panel')
def admin_dashboard():
    """Displays the admin panel with stats and user management."""
    db = get_db()

    # --- Calculate Statistics ---
    total_users = (db.execute("SELECT COUNT(id) FROM users").fetchone()[0] or 0)
    total_sales = (db.execute("SELECT COUNT(id) FROM sales").fetchone()[0] or 0)
    total_expenses = (db.execute("SELECT COUNT(id) FROM journal_entries WHERE debit_account_id IN (SELECT id FROM accounts WHERE type = 'Expense')").fetchone()[0] or 0)
    inventory_items = (db.execute("SELECT COUNT(id) FROM inventory").fetchone()[0] or 0)
    
    # Get the list of all users for the table
    all_users = db.execute("SELECT * FROM users ORDER BY username").fetchall()
    today_str = date.today().strftime('%Y-%m-%d')
    closure_status = db.execute("SELECT id FROM daily_closures WHERE closure_date = ?", (today_str,)).fetchone()
    # --- Prepare the stats dictionary ---
    stats = {
        "total_users": total_users,
        "total_sales": total_sales,
        "total_expenses": total_expenses,
        "inventory_items": inventory_items
    }
    
    # This return statement now correctly includes the 'stats' dictionary
    return render_template(
        'admin_dashboard.html', 
        user=g.user, 
        stats=stats,
        all_users=all_users,
        is_today_closed=(closure_status is not None),
        now=datetime.utcnow()
    )

@app.route('/admin/users/create', methods=['POST'])
@login_required
@permission_required('add_users')
def admin_create_user():
    """
    Handles creating a new user and automatically provisions a dedicated cash
    account for them using a more robust code generation method.
    """
    db = get_db()
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and Password are required.', 'warning')
            return redirect(url_for('admin_dashboard'))

        if User.get_by_username(username):
             flash(f"A user with the name '{username}' already exists.", "danger")
             return redirect(url_for('admin_dashboard'))

        # --- Robust Account Code Logic ---
        last_code_row = db.execute("SELECT MAX(CAST(code AS INTEGER)) FROM accounts").fetchone()
        new_account_code = 1000
        if last_code_row and last_code_row[0] is not None:
            new_account_code = int(last_code_row[0]) + 1

        cash_account_name = f"Cash Drawer - {username}"
        
        existing_check = db.execute("SELECT id FROM accounts WHERE name = ? OR code = ?", (cash_account_name, new_account_code)).fetchone()
        if existing_check:
            flash(f"An account with the name '{cash_account_name}' or code '{new_account_code}' already exists. Please resolve manually.", "danger")
            return redirect(url_for('admin_dashboard'))

        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO accounts (code, name, type, is_active, created_at) VALUES (?, ?, 'Asset', 1, CURRENT_TIMESTAMP)",
            (new_account_code, cash_account_name)
        )
        new_cash_account_id = cursor.lastrowid
        
        # --- Create the user and link them to their new cash account ---
        admin_user = g.user
        farm_name = admin_user.farm_name
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # THIS IS THE FIX: We add a placeholder email to satisfy the database rule
        placeholder_email = f"{username}@local.farm"
        
        # And we add `email` to the INSERT statement
        db.execute("""
            INSERT INTO users (username, farm_name, email, password_hash, role, cash_account_id)
            VALUES (?, ?, ?, ?, 'user', ?)
        """, (username, farm_name, placeholder_email, hashed_password, new_cash_account_id))
        
        db.commit()
        
        flash(f"User '{username}' created with a dedicated cash account!", 'success')

    except Exception as e:
        db.rollback()
        flash(f"An unexpected error occurred: {e}", 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/profile/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    # Get the user object using the existing User class
    user = User.get_by_id(session['user_id'])

    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not user.check_password(old_password):
            flash("Incorrect old password.", "danger")
            return redirect(url_for('change_password'))
        if new_password != confirm_password:
            flash("New passwords do not match.", "danger")
            return redirect(url_for('change_password'))
        if not new_password:
            flash("New password cannot be empty.", "danger")
            return redirect(url_for('change_password'))

        # Hash the new password
        user.set_password(new_password)
        
        # Save the new hashed password to the database
        conn = get_db()
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", 
                     (user.password_hash, user.id))
        conn.commit()
        # conn.close() # get_db uses g.db, teardown will close it.
        
        flash("Password updated successfully!", "success")
        return redirect(url_for('dashboard'))

    # For a GET request, just show the page
    return render_template('change_password.html', user=user)

@app.route('/admin/user/<int:user_id>/permissions', methods=['GET', 'POST'])
@login_required
@permission_required('manage_users')
def edit_user_permissions(user_id):
    # This part handles the form submission (POST request)
    if request.method == 'POST':
        # Get a list of all the permission IDs that were checked
        permission_ids = request.form.getlist('permissions')
        # Use our new class method to update the permissions in the DB
        Permission.update_for_user(user_id, permission_ids)
        flash("User permissions updated successfully.", "success")
        return redirect(url_for('admin_dashboard'))

    # This part handles displaying the page (GET request)
    user_to_edit = User.get_by_id(user_id)
    if not user_to_edit:
        flash("User not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    all_permissions = Permission.get_all()
    
    # Get the IDs of the permissions this user currently has
    db = get_db()
    user_perms_rows = db.execute("SELECT permission_id FROM user_permissions WHERE user_id = ?", (user_id,)).fetchall()
    user_permission_ids = {row['permission_id'] for row in user_perms_rows}

    # Get the currently logged-in user for the navbar
    user = User.get_by_id(session['user_id'])
    
    return render_template('edit_user_permissions.html', 
                           user=user, 
                           user_to_edit=user_to_edit,
                           all_permissions=all_permissions,
                           user_permission_ids=user_permission_ids)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@permission_required('manage_users')
def delete_user(user_id):
    """Handles deleting a user."""
    if user_id == session['user_id']:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()

    flash("User successfully deleted.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/close-day', methods=['POST'])
@login_required
@permission_required('close_day') # Using a specific permission
def close_day():
    db = get_db()
    closure_date = request.form.get('closure_date')

    if not closure_date:
        flash("No date selected for closure.", "warning")
        return redirect(url_for('admin_dashboard'))

    # Check if the day is already closed
    is_already_closed = db.execute("SELECT id FROM daily_closures WHERE closure_date = ?", (closure_date,)).fetchone()
    if is_already_closed:
        flash(f"The day {closure_date} has already been closed.", 'info')
        return redirect(url_for('admin_dashboard'))

    # If not closed, insert a new record to close it
    db.execute("""
        INSERT INTO daily_closures (closure_date, closed_at, closed_by_user_id)
        VALUES (?, ?, ?)
    """, (closure_date, datetime.utcnow(), g.user.id))
    db.commit()

    # The act of closing the day is our "backup" event log.
    flash(f"Success! Day {closure_date} has been closed and all transactions are now final.", 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/execute-year-end-close', methods=['POST'])
@login_required
@permission_required('close_day') # Re-use permission, or create a new 'year_end_close' permission
def execute_year_end_close():
    """
    Performs the year-end closing procedure. This is a critical, irreversible action.
    It calculates net profit for a given year and transfers it to Retained Earnings.
    """
    db = get_db()
    try:
        year_to_close = request.form.get('year')
        closing_date = f"{year_to_close}-12-31" # Standard closing date

        if not year_to_close:
            flash("You must specify a year to close.", "danger")
            return redirect(url_for('admin_dashboard'))

        # --- PRE-CHECKS ---
        # 1. Get the Retained Earnings account ID
        retained_earnings_acc = db.execute("SELECT id FROM accounts WHERE name = 'Retained Earnings'").fetchone()
        if not retained_earnings_acc:
            raise Exception("CRITICAL: 'Retained Earnings' account not found in Chart of Accounts.")
        retained_earnings_id = retained_earnings_acc['id']

        # 2. Get all Revenue and Expense accounts with their balances for the year
        accounts_to_close = db.execute("""
            SELECT
                acc.id, acc.name, acc.type,
                (SELECT COALESCE(SUM(je.amount), 0) FROM journal_entries je WHERE je.debit_account_id = acc.id AND strftime('%Y', je.transaction_date) = ?) -
                (SELECT COALESCE(SUM(je.amount), 0) FROM journal_entries je WHERE je.credit_account_id = acc.id AND strftime('%Y', je.transaction_date) = ?)
                as balance
            FROM accounts acc
            WHERE acc.type IN ('Revenue', 'Expense')
        """, (year_to_close, year_to_close)).fetchall()

        total_revenue = 0
        total_expense = 0
        
        # --- START THE DATABASE TRANSACTION ---
        
        # 3. Create a single, massive closing journal entry
        # The closing entry itself will be built up

        # Zero out all revenue accounts (they have credit balances, so we debit them)
        for acc in accounts_to_close:
            if acc['type'] == 'Revenue' and acc['balance'] != 0:
                balance_to_close = -acc['balance'] # Flip sign for debiting revenue
                total_revenue += balance_to_close
                db.execute("""
                    INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (closing_date, f"Close {acc['name']}", acc['id'], retained_earnings_id, balance_to_close, g.user.id))

        # Zero out all expense accounts (they have debit balances, so we credit them)
        for acc in accounts_to_close:
            if acc['type'] == 'Expense' and acc['balance'] != 0:
                balance_to_close = acc['balance'] # Positive balance for debit, so credit it
                total_expense += balance_to_close
                db.execute("""
                    INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (closing_date, f"Close {acc['name']}", retained_earnings_id, acc['id'], balance_to_close, g.user.id))

        net_profit = total_revenue - total_expense
        
        # 4. Lock all transactions for the closed year
        db.execute("UPDATE journal_entries SET is_closed = 1 WHERE strftime('%Y', transaction_date) = ?", (year_to_close,))
        
        db.commit()
        # --- END OF TRANSACTION ---
        
        flash(f"Year {year_to_close} has been successfully closed. Net Profit of ₦{net_profit:,.2f} was transferred to Retained Earnings.", "success")

    except Exception as e:
        db.rollback()
        flash(f"A critical error occurred during year-end close: {e}", "danger")
        
    return redirect(url_for('admin_dashboard'))

# ==============================================================================
# PERMISSION MODEL
# ==============================================================================
class Permission:
    @staticmethod
    def get_all():
        """Fetches all available permissions from the database."""
        db = get_db()
        return db.execute("SELECT * FROM permissions ORDER BY name ASC").fetchall()

    @staticmethod
    def update_for_user(user_id, permission_ids):
        """
        Updates the permissions for a specific user.
        This first deletes all old permissions and then adds the new ones.
        """
        db = get_db()
        try:
            db.execute("DELETE FROM user_permissions WHERE user_id = ?", (user_id,))
            permissions_to_insert = [(user_id, int(pid)) for pid in permission_ids]
            
            if permissions_to_insert:
                db.executemany(
                    "INSERT INTO user_permissions (user_id, permission_id) VALUES (?, ?)",
                    permissions_to_insert
                )
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"ERROR updating permissions: {e}")
            raise e

# ==============================================================================
# 6. CORE APPLICATION DASHBOARD ROUTES
# ==============================================================================
@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    today_str = date.today().strftime('%Y-%m-%d')

    financial_summary = db.execute("""
        SELECT
            SUM(CASE WHEN acc.type = 'Revenue' THEN je.amount ELSE 0 END) as total_income,
            SUM(CASE WHEN acc.type = 'Expense' THEN je.amount ELSE 0 END) as total_expenses
        FROM journal_entries je
        LEFT JOIN accounts acc ON je.credit_account_id = acc.id OR je.debit_account_id = acc.id
    """).fetchone()

    poultry_stats_row = db.execute("SELECT (SELECT COALESCE(SUM(bird_count), 0) FROM poultry_flocks WHERE status = 'Active') as total_active_birds, (SELECT COALESCE(SUM(quantity), 0) FROM egg_log WHERE log_date = date('now', 'localtime')) as eggs_today, (SELECT COALESCE(SUM(quantity), 0) FROM egg_log WHERE log_date >= date('now', '-6 days')) as eggs_last_7_days").fetchone()
    
    total_income = financial_summary['total_income'] or 0
    total_expenses = financial_summary['total_expenses'] or 0

    # NEW: Calculate daily egg production costs for today
    # This query sums up all relevant expenses for flocks for TODAY
    daily_egg_costs_row = db.execute("""
        SELECT
            COALESCE(SUM(CASE WHEN acc.name = 'Poultry Feed Expense' THEN je.amount ELSE 0 END), 0) as daily_feed_cost,
            COALESCE(SUM(CASE WHEN acc.name = 'Poultry Medication Expense' THEN je.amount ELSE 0 END), 0) as daily_medication_cost,
            COALESCE(SUM(CASE WHEN acc.name = 'Poultry Labor Expense' THEN je.amount ELSE 0 END), 0) as daily_labor_cost,
            COALESCE(SUM(CASE WHEN acc.name = 'Poultry Consultancy Expense' THEN je.amount ELSE 0 END), 0) as daily_consultancy_cost,
            COALESCE(SUM(CASE WHEN acc.name = 'Poultry Other Expense' THEN je.amount ELSE 0 END), 0) as daily_other_cost,
            COALESCE(SUM(je.amount), 0) as total_daily_flock_expenses
        FROM journal_entries je
        JOIN accounts acc ON je.debit_account_id = acc.id
        WHERE je.transaction_date = ?
          AND je.related_flock_id IS NOT NULL -- Only expenses explicitly linked to a flock
          AND acc.type = 'Expense'
          AND acc.name IN (
                'Poultry Feed Expense', 'Poultry Medication Expense', 
                'Poultry Labor Expense', 'Poultry Consultancy Expense', 
                'Poultry Other Expense'
            )
    """, (today_str,)).fetchone()
    
    daily_egg_costs = dict(daily_egg_costs_row) if daily_egg_costs_row else {
        'daily_feed_cost': 0, 'daily_medication_cost': 0, 'daily_labor_cost': 0,
        'daily_consultancy_cost': 0, 'daily_other_cost': 0, 'total_daily_flock_expenses': 0
    }

    stats = {
        'net_profit': total_income - total_expenses,
        'total_income': total_income,
        'total_expenses': total_expenses,
        'total_active_birds': poultry_stats_row['total_active_birds'] or 0,
        'eggs_today': poultry_stats_row['eggs_today'] or 0,
        'eggs_last_7_days': poultry_stats_row['eggs_last_7_days'] or 0,
        'avg_production_rate': (poultry_stats_row['eggs_today'] / poultry_stats_row['total_active_birds']) if (poultry_stats_row['total_active_birds'] and poultry_stats_row['total_active_birds'] > 0) else 0,

        # NEW: Daily Egg Production Costs for Dashboard
        'daily_feed_cost': daily_egg_costs['daily_feed_cost'],
        'daily_medication_cost': daily_egg_costs['daily_medication_cost'],
        'daily_labor_cost': daily_egg_costs['daily_labor_cost'],
        'daily_consultancy_cost': daily_egg_costs['daily_consultancy_cost'],
        'daily_other_cost': daily_egg_costs['daily_other_cost'],
        'total_daily_flock_expenses': daily_egg_costs['total_daily_flock_expenses']
    }
    
    # Pass financial_chart_data, expense_data, egg_chart_data, table_water_chart_data as empty lists for now
    return render_template('dashboard.html', user=g.user, stats=stats, financial_chart_data=[], expense_data=[], egg_chart_data=[], table_water_chart_data=[], date=date)
@app.route('/inventory')
@login_required
@permission_required('view_inventory_dashboard')
def inventory_dashboard():
    db = get_db()
    inventory_items = db.execute("SELECT * FROM inventory ORDER BY name ASC").fetchall()
    total_value, low_stock_count, expiring_soon_count = 0, 0, 0
    processed_inventory_list = []
    for item_row in inventory_items:
        item = dict(item_row)
        total_value += item.get('quantity', 0) * (item.get('unit_cost') or 0)
        
        is_low_stock = item.get('low_stock_threshold') is not None and item.get('quantity', 0) <= item.get('low_stock_threshold')
        if is_low_stock: low_stock_count += 1
        
        is_expiring_soon = False
        if item.get('expiry_date') and item.get('expiry_date') != '':
            try:
                expiry_dt = date.fromisoformat(item['expiry_date'])
                if (expiry_dt - date.today()).days <= 30:
                    is_expiring_soon = True
            except (ValueError, TypeError):
                pass
        if is_expiring_soon: expiring_soon_count += 1
        
        item['is_low_stock'] = is_low_stock
        item['is_expiring_soon'] = is_expiring_soon
        processed_inventory_list.append(item)
        
    stats = {'total_value': total_value, 'low_stock_count': low_stock_count, 'expiring_soon_count': expiring_soon_count}

    # NEW: Fetch asset accounts and suppliers to pass to modals
    asset_accounts = db.execute("SELECT id, name FROM accounts WHERE type = 'Asset' AND is_active = 1 ORDER BY name ASC").fetchall()
    suppliers = db.execute("SELECT id, name FROM contacts WHERE type = 'Supplier' ORDER BY name ASC").fetchall()
    
    return render_template(
        'inventory.html', 
        user=g.user, 
        stats=stats, 
        inventory_list=processed_inventory_list,
        today_date=date.today().strftime('%Y-%m-%d'),
        asset_accounts=asset_accounts,  # Pass this to the template
        suppliers=suppliers              # Pass this to the template
    )
@app.route('/poultry')
@login_required
@permission_required('view_poultry_dashboard')
def poultry_dashboard():
    db = get_db()
    
    poultry_stats_row = db.execute("SELECT (SELECT COALESCE(SUM(bird_count), 0) FROM poultry_flocks WHERE status = 'Active') as total_active_birds, (SELECT COALESCE(SUM(quantity), 0) FROM egg_log WHERE log_date = date('now', 'localtime')) as eggs_today, (SELECT COALESCE(SUM(quantity), 0) FROM egg_log WHERE log_date >= date('now', '-6 days')) as eggs_last_7_days").fetchone()
    total_active_birds = poultry_stats_row['total_active_birds'] or 0
    eggs_today = poultry_stats_row['eggs_today'] or 0
    stats = {
        'total_active_birds': total_active_birds,
        'eggs_today': eggs_today,
        'eggs_last_7_days': poultry_stats_row['eggs_last_7_days'] or 0,
        'avg_production_rate': (eggs_today / total_active_birds) if total_active_birds > 0 else 0
    }

    active_flocks = db.execute("SELECT * FROM poultry_flocks WHERE status = 'Active' ORDER BY acquisition_date DESC").fetchall()
    inactive_flocks = db.execute("SELECT * FROM poultry_flocks WHERE status = 'Inactive' ORDER BY acquisition_date DESC").fetchall()
    egg_logs = db.execute("SELECT el.*, pf.flock_name FROM egg_log el JOIN poultry_flocks pf ON el.flock_id = pf.id ORDER BY el.log_date DESC, el.id DESC LIMIT 10").fetchall()

    feed_items = db.execute(
        "SELECT * FROM inventory WHERE category = 'Feed' AND quantity > 0 ORDER BY name ASC"
    ).fetchall()
    
    # NEW: Fetch medication items for the modal dropdown
    medication_items = db.execute(
        "SELECT * FROM inventory WHERE category = 'Medication' AND quantity > 0 ORDER BY name ASC"
    ).fetchall()

    return render_template(
        'poultry.html', 
        user=g.user, 
        stats=stats, 
        active_flocks=active_flocks, 
        inactive_flocks=inactive_flocks,
        egg_logs=egg_logs,
        feed_items=feed_items,
        medication_items=medication_items, # <-- Passing new list here
        today_date=date.today().strftime('%Y-%m-%d')
    )

@app.route('/water')
@login_required
@permission_required('view_water_dashboard')
def water_dashboard():
    db = get_db()
    
    stats_row = db.execute("SELECT (SELECT COALESCE(SUM(quantity * price), 0) FROM water_products) as total_stock_value, (SELECT COALESCE(SUM(quantity), 0) FROM water_products) as total_units_in_stock, (SELECT COALESCE(SUM(quantity_produced), 0) FROM water_production_log WHERE production_date = date('now', 'localtime')) as produced_today, (SELECT COALESCE(SUM(quantity_produced), 0) FROM water_production_log WHERE production_date >= date('now', '-6 days')) as produced_last_7_days").fetchone()
    stats = {
        'total_stock_value': stats_row['total_stock_value'] or 0,
        'total_units_in_stock': stats_row['total_units_in_stock'] or 0,
        'produced_today': stats_row['produced_today'] or 0,
        'produced_last_7_days': stats_row['produced_last_7_days'] or 0
    }
    
    production_logs = db.execute("""
        SELECT wpl.*, wp.name as product_name, wp.price
        FROM water_production_log wpl 
        JOIN water_products wp ON wpl.product_id = wp.id 
        ORDER BY wpl.production_date DESC, wpl.id DESC
    """).fetchall()
    
    water_materials = db.execute("SELECT * FROM inventory WHERE category = 'Water Production' AND quantity > 0").fetchall()
    water_products = db.execute("SELECT * FROM water_products ORDER BY name ASC").fetchall()

    return render_template(
        'water_management.html', 
        user=g.user, 
        stats=stats, 
        production_logs=production_logs,
        water_materials=water_materials,
        water_products=water_products,
        today_date=date.today().strftime('%Y-%m-%d')
    )

@app.route('/contacts')
@login_required
@permission_required('view_contacts_dashboard')
def contacts_dashboard():
    db = get_db()
    search_query = request.args.get('q', '')

    base_sql = """
        SELECT
            c.id, c.name, c.type, c.phone, c.email, c.assigned_user_id,
            u.username as assigned_username,
            (
                (SELECT COALESCE(SUM(je.amount), 0) FROM journal_entries je WHERE je.debit_account_id = c.account_id)
                -
                (SELECT COALESCE(SUM(je.amount), 0) FROM journal_entries je WHERE je.credit_account_id = c.account_id)
            ) as balance
        FROM contacts c
        LEFT JOIN users u ON c.assigned_user_id = u.id
    """
    params = []
    
    where_clauses = []
    if search_query:
        where_clauses.append("c.name LIKE ?")
        params.append(f"%{search_query}%")

    if g.user.role != 'admin':
        where_clauses.append("c.assigned_user_id = ?") 
        params.append(g.user.id)
    
    if where_clauses:
        base_sql += " WHERE " + " AND ".join(where_clauses)
        
    base_sql += " ORDER BY c.name ASC"
    contacts_list = db.execute(base_sql, params).fetchall()
    
    assignable_users = []
    if g.user.role == 'admin':
        assignable_users = db.execute(
            "SELECT id, username FROM users WHERE role = 'user' ORDER BY username"
        ).fetchall()

    accounts_receivable = 0
    accounts_payable = 0
    for contact in contacts_list:
        if contact['type'] == 'Customer' and contact['balance'] > 0:
            accounts_receivable += contact['balance']
        elif contact['type'] == 'Supplier' and contact['balance'] < 0:
            accounts_payable += -contact['balance']
            
    stats = {
        'total_contacts': len(contacts_list),
        'accounts_receivable': accounts_receivable,
        'accounts_payable': accounts_payable
    }
    
    return render_template(
        'contacts.html',
        user=g.user,
        stats=stats,
        contacts_list=contacts_list,
        assignable_users=assignable_users
    )

@app.route('/contacts/assign/<int:contact_id>', methods=['POST'])
@login_required
@permission_required('assign_contact_user')
def assign_contact_user(contact_id):
    db = get_db()
    try:
        assigned_user_id = request.form.get('assigned_user_id')
        
        if not assigned_user_id:
            assigned_user_id = None
        
        db.execute(
            "UPDATE contacts SET assigned_user_id = ? WHERE id = ?",
            (assigned_user_id, contact_id)
        )
        db.commit()
        flash("Contact assignment updated successfully.", "success")
    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")
        
    return redirect(url_for('contacts_dashboard'))

# ==============================================================================
# 7. FINANCIAL CENTER & BOOKKEEPING ROUTES
# ==============================================================================
@app.route('/financials')
@login_required
@permission_required('view_financial_center')
def financial_center():
    db = get_db()
    thirty_days_ago = (date.today() - timedelta(days=30)).strftime('%Y-%m-%d')
    kpi_stats_row = db.execute("SELECT SUM(CASE WHEN acc.type = 'Revenue' AND je.transaction_date >= ? THEN je.amount ELSE 0 END) as income_30d, SUM(CASE WHEN acc.type = 'Expense' AND je.transaction_date >= ? THEN je.amount ELSE 0 END) as expenses_30d, (SELECT COALESCE(SUM((SELECT SUM(amount) FROM journal_entries WHERE debit_account_id = a.id) - (SELECT SUM(amount) FROM journal_entries WHERE credit_account_id = a.id)), 0) FROM accounts a WHERE a.name = 'Accounts Receivable') as accounts_receivable FROM journal_entries je LEFT JOIN accounts acc ON je.credit_account_id = acc.id OR je.debit_account_id = acc.id", (thirty_days_ago, thirty_days_ago)).fetchone()
    six_months_ago = (date.today() - timedelta(days=180)).strftime('%Y-%m-01')
    financial_chart_rows = db.execute("SELECT strftime('%Y-%m', transaction_date) as month, SUM(CASE WHEN acc.type = 'Revenue' THEN je.amount ELSE 0 END) as monthly_income, SUM(CASE WHEN acc.type = 'Expense' THEN je.amount ELSE 0 END) as monthly_expenses FROM journal_entries je LEFT JOIN accounts acc ON je.credit_account_id = acc.id OR je.debit_account_id = acc.id WHERE je.transaction_date >= ? GROUP BY month ORDER BY month ASC", (six_months_ago,)).fetchall()
    recent_journal_entries = db.execute("SELECT je.transaction_date as date, je.description, je.amount, CASE WHEN credit_acc.type = 'Revenue' THEN 'income' WHEN debit_acc.type = 'Expense' THEN 'expense' ELSE 'journal' END as type FROM journal_entries je JOIN accounts debit_acc ON je.debit_account_id = debit_acc.id JOIN accounts credit_acc ON je.credit_account_id = credit_acc.id ORDER BY je.transaction_date DESC, je.id DESC LIMIT 5").fetchall()
    key_accounts = db.execute("SELECT acc.name, (SELECT COALESCE(SUM(je.amount), 0) FROM journal_entries je WHERE je.debit_account_id = acc.id) - (SELECT COALESCE(SUM(je.amount), 0) FROM journal_entries je WHERE je.credit_account_id = acc.id) as balance FROM accounts acc WHERE acc.type = 'Asset' AND acc.name IN ('Cash on Hand', 'Bank Account')").fetchall()
    income_30d = kpi_stats_row['income_30d'] or 0
    expenses_30d = kpi_stats_row['expenses_30d'] or 0
    stats = {'net_profit_30d': income_30d - expenses_30d, 'income_30d': income_30d, 'expenses_30d': expenses_30d, 'accounts_receivable': kpi_stats_row['accounts_receivable'] or 0}
    financial_chart_data = [dict(row) for row in financial_chart_rows]
    return render_template('financial.html', user=g.user, stats=stats, financial_chart_data=financial_chart_data, recent_journal_entries=recent_journal_entries, key_accounts=key_accounts)

@app.route('/financials/accounts')
@login_required
@permission_required('view_chart_of_accounts')
def chart_of_accounts():
    db = get_db()
    all_accounts_rows = db.execute("SELECT acc.id, acc.code, acc.name, acc.type, (SELECT COALESCE(SUM(je.amount), 0) FROM journal_entries je WHERE je.debit_account_id = acc.id) - (SELECT COALESCE(SUM(je.amount), 0) FROM journal_entries je WHERE je.credit_account_id = acc.id) as balance FROM accounts acc ORDER BY acc.code").fetchall()
    accounts_by_type = {'Asset': {'accounts': [], 'total': 0}, 'Liability': {'accounts': [], 'total': 0}, 'Equity': {'accounts': [], 'total': 0}, 'Revenue': {'accounts': [], 'total': 0}, 'Expense': {'accounts': [], 'total': 0}}
    net_profit_row = db.execute("SELECT (SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE credit_account_id IN (SELECT id FROM accounts WHERE type = 'Revenue')) - (SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE debit_account_id IN (SELECT id FROM accounts WHERE type = 'Expense')) as profit").fetchone()
    net_profit = net_profit_row['profit'] if net_profit_row else 0
    for account_row in all_accounts_rows:
        account = dict(account_row)
        account_type = account['type']
        if account_type in ['Liability', 'Equity', 'Revenue']:
            account['balance'] = -account['balance']
        if account_type in accounts_by_type:
            accounts_by_type[account_type]['accounts'].append(account)
            accounts_by_type[account_type]['total'] += account['balance']
    accounts_by_type['Equity']['accounts'].append({'id': None, 'code': '3999', 'name': 'Retained Earnings (Current Period Profit)', 'balance': net_profit})
    accounts_by_type['Equity']['total'] += net_profit
    totals = {'assets': accounts_by_type['Asset']['total'], 'liabilities': accounts_by_type['Liability']['total'], 'equity': accounts_by_type['Equity']['total']}
    return render_template('chart_of_accounts.html', user=g.user, accounts_by_type=accounts_by_type, totals=totals)

@app.route('/financials/journal')
@login_required
@permission_required('view_general_journal')
def general_journal():
    db = get_db()
    
    chart_of_accounts = db.execute("SELECT * FROM accounts WHERE is_active = 1 ORDER BY type, name").fetchall()
    search_query = request.args.get('q', '')
    
    sql = """
        SELECT
            je.id, je.transaction_date, je.description, je.amount,
            debit_acc.id as debit_account_id,
            debit_acc.name as debit_account_name,
            credit_acc.id as credit_account_id,
            credit_acc.name as credit_account_name
        FROM journal_entries je
        JOIN accounts debit_acc ON je.debit_account_id = debit_acc.id
        JOIN accounts credit_acc ON je.credit_account_id = credit_acc.id
    """
    params = []

    if search_query:
        sql += " WHERE je.description LIKE ?"
        params.append(f"%{search_query}%")

    sql += " ORDER BY je.transaction_date DESC, je.id DESC"
    
    entries = db.execute(sql, params).fetchall()
    
    return render_template(
    'general_journal.html', 
    user=g.user,
    entries=entries,
    search_query=search_query,
    chart_of_accounts=chart_of_accounts,
    today_date=date.today().strftime('%Y-%m-%d')
)

@app.route('/financials/ledger/<int:account_id>')
@login_required
@permission_required('view_general_journal')
def account_ledger(account_id):
    db = get_db()
    account_row = db.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
    if not account_row:
        flash("Account not found.", "danger")
        return redirect(url_for('chart_of_accounts'))
    account = dict(account_row)
    balance_row = db.execute("SELECT (SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE debit_account_id = ?) - (SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE credit_account_id = ?) as current_balance", (account_id, account_id)).fetchone()
    current_balance = balance_row['current_balance'] if balance_row else 0
    account['balance'] = -current_balance if account['type'] in ['Liability', 'Equity', 'Revenue'] else current_balance
    start_date = request.args.get('start_date', date.today().replace(month=1, day=1).strftime('%Y-%m-%d'))
    opening_balance_row = db.execute("SELECT (SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE debit_account_id = ? AND transaction_date < ?) - (SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE credit_account_id = ? AND transaction_date < ?) as opening_balance", (account_id, start_date, account_id, start_date)).fetchone()
    opening_balance = opening_balance_row['opening_balance'] if opening_balance_row else 0
    transactions = db.execute("SELECT transaction_date as date, description, CASE WHEN debit_account_id = ? THEN amount ELSE 0 END as debit, CASE WHEN credit_account_id = ? THEN amount ELSE 0 END as credit FROM journal_entries WHERE (debit_account_id = ? OR credit_account_id = ?) AND transaction_date >= ? ORDER BY transaction_date ASC, id ASC", (account_id, account_id, account_id, account_id, start_date)).fetchall()
    running_balance = opening_balance
    ledger_entries = []
    for tx_row in transactions:
        tx = dict(tx_row)
        running_balance += tx['debit'] - tx['credit']
        tx['running_balance'] = running_balance
        ledger_entries.append(tx)
    return render_template('account_ledger.html', user=g.user, account=account, ledger_entries=ledger_entries, opening_balance=opening_balance)

@app.route('/financials/accounts/add', methods=['POST'])
@login_required
@permission_required('add_chart_of_accounts')
def add_account():
    """Handles creating a new account from the modal form."""
    db = get_db()
    try:
        name = request.form.get('name')
        code = request.form.get('code')
        account_type = request.form.get('type')
        opening_balance = float(request.form.get('opening_balance', 0))

        if not all([name, code, account_type]):
            flash('Account Name, Code, and Type are required.', 'warning')
            return redirect(url_for('chart_of_accounts'))

        cursor = db.cursor()
        cursor.execute("INSERT INTO accounts (code, name, type, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                       (code, name, account_type))
        new_account_id = cursor.lastrowid

        if opening_balance > 0:
            balancing_account = db.execute("SELECT id FROM accounts WHERE name = 'Opening Balance Equity'").fetchone()
            if not balancing_account:
                cursor.execute("INSERT INTO accounts (code, name, type, created_at) VALUES ('3998', 'Opening Balance Equity', 'Equity', CURRENT_TIMESTAMP)")
                balancing_account_id = cursor.lastrowid
            else:
                balancing_account_id = balancing_account['id']

            if account_type in ['Asset', 'Expense']:
                debit_id, credit_id = new_account_id, balancing_account_id
            else: # Liability, Equity, Revenue
                debit_id, credit_id = balancing_account_id, new_account_id
            
            db.execute("""
                INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (date.today().strftime('%Y-%m-%d'), f"Opening Balance for {name}", debit_id, credit_id, opening_balance, g.user.id))

        db.commit()
        flash(f"Account '{name}' created successfully!", 'success')

    except (ValueError, TypeError) as e:
        flash(f"Invalid opening balance provided. Please enter a valid number. Error: {e}", 'danger')
        db.rollback()
    except sqlite3.IntegrityError:
        flash(f"An account with that name or code already exists.", 'danger')
        db.rollback()
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'danger')
        db.rollback()

    return redirect(url_for('chart_of_accounts'))

@app.route('/journal/reverse/<int:entry_id>', methods=['POST'])
@login_required
@permission_required('reverse_journal_entry')
def reverse_journal_entry(entry_id):
    """
    Creates a new journal entry that is the exact reverse of an existing one.
    """
    db = get_db()
    try:
        original_entry = db.execute(
            "SELECT * FROM journal_entries WHERE id = ?", (entry_id,)
        ).fetchone()

        if not original_entry:
            flash("Original transaction not found.", "danger")
            return redirect(url_for('general_journal'))

        reversal_date = date.today().strftime('%Y-%m-%d')
        reversal_desc = f"REVERSAL of Entry #{original_entry['id']}: {original_entry['description']}"
        
        reversal_debit_id = original_entry['credit_account_id']
        reversal_credit_id = original_entry['debit_account_id']
        
        db.execute("""
            INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (reversal_date, reversal_desc, reversal_debit_id, reversal_credit_id, original_entry['amount'], g.user.id))
        
        db.commit()
        flash(f"Entry #{entry_id} successfully reversed.", "success")

    except Exception as e:
        db.rollback()
        flash(f"An error occurred during reversal: {e}", "danger")

    return redirect(url_for('general_journal'))

# ==============================================================================
# 8. DATA ENTRY ROUTES (THE "THREE PILLARS")
# ==============================================================================
@app.route('/transactions/customer', methods=['GET', 'POST'])
@login_required
@permission_required('record_customer_transaction')
def customer_transaction():
    db = get_db()
    
    if request.method == 'POST':
        try:
            tx_date = request.form.get('date')
            customer_id = int(request.form.get('customer_id'))
            tx_type = request.form.get('transaction_type')
            
            customer = db.execute("SELECT * FROM contacts WHERE id = ?", (customer_id,)).fetchone()
            if not customer or not customer['account_id']:
                raise Exception("This customer does not have a linked receivable account.")
            customer_ar_id = customer['account_id']

            if tx_type == 'deposit':
                payments = []
                i = 0
                while True:
                    account_id = request.form.get(f'payments[{i}][account_id]')
                    if not account_id: break
                    amount = float(request.form.get(f'payments[{i}][amount]'))
                    payments.append({'account_id': int(account_id), 'amount': amount})
                    i += 1
                
                if not payments:
                    raise Exception("No payment amounts were added for the deposit.")
                
                description = request.form.get('description') or f"Payment from {customer['name']}"

                for payment in payments:
                    payment_account_id = payment['account_id']
                    payment_amount = payment['amount']
                    db.execute("""
                        INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id, related_contact_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (tx_date, description, payment_account_id, customer_ar_id, payment_amount, g.user.id, customer_id))

            elif tx_type == 'credit_sale':
                total_amount = float(request.form.get('total_amount'))
                description = f"Credit Sale to {customer['name']}"
                
                packages_sold = []
                i = 0
                while True:
                    package_id = request.form.get(f'items[{i}][id]')
                    if not package_id: break
                    quantity_of_packages = float(request.form.get(f'items[{i}][quantity]'))
                    packages_sold.append({'id': int(package_id), 'quantity': quantity_of_packages})
                    i += 1
                
                if not packages_sold: raise Exception("Cannot record a credit sale with no items.")

                inventory_reduction_list = {}
                for package in packages_sold:
                    package_info = db.execute("SELECT base_inventory_item_id, quantity_per_package FROM sales_packages WHERE id = ?", (package['id'],)).fetchone()
                    base_item_id = package_info['base_inventory_item_id']
                    pieces_to_reduce = package['quantity'] * package_info['quantity_per_package']
                    inventory_reduction_list[base_item_id] = inventory_reduction_list.get(base_item_id, 0) + pieces_to_reduce
                
                sales_revenue_id = db.execute("SELECT id FROM accounts WHERE name = 'Product Sales'").fetchone()['id']
                db.execute("""
                    INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id, related_contact_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (tx_date, description, customer_ar_id, sales_revenue_id, total_amount, g.user.id, customer_id))

                for item_id, total_pieces in inventory_reduction_list.items():
                    db.execute("UPDATE inventory SET quantity = quantity - ? WHERE id = ?", (total_pieces, item_id))

            else:
                raise Exception("Invalid transaction type specified.")

            db.commit()
            flash(f"Transaction for {customer['name']} recorded successfully.", "success")
            return redirect(url_for('contact_ledger', contact_id=customer_id))
            
        except Exception as e:
            db.rollback()
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for('customer_transaction'))

    customers = db.execute("SELECT * FROM contacts WHERE type = 'Customer' ORDER BY name").fetchall()
    asset_accounts = db.execute("SELECT * FROM accounts WHERE type = 'Asset' AND name NOT LIKE 'A/R - %' ORDER BY name").fetchall()
    packages_for_sale = db.execute("SELECT sp.* FROM sales_packages sp JOIN inventory i ON sp.base_inventory_item_id = i.id WHERE i.quantity >= sp.quantity_per_package").fetchall()
    
    return render_template('customer_transaction.html', user=g.user, customers=customers, asset_accounts=asset_accounts, inventory_items=packages_for_sale, today_date=date.today().strftime('%Y-%m-%d'))

@app.route('/financials/batch-deposit')
@login_required
@permission_required('record_batch_deposit')
def batch_deposit():
    """Displays the batch customer deposit entry page."""
    db = get_db()
    customers = db.execute("SELECT * FROM contacts WHERE type = 'Customer' ORDER BY name").fetchall()
    asset_accounts = db.execute("SELECT * FROM accounts WHERE type = 'Asset' AND name NOT LIKE 'A/R - %' ORDER BY name").fetchall()
    
    return render_template(
        'batch_deposit.html',
        user=g.user,
        customers=customers,
        asset_accounts=asset_accounts,
        today_date=date.today().strftime('%Y-%m-%d')
    )

@app.route('/financials/batch-deposit/post', methods=['POST'])
@login_required
@permission_required('record_batch_deposit')
@check_day_closed('date')
def batch_deposit_post():
    """Processes the submission of multiple customer payments."""
    db = get_db()
    try:
        deposit_date = request.form.get('date')
        deposit_account_id = int(request.form.get('deposit_account_id'))

        i = 0
        total_batch_amount = 0
        while True:
            customer_id_str = request.form.get(f'tx[{i}][customer_id]')
            amount_str = request.form.get(f'tx[{i}][amount]')
            
            if not customer_id_str or not amount_str:
                break

            customer_id = int(customer_id_str)
            amount = float(amount_str)
            memo = request.form.get(f'tx[{i}][memo]')
            
            if amount > 0:
                customer = db.execute("SELECT name, account_id FROM contacts WHERE id = ?", (customer_id,)).fetchone()
                if not customer or not customer['account_id']:
                    raise Exception(f"Customer '{customer['name'] if customer else 'ID ' + str(customer_id)}' does not have a linked receivable account.")
                
                customer_ar_id = customer['account_id']
                description = f"Batch deposit: {memo}" if memo else f"Batch deposit from {customer['name']}"

                db.execute("""
                    INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id, related_contact_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (deposit_date, description, deposit_account_id, customer_ar_id, amount, g.user.id, customer_id))
                
                total_batch_amount += amount
            
            i += 1
        
        if total_batch_amount == 0:
            flash("No valid payment lines were entered.", "warning")
            return redirect(url_for('batch_deposit'))

        db.commit()
        flash(f"Batch deposit of ₦{total_batch_amount:,.2f} with {i} transaction(s) posted successfully!", "success")

    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")

    return redirect(url_for('batch_deposit'))

@app.route('/financials/batch-expense')
@login_required
@permission_required('record_batch_expense')
def batch_expense():
    """Displays the batch expense entry page."""
    db = get_db()
    expense_accounts = db.execute("SELECT * FROM accounts WHERE type = 'Expense' AND is_active = 1 ORDER BY name").fetchall()
    asset_accounts = db.execute("SELECT * FROM accounts WHERE type = 'Asset' AND name NOT LIKE 'A/R - %' ORDER BY name").fetchall()
    
    return render_template(
        'batch_expense.html',
        user=g.user,
        expense_accounts=expense_accounts,
        asset_accounts=asset_accounts,
        today_date=date.today().strftime('%Y-%m-%d')
    )

@app.route('/financials/batch-expense/post', methods=['POST'])
@login_required
@permission_required('record_batch_expense')
@check_day_closed('date')
def batch_expense_post():
    db = get_db()
    try:
        tx_date = request.form.get('date')
        
        debits = []
        total_debits = 0
        i = 0
        while True:
            account_id = request.form.get(f'debits[{i}][account_id]')
            if not account_id: break
            amount = float(request.form.get(f'debits[{i}][amount]'))
            debits.append({'account_id': int(account_id), 'amount': amount, 'description': request.form.get(f'debits[{i}][description]')})
            total_debits += amount
            i += 1

        credits = []
        total_credits = 0
        i = 0
        while True:
            account_id = request.form.get(f'credits[{i}][account_id]')
            if not account_id: break
            amount = float(request.form.get(f'credits[{i}][amount]'))
            credits.append({'account_id': int(account_id), 'amount': amount, 'description': request.form.get(f'credits[{i}][description]')})
            total_credits += amount
            i += 1

        if not debits or not credits:
            raise Exception("Batch must contain at least one debit and one credit line.")
        if abs(total_debits - total_credits) > 0.01:
            raise Exception("Batch is out of balance. Total debits must equal total credits.")

        for debit in debits:
            for credit in credits:
                proportional_amount = debit['amount'] * (credit['amount'] / total_credits)
                if proportional_amount > 0:
                    description = debit['description'] or "Batch expense entry"
                    db.execute("""
                        INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (tx_date, description, debit['account_id'], credit['account_id'], proportional_amount, g.user.id))

        db.commit()
        flash(f"Batch of ₦{total_debits:,.2f} posted successfully!", "success")

    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")

    return redirect(url_for('batch_expense'))

@app.route('/sales/new')
@login_required
@permission_required('record_new_sale')
def new_sale():
    """
    Displays the Point of Sale page. It fetches all sales packages that are currently in stock
    and the asset accounts available for receiving payment.
    """
    db = get_db()
    
    packages_for_sale = db.execute("""
        SELECT sp.*, i.name as base_item_name, i.quantity as stock_on_hand
        FROM sales_packages sp
        JOIN inventory i ON sp.base_inventory_item_id = i.id
        WHERE i.quantity >= sp.quantity_per_package
    """).fetchall()
    
    if g.user.cash_account_id:
        asset_accounts = db.execute("SELECT * FROM accounts WHERE id = ?", (g.user.cash_account_id,)).fetchall()
    else:
        asset_accounts = db.execute("SELECT * FROM accounts WHERE type = 'Asset' AND is_active = 1 ORDER BY name ASC").fetchall()

    return render_template(
        'add_sale.html', 
        user=g.user, 
        inventory_items=packages_for_sale, 
        asset_accounts=asset_accounts,
        today_date=date.today().strftime('%Y-%m-%d')
    )

@app.route('/sales/add', methods=['POST'])
@login_required
@permission_required('record_new_sale')
@check_day_closed('date')
def add_sale_post():
    db = get_db()
    try:
        sale_date = request.form.get('date')
        total_sale_amount = float(request.form.get('total_amount'))

        packages_sold = []
        i = 0
        while True:
            package_id = request.form.get(f'items[{i}][id]')
            if not package_id: break
            quantity_of_packages = float(request.form.get(f'items[{i}][quantity]'))
            packages_sold.append({'id': int(package_id), 'quantity': quantity_of_packages})
            i += 1

        if not packages_sold:
            raise Exception('Cannot record a sale with no items.')

        payments = []
        total_paid = 0
        i = 0
        while True:
            account_id = request.form.get(f'payments[{i}][account_id]')
            if not account_id: break
            amount = float(request.form.get(f'payments[{i}][amount]'))
            payments.append({'account_id': int(account_id), 'amount': amount})
            total_paid += amount
            i += 1
        
        if not payments:
            raise Exception('No payments were applied to this sale.')
        
        if abs(total_paid - total_sale_amount) > 0.01:
            raise Exception(f"Payment mismatch: Total paid (₦{total_paid:,.2f}) does not equal the grand total (₦{total_sale_amount:,.2f}).")

        inventory_reduction_list = {}
        total_cost_of_goods_sold = 0
        for package in packages_sold:
            package_info = db.execute("""
                SELECT sp.base_inventory_item_id, sp.quantity_per_package, i.unit_cost
                FROM sales_packages sp JOIN inventory i ON sp.base_inventory_item_id = i.id
                WHERE sp.id = ?
            """, (package['id'],)).fetchone()
            base_item_id = package_info['base_inventory_item_id']
            unit_cost = package_info['unit_cost'] or 0
            pieces_to_reduce = package['quantity'] * package_info['quantity_per_package']
            inventory_reduction_list[base_item_id] = inventory_reduction_list.get(base_item_id, 0) + pieces_to_reduce
            total_cost_of_goods_sold += pieces_to_reduce * unit_cost

        # Using the centralized helper function for account IDs
        sales_revenue_id = get_account_id('Product Sales', 'Revenue', create_if_not_found=False)
        cogs_expense_id = get_account_id('Cost of Goods Sold', 'Expense', create_if_not_found=False)
        inventory_asset_id = get_account_id('Inventory - Eggs', 'Asset', create_if_not_found=False) # Assuming eggs are the main sales item

        for payment in payments:
            payment_account_id = payment['account_id']
            payment_amount = payment['amount']
            description = f"POS transaction portion by {g.user.username}"
            db.execute("""
                INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (sale_date, description, payment_account_id, sales_revenue_id, payment_amount, g.user.id))

        if total_cost_of_goods_sold > 0:
            description_cogs = f"COGS for POS transaction"
            db.execute("""
                INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (sale_date, description_cogs, cogs_expense_id, inventory_asset_id, total_cost_of_goods_sold, g.user.id))
        
        for item_id, total_pieces in inventory_reduction_list.items():
            db.execute("UPDATE inventory SET quantity = quantity - ? WHERE id = ?", (total_pieces, item_id))
        
        db.commit()
        flash(f"Sale of ₦{total_sale_amount:,.2f} recorded successfully with split payment.", 'success')
        return redirect(url_for('new_sale'))

    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")
        return redirect(url_for('new_sale'))

@app.route('/sales/packages')
@login_required
@permission_required('view_sales_packages')
def manage_sales_packages():
    """Displays the new page for managing sales packages."""
    db = get_db()
    base_items = db.execute("SELECT * FROM inventory WHERE category = 'Produce' ORDER BY name").fetchall()
    packages = db.execute("""
        SELECT sp.*, i.name as base_item_name
        FROM sales_packages sp JOIN inventory i ON sp.base_inventory_item_id = i.id
        ORDER BY sp.package_name
    """).fetchall()
    
    return render_template(
        'manage_sales_packages.html',
        user=g.user,
        base_items=base_items,
        packages=packages
    )

@app.route('/sales/packages/add', methods=['POST'])
@login_required
@permission_required('edit_inventory')
def add_sales_package():
    db = get_db()
    try:
        name = request.form.get('package_name')
        base_item_id = int(request.form.get('base_inventory_item_id'))
        qty_per_package = int(request.form.get('quantity_per_package'))
        price = float(request.form.get('sale_price'))

        existing_inventory_item = db.execute("SELECT id FROM inventory WHERE name = ?", (name,)).fetchone()
        if existing_inventory_item:
            flash(f"An inventory item named '{name}' already exists. Please delete it from the main Inventory page before creating this package.", "danger")
            return redirect(url_for('manage_sales_packages'))

        db.execute("""
            INSERT INTO sales_packages (package_name, base_inventory_item_id, quantity_per_package, sale_price)
            VALUES (?, ?, ?, ?)
        """, (name, base_item_id, qty_per_package, price))
        
        db.execute("""
            INSERT INTO inventory (name, category, quantity, unit, sale_price, unit_cost)
            VALUES (?, 'Finished Goods', 0, 'Package', ?, 0)
        """, (name, price))

        db.commit()
        flash(f"New sales package '{name}' created successfully.", "success")
    except sqlite3.IntegrityError:
        db.rollback()
        flash(f"A sales package with the name '{name}' already exists.", 'danger')
    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")
        
    return redirect(url_for('manage_sales_packages'))

@app.route('/sales/packages/update/<int:package_id>', methods=['POST'])
@login_required
@permission_required('edit_inventory')
def update_sales_package(package_id):
    """Handles updating an existing sales package."""
    db = get_db()
    try:
        name = request.form.get('package_name')
        base_item_id = int(request.form.get('base_inventory_item_id'))
        qty_per_package = int(request.form.get('quantity_per_package'))
        price = float(request.form.get('sale_price'))

        db.execute("""
            UPDATE sales_packages SET
                package_name = ?,
                base_inventory_item_id = ?,
                quantity_per_package = ?,
                sale_price = ?
            WHERE id = ?
        """, (name, base_item_id, qty_per_package, price, package_id))
        db.commit()
        flash(f"Sales package '{name}' updated successfully.", "success")
    except Exception as e:
        db.rollback()
        flash(f"An error occurred while updating the package: {e}", "danger")
        
    return redirect(url_for('manage_sales_packages'))

@app.route('/sales/packages/delete/<int:package_id>', methods=['POST'])
@login_required
@permission_required('edit_inventory')
def delete_sales_package(package_id):
    """Handles deleting a sales package."""
    db = get_db()
    try:
        db.execute("DELETE FROM sales_packages WHERE id = ?", (package_id,))
        db.commit()
        flash("Sales package deleted successfully.", "success")
    except Exception as e:
        db.rollback()
        flash(f"An error occurred while deleting the package: {e}", "danger")
        
    return redirect(url_for('manage_sales_packages'))

@app.route('/expenses/new')
@login_required
@check_day_closed('date')
@permission_required('record_new_expense')
def new_expense():
    db = get_db()
    suppliers = db.execute("SELECT * FROM contacts WHERE type = 'Supplier' ORDER BY name ASC").fetchall()
    
    # Prepare expense_accounts to include data-inventory-category for frontend JS
    expense_accounts_raw = db.execute("SELECT id, name, type FROM accounts WHERE type = 'Expense' AND is_active = 1 ORDER BY name ASC").fetchall()
    expense_accounts_processed = []
    for acc in expense_accounts_raw:
        acc_dict = dict(acc)
        # Map expense account names to a general inventory category.
        # These strings must match the 'category' column in your 'inventory' table.
        if 'Poultry Feed Expense' in acc_dict['name'] or 'General Feed Expense' in acc_dict['name']:
            acc_dict['data_inventory_category'] = 'Feed'
        elif 'Poultry Medication Expense' in acc_dict['name'] or 'General Medication Expense' in acc_dict['name'] or 'Veterinary Expense' in acc_dict['name']:
            acc_dict['data_inventory_category'] = 'Medication'
        elif 'Water Production Expenses' in acc_dict['name']:
            acc_dict['data_inventory_category'] = 'Water Production'
        elif 'General Goods Expense' in acc_dict['name']: # Add if you have such an account/inventory category
            acc_dict['data_inventory_category'] = 'General Goods'
        else:
            acc_dict['data_inventory_category'] = '' # No inventory linkage for this expense
        expense_accounts_processed.append(acc_dict)

    asset_accounts = db.execute("SELECT * FROM accounts WHERE type = 'Asset' AND is_active = 1 ORDER BY name ASC").fetchall()
    
    # Prepare inventory_items for JSON passing to the frontend JavaScript
    inventory_items_raw = db.execute("SELECT id, name, category FROM inventory ORDER BY name ASC").fetchall()
    inventory_items_json_list = [dict(row) for row in inventory_items_raw]
    inventory_items_json = jsonify(inventory_items_json_list).get_data(as_text=True)

    # Fetch active flocks for the new "Related Flock" dropdown
    active_flocks = db.execute("SELECT id, flock_name FROM poultry_flocks WHERE status = 'Active' ORDER BY flock_name ASC").fetchall()

    return render_template(
        'add_expense.html', 
        user=g.user, 
        suppliers=suppliers, 
        expense_accounts=expense_accounts_processed, # Pass the processed list
        asset_accounts=asset_accounts, 
        inventory_items_json=inventory_items_json, # Pass JSON string
        active_flocks=active_flocks, 
        today_date=date.today().strftime('%Y-%m-%d') # Ensure current date is passed
    )

@app.route('/expenses/add', methods=['POST'])
@login_required
@check_day_closed('date')
@permission_required('record_new_expense')
def add_expense_post():
    db = get_db()
    try:
        date = request.form.get('date')
        description = request.form.get('description')
        debit_acc_id = int(request.form.get('debit_account_id'))
        credit_acc_id = int(request.form.get('credit_account_id'))
        amount = float(request.form.get('amount'))
        contact_id = request.form.get('contact_id') or None
        inventory_item_id = request.form.get('inventory_item_id')
        quantity_purchased_str = request.form.get('quantity_purchased')
        
        # Get related flock ID
        related_flock_id = request.form.get('related_flock_id')
        if related_flock_id:
            related_flock_id = int(related_flock_id)
        else:
            related_flock_id = None

        if not all([date, description, debit_acc_id, credit_acc_id, amount]) or amount <= 0:
            flash('Date, description, accounts, and a positive amount are required.', 'warning')
            return redirect(url_for('new_expense'))
        
        # Insert into journal_entries, now with related_flock_id
        db.execute("INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id, related_contact_id, related_flock_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", 
                   (date, description, debit_acc_id, credit_acc_id, amount, g.user.id, contact_id, related_flock_id))
        
        if inventory_item_id and quantity_purchased_str and float(quantity_purchased_str) > 0:
            db.execute("UPDATE inventory SET quantity = quantity + ? WHERE id = ?", (float(quantity_purchased_str), int(inventory_item_id)))
        
        db.commit()
        flash(f"Expense of ₦{amount:,.2f} for '{description}' recorded successfully!", 'success')
        return redirect(url_for('financial_center'))
    except Exception as e:
        db.rollback()
        flash(f"An error occurred while recording the expense: {e}", "danger")
        return redirect(url_for('new_expense'))

@app.route('/journal/add_manual', methods=['POST'])
@login_required
@check_day_closed('date')
@permission_required('add_manual_journal_entry')
def add_journal_entry():
    db = get_db()
    try:
        date = request.form.get('transaction_date')
        description = request.form.get('description')
        debit_acc_id_str = request.form.get('debit_account_id')
        credit_acc_id_str = request.form.get('credit_account_id')
        amount_str = request.form.get('amount')

        if not all([date, description, debit_acc_id_str, credit_acc_id_str, amount_str]):
            flash("All fields are required.", "warning")
            return redirect(url_for('general_journal'))
        
        debit_acc_id = int(debit_acc_id_str)
        credit_acc_id = int(credit_acc_id_str)
        amount = float(amount_str)

        if debit_acc_id == credit_acc_id:
            flash("Debit and Credit accounts cannot be the same.", "warning")
            return redirect(url_for('general_journal'))

        if amount <= 0:
            flash("Amount must be a positive number.", "warning")
            return redirect(url_for('general_journal'))

        db.execute("""
            INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (date, description, debit_acc_id, credit_acc_id, amount, g.user.id))
        
        db.commit()
        flash("Manual journal entry recorded successfully!", "success")

    except (ValueError, TypeError):
        flash("Invalid data provided. Please check your numbers.", "danger")
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", "danger")
        db.rollback()

    return redirect(url_for('general_journal'))

@app.route('/sales/receipt/<int:entry_id>')
@login_required
@permission_required('record_new_sale')
@check_day_closed('date')
def sale_receipt(entry_id):
    db = get_db()
    transaction = db.execute("""
        SELECT id, transaction_date as date, description, amount 
        FROM journal_entries WHERE id = ?
    """, (entry_id,)).fetchone()
    
    if not transaction:
        flash("Sale transaction not found.", "danger")
        return redirect(url_for('dashboard'))
        
    return render_template('receipt.html', user=g.user, transaction=transaction)

def _get_report_dates(request_args):
    """
    Helper function to get and validate start and end dates from URL arguments.
    Defaults to the beginning of the current month and today's date.
    """
    default_start = date.today().replace(day=1).strftime('%Y-%m-%d')
    default_end = date.today().strftime('%Y-%m-%d')
    
    start_str = request_args.get('start_date', default_start)
    end_str = request_args.get('end_date', default_end)
    
    if not start_str:
        start_str = default_start
    if not end_str:
        end_str = default_end

    return start_str, end_str

@app.route('/reports')
@login_required
@permission_required('view_reports_dashboard')
def reports_dashboard():
    return render_template('reports_dashboard.html', user=g.user)

@app.route('/report/profit-loss')
@login_required
@permission_required('run_financial_reports')
def report_profit_loss():
    """Calculates and displays the Profit & Loss statement for a date range."""
    start_date, end_date = _get_report_dates(request.args)
    
    db = get_db()
    
    sql_query = """
        SELECT
            acc.name,
            acc.type,
            (SELECT COALESCE(SUM(je.amount), 0) FROM journal_entries je WHERE je.credit_account_id = acc.id AND je.transaction_date BETWEEN ? AND ?)
            -
            (SELECT COALESCE(SUM(je.amount), 0) FROM journal_entries je WHERE je.debit_account_id = acc.id AND je.transaction_date BETWEEN ? AND ?)
            as balance
        FROM accounts acc
        WHERE acc.type IN ('Revenue', 'Expense')
    """
    
    params = (start_date, end_date, start_date, end_date)
    account_balances = db.execute(sql_query, params).fetchall()

    revenue_accounts = []
    expense_accounts = []
    total_revenue = 0
    total_expenses = 0

    for acc in account_balances:
        if acc['type'] == 'Revenue':
            balance = -acc['balance']
            if balance != 0:
                revenue_accounts.append({'name': acc['name'], 'balance': balance})
                total_revenue += balance
        elif acc['type'] == 'Expense':
            balance = acc['balance']
            if balance != 0:
                expense_accounts.append({'name': acc['name'], 'balance': balance})
                total_expenses += balance

    data = {
        "revenue_accounts": revenue_accounts,
        "expense_accounts": expense_accounts,
        "total_revenue": total_revenue,
        "total_expenses": total_expenses,
        "net_profit": total_revenue - total_expenses
    }
    
    return render_template(
        'report_profit_loss.html', 
        user=g.user,
        data=data,
        start_date=start_date,
        end_date=end_date,
        now=datetime.utcnow()
    )

@app.route('/report/balance-sheet')
@login_required
@permission_required('run_financial_reports')
def report_balance_sheet():
    """Calculates and displays the Balance Sheet as of a specific date."""
    start_date, end_date = _get_report_dates(request.args)
    
    db = get_db()
    
    sql_query = """
        SELECT
            acc.name,
            acc.type,
            (SELECT COALESCE(SUM(je.amount), 0) FROM journal_entries je WHERE je.debit_account_id = acc.id AND je.transaction_date <= ?)
            -
            (SELECT COALESCE(SUM(je.amount), 0) FROM journal_entries je WHERE je.credit_account_id = acc.id AND je.transaction_date <= ?)
            as balance
        FROM accounts acc
        WHERE acc.type IN ('Asset', 'Liability', 'Equity')
    """
    
    params = (end_date, end_date)
    account_balances = db.execute(sql_query, params).fetchall()

    net_profit_row = db.execute("""
        SELECT 
            (SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE credit_account_id IN (SELECT id FROM accounts WHERE type = 'Revenue') AND transaction_date <= ?)
            -
            (SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE debit_account_id IN (SELECT id FROM accounts WHERE type = 'Expense') AND transaction_date <= ?)
            as profit
    """, (end_date, end_date)).fetchone()
    net_profit = net_profit_row['profit'] if net_profit_row else 0

    asset_accounts, liability_accounts, equity_accounts = [], [], []
    total_assets, total_liabilities, total_equity = 0, 0, 0

    for acc in account_balances:
        balance = acc['balance']
        if acc['type'] == 'Asset':
            if balance != 0:
                asset_accounts.append({'name': acc['name'], 'balance': balance})
                total_assets += balance
        elif acc['type'] == 'Liability':
            if balance != 0:
                liability_accounts.append({'name': acc['name'], 'balance': -balance}) # Changed 'liabilities' to 'liability_accounts' for consistency
                total_liabilities += -balance
        elif acc['type'] == 'Equity':
            if balance != 0:
                equity_accounts.append({'name': acc['name'], 'balance': -balance})
                total_equity += -balance
    
    if net_profit != 0:
        equity_accounts.append({'name': 'Retained Earnings', 'balance': net_profit})
        total_equity += net_profit
    
    data = {
        "asset_accounts": asset_accounts,
        "liability_accounts": liability_accounts,
        "equity_accounts": equity_accounts,
        "total_assets": total_assets,
        "total_liabilities": total_liabilities,
        "total_equity": total_equity,
        "total_liabilities_and_equity": total_liabilities + total_equity
    }
    
    return render_template(
        'report_balance_sheet.html', 
        user=g.user,
        data=data,
        start_date=start_date,
        end_date=end_date,
        now=datetime.utcnow()
    )

@app.route('/report/trial-balance')
@login_required
@permission_required('run_financial_reports')
def report_trial_balance():
    """Calculates and displays the Trial Balance as of a specific date."""
    start_date, end_date = _get_report_dates(request.args)
    db = get_db()

    sql_query = """
        SELECT
            acc.code,
            acc.name,
            acc.type,
            (SELECT COALESCE(SUM(je.amount), 0) FROM journal_entries je WHERE je.debit_account_id = acc.id AND je.transaction_date <= ?)
            -
            (SELECT COALESCE(SUM(je.amount), 0) FROM journal_entries je WHERE je.credit_account_id = acc.id AND je.transaction_date <= ?)
            as balance
        FROM accounts acc
        ORDER BY acc.code
    """
    params = (end_date, end_date)
    all_accounts = db.execute(sql_query, params).fetchall()

    trial_balance_accounts = []
    total_debits = 0
    total_credits = 0

    for acc in all_accounts:
        balance = acc['balance']
        
        if balance == 0:
            continue

        debit_amount = 0
        credit_amount = 0

        if acc['type'] in ['Asset', 'Expense']:
            debit_amount = balance
            total_debits += balance
        else:
            credit_amount = -balance
            total_credits += credit_amount
        
        trial_balance_accounts.append({
            'code': acc['code'],
            'name': acc['name'],
            'debit': debit_amount,
            'credit': credit_amount
        })

    data = {
        "accounts": trial_balance_accounts,
        "total_debits": total_debits,
        "total_credits": total_credits
    }
    
    return render_template(
        'report_trial_balance.html', 
        user=g.user,
        data=data,
        start_date=start_date,
        end_date=end_date,
        now=datetime.utcnow()
    )

@app.route('/report/eggs')
@login_required
@permission_required('run_operational_reports')
def report_eggs():
    """Calculates and displays the Egg Collection report."""
    start_date, end_date = _get_report_dates(request.args)
    db = get_db()
    
    egg_logs = db.execute("""
        SELECT el.log_date, el.quantity, pf.flock_name
        FROM egg_log el JOIN poultry_flocks pf ON el.flock_id = pf.id
        WHERE el.log_date BETWEEN ? AND ? ORDER BY el.log_date ASC
    """, (start_date, end_date)).fetchall()
    
    total_eggs = sum(log['quantity'] for log in egg_logs)
    
    try:
        start_dt = date.fromisoformat(start_date)
        end_dt = date.fromisoformat(end_date)
        num_days = (end_dt - start_dt).days + 1
        average_daily = total_eggs / num_days if num_days > 0 else 0
    except (ValueError, TypeError):
        average_daily = 0

    data = {
        "egg_logs": egg_logs,
        "total_eggs": total_eggs,
        "average_daily": average_daily
    }
    
    return render_template(
        'report_eggs.html', 
        user=g.user,
        data=data,
        start_date=start_date,
        end_date=end_date,
        now=datetime.utcnow()
    )

@app.route('/report/water')
@login_required
@permission_required('run_operational_reports')
def report_water():
    db = get_db()
    start_date, end_date = _get_report_dates(request.args)
    
    production_logs = db.execute("""
        SELECT 
            wpl.production_date, 
            wpl.quantity_produced,
            wpl.production_labor_cost,
            wpl.sales_commission,
            wpl.total_cost,
            wpl.cost_per_unit,
            (SELECT COALESCE(SUM(il.cost_of_usage), 0) 
             FROM inventory_log il 
             WHERE il.water_production_log_id = wpl.id) as total_material_cost
        FROM water_production_log wpl
        JOIN water_products wp ON wpl.product_id = wp.id
        WHERE wpl.production_date BETWEEN ? AND ?
        ORDER BY wpl.production_date ASC
    """, (start_date, end_date)).fetchall()
    
    total_produced = sum(log['quantity_produced'] for log in production_logs)
    grand_total_material_cost = sum(log['total_material_cost'] or 0 for log in production_logs)
    grand_total_labor_cost = sum(log['production_labor_cost'] or 0 for log in production_logs)
    grand_total_commission = sum(log['sales_commission'] or 0 for log in production_logs)
    grand_total_cost = sum(log['total_cost'] or 0 for log in production_logs)

    data = {
        "production_logs": production_logs,
        "total_produced": total_produced,
        "grand_total_material_cost": grand_total_material_cost,
        "grand_total_labor_cost": grand_total_labor_cost,
        "grand_total_commission": grand_total_commission,
        "grand_total_cost": grand_total_cost
    }
    
    return render_template(
        'report_water.html', 
        user=g.user,
        data=data,
        start_date=start_date,
        end_date=end_date,
        now=datetime.utcnow(),
        report_title="Water Production Cost Analysis"
    )

@app.route('/water/production/costs/<int:log_id>', methods=['GET'])
@login_required
@permission_required('edit_production_log')
def get_production_costs(log_id):
    """API endpoint to fetch all costs for a specific production log."""
    db = get_db()
    
    direct_costs = db.execute(
        "SELECT production_labor_cost, sales_commission FROM water_production_log WHERE id = ?",
        (log_id,)
    ).fetchone()
    
    material_costs = db.execute("""
        SELECT il.id as inventory_log_id, i.name, il.cost_of_usage
        FROM inventory_log il
        JOIN inventory i ON il.inventory_item_id = i.id
        WHERE il.water_production_log_id = ?
    """, (log_id,)).fetchall()
    
    if not direct_costs:
        return jsonify({'error': 'Production log not found'}), 404
        
    return jsonify({
        'production_labor_cost': direct_costs['production_labor_cost'] or 0,
        'sales_commission': direct_costs['sales_commission'] or 0,
        'materials': [dict(row) for row in material_costs]
    })

@app.route('/water/production/costs/direct/edit/<int:log_id>', methods=['POST'])
@login_required
@permission_required('edit_production_log')
def edit_direct_costs(log_id):
    db = get_db()
    try:
        new_labor = float(request.form.get('production_labor_cost', 0))
        new_commission = float(request.form.get('sales_commission', 0))
        
        db.execute("""
            UPDATE water_production_log SET
                production_labor_cost = ?,
                sales_commission = ?
            WHERE id = ?
        """, (new_labor, new_commission, log_id))
        
        db.execute("UPDATE water_production_log SET total_cost = NULL, cost_per_unit = NULL WHERE id = ?", (log_id,))
        
        db.commit()
        flash("Direct costs updated. Please re-finalize the production run.", "success")
    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")
    
    return redirect(url_for('water_dashboard'))

@app.route('/water/production/costs/material/edit/<int:inventory_log_id>', methods=['POST'])
@login_required
@permission_required('edit_production_log')
def edit_material_cost(inventory_log_id):
    db = get_db()
    try:
        new_cost = float(request.form.get('cost_of_usage', 0))
        
        log_info = db.execute("SELECT water_production_log_id FROM inventory_log WHERE id = ?", (inventory_log_id,)).fetchone()
        
        db.execute("UPDATE inventory_log SET cost_of_usage = ? WHERE id = ?", (new_cost, inventory_log_id))
        
        if log_info and log_info['water_production_log_id']:
            db.execute("UPDATE water_production_log SET total_cost = NULL, cost_per_unit = NULL WHERE id = ?", (log_info['water_production_log_id'],))
        
        db.commit()
        flash("Material cost updated. Please re-finalize the production run.", "success")
    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")
        
    return redirect(url_for('water_dashboard'))

@app.route('/reports/inventory') # This seems like a duplicate of /report/inventory
@login_required
@permission_required('view_reports')
def inventory_report():
    """Generates a detailed report of current inventory status and valuation."""
    db = get_db()
    
    inventory_items = db.execute("""
        SELECT 
            name, 
            category, 
            quantity, 
            unit, 
            unit_cost,
            sale_price,
            low_stock_threshold,
            expiry_date,
            (quantity * unit_cost) AS total_cost_value,
            (quantity * sale_price) AS total_sale_value
        FROM inventory 
        ORDER BY category, name
    """).fetchall()

    total_inventory_cost = sum(item['total_cost_value'] for item in inventory_items)
    total_inventory_sale_value = sum(item['total_sale_value'] for item in inventory_items)
    
    report_date = date.today().strftime('%B %d, %Y')

    return render_template(
        'inventory_report.html',
        user=g.user,
        inventory_items=inventory_items,
        total_inventory_cost=total_inventory_cost,
        total_inventory_sale_value=total_inventory_sale_value,
        report_date=report_date
    )

@app.route('/report/inventory')
@login_required
@permission_required('run_operational_reports')
def report_inventory():
    """
    Generates a detailed report of CURRENT inventory status and valuation.
    """
    db = get_db()
    
    inventory_items = db.execute("""
        SELECT 
            name, category, quantity, unit, 
            unit_cost, sale_price, low_stock_threshold,
            (quantity * unit_cost) AS total_cost_value,
            (quantity * sale_price) AS total_sale_value
        FROM inventory 
        ORDER BY category, name
    """).fetchall()

    total_inventory_cost = sum(item['total_cost_value'] for item in inventory_items if item['total_cost_value'] is not None)
    total_inventory_sale_value = sum(item['total_sale_value'] for item in inventory_items if item['total_sale_value'] is not None)
    
    report_date = date.today().strftime('%B %d, %Y')

    return render_template(
        'report_inventory.html',
        user=g.user,
        inventory_items=inventory_items,
        total_inventory_cost=total_inventory_cost,
        total_inventory_sale_value=total_inventory_sale_value,
        report_date=report_date,
        now=datetime.utcnow()
    )

@app.route('/report/daily-sales')
@login_required
@permission_required('run_operational_reports')
def report_daily_sales():
    """
    Generates a report of all sales for a specific day, grouped by the user
    who made the sale, with subtotals and a grand total.
    """
    db = get_db()
    
    report_date_str = request.args.get('report_date', date.today().strftime('%Y-%m-%d'))
    
    sql_query = """
        SELECT
            je.id,
            je.transaction_date,
            je.description,
            je.amount,
            u.username,
            debit_acc.name as deposit_account_name
        FROM journal_entries je
        JOIN users u ON je.created_by_user_id = u.id
        JOIN accounts credit_acc ON je.credit_account_id = credit_acc.id
        JOIN accounts debit_acc ON je.debit_account_id = debit_acc.id
        WHERE
            credit_acc.name = 'Product Sales' AND je.transaction_date = ?
        ORDER BY
            u.username, je.id
    """
    transactions = db.execute(sql_query, (report_date_str,)).fetchall()
    
    sales_by_user = {}
    grand_total = 0

    for tx in transactions:
        username = tx['username']
        if username not in sales_by_user:
            sales_by_user[username] = {
                'transactions': [],
                'total': 0
            }
        
        sales_by_user[username]['transactions'].append(dict(tx))
        sales_by_user[username]['total'] += tx['amount']
        grand_total += tx['amount']

    return render_template(
        'report_daily_sales.html',
        user=g.user,
        report_date=report_date_str,
        sales_by_user=sales_by_user,
        grand_total=grand_total,
        now=datetime.utcnow()
    )

@app.route('/report/feed-movement')
@login_required
@permission_required('run_operational_reports')
def report_feed_movement():
    """Generates a report on feed usage across all farm sections."""
    db = get_db()
    start_date, end_date = _get_report_dates(request.args)
    
    feed_logs = db.execute("""
        SELECT
            il.log_date,
            i.name as item_name,
            il.quantity_used,
            il.cost_of_usage,
            COALESCE(bb.batch_name, pf.flock_name, 'General Use') as used_for,
            CASE 
                WHEN il.brooding_batch_id IS NOT NULL THEN 'Brooding'
                WHEN il.flock_id IS NOT NULL THEN 'Poultry Flock'
                ELSE 'Inventory'
            END as section
        FROM inventory_log il
        JOIN inventory i ON il.inventory_item_id = i.id
        LEFT JOIN brooding_batches bb ON il.brooding_batch_id = bb.id
        LEFT JOIN poultry_flocks pf ON il.flock_id = pf.id
        WHERE
            i.category = 'Feed' AND il.log_date BETWEEN ? AND ?
        ORDER BY il.log_date DESC
    """, (start_date, end_date)).fetchall()

    total_cost = sum(log['cost_of_usage'] for log in feed_logs)

    return render_template(
        'report_feed_movement.html',
        user=g.user,
        start_date=start_date,
        end_date=end_date,
        feed_logs=feed_logs,
        total_cost=total_cost,
        now=datetime.utcnow()
    )

@app.route('/report/flock-movement')
@login_required
@permission_required('run_operational_reports')
def report_flock_movement():
    """Shows a historical view of all flocks, both active and completed."""
    db = get_db()
    
    all_flocks = db.execute("""
        SELECT
            pf.*,
            (SELECT COALESCE(SUM(il.cost_of_usage), 0) FROM inventory_log il WHERE il.flock_id = pf.id) as calculated_feed_cost
        FROM poultry_flocks pf
        ORDER BY pf.acquisition_date DESC
    """).fetchall()

    return render_template(
        'report_flock_movement.html',
        user=g.user,
        all_flocks=all_flocks,
        now=datetime.utcnow()
    )

# NEW REPORT: Laying Flock Costing Report
@app.route('/report/flock-costing')
@login_required
@permission_required('run_operational_reports')
def report_flock_costing():
    db = get_db()
    
    all_flocks_dropdown = db.execute("SELECT id, flock_name FROM poultry_flocks ORDER BY flock_name ASC").fetchall()
    
    selected_flock_id = request.args.get('flock_id')
    flock_data = None
    flock_costs = []
    total_flock_cost = 0
    total_eggs_produced = 0
    cost_per_egg = 0
    
    if selected_flock_id:
        selected_flock_id = int(selected_flock_id)
        flock_data = db.execute("SELECT * FROM poultry_flocks WHERE id = ?", (selected_flock_id,)).fetchone()
        
        if flock_data:
            # 1. Initial Flock Cost
            if flock_data['initial_cost'] is not None and flock_data['initial_cost'] > 0:
                flock_costs.append({
                    'date': flock_data['acquisition_date'],
                    'description': f"Initial purchase of {flock_data['initial_chick_count']} chicks",
                    'amount': flock_data['initial_cost'],
                    'type': 'Initial Purchase'
                })
                total_flock_cost += flock_data['initial_cost']
            
            # 2. Inventory Usage (Feed, Medication)
            inventory_usage = db.execute("""
                SELECT 
                    il.log_date as date, 
                    i.name || ' usage' as description, 
                    il.cost_of_usage as amount,
                    'Inventory Usage - ' || i.category as type
                FROM inventory_log il
                JOIN inventory i ON il.inventory_item_id = i.id
                WHERE il.flock_id = ?
                ORDER BY il.log_date ASC
            """, (selected_flock_id,)).fetchall()
            
            for usage in inventory_usage:
                flock_costs.append(dict(usage))
                total_flock_cost += (usage['amount'] or 0)
            
            # 3. Other Direct Expenses (Consultation, Special Work etc.)
            other_expenses = db.execute("""
                SELECT 
                    je.transaction_date as date, 
                    je.description, 
                    je.amount,
                    acc.name as type
                FROM journal_entries je
                JOIN accounts acc ON je.debit_account_id = acc.id
                WHERE je.related_flock_id = ? AND acc.type = 'Expense'
                ORDER BY je.transaction_date ASC
            """, (selected_flock_id,)).fetchall()
            
            for expense in other_expenses:
                flock_costs.append(dict(expense))
                total_flock_cost += (expense['amount'] or 0)
                
            # Sort all costs by date
            flock_costs = sorted(flock_costs, key=lambda x: x['date'])

            # Calculate total eggs produced by this flock
            total_eggs_row = db.execute("""
                SELECT COALESCE(SUM(quantity), 0) FROM egg_log WHERE flock_id = ?
            """, (selected_flock_id,)).fetchone()
            total_eggs_produced = total_eggs_row[0] if total_eggs_row else 0
            
            if total_eggs_produced > 0:
                cost_per_egg = total_flock_cost / total_eggs_produced
            
    data = {
        "flock_data": flock_data,
        "flock_costs": flock_costs,
        "total_flock_cost": total_flock_cost,
        "total_eggs_produced": total_eggs_produced,
        "cost_per_egg": cost_per_egg
    }

    return render_template(
        'report_flock_costing.html',
        user=g.user,
        all_flocks_dropdown=all_flocks_dropdown,
        selected_flock_id=selected_flock_id,
        data=data,
        now=datetime.utcnow(),
        report_title="Laying Flock Costing Report"
    )

# NEW REPORT: Daily Egg Production Cost Analysis
@app.route('/report/daily-egg-production-cost')
@login_required
@permission_required('run_operational_reports') # You can create a more specific permission if needed
def report_daily_egg_production_cost():
    db = get_db()
    
    report_date_str = request.args.get('report_date', date.today().strftime('%Y-%m-%d'))
    
    # Get total eggs collected for the day
    total_eggs_collected_row = db.execute("""
        SELECT COALESCE(SUM(quantity), 0) FROM egg_log WHERE log_date = ?
    """, (report_date_str,)).fetchone()
    total_eggs_collected = total_eggs_collected_row[0] or 0

    # Gather all related expenses for this day that are linked to flocks (egg production)
    daily_flock_expenses = db.execute("""
        SELECT
            je.id,
            je.description,
            je.amount,
            acc.name as expense_category,
            pf.flock_name
        FROM journal_entries je
        JOIN accounts acc ON je.debit_account_id = acc.id
        LEFT JOIN poultry_flocks pf ON je.related_flock_id = pf.id
        WHERE je.transaction_date = ?
          AND je.related_flock_id IS NOT NULL -- Only expenses explicitly linked to a flock
          AND acc.type = 'Expense'
          AND acc.name IN (
                'Poultry Feed Expense', 'Poultry Medication Expense', 
                'Poultry Labor Expense', 'Poultry Consultancy Expense', 
                'Poultry Other Expense'
            )
        ORDER BY acc.name, pf.flock_name
    """, (report_date_str,)).fetchall()

    total_daily_cost = sum(expense['amount'] for expense in daily_flock_expenses)
    cost_per_egg = total_daily_cost / total_eggs_collected if total_eggs_collected > 0 else 0

    data = {
        'report_date': report_date_str,
        'total_eggs_collected': total_eggs_collected,
        'daily_flock_expenses': [dict(row) for row in daily_flock_expenses], # Convert to dict list
        'total_daily_cost': total_daily_cost,
        'cost_per_egg': cost_per_egg
    }

    return render_template(
        'report_daily_egg_production_cost.html',
        user=g.user,
        data=data,
        report_date=report_date_str,
        now=datetime.utcnow(),
        report_title=f"Daily Egg Production Cost Analysis ({report_date_str})"
    )


# ==============================================================================
# 12. DATA MODIFICATION & ACTION ROUTES (Called by Modals)
# ==============================================================================
from flask import jsonify # Ensure jsonify is imported
@app.route('/purchases/new') # Changed from /add_purchase to /purchases/new for consistency
@login_required
@check_day_closed('date')
@permission_required('record_new_expense') # Or a specific 'record_new_purchase' permission
def new_purchase(): # Renamed from add_purchase
    db = get_db()
    suppliers = db.execute("SELECT * FROM contacts WHERE type = 'Supplier' ORDER BY name ASC").fetchall()
    
    # Prepare expense_accounts to include data-inventory-category for frontend JS
    expense_accounts_raw = db.execute("SELECT id, name, type FROM accounts WHERE type = 'Expense' AND is_active = 1 ORDER BY name ASC").fetchall()
    expense_accounts_processed = []
    for acc in expense_accounts_raw:
        acc_dict = dict(acc)
        # Map expense account names to a general inventory category.
        # These strings must match the 'category' column in your 'inventory' table.
        if 'Poultry Feed Expense' in acc_dict['name'] or 'General Feed Expense' in acc_dict['name']:
            acc_dict['data_inventory_category'] = 'Feed'
        elif 'Poultry Medication Expense' in acc_dict['name'] or 'General Medication Expense' in acc_dict['name'] or 'Veterinary Expense' in acc_dict['name']:
            acc_dict['data_inventory_category'] = 'Medication'
        elif 'Water Production Expenses' in acc_dict['name']:
            acc_dict['data_inventory_category'] = 'Water Production'
        elif 'Equipment Expense' in acc_dict['name']: # Example for Equipment category
            acc_dict['data_inventory_category'] = 'Equipment'
        elif 'Produce Purchase Expense' in acc_dict['name']: # Example for Produce category
            acc_dict['data_inventory_category'] = 'Produce'
        elif 'Other Expense' in acc_dict['name'] or 'General Goods Expense' in acc_dict['name']:
            acc_dict['data_inventory_category'] = 'General Goods' # Or 'Other'
        else:
            acc_dict['data_inventory_category'] = '' # No inventory linkage for this expense
        expense_accounts_processed.append(acc_dict)

    asset_accounts = db.execute("SELECT * FROM accounts WHERE type = 'Asset' AND is_active = 1 ORDER BY name ASC").fetchall()
    
    # Prepare inventory_items for JSON passing to the frontend JavaScript
    inventory_items_raw = db.execute("SELECT id, name, category FROM inventory ORDER BY name ASC").fetchall()
    inventory_items_json_list = [dict(row) for row in inventory_items_raw]
    inventory_items_json = jsonify(inventory_items_json_list).get_data(as_text=True)

    # Fetch active flocks for the "Related Flock" dropdown
    active_flocks = db.execute("SELECT id, flock_name FROM poultry_flocks WHERE status = 'Active' ORDER BY flock_name ASC").fetchall()

    return render_template(
        'add_purchase.html', # Make sure this matches your template filename
        user=g.user, 
        suppliers=suppliers, 
        expense_accounts=expense_accounts_processed, 
        asset_accounts=asset_accounts, 
        inventory_items_json=inventory_items_json, 
        active_flocks=active_flocks,
        today_date=date.today().strftime('%Y-%m-%d')
    )

# You will then point this form's POST request to your add_expense_post function:
# @app.route('/purchases/add', methods=['POST']) # This route would be used if you have a separate backend for purchases
# ...
# def add_purchase_post():
#    # ... this would call add_expense_post's logic or duplicate it if truly separate
@app.route('/inventory/item/add', methods=['POST'])
@login_required
@check_day_closed('date') # Assuming 'date' is the name for purchase_date in the form
@permission_required('add_inventory_item')
def add_inventory_item():
    db = get_db() # Ensure db connection
    try:
        name = request.form.get('name')
        category = request.form.get('category')
        quantity = float(request.form.get('quantity', 0))
        unit = request.form.get('unit')
        low_stock_threshold = float(request.form.get('low_stock_threshold', 0))
        unit_cost = float(request.form.get('unit_cost', 0))
        sale_price = float(request.form.get('sale_price', 0))
        expiry_date = request.form.get('expiry_date') or None
        
        # NEW: Financial details for the initial purchase
        purchase_date = request.form.get('purchase_date') or date.today().strftime('%Y-%m-%d')
        payment_account_id = request.form.get('payment_account_id') # This comes from the new form field
        supplier_id = request.form.get('supplier_id') or None # Optional supplier link

        if not all([name, category, unit, payment_account_id]): # payment_account_id is now required for initial stock
            flash('Item Name, Category, Unit, and Payment Source are required.', 'warning')
            return redirect(url_for('inventory_dashboard'))

        # Check if an item with this name already exists before inserting
        existing_item = db.execute("SELECT id FROM inventory WHERE name = ?", (name,)).fetchone()
        if existing_item:
            flash(f"An inventory item with the name '{name}' already exists. Please update its stock instead of adding a new item.", 'danger')
            return redirect(url_for('inventory_dashboard'))

        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO inventory (name, category, quantity, unit, low_stock_threshold, unit_cost, sale_price, expiry_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, category, quantity, unit, low_stock_threshold, unit_cost, sale_price, expiry_date))
        new_item_id = cursor.lastrowid # Get the ID of the newly created item

        # NEW: Create a journal entry for the initial purchase of this item
        if quantity > 0 and unit_cost > 0:
            total_purchase_value = quantity * unit_cost
            
            # Debit the specific Inventory Asset account based on category
            debit_inventory_asset_id = get_account_id(
                f"Inventory - {category}", 
                acc_type='Asset', 
                create_if_not_found=True # Allow creation if a category-specific inventory asset isn't pre-defined
            )
            credit_payment_account_id = int(payment_account_id)

            description = f"Initial stock purchase of {name} ({quantity} {unit} @ ₦{unit_cost:,.2f}/{unit})"
            
            db.execute("""
                INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id, related_contact_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (purchase_date, description, debit_inventory_asset_id, credit_payment_account_id, total_purchase_value, g.user.id, supplier_id))

        db.commit()

        flash(f"New inventory item '{name}' added successfully and purchase recorded!", 'success')

    except (ValueError, TypeError) as e:
        flash(f"Invalid data provided. Please check your numbers (e.g., quantity, cost, payment source). Error: {e}", 'danger')
        db.rollback()
    except sqlite3.IntegrityError:
        flash(f"A database integrity error occurred, possibly a duplicate entry. Ensure item name is unique.", 'danger')
        db.rollback()
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'danger')
        db.rollback()

    return redirect(url_for('inventory_dashboard'))
@app.route('/inventory/stock/add', methods=['POST'])
@login_required
@check_day_closed('purchase_date')
@permission_required('add_inventory_stock')
def add_inventory_stock():
    db = get_db()
    try:
        # --- Form Data Parsing and Validation (keep as is from last fix) ---
        item_id_str = request.form.get('inventory_item_id')
        if not item_id_str:
            flash('Error: Inventory item not specified.', 'danger')
            return redirect(url_for('inventory_dashboard'))
        try: item_id = int(item_id_str)
        except ValueError:
            flash('Error: Invalid inventory item ID provided.', 'danger')
            return redirect(url_for('inventory_dashboard'))

        quantity_added_str = request.form.get('quantity_added')
        purchase_date = request.form.get('purchase_date')
        unit_cost_at_purchase_str = request.form.get('unit_cost_at_purchase')
        payment_account_id_str = request.form.get('payment_account_id')
        supplier_id = request.form.get('supplier_id') or None

        if not all([quantity_added_str, purchase_date, unit_cost_at_purchase_str, payment_account_id_str]):
            flash('Quantity, Purchase Date, Unit Cost, and Payment Source are all required.', 'warning')
            return redirect(url_for('inventory_dashboard'))
        
        try:
            quantity_added = float(quantity_added_str)
            unit_cost_at_purchase = float(unit_cost_at_purchase_str)
            payment_account_id = int(payment_account_id_str)
        except ValueError:
            flash('Invalid numbers provided for quantity or unit cost.', 'danger')
            return redirect(url_for('inventory_dashboard'))

        if quantity_added <= 0 or unit_cost_at_purchase < 0:
            flash('Quantity to add must be positive. Unit cost cannot be negative.', 'warning')
            return redirect(url_for('inventory_dashboard'))

        # --- Fetch current item state for debugging ---
        current_item = db.execute("SELECT quantity, unit_cost, name, unit, category FROM inventory WHERE id = ?", (item_id,)).fetchone()
        if not current_item:
            flash(f"Error: Inventory item with ID {item_id} not found in the database.", 'danger')
            return redirect(url_for('inventory_dashboard'))

        print(f"\n--- DEBUG: Stock Addition for Item ID: {item_id} ({current_item['name']}) ---")
        print(f"  Initial Quantity: {current_item['quantity']}")
        print(f"  Quantity Added: {quantity_added}")
        print(f"  Unit Cost at Purchase: {unit_cost_at_purchase}")
        print(f"  Initial Unit Cost: {current_item['unit_cost']}")
        print(f"  Payment Account ID: {payment_account_id}")
        print(f"  Purchase Date: {purchase_date}")
        print(f"  Supplier ID: {supplier_id}")


        # --- Calculate new average unit cost ---
        current_total_value = (current_item['quantity'] or 0) * (current_item['unit_cost'] or 0)
        added_value = quantity_added * unit_cost_at_purchase
        new_total_quantity = (current_item['quantity'] or 0) + quantity_added
        
        new_average_unit_cost = (current_total_value + added_value) / new_total_quantity if new_total_quantity > 0 else 0

        print(f"  Calculated New Total Quantity: {new_total_quantity}")
        print(f"  Calculated New Average Unit Cost: {new_average_unit_cost}")

        # --- 1. Update the inventory quantity and unit cost ---
        db.execute("UPDATE inventory SET quantity = ?, unit_cost = ? WHERE id = ?", 
                   (new_total_quantity, new_average_unit_cost, item_id))
        print(f"  SQL UPDATE inventory executed for ID {item_id}.")
        
        # --- Fetch item state IMMEDIATELY AFTER UPDATE (before commit) ---
        post_update_item = db.execute("SELECT quantity, unit_cost FROM inventory WHERE id = ?", (item_id,)).fetchone()
        print(f"  Post-UPDATE (pre-commit) Quantity: {post_update_item['quantity']}, Unit Cost: {post_update_item['unit_cost']}")


        # --- 2. Create a journal entry for the stock purchase ---
        total_purchase_value = quantity_added * unit_cost_at_purchase
        debit_inventory_asset_id = get_account_id(
            f"Inventory - {current_item['category']}", 
            acc_type='Asset', 
            create_if_not_found=True
        )
        credit_payment_account_id = payment_account_id 

        description = f"Stock purchase of {current_item['name']} ({quantity_added} {current_item['unit']} @ ₦{unit_cost_at_purchase:,.2f}/{current_item['unit']})"
        
        db.execute("""
            INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id, related_contact_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (purchase_date, description, debit_inventory_asset_id, credit_payment_account_id, total_purchase_value, g.user.id, supplier_id))
        print(f"  SQL INSERT journal_entries executed for purchase of ₦{total_purchase_value}.")


        # --- COMMIT THE TRANSACTION ---
        db.commit()
        print("  Database transaction COMMITTED.")

        flash(f"Stock added successfully to '{current_item['name']}'! New average unit cost: ₦{new_average_unit_cost:,.2f}", 'success')

    except Exception as e:
        db.rollback() # Rollback if any error occurs
        print(f"EXCEPTION during stock addition, rolling back: {e}")
        flash(f"An unexpected error occurred during stock addition: {e}", 'danger') 

    return redirect(url_for('inventory_dashboard'))
@app.route('/inventory/usage/log', methods=['POST'])
@login_required
@permission_required('log_inventory_usage')
@check_day_closed('log_date')
def log_inventory_usage():
    """
    Handles logging the usage of an inventory item and calculates the cost.
    This single function can now link usage to a poultry flock, a water 
    production run, OR a brooding batch, making it highly flexible.
    
    Updated: Now creates financial journal entries for Laying Flock (Poultry) usage
    and other specific usages.
    """
    db = get_db()
    try:
        item_id = int(request.form.get('inventory_item_id'))
        quantity_used = float(request.form.get('quantity_used'))
        log_date = request.form.get('log_date')

        flock_id = request.form.get('flock_id') or None
        water_log_id = request.form.get('water_production_log_id') or None
        brooding_batch_id = request.form.get('brooding_batch_id') or None

        if not all([item_id, quantity_used, log_date]) or quantity_used <= 0:
            flash('Invalid item, quantity, or date provided.', 'warning')
            return redirect(request.referrer or url_for('dashboard'))

        item = db.execute("SELECT id, quantity, name, unit_cost, category FROM inventory WHERE id = ?", (item_id,)).fetchone()
        if not item or item['quantity'] < quantity_used:
            flash(f"Not enough stock for '{item['name'] if item else 'item'}'. Only {item['quantity'] if item else 0} available.", 'danger')
            return redirect(request.referrer or url_for('dashboard'))

        cost_of_this_usage = quantity_used * (item['unit_cost'] or 0)
        
        # 1. Operationally: Decrease the quantity in the main inventory table
        db.execute("UPDATE inventory SET quantity = quantity - ? WHERE id = ?", (quantity_used, item_id))

        # 2. Operationally: Add a record to the inventory_log table for history
        db.execute("""
            INSERT INTO inventory_log 
            (log_date, inventory_item_id, quantity_used, cost_of_usage, flock_id, water_production_log_id, brooding_batch_id, created_by_user_id) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (log_date, item_id, quantity_used, cost_of_this_usage, flock_id, water_log_id, brooding_batch_id, g.user.id))
        
        # 3. Financially: Create journal entries based on the usage type
        if cost_of_this_usage > 0:
            # Determine the credit account (the inventory asset being used)
            # Fetch inventory account ID. If it doesn't exist, it's a critical setup issue.
            credit_inventory_asset_id = get_account_id(f"Inventory - {item['category']}", acc_type='Asset', create_if_not_found=False) 
            description = f"Usage of {item['name']} for "
            debit_account_id = None

            if brooding_batch_id:
                # Brooding livestock is an asset that accumulates cost
                debit_account_id = get_account_id('Inventory - Brooding Livestock', acc_type='Asset', create_if_not_found=False)
                description += f"brooding batch ID {brooding_batch_id}"
            elif flock_id:
                # NEW LOGIC FOR LAYING FLOCKS (Debit specific expense accounts)
                if item['category'] == 'Feed':
                    debit_account_id = get_account_id('Poultry Feed Expense', acc_type='Expense')
                elif item['category'] == 'Medication':
                    debit_account_id = get_account_id('Poultry Medication Expense', acc_type='Expense')
                else:
                    # Fallback for other inventory types used by a flock
                    debit_account_id = get_account_id('Poultry Other Expense', acc_type='Expense') 
                description += f"laying flock ID {flock_id}"
            elif water_log_id:
                debit_account_id = get_account_id('Water Production Expenses', acc_type='Expense')
                description += f"water production log ID {water_log_id}"
            else:
                # Default for general inventory usage not tied to specific operations
                debit_account_id = get_account_id(f"General {item['category']} Expense", acc_type='Expense') 
                description += f"general inventory usage"

            db.execute("""
                INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id, related_flock_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (log_date, description, debit_account_id, credit_inventory_asset_id, cost_of_this_usage, g.user.id, flock_id))

        db.commit()

        flash(f'Usage of {item["name"]} logged successfully (Cost: ₦{cost_of_this_usage:,.2f})', 'success')

    except Exception as e:
        db.rollback()
        flash(f"An unexpected error occurred: {e}", 'danger')

    return redirect(request.referrer or url_for('dashboard'))

@app.route('/brooding/batch/report/<int:batch_id>')
@login_required
@permission_required('run_brooding_report')
def brooding_batch_report(batch_id):
    db = get_db()
    
    batch = db.execute("SELECT * FROM brooding_batches WHERE id = ?", (batch_id,)).fetchone()
    if not batch:
        flash("Brooding batch not found.", "danger")
        return redirect(url_for('brooding_dashboard'))

    mortality_logs = db.execute(
        "SELECT log_date, mortality_count FROM brooding_log WHERE batch_id = ? ORDER BY log_date",
        (batch_id,)
    ).fetchall()

    usage_logs = db.execute("""
        SELECT il.log_date, i.name, il.quantity_used, il.cost_of_usage
        FROM inventory_log il
        JOIN inventory i ON il.inventory_item_id = i.id
        WHERE il.brooding_batch_id = ? ORDER BY il.log_date
    """, (batch_id,)).fetchall()

    daily_events = {}
    
    for log in mortality_logs:
        date_str = log['log_date']
        if date_str not in daily_events:
            daily_events[date_str] = {'mortality': 0, 'usage': []}
        daily_events[date_str]['mortality'] += log['mortality_count']

    for log in usage_logs:
        date_str = log['log_date']
        if date_str not in daily_events:
            daily_events[date_str] = {'mortality': 0, 'usage': []}
        daily_events[date_str]['usage'].append(dict(log))

    sorted_daily_events = sorted(daily_events.items())

    total_feed_cost = sum(log['cost_of_usage'] for log in usage_logs)
    total_mortality = sum(log['mortality_count'] for log in mortality_logs)
    total_cost = (batch['initial_cost'] or 0) + total_feed_cost
    
    summary = {
        'total_feed_cost': total_feed_cost,
        'total_mortality': total_mortality,
        'total_cost': total_cost
    }

    return render_template(
        'brooding_batch_report.html',
        user=g.user,
        batch=batch,
        daily_events=sorted_daily_events,
        summary=summary,
        now=datetime.utcnow()
    )

# ==============================================================================
# 13. DATA MODIFICATION & ACTION ROUTES
# ==============================================================================
@app.route('/poultry/eggs/log', methods=['POST'])
@login_required
@permission_required('log_poultry_eggs')
@check_day_closed('log_date')
def add_egg_log():
    db = get_db()
    try:
        log_date = request.form.get('log_date')
        flock_id = int(request.form.get('flock_id'))
        feed_item_id = int(request.form.get('feed_item_id'))
        feed_quantity_used = float(request.form.get('feed_quantity_used'))
        crates = int(request.form.get('crates', 0) or 0)
        pieces = int(request.form.get('pieces', 0) or 0)
        spoiled_count = int(request.form.get('spoiled_count', 0) or 0)

        # --- Get Current State of Eggs Inventory ---
        eggs_item = db.execute("SELECT id, quantity, unit_cost FROM inventory WHERE name = 'Eggs'").fetchone()
        if not eggs_item:
            raise Exception("CRITICAL: Inventory item 'Eggs' not found. Please create it first (Category: Produce, Unit: Piece).")
        
        current_egg_quantity = eggs_item['quantity'] or 0
        current_egg_unit_cost = eggs_item['unit_cost'] or 0
        current_total_value = current_egg_quantity * current_egg_unit_cost

        # --- Get the feed item to calculate the cost of today's production ---
        feed_item = db.execute("SELECT unit_cost, quantity, name FROM inventory WHERE id = ?", (feed_item_id,)).fetchone()
        if not feed_item: raise Exception("Feed item not found.")
        if feed_quantity_used > feed_item['quantity']: raise Exception(f"Not enough {feed_item['name']} in stock. Only {feed_item['quantity']} available.")
        
        cost_of_feed_today = feed_quantity_used * (feed_item['unit_cost'] or 0)
        
        # --- Calculations ---
        EGGS_PER_CRATE = 30
        total_eggs_laid = (crates * EGGS_PER_CRATE) + pieces
        good_eggs_produced_today = total_eggs_laid - spoiled_count
        
        if good_eggs_produced_today < 0:
            raise Exception("Spoiled count cannot be greater than total eggs laid.")
            
        # --- THE AVERAGE COST CALCULATION ---
        new_total_value = current_total_value + cost_of_feed_today
        new_total_quantity = current_egg_quantity + good_eggs_produced_today
        new_average_unit_cost = new_total_value / new_total_quantity if new_total_quantity > 0 else 0

        # --- Get Account IDs (using centralized helper function) ---
        feed_inventory_acc_id = get_account_id('Inventory - Feed', acc_type='Asset', create_if_not_found=False)
        egg_inventory_acc_id = get_account_id('Inventory - Eggs', acc_type='Asset', create_if_not_found=False)
        poultry_feed_expense_id = get_account_id('Poultry Feed Expense', acc_type='Expense')
        poultry_production_income_id = get_account_id('Poultry Production Income', acc_type='Revenue') 

        # --- DATABASE TRANSACTION ---
        
        # 1. Update the operational log for egg production
        db.execute("""
            INSERT INTO egg_log (log_date, flock_id, crates, pieces, quantity, spoiled_count, feed_cost)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (log_date, flock_id, crates, pieces, good_eggs_produced_today, spoiled_count, cost_of_feed_today))

        # 2. Decrease feed stock
        db.execute("UPDATE inventory SET quantity = quantity - ? WHERE id = ?", (feed_quantity_used, feed_item_id))
        
        # 3. CRITICAL UPDATE: Update "Eggs" item with new quantity AND new average unit cost
        db.execute("UPDATE inventory SET quantity = ?, unit_cost = ? WHERE id = ?", 
                   (new_total_quantity, new_average_unit_cost, eggs_item['id']))

        # 4. Create journal entry for feed consumption (moving asset to expense)
        description_feed = f"Feed consumption for egg production for flock {flock_id} on {log_date}"
        db.execute("""
            INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id, related_flock_id) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (log_date, description_feed, poultry_feed_expense_id, feed_inventory_acc_id, cost_of_feed_today, g.user.id, flock_id))
        
        # 5. NEW: Create journal entry for the VALUE of the eggs produced (Asset increase, Revenue increase)
        if good_eggs_produced_today > 0 and new_average_unit_cost > 0:
            value_of_new_eggs = good_eggs_produced_today * new_average_unit_cost
            description_eggs_prod = f"Egg production (good eggs) added to inventory for flock {flock_id} on {log_date}"
            db.execute("""
                INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id, related_flock_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (log_date, description_eggs_prod, egg_inventory_acc_id, poultry_production_income_id, value_of_new_eggs, g.user.id, flock_id))

        db.commit()
        flash(f"Production logged. New average cost for eggs is now ₦{new_average_unit_cost:,.2f} per piece.", "success")

    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")
        
    return redirect(url_for('poultry_dashboard'))

@app.route('/poultry/flock/add', methods=['POST'])
@login_required
@check_day_closed('date')
@permission_required('add_poultry_flock')
def add_flock_post():
    """Handles creating a new flock from the modal form."""
    try:
        name = request.form.get('flock_name')
        breed = request.form.get('breed')
        acq_date = request.form.get('acquisition_date')
        bird_count = int(request.form.get('bird_count', 0))
        status = request.form.get('status')

        if not all([name, breed, acq_date, status]) or bird_count <= 0:
            flash('All fields are required and bird count must be positive.', 'warning')
            return redirect(url_for('poultry_dashboard'))

        db = get_db()
        db.execute("""
            INSERT INTO poultry_flocks (flock_name, breed, acquisition_date, bird_count, status)
            VALUES (?, ?, ?, ?, ?)
        """, (name, breed, acq_date, bird_count, status))
        db.commit()

        flash(f"New flock '{name}' added successfully!", 'success')

    except (ValueError, TypeError) as e:
        flash(f"Invalid data provided. Please check your numbers. Error: {e}", 'danger')
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'danger')

    return redirect(url_for('poultry_dashboard'))

@app.route('/poultry/flock/deactivate', methods=['POST'])
@login_required
@permission_required('deactivate_poultry_flock')
def deactivate_flock():
    """Calculates the final profit/loss for a flock and sets it to inactive."""
    db = get_db()
    try:
        flock_id = int(request.form.get('flock_id'))
        final_price = float(request.form.get('final_sale_price'))
        
        # --- CALCULATE TOTAL COSTS ---
        # Sum all inventory usage costs linked to this specific flock
        inventory_cost_row = db.execute(
            "SELECT COALESCE(SUM(cost_of_usage), 0) as total FROM inventory_log WHERE flock_id = ?",
            (flock_id,)
        ).fetchone()
        
        # Sum all other direct expenses linked to this flock
        other_expense_row = db.execute(
            "SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE related_flock_id = ? AND debit_account_id IN (SELECT id FROM accounts WHERE type = 'Expense')",
            (flock_id,)
        ).fetchone()

        # Get initial purchase cost (from poultry_flocks table itself)
        flock_initial_cost_row = db.execute(
            "SELECT initial_cost FROM poultry_flocks WHERE id = ?", (flock_id,)
        ).fetchone()
        
        total_initial_cost = flock_initial_cost_row['initial_cost'] if flock_initial_cost_row and flock_initial_cost_row['initial_cost'] else 0
        total_inventory_cost = inventory_cost_row['total'] if inventory_cost_row and inventory_cost_row['total'] else 0
        total_other_expenses = other_expense_row['total'] if other_expense_row and other_expense_row['total'] else 0

        total_flock_cost = total_initial_cost + total_inventory_cost + total_other_expenses

        # --- CALCULATE NET PROFIT ---
        net_profit = final_price - total_flock_cost

        # --- UPDATE THE FLOCK RECORD ---
        db.execute("""
            UPDATE poultry_flocks SET 
                status = 'Inactive', 
                final_sale_price = ?, 
                total_cost = ?, 
                net_profit = ?
            WHERE id = ?
        """, (final_price, total_flock_cost, net_profit, flock_id))
        db.commit()

        flash(f"Flock successfully deactivated. Final Profit: ₦{net_profit:,.2f}", "success")
    
    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")
        
    return redirect(url_for('poultry_dashboard'))

@app.route('/inventory/item/update/<int:item_id>', methods=['POST'])
@login_required
@permission_required('edit_inventory_item')
def update_inventory_item(item_id):
    """
    Handles updating an existing inventory item's details.
    """
    db = get_db()
    try:
        name = request.form.get('name')
        category = request.form.get('category')
        unit = request.form.get('unit')
        low_stock_threshold = float(request.form.get('low_stock_threshold', 0))
        unit_cost = float(request.form.get('unit_cost', 0))
        sale_price = float(request.form.get('sale_price', 0))
        expiry_date = request.form.get('expiry_date') or None

        if not all([name, category, unit]):
            flash('Item Name, Category, and Unit are required.', 'warning')
            return redirect(url_for('inventory_dashboard'))

        db.execute("""
            UPDATE inventory SET
                name = ?, category = ?, unit = ?, low_stock_threshold = ?,
                unit_cost = ?, sale_price = ?, expiry_date = ?
            WHERE id = ?
        """, (name, category, unit, low_stock_threshold, unit_cost, sale_price, expiry_date, item_id))
        db.commit()

        flash(f"Item '{name}' updated successfully!", 'success')

    except (ValueError, TypeError):
        flash("Invalid data provided. Please check your numbers.", 'danger')
    except sqlite3.IntegrityError:
        flash("An inventory item with that name might already exist.", 'danger')
        db.rollback()
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'danger')
        db.rollback()

    return redirect(url_for('inventory_dashboard'))

@app.route('/inventory/item/delete/<int:item_id>', methods=['POST'])
@login_required
@permission_required('delete_inventory_item')
def delete_inventory_item(item_id):
    """
    Handles deleting an inventory item ONLY if it has no transaction history.
    """
    db = get_db()
    try:
        usage_count = db.execute("SELECT COUNT(id) FROM inventory_log WHERE inventory_item_id = ?", (item_id,)).fetchone()[0]

        if usage_count > 0:
            flash("Cannot delete this item because it has a history of being used. Deleting it would corrupt your old reports.", "danger")
            return redirect(url_for('inventory_dashboard'))

        db.execute("DELETE FROM inventory WHERE id = ?", (item_id,))
        db.commit()
        flash("Inventory item successfully deleted.", "success")

    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        db.rollback()

    return redirect(url_for('inventory_dashboard'))

# ==============================================================================
# 13B. BROODING MANAGEMENT ROUTES
# ==============================================================================
@app.route('/brooding')
@login_required
@permission_required('view_brooding_dashboard')
def brooding_dashboard():
    """Displays the new Brooding Management dashboard."""
    db = get_db()
    
    active_batches_rows = db.execute("""
        SELECT 
            b.*,
            (SELECT COALESCE(SUM(il.cost_of_usage), 0) FROM inventory_log il WHERE il.brooding_batch_id = b.id) as running_feed_cost,
            (SELECT COALESCE(SUM(bl.mortality_count), 0) FROM brooding_log bl WHERE bl.batch_id = b.id) as total_mortality
        FROM brooding_batches b
        WHERE b.status = 'Brooding'
        ORDER BY b.arrival_date DESC
    """).fetchall()

    active_batches = []
    for row in active_batches_rows:
        batch = dict(row)
        
        total_running_cost = (batch['initial_cost'] or 0) + (batch['running_feed_cost'] or 0)
        batch['total_running_cost'] = total_running_cost
        
        current_chick_count = batch['current_chick_count']
        if current_chick_count > 0:
            batch['cost_per_bird_to_date'] = total_running_cost / current_chick_count
        else:
            batch['cost_per_bird_to_date'] = 0
            
        active_batches.append(batch)

    brooding_supplies = db.execute("SELECT * FROM inventory WHERE category IN ('Feed', 'Medication') AND quantity > 0").fetchall()
    active_flocks = db.execute("SELECT id, flock_name FROM poultry_flocks WHERE status = 'Active'").fetchall()
    asset_accounts = db.execute("SELECT * FROM accounts WHERE type = 'Asset' AND name NOT LIKE 'Inventory%' ORDER BY name").fetchall()
    
    return render_template(
        'brooding.html',
        user=g.user,
        active_batches=active_batches,
        brooding_supplies=brooding_supplies,
        active_flocks=active_flocks,
        asset_accounts=asset_accounts,
        today_date=date.today().strftime('%Y-%m-%d')
    )

@app.route('/brooding/batch/add', methods=['POST'])
@login_required
@permission_required('add_brooding_batch')
@check_day_closed('arrival_date')
def add_brooding_batch():
    db = get_db()
    try:
        name = request.form.get('batch_name')
        breed = request.form.get('breed')
        arrival_date = request.form.get('arrival_date')
        chick_count = int(request.form.get('initial_chick_count'))
        initial_cost = float(request.form.get('initial_cost'))
        payment_account_id = int(request.form.get('payment_account_id'))

        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO brooding_batches (batch_name, breed, arrival_date, initial_chick_count, initial_cost, current_chick_count)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, breed, arrival_date, chick_count, initial_cost, chick_count))
        new_batch_id = cursor.lastrowid
        
        if initial_cost > 0:
            brooding_asset_id = get_account_id('Inventory - Brooding Livestock', acc_type='Asset', create_if_not_found=False)
            description = f"Purchase of {chick_count} chicks for batch: {name}"
            db.execute("""
                INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (arrival_date, description, brooding_asset_id, payment_account_id, initial_cost, g.user.id))

        db.commit()
        flash(f"New brooding batch '{name}' added successfully and purchase recorded.", "success")
        
    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")
        
    return redirect(url_for('brooding_dashboard'))

@app.route('/brooding/log/mortality', methods=['POST'])
@login_required
@permission_required('log_brooding_mortality')
@check_day_closed('log_date')
def log_brooding_mortality():
    """Logs daily mortality and updates the current chick count."""
    db = get_db()
    try:
        log_date = request.form.get('log_date')
        batch_id = int(request.form.get('batch_id'))
        mortality_count = int(request.form.get('mortality_count'))

        db.execute("INSERT INTO brooding_log (log_date, batch_id, mortality_count) VALUES (?, ?, ?)",
                   (log_date, batch_id, mortality_count))
        
        db.execute("UPDATE brooding_batches SET current_chick_count = current_chick_count - ? WHERE id = ?",
                   (mortality_count, batch_id))
        db.commit()
        flash(f"{mortality_count} mortalities logged successfully.", "success")
    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")
    return redirect(url_for('brooding_dashboard'))

@app.route('/brooding/batch/transfer', methods=['POST'])
@login_required
@permission_required('transfer_brooding_batch')
def transfer_brooding_batch():
    """
    Handles transferring a completed brooding batch to a laying flock.
    """
    db = get_db()
    try:
        batch_id = int(request.form.get('batch_id'))
        target_flock_id = int(request.form.get('target_flock_id'))
        transfer_date = request.form.get('transfer_date')

        batch = db.execute("SELECT * FROM brooding_batches WHERE id = ?", (batch_id,)).fetchone()
        if not batch:
            flash("Brooding batch not found.", "danger")
            return redirect(url_for('brooding_dashboard'))
        
        feed_cost_row = db.execute(
            "SELECT COALESCE(SUM(cost_of_usage), 0) as total FROM inventory_log WHERE brooding_batch_id = ?",
            (batch_id,)
        ).fetchone()
        
        final_total_cost = (batch['initial_cost'] or 0) + (feed_cost_row['total'] or 0)
        surviving_birds = batch['current_chick_count']
        final_cost_per_bird = final_total_cost / surviving_birds if surviving_birds > 0 else 0

        target_flock = db.execute("SELECT bird_count, cost_per_bird FROM poultry_flocks WHERE id = ?", (target_flock_id,)).fetchone()
        
        current_flock_value = (target_flock['bird_count'] or 0) * (target_flock['cost_per_bird'] or 0)
        new_birds_value = surviving_birds * final_cost_per_bird
        new_total_birds_in_flock = (target_flock['bird_count'] or 0) + surviving_birds
        new_average_cost = (current_flock_value + new_birds_value) / new_total_birds_in_flock if new_total_birds_in_flock > 0 else 0

        db.execute("""
            UPDATE brooding_batches SET 
                status = 'Transferred',
                transfer_date = ?,
                final_chick_count = ?,
                final_total_cost = ?,
                final_cost_per_bird = ?
            WHERE id = ?
        """, (transfer_date, surviving_birds, final_total_cost, final_cost_per_bird, batch_id))
        
        db.execute("""
            UPDATE poultry_flocks SET bird_count = ?, cost_per_bird = ? 
            WHERE id = ?
        """, (new_total_birds_in_flock, new_average_cost, target_flock_id))
        
        if final_total_cost > 0:
            flock_asset_id = get_account_id('Inventory - Laying Flock Asset', acc_type='Asset', create_if_not_found=False)
            brooding_asset_id = get_account_id('Inventory - Brooding Livestock', acc_type='Asset', create_if_not_found=False)
            
            description = f"Transfer of batch ID {batch_id} value to flock ID {target_flock_id}"
            
            db.execute("""
                INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (transfer_date, description, flock_asset_id, brooding_asset_id, final_total_cost, g.user.id))

        db.commit()
        flash(f"{surviving_birds} birds successfully transferred. New flock average cost/bird: ₦{new_average_cost:,.2f}", "success")

    except Exception as e:
        db.rollback()
        flash(f"An error occurred during transfer: {e}", "danger")
        
    return redirect(url_for('brooding_dashboard'))

@app.route('/poultry/flock/log-mortality', methods=['POST'])
@login_required
@permission_required('log_poultry_mortality')
@check_day_closed('log_date')
def log_flock_mortality():
    db = get_db()
    try:
        flock_id = int(request.form.get('flock_id'))
        mortality_count = int(request.form.get('mortality_count'))
        log_date = request.form.get('log_date')
        
        flock = db.execute("SELECT bird_count, cost_per_bird FROM poultry_flocks WHERE id = ?", (flock_id,)).fetchone()
        if not flock:
            raise Exception("Flock not found.")

        if mortality_count > flock['bird_count']:
            flash(f"Cannot log {mortality_count} mortalities. Only {flock['bird_count']} birds in flock.", "danger")
            return redirect(url_for('poultry_dashboard'))
        
        asset_account = get_account_id('Inventory - Laying Flock Asset', acc_type='Asset', create_if_not_found=False)
        expense_account = get_account_id('Livestock Loss Expense', acc_type='Expense')
        if not asset_account or not expense_account:
            raise Exception("Required asset or expense accounts not found in Chart of Accounts.")

        total_loss_value = mortality_count * (flock['cost_per_bird'] or 0)
        
        db.execute("UPDATE poultry_flocks SET bird_count = bird_count - ? WHERE id = ?", (mortality_count, flock_id))
        
        if total_loss_value > 0:
            db.execute("""
                INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id, related_flock_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (log_date, f"Mortality loss of {mortality_count} bird(s) from flock ID {flock_id}", expense_account, asset_account, total_loss_value, g.user.id, flock_id))

        db.commit()
        flash(f"{mortality_count} mortalities recorded. Financial loss of ₦{total_loss_value:,.2f} posted to expenses.", "success")

    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")

    return redirect(url_for('poultry_dashboard'))

@app.route('/brooding/batch/edit/<int:batch_id>', methods=['POST'])
@login_required
@permission_required('add_brooding_batch')
def edit_brooding_batch(batch_id):
    db = get_db()
    try:
        name = request.form.get('batch_name')
        breed = request.form.get('breed')
        arrival_date = request.form.get('arrival_date')
        initial_count = int(request.form.get('initial_chick_count'))
        initial_cost = float(request.form.get('initial_cost'))
        
        db.execute("""
            UPDATE brooding_batches SET
                batch_name = ?,
                breed = ?,
                arrival_date = ?,
                initial_chick_count = ?,
                initial_cost = ?
            WHERE id = ?
        """, (name, breed, arrival_date, initial_count, initial_cost, batch_id))
        db.commit()
        flash(f"Batch '{name}' updated successfully.", "success")
        
    except Exception as e:
        db.rollback()
        flash(f"An error occurred while updating the batch: {e}", "danger")
        
    return redirect(url_for('brooding_dashboard'))

@app.route('/brooding/batch/delete/<int:batch_id>', methods=['POST'])
@login_required
@permission_required('add_brooding_batch')
def delete_brooding_batch(batch_id):
    db = get_db()
    try:
        feed_logs = db.execute("SELECT id FROM inventory_log WHERE brooding_batch_id = ?", (batch_id,)).fetchone()
        mortality_logs = db.execute("SELECT id FROM brooding_log WHERE batch_id = ?", (batch_id,)).fetchone()

        if feed_logs or mortality_logs:
            flash("Cannot delete this batch because it has a history of feed usage or mortality. Deleting it would corrupt your reports.", "danger")
            return redirect(url_for('brooding_dashboard'))

        db.execute("DELETE FROM brooding_batches WHERE id = ?", (batch_id,))
        db.commit()
        flash("Brooding batch deleted successfully.", "success")

    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")
        
    return redirect(url_for('brooding_dashboard'))

@app.route('/report/brooding')
@login_required
@permission_required('run_brooding_report')
def report_brooding():
    db = get_db()
    start_date, end_date = _get_report_dates(request.args)
    
    brooding_report_data = db.execute("""
        SELECT
            b.id,
            b.batch_name,
            b.breed,
            b.arrival_date,
            b.transfer_date,
            b.initial_chick_count,
            b.initial_cost,
            (b.initial_chick_count - b.current_chick_count) as total_mortality,
            (SELECT COALESCE(SUM(il.cost_of_usage), 0) FROM inventory_log il WHERE il.brooding_batch_id = b.id) as total_feed_cost
        FROM brooding_batches b
        WHERE b.arrival_date BETWEEN ? AND ?
        ORDER BY b.arrival_date DESC
    """, (start_date, end_date)).fetchall()
    
    report_rows = []
    for row in brooding_report_data:
        row_dict = dict(row)
        total_cost = (row_dict['initial_cost'] or 0) + (row_dict['total_feed_cost'] or 0)
        row_dict['total_cost'] = total_cost
        
        mortality_rate = 0
        if row_dict['initial_chick_count'] > 0:
            mortality_rate = row_dict['total_mortality'] / row_dict['initial_chick_count']
        row_dict['mortality_rate'] = mortality_rate
        
        report_rows.append(row_dict)

    return render_template(
        'report_brooding.html',
        user=g.user,
        start_date=start_date,
        end_date=end_date,
        report_data=report_rows,
        now=datetime.utcnow(),
        report_title="Brooding Performance Report"
    )

@app.route('/report/brooding-mortality')
@login_required
@permission_required('run_mortality_report')
def report_brooding_mortality():
    db = get_db()
    start_date, end_date = _get_report_dates(request.args)
    
    mortality_logs = db.execute("""
        SELECT
            bl.log_date,
            bb.batch_name,
            bb.initial_chick_count,
            bl.mortality_count
        FROM brooding_log bl
        JOIN brooding_batches bb ON bl.batch_id = bb.id
        WHERE
            bl.log_date BETWEEN ? AND ?
        ORDER BY bl.log_date DESC, bb.batch_name
    """, (start_date, end_date)).fetchall()

    total_mortality = sum(log['mortality_count'] for log in mortality_logs)

    return render_template(
        'report_brooding_mortality.html',
        user=g.user,
        start_date=start_date,
        end_date=end_date,
        mortality_logs=mortality_logs,
        total_mortality=total_mortality,
        now=datetime.utcnow(),
        report_title="Brooding Section Mortality Log"
    )

@app.route('/report/mortality')
@login_required
@permission_required('run_mortality_report')
def report_mortality():
    db = get_db()
    start_date, end_date = _get_report_dates(request.args)
    
    mortality_logs = db.execute("""
        SELECT
            bl.log_date,
            bb.batch_name,
            bb.initial_chick_count,
            bl.mortality_count
        FROM brooding_log bl
        JOIN brooding_batches bb ON bl.batch_id = bb.id
        WHERE
            bl.log_date BETWEEN ? AND ?
        ORDER BY bl.log_date DESC, bb.batch_name
    """, (start_date, end_date)).fetchall()

    total_mortality = sum(log['mortality_count'] for log in mortality_logs)

    return render_template(
        'report_mortality.html',
        user=g.user,
        start_date=start_date,
        end_date=end_date,
        mortality_logs=mortality_logs,
        total_mortality=total_mortality,
        now=datetime.utcnow(),
        report_title="Brooding Mortality Report"
    )

# ==============================================================================
# 14. Table Water  route
# ==============================================================================
@app.route('/water/product/add', methods=['POST'])
@login_required
@permission_required('add_water_product')
def add_water_product():
    db = get_db()
    cursor = db.cursor()
    try:
        name = request.form.get('name')
        price = float(request.form.get('price', 0))

        if not name or price <= 0:
            flash('Product Name and a positive Price are required.', 'warning')
            return redirect(url_for('water_dashboard'))
        
        cursor.execute("""
            INSERT INTO inventory (name, category, quantity, unit, sale_price, unit_cost)
            VALUES (?, 'Finished Goods', 0, 'Unit', ?, 0)
        """, (name, price))
        new_inventory_item_id = cursor.lastrowid
        
        cursor.execute("""
            INSERT INTO water_products (name, price, quantity, inventory_item_id) 
            VALUES (?, ?, 0, ?)
        """, (name, price, new_inventory_item_id))
        
        cursor.execute("""
            INSERT INTO sales_packages (package_name, base_inventory_item_id, quantity_per_package, sale_price)
            VALUES (?, ?, 1, ?)
        """, (name, new_inventory_item_id, price))
        
        db.commit()
        flash(f"New water product '{name}' fully created and linked for sales!", 'success')

    except sqlite3.IntegrityError:
        db.rollback()
        flash(f"A product or inventory item with the name '{name}' already exists.", 'danger')
    except Exception as e:
        db.rollback()
        flash(f"An unexpected error occurred: {e}", 'danger')

    return redirect(url_for('water_dashboard'))

@app.route('/water/production/log', methods=['POST'])
@login_required
@permission_required('log_water_production')
@check_day_closed('production_date')
def add_water_production_log():
    db = get_db()
    try:
        production_date = request.form.get('production_date')
        product_id = int(request.form.get('product_id'))
        quantity_produced = int(request.form.get('quantity_produced'))
        notes = request.form.get('notes')

        if not all([production_date, product_id, quantity_produced]) or quantity_produced <= 0:
            flash('Date, Product, and a positive Quantity are required.', 'warning')
            return redirect(url_for('water_dashboard'))

        product_info = db.execute("SELECT inventory_item_id FROM water_products WHERE id = ?", (product_id,)).fetchone()
        if not product_info or not product_info['inventory_item_id']:
            flash("CRITICAL ERROR: This water product is not linked to an inventory item. Please delete and recreate it.", "danger")
            return redirect(url_for('water_dashboard'))
        
        inventory_id_to_update = product_info['inventory_item_id']

        db.execute("""
            INSERT INTO water_production_log (production_date, product_id, quantity_produced, notes)
            VALUES (?, ?, ?, ?)
        """, (production_date, product_id, quantity_produced, notes))
        
        db.execute("UPDATE water_products SET quantity = quantity + ? WHERE id = ?", (quantity_produced, product_id))

        db.execute("UPDATE inventory SET quantity = quantity + ? WHERE id = ?", 
                   (quantity_produced, inventory_id_to_update))
        
        db.commit()
        flash('Water production logged and stock updated successfully!', 'success')

    except Exception as e:
        db.rollback()
        flash(f"An unexpected error occurred: {e}", 'danger')
        
    return redirect(url_for('water_dashboard'))

@app.route('/water/product/update/<int:product_id>', methods=['POST'])
@login_required
@permission_required('edit_water_product')
def update_water_product(product_id):
    """Handles updating a water product and keeps prices in sync across all tables."""
    db = get_db()
    try:
        name = request.form.get('name')
        price = float(request.form.get('price', 0))

        if not name or price <= 0:
            flash('Product Name and a positive Price are required.', 'warning')
            return redirect(url_for('water_dashboard'))
        
        original_product = db.execute("SELECT name FROM water_products WHERE id = ?", (product_id,)).fetchone()
        if not original_product:
            flash("Product not found.", "danger")
            return redirect(url_for('water_dashboard'))

        db.execute("UPDATE water_products SET name = ?, price = ? WHERE id = ?", 
                   (name, price, product_id))
        
        db.execute("UPDATE inventory SET name = ?, sale_price = ? WHERE name = ?", 
                   (name, price, original_product['name']))
                   
        db.execute("UPDATE sales_packages SET package_name = ?, sale_price = ? WHERE package_name = ?", 
                   (name, price, original_product['name']))
        
        db.commit()
        flash(f"Product '{name}' updated successfully across all systems.", 'success')

    except (ValueError, TypeError) as e:
        db.rollback()
        flash(f"Invalid price provided. Please enter a valid number. Error: {e}", 'danger')
    except Exception as e:
        db.rollback()
        flash(f"An unexpected error occurred: {e}", 'danger')

    return redirect(url_for('water_dashboard'))

@app.route('/water/production/calculate-cost', methods=['POST'])
@login_required
@permission_required('calculate_water_cost')
def calculate_water_cost():
    db = get_db()
    try:
        production_log_id = int(request.form.get('production_log_id'))

        prod_log = db.execute(
            "SELECT quantity_produced, production_labor_cost, sales_commission FROM water_production_log WHERE id = ?",
            (production_log_id,)
        ).fetchone()

        if not prod_log:
            flash("Production run not found.", "danger")
            return redirect(url_for('water_dashboard'))

        material_cost_row = db.execute(
            "SELECT SUM(COALESCE(cost_of_usage, 0)) as total FROM inventory_log WHERE water_production_log_id = ?",
            (production_log_id,)
        ).fetchone()
        total_material_cost = material_cost_row['total'] if material_cost_row and material_cost_row['total'] else 0
        
        total_labor_cost = prod_log['production_labor_cost'] or 0
        total_commission_cost = prod_log['sales_commission'] or 0
        
        grand_total_cost = total_material_cost + total_labor_cost + total_commission_cost

        quantity_produced = prod_log['quantity_produced']
        cost_per_unit = grand_total_cost / quantity_produced if quantity_produced > 0 else 0

        db.execute("""
            UPDATE water_production_log SET 
                total_cost = ?, 
                cost_per_unit = ?
            WHERE id = ?
        """, (grand_total_cost, cost_per_unit, production_log_id))
        db.commit()

        flash(f"Costs finalized for production run. Total Cost: ₦{grand_total_cost:,.2f}, Cost per unit: ₦{cost_per_unit:,.2f}", "success")
    
    except Exception as e:
        db.rollback()
        flash(f"An error occurred while calculating costs: {e}", "danger")
        
    return redirect(url_for('water_dashboard'))

@app.route('/water/production/log/edit/<int:log_id>', methods=['POST'])
@login_required
@permission_required('edit_production_log')
def edit_production_log(log_id):
    db = get_db()
    try:
        original_log = db.execute("SELECT * FROM water_production_log WHERE id = ?", (log_id,)).fetchone()
        if not original_log:
            flash("Production log not found.", "danger")
            return redirect(url_for('water_dashboard'))
        
        original_qty = original_log['quantity_produced']
        original_product_info = db.execute("SELECT inventory_item_id FROM water_products WHERE id = ?", (original_log['product_id'],)).fetchone()
        
        new_date = request.form.get('production_date')
        new_product_id = int(request.form.get('product_id'))
        new_qty = int(request.form.get('quantity_produced'))
        new_notes = request.form.get('notes')
        
        if original_product_info and original_product_info['inventory_item_id']:
            db.execute("UPDATE inventory SET quantity = quantity - ? WHERE id = ?", 
                       (original_qty, original_product_info['inventory_item_id']))
        
        new_product_info = db.execute("SELECT inventory_item_id FROM water_products WHERE id = ?", (new_product_id,)).fetchone()
        if new_product_info and new_product_info['inventory_item_id']:
            db.execute("UPDATE inventory SET quantity = quantity + ? WHERE id = ?", 
                       (new_qty, new_product_info['inventory_item_id']))
        
        db.execute("""
            UPDATE water_production_log SET
                production_date = ?, product_id = ?, quantity_produced = ?, notes = ?
            WHERE id = ?
        """, (new_date, new_product_id, new_qty, new_notes, log_id))
        
        db.commit()
        flash("Production log updated successfully and inventory adjusted.", "success")

    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")
        
    return redirect(url_for('water_dashboard'))

@app.route('/water/production/log/delete/<int:log_id>', methods=['POST'])
@login_required
@permission_required('edit_production_log')
def delete_production_log(log_id):
    db = get_db()
    try:
        log_to_delete = db.execute("SELECT * FROM water_production_log WHERE id = ?", (log_id,)).fetchone()
        if not log_to_delete:
            flash("Production log not found.", "danger")
            return redirect(url_for('water_dashboard'))
        
        qty_to_remove = log_to_delete['quantity_produced']
        product_info = db.execute("SELECT inventory_item_id FROM water_products WHERE id = ?", (log_to_delete['product_id'],)).fetchone()

        if product_info and product_info['inventory_item_id']:
            db.execute("UPDATE inventory SET quantity = quantity - ? WHERE id = ?", 
                       (qty_to_remove, product_info['inventory_item_id']))
        
        db.execute("DELETE FROM water_production_log WHERE id = ?", (log_id,))

        db.commit()
        flash("Production log deleted and inventory stock reversed.", "success")
        
    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")
        
    return redirect(url_for('water_dashboard'))

@app.route('/water/production/other-costs/log', methods=['POST'])
@login_required
@permission_required('calculate_water_cost') # Reusing permission for this
def log_other_water_costs():
    db = get_db()
    try:
        log_id = int(request.form.get('production_log_id'))
        labor_cost = float(request.form.get('production_labor_cost', 0))
        commission_cost = float(request.form.get('sales_commission', 0))
        
        db.execute("""
            UPDATE water_production_log 
            SET 
                production_labor_cost = COALESCE(production_labor_cost, 0) + ?,
                sales_commission = COALESCE(sales_commission, 0) + ?
            WHERE id = ?
        """, (labor_cost, commission_cost, log_id))
        
        db.commit()
        flash("Labor and commission costs logged successfully.", "success")
        
    except Exception as e:
        db.rollback()
        flash(f"An error occurred while logging costs: {e}", "danger")
        
    return redirect(url_for('water_dashboard'))

# ==============================================================================
# 15. CONTACT ROUTES
# ==============================================================================
@app.route('/bookkeeping/contact_ledger/<int:contact_id>')
@login_required
@permission_required('view_bookkeeping')
def contact_ledger(contact_id):
    """
    Displays a detailed, printable Statement of Account for a specific contact,
    including a date range filter, opening balance, and running balance.
    """
    db = get_db()
    
    contact = db.execute("SELECT * FROM contacts WHERE id = ?", (contact_id,)).fetchone()
    if not contact or not contact['account_id']:
        flash("Contact not found or does not have a linked ledger account.", "danger")
        return redirect(url_for('contacts_dashboard'))
    
    contact_account_id = contact['account_id']

    start_date, end_date = _get_report_dates(request.args)
    
    opening_balance_row = db.execute("""
        SELECT (
            (SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE debit_account_id = ? AND transaction_date < ?) -
            (SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE credit_account_id = ? AND transaction_date < ?)
        ) as opening_balance
    """, (contact_account_id, start_date, contact_account_id, start_date)).fetchone()
    opening_balance = opening_balance_row['opening_balance'] if opening_balance_row else 0

    transactions = db.execute("""
        SELECT 
            je.transaction_date, 
            je.description,
            CASE WHEN je.debit_account_id = ? THEN je.amount ELSE 0 END as debit,
            CASE WHEN je.credit_account_id = ? THEN je.amount ELSE 0 END as credit,
            debit_acc.name as debit_account_name,
            credit_acc.name as credit_account_name
        FROM journal_entries je
        JOIN accounts debit_acc ON je.debit_account_id = debit_acc.id
        JOIN accounts credit_acc ON je.credit_account_id = credit_acc.id
        WHERE (je.debit_account_id = ? OR je.credit_account_id = ?)
        AND je.transaction_date BETWEEN ? AND ?
        ORDER BY je.transaction_date ASC, je.id ASC
    """, (contact_account_id, contact_account_id, contact_account_id, contact_account_id, start_date, end_date)).fetchall()

    ledger_entries = []
    running_balance = opening_balance
    for tx_row in transactions:
        tx = dict(tx_row)
        running_balance += tx['debit'] - tx['credit']
        tx['running_balance'] = running_balance
        ledger_entries.append(tx)

    closing_balance = running_balance

    return render_template(
        'contact_ledger.html', 
        user=g.user,
        contact=contact,
        start_date=start_date,
        end_date=end_date,
        opening_balance=opening_balance,
        closing_balance=closing_balance,
        ledger_entries=ledger_entries,
        now=datetime.utcnow()
    )

@app.route('/contacts/edit/<int:contact_id>', methods=['GET'])
@login_required
@permission_required('edit_contact')
def edit_contact(contact_id):
    """Displays the form to edit an existing contact."""
    user = User.get_by_id(session['user_id'])
    conn = get_db()
    contact = conn.execute("SELECT * FROM contacts WHERE id = ?", (contact_id,)).fetchone()

    if not contact:
        flash("Contact not found.", "danger")
        return redirect(url_for('contacts_dashboard'))

    return render_template('edit_contact.html', user=user, contact=contact)

@app.route('/contacts/update/<int:contact_id>', methods=['POST'])
@login_required
@check_day_closed('date') # Consider if editing contact should be blocked by day closure
@permission_required('edit_contact')
def update_contact(contact_id):
    """Handles updating an existing contact."""
    if request.method == 'POST':
        name = request.form.get('name')
        contact_type = request.form.get('type')
        phone = request.form.get('phone')
        email = request.form.get('email')

        if not name or not contact_type:
            flash("Name and Contact Type are required.", "warning")
            return redirect(url_for('edit_contact', contact_id=contact_id))

        try:
            conn = get_db()
            conn.execute("UPDATE contacts SET name = ?, type = ?, phone = ?, email = ? WHERE id = ?",
                         (name, contact_type, phone, email, contact_id))
            conn.commit()
            flash(f"Contact '{name}' updated successfully!", "success")
        except sqlite3.IntegrityError:
            flash(f"Error: A contact with the name '{name}' already exists.", "danger")
        except sqlite3.Error as e:
            flash(f"Database error: {e}", "danger")
    
    return redirect(url_for('contacts_dashboard'))

@app.route('/contacts/delete/<int:contact_id>', methods=['POST'])
@login_required
@check_day_closed('date') # Consider if deleting contact should be blocked by day closure
@permission_required('delete_contact')
def delete_contact(contact_id):
    """Handles deleting a contact."""
    db = get_db()
    try:
        # Check for related journal entries first
        transaction_count = db.execute("SELECT COUNT(*) FROM journal_entries WHERE related_contact_id = ?", (contact_id,)).fetchone()[0]
        if transaction_count > 0:
            flash("Cannot delete contact with existing transactions. Please unlink transactions or mark contact as inactive.", "danger")
            return redirect(url_for('contacts_dashboard'))
        
        db.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
        db.commit()
        flash("Contact successfully deleted.", "success")
    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")
    return redirect(url_for('contacts_dashboard'))

@app.route('/contacts/add', methods=['POST'])
@login_required
@permission_required('add_contact')
def add_contact():
    db = get_db()
    try:
        name = request.form.get('name')
        contact_type = request.form.get('type')
        phone = request.form.get('phone')
        email = request.form.get('email')

        if not name or not contact_type:
            flash("Name and Contact Type are required.", "warning")
            return redirect(url_for('contacts_dashboard'))

        new_account_id = None
        if contact_type == 'Customer':
            parent_ar_acc = db.execute("SELECT code FROM accounts WHERE name = 'Accounts Receivable'").fetchone()
            if not parent_ar_acc:
                raise Exception("CRITICAL: Parent 'Accounts Receivable' account not found.")
            parent_code = parent_ar_acc['code']
            like_pattern = f"{parent_code}.%"
            sub_accounts = db.execute("SELECT code FROM accounts WHERE code LIKE ?", (like_pattern,)).fetchall()
            highest_sub_num = 0
            for acc in sub_accounts:
                try:
                    sub_num = int(acc['code'].split('.')[1])
                    if sub_num > highest_sub_num:
                        highest_sub_num = sub_num
                except (IndexError, ValueError):
                    continue
            new_sub_num = highest_sub_num + 1
            new_code = f"{parent_code}.{new_sub_num:02d}"
            account_name = f"A/R - {name}"
            cursor = db.cursor()
            cursor.execute("INSERT INTO accounts (code, name, type, created_at) VALUES (?, ?, 'Asset', CURRENT_TIMESTAMP)", (new_code, account_name))
            new_account_id = cursor.lastrowid

        assigned_id = None
        if g.user.role != 'admin':
            assigned_id = g.user.id

        db.execute("INSERT INTO contacts (name, type, phone, email, account_id, assigned_user_id) VALUES (?, ?, ?, ?, ?, ?)",
                     (name, contact_type, phone, email, new_account_id, assigned_id))
        db.commit()
        flash(f"Contact '{name}' added successfully!", "success")

    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")
    
    return redirect(url_for('contacts_dashboard'))

# ==============================================================================
# 16. ERROR HANDLERS & MAIN EXECUTION
# ==============================================================================
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# ==============================================================================
# 17. API ROUTES FOR OFFLINE SYNC
# ==============================================================================

@app.route('/api/sync/expense', methods=['POST'])
@login_required 
def sync_expense():
    """API endpoint to receive offline expense data."""
    data = request.get_json()
    db = get_db()

    try:
        # Use get_account_id helper for robustness
        payment_account_id = get_account_id(data['credit_account_id'], acc_type='Asset', create_if_not_found=False) 
        expense_account_id = get_account_id(data['debit_account_id'], acc_type='Expense', create_if_not_found=False)

        # Retrieve related_flock_id if it exists in the offline data
        related_flock_id = data.get('related_flock_id') 
        if related_flock_id:
            related_flock_id = int(related_flock_id)
        else:
            related_flock_id = None

        db.execute("""
            INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id, related_flock_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (data['date'], data['description'], expense_account_id, payment_account_id, float(data['amount']), g.user.id, related_flock_id))

        db.commit()
        print(f"Successfully synced offline expense: {data['description']}")
        return jsonify({'status': 'success', 'message': 'Synced'}), 200

    except Exception as e:
        db.rollback()
        print(f"Error syncing expense: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)