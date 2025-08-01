# ==============================================================================
# Babura Farm Manager - app.py (Version 4.0 - Final Cleaned Structure)
# ==============================================================================

# --- Core Imports ---
import os
import sqlite3
from datetime import date, timedelta
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for, flash,
                   session, g)
from flask_bcrypt import Bcrypt


from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from flask_bcrypt import Bcrypt
import sqlite3
import os
from datetime import date, timedelta, datetime # <-- ADD THIS LINE
from flask import Flask, render_template, request, redirect, url_for, flash, g, jsonify

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
from flask import send_from_directory
import os

@app.route('/sw.js')
def serve_sw():
    # This sends the sw.js file from your project's root directory
    return send_from_directory(os.path.join(app.root_path, ''), 'sw.js')
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
        # ===================== CORRECTED DEBUG CODE =====================
        print(f"\n--- PERMISSION CHECK ---")
        print(f"User checking: '{self.username}' (ID: {self.id})")
        print(f"User's role is: '{self.role}'")
        print(f"Permission required: '{required_permission}'")
        # ================================================================

        if self.role == 'admin':
            print("RESULT: Role is 'admin', access GRANTED.")
            print(f"------------------------")
            return True
        
        print("INFO: Role is not 'admin', checking the user_permissions table...")
        if self._permissions is None:
            db = get_db()
            perms_rows = db.execute("SELECT p.name FROM permissions p JOIN user_permissions up ON p.id = up.permission_id WHERE up.user_id = ?", (self.id,)).fetchall()
            self._permissions = {row['name'] for row in perms_rows}
        
        has_perm = required_permission in self._permissions
        if has_perm:
            print(f"RESULT: User HAS the specific permission '{required_permission}'. Access GRANTED.")
        else:
            print(f"RESULT: User does NOT have the specific permission '{required_permission}'. Access DENIED.")
        print(f"------------------------")
        return has_perm

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
# Add this new decorator in Section 4 of app.py

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
        now=datetime.utcnow() # <-- ADD THIS LINE
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
            "INSERT INTO accounts (code, name, type, is_active) VALUES (?, ?, 'Asset', 1)",
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
        conn.close()
        
        flash("Password updated successfully!", "success")
        return redirect(url_for('dashboard'))

    # For a GET request, just show the page
    return render_template('change_password.html', user=user)
@app.route('/admin/user/<int:user_id>/permissions', methods=['GET', 'POST'])
@login_required  # <--- THIS IS THE FIX
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
@login_required # Always good to have login_required here too
@permission_required('manage_users')
def delete_user(user_id): # <-- Add user_id here
    """Handles deleting a user."""
    if user_id == session['user_id']:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    # Use the new User.delete_by_id(user_id) static method
    # (Assuming you create this method for consistency)
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()

    flash("User successfully deleted.", "success")
    return redirect(url_for('admin_dashboard'))
# Add this new route in Section 5 of app.py

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
        # This ensures all steps succeed or none of them do.
        
        # 3. Create a single, massive closing journal entry
        description = f"Year-End Closing Entry for {year_to_close}"
        
        # The closing entry itself will be built up
        closing_entries = []

        # Zero out all revenue accounts (they have credit balances, so we debit them)
        for acc in accounts_to_close:
            if acc['type'] == 'Revenue' and acc['balance'] != 0:
                balance_to_close = -acc['balance']
                total_revenue += balance_to_close
                db.execute("""
                    INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (closing_date, f"Close {acc['name']}", acc['id'], retained_earnings_id, balance_to_close, g.user.id))

        # Zero out all expense accounts (they have debit balances, so we credit them)
        for acc in accounts_to_close:
            if acc['type'] == 'Expense' and acc['balance'] != 0:
                balance_to_close = acc['balance']
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
# PERMISSION MODEL (Add this after the User class)
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
            # Start a transaction
            # 1. Delete all existing permissions for this user
            db.execute("DELETE FROM user_permissions WHERE user_id = ?", (user_id,))

            # 2. Insert the new permissions
            # We convert the list of IDs into a list of tuples for executemany
            permissions_to_insert = [(user_id, int(pid)) for pid in permission_ids]
            
            if permissions_to_insert:
                db.executemany(
                    "INSERT INTO user_permissions (user_id, permission_id) VALUES (?, ?)",
                    permissions_to_insert
                )
            
            # 3. Commit the changes
            db.commit()

        except Exception as e:
            # If any error occurs, roll back the transaction
            db.rollback()
            print(f"ERROR updating permissions: {e}")
            # Optionally re-raise the exception or flash a message
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
    stats = {
        'net_profit': total_income - total_expenses,
        'total_income': total_income,
        'total_expenses': total_expenses,
        'total_active_birds': poultry_stats_row['total_active_birds'] or 0,
        'eggs_today': poultry_stats_row['eggs_today'] or 0,
        'eggs_last_7_days': poultry_stats_row['eggs_last_7_days'] or 0,
    }
    return render_template('dashboard.html', user=g.user, stats=stats, financial_chart_data=[], expense_data=[], egg_chart_data=[], table_water_chart_data=[])

@app.route('/inventory')
@login_required
@permission_required('view_inventory')
def inventory_dashboard():
    #
    # NOTE: I have removed the @check_day_closed decorator.
    # This decorator is for POST requests (forms) and should not be on a
    # GET request that just displays a page.
    #
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
                # Add a check to ensure the date is valid before comparing
                expiry_dt = date.fromisoformat(item['expiry_date'])
                if (expiry_dt - date.today()).days <= 30:
                    is_expiring_soon = True
            except (ValueError, TypeError):
                pass # Ignore invalid date formats
        if is_expiring_soon: expiring_soon_count += 1
        
        item['is_low_stock'] = is_low_stock
        item['is_expiring_soon'] = is_expiring_soon
        processed_inventory_list.append(item)
        
    stats = {'total_value': total_value, 'low_stock_count': low_stock_count, 'expiring_soon_count': expiring_soon_count}
    
    # ======================================================
    # THIS IS THE CORRECTED RETURN STATEMENT
    # ======================================================
    return render_template(
        'inventory.html', 
        user=g.user, 
        stats=stats, 
        inventory_list=processed_inventory_list,
        today_date=date.today().strftime('%Y-%m-%d') # <-- THE MISSING LINE IS ADDED HERE
    )
@app.route('/poultry')
@login_required
@permission_required('view_poultry')
def poultry_dashboard():
    db = get_db()
    
    # --- YOUR EXISTING STATS QUERIES (They are perfect) ---
    poultry_stats_row = db.execute("SELECT (SELECT COALESCE(SUM(bird_count), 0) FROM poultry_flocks WHERE status = 'Active') as total_active_birds, (SELECT COALESCE(SUM(quantity), 0) FROM egg_log WHERE log_date = date('now', 'localtime')) as eggs_today, (SELECT COALESCE(SUM(quantity), 0) FROM egg_log WHERE log_date >= date('now', '-6 days')) as eggs_last_7_days").fetchone()
    total_active_birds = poultry_stats_row['total_active_birds'] or 0
    eggs_today = poultry_stats_row['eggs_today'] or 0
    stats = {
        'total_active_birds': total_active_birds,
        'eggs_today': eggs_today,
        'eggs_last_7_days': poultry_stats_row['eggs_last_7_days'] or 0,
        'avg_production_rate': (eggs_today / total_active_birds) if total_active_birds > 0 else 0
    }

    # --- YOUR EXISTING DATA QUERIES (Also perfect) ---
    active_flocks = db.execute("SELECT * FROM poultry_flocks WHERE status = 'Active' ORDER BY acquisition_date DESC").fetchall()
    inactive_flocks = db.execute("SELECT * FROM poultry_flocks WHERE status = 'Inactive' ORDER BY acquisition_date DESC").fetchall()
    egg_logs = db.execute("SELECT el.*, pf.flock_name FROM egg_log el JOIN poultry_flocks pf ON el.flock_id = pf.id ORDER BY el.log_date DESC, el.id DESC LIMIT 10").fetchall()

    # --- THIS IS THE CRITICAL FIX ---
    # We must fetch the list of inventory items that are in the 'Feed' category
    # and pass this list to the template for the modal's dropdown.
    feed_items = db.execute(
        "SELECT * FROM inventory WHERE category = 'Feed' AND quantity > 0 ORDER BY name ASC"
    ).fetchall()
    # --- END OF FIX ---

    # This is the final, correct return statement that sends ALL necessary data
    return render_template(
        'poultry.html', 
        user=g.user, 
        stats=stats, 
        active_flocks=active_flocks, 
        inactive_flocks=inactive_flocks,
        egg_logs=egg_logs,
        feed_items=feed_items,  # <-- Passing the new list here
        today_date=date.today().strftime('%Y-%m-%d')
    )
@app.route('/water')
@login_required
@permission_required('view_water')
def water_dashboard():
    db = get_db()
    
    # --- STATS CALCULATION (Your original logic is good) ---
    stats_row = db.execute("SELECT (SELECT COALESCE(SUM(quantity * price), 0) FROM water_products) as total_stock_value, (SELECT COALESCE(SUM(quantity), 0) FROM water_products) as total_units_in_stock, (SELECT COALESCE(SUM(quantity_produced), 0) FROM water_production_log WHERE production_date = date('now', 'localtime')) as produced_today, (SELECT COALESCE(SUM(quantity_produced), 0) FROM water_production_log WHERE production_date >= date('now', '-6 days')) as produced_last_7_days").fetchone()
    stats = {
        'total_stock_value': stats_row['total_stock_value'] or 0,
        'total_units_in_stock': stats_row['total_units_in_stock'] or 0,
        'produced_today': stats_row['produced_today'] or 0,
        'produced_last_7_days': stats_row['produced_last_7_days'] or 0
    }
    
    # --- DATA FETCHING (This is the crucial part) ---
    # This query now includes the new cost columns and the product price for the edit modal
    production_logs = db.execute("""
        SELECT wpl.*, wp.name as product_name, wp.price
        FROM water_production_log wpl 
        JOIN water_products wp ON wpl.product_id = wp.id 
        ORDER BY wpl.production_date DESC, wpl.id DESC
    """).fetchall()
    
    # NEW: Fetch inventory items that are materials for water production
    water_materials = db.execute("SELECT * FROM inventory WHERE category = 'Water Production' AND quantity > 0").fetchall()

    # CRITICAL FIX: Fetch the list of water product types for the "Log Production" form
    water_products = db.execute("SELECT * FROM water_products ORDER BY name ASC").fetchall()

    # This is the return statement that sends ALL necessary data to the template
    return render_template(
        'water_management.html', 
        user=g.user, 
        stats=stats, 
        production_logs=production_logs,
        water_materials=water_materials,
        water_products=water_products, # <-- THE MISSING PIECE
        today_date=date.today().strftime('%Y-%m-%d')
    )
@app.route('/contacts')
@login_required
@permission_required('view_contacts')
def contacts_dashboard():
    db = get_db()
    
    # --- Search Logic ---
    search_query = request.args.get('q', '')
    base_sql = """
        SELECT
            c.id, c.name, c.type, c.phone, c.email,
            (
                (SELECT COALESCE(SUM(je.amount), 0) FROM journal_entries je WHERE je.debit_account_id = c.account_id)
                -
                (SELECT COALESCE(SUM(je.amount), 0) FROM journal_entries je WHERE je.credit_account_id = c.account_id)
            ) as balance
        FROM contacts c
    """
    params = []
    if search_query:
        base_sql += " WHERE c.name LIKE ?"
        params.append(f"%{search_query}%")
    base_sql += " ORDER BY c.name ASC"
    
    contacts_list = db.execute(base_sql, params).fetchall()

    # --- KPI Card Calculations ---
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
        'contacts.html', # This now points to our single, redesigned template
        user=g.user,
        stats=stats,
        contacts_list=contacts_list
    )
# ==============================================================================
# 7. FINANCIAL CENTER & BOOKKEEPING ROUTES
# ==============================================================================
@app.route('/financials')
@login_required
@permission_required('view_bookkeeping')
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
@permission_required('view_bookkeeping')
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
# In app.py, replace your existing general_journal function

@app.route('/financials/journal')
@login_required
@permission_required('view_bookkeeping')
def general_journal():
    db = get_db()
    
    # Fetch all accounts for the "Add New Entry" modal dropdowns
    chart_of_accounts = db.execute("SELECT * FROM accounts WHERE is_active = 1 ORDER BY type, name").fetchall()

    # Get the search query from the URL arguments
    search_query = request.args.get('q', '')
    
    # Base SQL query to fetch existing journal entries
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
        chart_of_accounts=chart_of_accounts # Pass the accounts list to the template
    )

@app.route('/financials/ledger/<int:account_id>')
@login_required
@permission_required('view_bookkeeping')
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
@permission_required('edit_bookkeeping') # Or a more specific permission
def add_account():
    """Handles creating a new account from the modal form."""
    db = get_db()
    try:
        # Extract data from the form
        name = request.form.get('name')
        code = request.form.get('code')
        account_type = request.form.get('type')
        opening_balance = float(request.form.get('opening_balance', 0))

        # Basic validation
        if not all([name, code, account_type]):
            flash('Account Name, Code, and Type are required.', 'warning')
            return redirect(url_for('chart_of_accounts'))

        # --- Start Database Transaction ---
        # 1. Insert the new account
        cursor = db.cursor()
        cursor.execute("INSERT INTO accounts (code, name, type) VALUES (?, ?, ?)",
                       (code, name, account_type))
        new_account_id = cursor.lastrowid

        # 2. If there's an opening balance, create an initial journal entry
        if opening_balance > 0:
            # We need a balancing account, usually 'Opening Balance Equity'
            balancing_account = db.execute("SELECT id FROM accounts WHERE name = 'Opening Balance Equity'").fetchone()
            if not balancing_account:
                # If it doesn't exist, create it
                cursor.execute("INSERT INTO accounts (code, name, type) VALUES ('3998', 'Opening Balance Equity', 'Equity')")
                balancing_account_id = cursor.lastrowid
            else:
                balancing_account_id = balancing_account['id']

            # Determine if the new account should be debited or credited
            if account_type in ['Asset', 'Expense']:
                # Debit the new account, Credit Opening Balance Equity
                debit_id, credit_id = new_account_id, balancing_account_id
            else: # Liability, Equity, Revenue
                # Credit the new account, Debit Opening Balance Equity
                debit_id, credit_id = balancing_account_id, new_account_id
            
            db.execute("""
                INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (date.today().strftime('%Y-%m-%d'), f"Opening Balance for {name}", debit_id, credit_id, opening_balance, g.user.id))

        db.commit()
        # --- End of Transaction ---

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
# ==============================================================================
# 8. DATA ENTRY ROUTES (THE "THREE PILLARS")
# ==============================================================================
@app.route('/transactions/customer', methods=['GET', 'POST'])
@login_required
@permission_required('add_sale')
def customer_transaction():
    db = get_db()
    
    if request.method == 'POST':
        try:
            # --- Common data for both transaction types ---
            tx_date = request.form.get('date')
            customer_id = int(request.form.get('customer_id'))
            tx_type = request.form.get('transaction_type')
            
            customer = db.execute("SELECT * FROM contacts WHERE id = ?", (customer_id,)).fetchone()
            if not customer or not customer['account_id']:
                raise Exception("This customer does not have a linked receivable account.")
            customer_ar_id = customer['account_id']

            # --- SMART LOGIC: Handle each transaction type separately ---
            
            if tx_type == 'deposit':
                # This block only runs for DEPOSITS (no inventory change)
                payment_account_id = int(request.form.get('payment_account_id'))
                amount = float(request.form.get('amount'))
                description = request.form.get('description')
                
                debit_id, credit_id = payment_account_id, customer_ar_id
                db.execute("""
                    INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id, related_contact_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (tx_date, description, debit_id, credit_id, amount, g.user.id, customer_id))

            elif tx_type == 'credit_sale':
                # This block only runs for CREDIT SALES (with inventory change)
                total_amount = float(request.form.get('total_amount'))
                description = f"Credit Sale to {customer['name']}"
                
                # --- NEW INVENTORY LOGIC (COPIED FROM add_sale_post) ---
                packages_sold = []
                i = 0
                while True:
                    package_id = request.form.get(f'items[{i}][id]')
                    if not package_id: break
                    quantity_of_packages = float(request.form.get(f'items[{i}][quantity]'))
                    packages_sold.append({'id': int(package_id), 'quantity': quantity_of_packages})
                    i += 1
                
                if not packages_sold:
                    raise Exception("Cannot record a credit sale with no items.")

                inventory_reduction_list = {}
                for package in packages_sold:
                    package_info = db.execute("SELECT base_inventory_item_id, quantity_per_package FROM sales_packages WHERE id = ?", (package['id'],)).fetchone()
                    base_item_id = package_info['base_inventory_item_id']
                    pieces_to_reduce = package['quantity'] * package_info['quantity_per_package']
                    inventory_reduction_list[base_item_id] = inventory_reduction_list.get(base_item_id, 0) + pieces_to_reduce
                # --- END OF NEW INVENTORY LOGIC ---
                
                # Debit Customer's A/R, Credit Sales Revenue
                sales_revenue_id = db.execute("SELECT id FROM accounts WHERE name = 'Product Sales'").fetchone()['id']
                debit_id, credit_id = customer_ar_id, sales_revenue_id
                
                cursor = db.cursor()
                cursor.execute("""
                    INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id, related_contact_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (tx_date, description, debit_id, credit_id, total_amount, g.user.id, customer_id))

                # Reduce inventory for each item sold
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

    # --- GET request logic (this is perfect as is) ---
    customers = db.execute("SELECT * FROM contacts WHERE type = 'Customer' ORDER BY name").fetchall()
    asset_accounts = db.execute("SELECT * FROM accounts WHERE type = 'Asset' AND name NOT LIKE 'A/R - %' ORDER BY name").fetchall()
    
    # We must fetch the packages for sale here too
    packages_for_sale = db.execute("""
        SELECT sp.* FROM sales_packages sp
        JOIN inventory i ON sp.base_inventory_item_id = i.id
        WHERE i.quantity >= sp.quantity_per_package
    """).fetchall()
    
    return render_template('customer_transaction.html', user=g.user, customers=customers, asset_accounts=asset_accounts, inventory_items=packages_for_sale, today_date=date.today().strftime('%Y-%m-%d'))

@app.route('/sales/new')
@login_required
@permission_required('add_sale')
def new_sale():
    """Diagnostic version to find the empty dropdown problem."""
    db = get_db()
    print("\n--- RUNNING DIAGNOSTIC FOR /sales/new ---")

    # Test 1: Do any sales packages exist at all?
    all_packages = db.execute("SELECT * FROM sales_packages").fetchall()
    print(f"Found {len(all_packages)} total sales package(s) defined.")
    for pkg in all_packages:
        print(f"  - Package: ID={pkg['id']}, Name='{pkg['package_name']}', BaseItemID={pkg['base_inventory_item_id']}")

    # Test 2: Let's check the inventory status for those base items
    print("\nChecking inventory status for base items...")
    base_item_ids = {pkg['base_inventory_item_id'] for pkg in all_packages}
    if base_item_ids:
        # Create the correct number of placeholders for the query
        placeholders = ', '.join('?' for _ in base_item_ids)
        inventory_status = db.execute(f"SELECT id, name, quantity FROM inventory WHERE id IN ({placeholders})", list(base_item_ids)).fetchall()
        for item in inventory_status:
            print(f"  - Inventory: ID={item['id']}, Name='{item['name']}', Quantity on Hand={item['quantity']}")
    else:
        print("  - No base items to check.")
        
    # This is the real query we are debugging
    packages_for_sale = db.execute("""
        SELECT sp.*, i.name as base_item_name, i.quantity as stock_on_hand
        FROM sales_packages sp
        JOIN inventory i ON sp.base_inventory_item_id = i.id
        WHERE i.quantity >= sp.quantity_per_package
    """).fetchall()
    
    print(f"\nFINAL RESULT: The query found {len(packages_for_sale)} package(s) available for sale.")
    print("-----------------------------------------\n")

    # The rest of the function remains the same
    if g.user.cash_account_id:
        asset_accounts = db.execute("SELECT * FROM accounts WHERE id = ?", (g.user.cash_account_id,)).fetchall()
    else:
        asset_accounts = db.execute("SELECT * FROM accounts WHERE type = 'Asset' AND is_active = 1 ORDER BY name ASC").fetchall()

    return render_template(
        'add_sale.html', 
        user=g.user, 
        inventory_items=packages_for_sale, 
        asset_accounts=asset_accounts
    )
@app.route('/sales/add', methods=['POST'])
@login_required
@permission_required('add_sale')
@check_day_closed('date')
def add_sale_post():
    """
    Handles a new sale, calculating inventory reduction based on packages sold.
    """
    db = get_db()
    cursor = db.cursor()
    try:
        sale_date = request.form.get('date')
        total_amount = float(request.form.get('total_amount'))
        
        if g.user.cash_account_id:
            payment_account_id = g.user.cash_account_id
        else:
            payment_account_id = int(request.form.get('debit_account_id'))

        # --- New Inventory Logic ---
        packages_sold = []
        i = 0
        while True:
            package_id = request.form.get(f'items[{i}][id]')
            if not package_id: break
            quantity_of_packages = float(request.form.get(f'items[{i}][quantity]'))
            packages_sold.append({'id': int(package_id), 'quantity': quantity_of_packages})
            i += 1

        if not packages_sold:
            flash('Cannot record a sale with no items.', 'warning')
            return redirect(url_for('new_sale'))
            
        inventory_reduction_list = {}
        
        for package in packages_sold:
            package_info = db.execute("SELECT base_inventory_item_id, quantity_per_package FROM sales_packages WHERE id = ?", (package['id'],)).fetchone()
            base_item_id = package_info['base_inventory_item_id']
            pieces_to_reduce = package['quantity'] * package_info['quantity_per_package']
            inventory_reduction_list[base_item_id] = inventory_reduction_list.get(base_item_id, 0) + pieces_to_reduce

        # --- DATABASE TRANSACTION ---
        
        # --- THIS IS THE CORRECTED JOURNAL ENTRY QUERY ---
        sales_account = cursor.execute("SELECT id FROM accounts WHERE name = 'Product Sales'").fetchone()
        if not sales_account:
            raise Exception("CRITICAL: 'Product Sales' account not found in Chart of Accounts.")
        credit_account_id = sales_account['id']
        description = f"Point of Sale transaction by {g.user.username}"
        
        cursor.execute("""
            INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (sale_date, description, payment_account_id, credit_account_id, total_amount, g.user.id))
        new_entry_id = cursor.lastrowid
        
        # Loop through our reduction list and update the main inventory
        for item_id, total_pieces in inventory_reduction_list.items():
            db.execute("UPDATE inventory SET quantity = quantity - ? WHERE id = ?", (total_pieces, item_id))
        
        db.commit()
        flash(f"Sale of ₦{total_amount:,.2f} recorded and inventory updated!", 'success')
        return redirect(url_for('sale_receipt', entry_id=new_entry_id))

    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")
        return redirect(url_for('new_sale'))
@app.route('/sales/packages')
@login_required
@permission_required('edit_inventory') # Reuse permission
def manage_sales_packages():
    """Displays the new page for managing sales packages."""
    db = get_db()
    # Get base inventory items (like 'Eggs') that can be packaged for sale.
    base_items = db.execute("SELECT * FROM inventory WHERE category = 'Produce' ORDER BY name").fetchall()
    # Get all existing packages to display in a list.
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

        # --- NEW ROBUST CHECK ---
        # Before we do anything, check if an inventory item with this package name
        # already exists. This will catch orphans left by previous deletes.
        existing_inventory_item = db.execute("SELECT id FROM inventory WHERE name = ?", (name,)).fetchone()
        if existing_inventory_item:
            # If an orphan exists, we should use it instead of creating a new one.
            # This is a more advanced concept. For now, the safest thing is to
            # inform the user to clean it up manually.
            flash(f"An inventory item named '{name}' already exists. Please delete it from the main Inventory page before creating this package.", "danger")
            return redirect(url_for('manage_sales_packages'))

        # Now we can proceed as before
        db.execute("""
            INSERT INTO sales_packages (package_name, base_inventory_item_id, quantity_per_package, sale_price)
            VALUES (?, ?, ?, ?)
        """, (name, base_item_id, qty_per_package, price))
        
        # Also create the corresponding item in the main inventory
        db.execute("""
            INSERT INTO inventory (name, category, quantity, unit, sale_price, unit_cost)
            VALUES (?, 'Finished Goods', 0, 'Package', ?, 0)
        """, (name, price))

        db.commit()
        flash(f"New sales package '{name}' created successfully.", "success")
    except sqlite3.IntegrityError:
        db.rollback()
        # This will now correctly catch duplicate package names
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
        # Get the new data from the edit form
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
        # It's safe to delete sales packages as they are not directly linked in historical logs.
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
@permission_required('add_expense')
def new_expense():
    db = get_db()
    suppliers = db.execute("SELECT * FROM contacts WHERE type = 'Supplier' ORDER BY name ASC").fetchall()
    expense_accounts = db.execute("SELECT * FROM accounts WHERE type = 'Expense' AND is_active = 1 ORDER BY name ASC").fetchall()
    asset_accounts = db.execute("SELECT * FROM accounts WHERE type = 'Asset' AND is_active = 1 ORDER BY name ASC").fetchall()
    inventory_items = [dict(row) for row in db.execute("SELECT id, name, category FROM inventory ORDER BY name ASC").fetchall()]
    return render_template('add_expense.html', user=g.user, suppliers=suppliers, expense_accounts=expense_accounts, asset_accounts=asset_accounts, inventory_items=inventory_items)

@app.route('/expenses/add', methods=['POST'])
@login_required
@check_day_closed('date')
@permission_required('add_expense')
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
        if not all([date, description, debit_acc_id, credit_acc_id, amount]) or amount <= 0:
            flash('Date, description, accounts, and a positive amount are required.', 'warning')
            return redirect(url_for('new_expense'))
        db.execute("INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id, related_contact_id) VALUES (?, ?, ?, ?, ?, ?, ?)", (date, description, debit_acc_id, credit_acc_id, amount, g.user.id, contact_id))
        if inventory_item_id and quantity_purchased_str and float(quantity_purchased_str) > 0:
            db.execute("UPDATE inventory SET quantity = quantity + ? WHERE id = ?", (float(quantity_purchased_str), int(inventory_item_id)))
        db.commit()
        flash(f"Expense of ₦{amount:,.2f} for '{description}' recorded successfully!", 'success')
        return redirect(url_for('financial_center'))
    except Exception as e:
        db.rollback()
        flash(f"An error occurred while recording the expense: {e}", "danger")
        return redirect(url_for('new_expense'))
# In app.py, replace your existing add_journal_entry function

@app.route('/journal/add_manual', methods=['POST'])
@login_required
@check_day_closed('date')
@permission_required('add_manual_journal')
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
@permission_required('add_sale')
@check_day_closed('date')
def sale_receipt(entry_id):
    db = get_db()
    # Fetch the journal entry for the sale
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
    # Default start date is the first day of the current month
    default_start = date.today().replace(day=1).strftime('%Y-%m-%d')
    # Default end date is today
    default_end = date.today().strftime('%Y-%m-%d')
    
    start_str = request_args.get('start_date', default_start)
    end_str = request_args.get('end_date', default_end)
    
    # Ensure dates are not empty, if so, use defaults
    if not start_str:
        start_str = default_start
    if not end_str:
        end_str = default_end

    return start_str, end_str
@app.route('/reports')
@login_required
def reports_dashboard():
    return render_template('reports_dashboard.html', user=g.user)
# Add this route to app.py, in Section 10

@app.route('/report/profit-loss')
@login_required
@permission_required('view_reports')
def report_profit_loss():
    """Calculates and displays the Profit & Loss statement for a date range."""
    # Use our helper to get the date range from the URL arguments
    start_date, end_date = _get_report_dates(request.args)
    
    db = get_db()
    
    # This powerful SQL query gets the final balance for all Revenue and Expense accounts
    # within the specified date range.
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

    # Process the results in Python
    revenue_accounts = []
    expense_accounts = []
    total_revenue = 0
    total_expenses = 0

    for acc in account_balances:
        if acc['type'] == 'Revenue':
            # Revenue has a natural credit balance, so its calculated balance will be negative.
            # We flip the sign to display it as a positive number.
            balance = -acc['balance']
            if balance != 0:
                revenue_accounts.append({'name': acc['name'], 'balance': balance})
                total_revenue += balance
        elif acc['type'] == 'Expense':
            # Expenses have a natural debit balance, so the calculated balance is already positive.
            balance = acc['balance']
            if balance != 0:
                expense_accounts.append({'name': acc['name'], 'balance': balance})
                total_expenses += balance

    # Prepare the final data dictionary for the template
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
# Add this route to app.py, in Section 10, after report_profit_loss

@app.route('/report/balance-sheet')
@login_required
@permission_required('view_reports')
def report_balance_sheet():
    """Calculates and displays the Balance Sheet as of a specific date."""
    # A balance sheet is as of a single date, so we primarily use the end_date.
    start_date, end_date = _get_report_dates(request.args)
    
    db = get_db()
    
    # This query gets the final balance for all Asset, Liability, and Equity accounts
    # as of the specified end_date.
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

    # We also need the net profit up to the end_date to calculate retained earnings.
    net_profit_row = db.execute("""
        SELECT 
            (SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE credit_account_id IN (SELECT id FROM accounts WHERE type = 'Revenue') AND transaction_date <= ?)
            -
            (SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE debit_account_id IN (SELECT id FROM accounts WHERE type = 'Expense') AND transaction_date <= ?)
            as profit
    """, (end_date, end_date)).fetchone()
    net_profit = net_profit_row['profit'] if net_profit_row else 0

    # Process the results in Python
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
                liabilities.append({'name': acc['name'], 'balance': -balance})
                total_liabilities += -balance
        elif acc['type'] == 'Equity':
            if balance != 0:
                equity_accounts.append({'name': acc['name'], 'balance': -balance})
                total_equity += -balance
    
    # Add Retained Earnings to the Equity section
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
        start_date=start_date, # Pass dates for consistency in the template
        end_date=end_date,
        now=datetime.utcnow()
    )
# Add this route to app.py, in Section 10

@app.route('/report/trial-balance')
@login_required
@permission_required('view_reports')
def report_trial_balance():
    """Calculates and displays the Trial Balance as of a specific date."""
    start_date, end_date = _get_report_dates(request.args)
    db = get_db()

    # This query gets the final balance for ALL accounts as of the end_date.
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

    # Process the results in Python
    trial_balance_accounts = []
    total_debits = 0
    total_credits = 0

    for acc in all_accounts:
        balance = acc['balance']
        
        # Skip accounts with a zero balance
        if balance == 0:
            continue

        debit_amount = 0
        credit_amount = 0

        # Assets and Expenses normally have a DEBIT balance
        if acc['type'] in ['Asset', 'Expense']:
            debit_amount = balance
            total_debits += balance
        # Liabilities, Equity, and Revenue normally have a CREDIT balance
        else:
            credit_amount = -balance # Flip the sign for display
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
# Add this route to app.py, in Section 10

@app.route('/report/eggs')
@login_required
@permission_required('view_reports')
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
    
    # Calculate number of days in the range to find the average
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
# Add this route to app.py, in Section 10

@app.route('/report/water')
@login_required
@permission_required('view_reports')
def report_water():
    """Calculates and displays the Water Production report."""
    start_date, end_date = _get_report_dates(request.args)
    db = get_db()
    
    production_logs = db.execute("""
        SELECT wpl.production_date, wpl.quantity_produced, wp.name as product_name
        FROM water_production_log wpl
        JOIN water_products wp ON wpl.product_id = wp.id
        WHERE wpl.production_date BETWEEN ? AND ?
        ORDER BY wpl.production_date ASC
    """, (start_date, end_date)).fetchall()
    
    total_produced = sum(log['quantity_produced'] for log in production_logs)
    
    # Calculate number of days in the range to find the average
    try:
        start_dt = date.fromisoformat(start_date)
        end_dt = date.fromisoformat(end_date)
        num_days = (end_dt - start_dt).days + 1
        average_daily = total_produced / num_days if num_days > 0 else 0
    except (ValueError, TypeError):
        average_daily = 0

    data = {
        "production_logs": production_logs,
        "total_produced": total_produced,
        "average_daily": average_daily
    }
    
    return render_template(
        'report_water.html', 
        user=g.user,
        data=data,
        start_date=start_date,
        end_date=end_date,
        now=datetime.utcnow()
    )
@app.route('/reports/inventory')
@login_required
@permission_required('view_reports') # Make sure you have a 'view_reports' permission
def inventory_report():
    """Generates a detailed report of current inventory status and valuation."""
    db = get_db()
    
    # This query calculates the value per item and gets all necessary details
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

    # Calculate overall summary statistics
    total_inventory_cost = sum(item['total_cost_value'] for item in inventory_items)
    total_inventory_sale_value = sum(item['total_sale_value'] for item in inventory_items)
    
    # Pass today's date for the report header
    report_date = date.today().strftime('%B %d, %Y')

    return render_template(
        'inventory_report.html',
        user=g.user,
        inventory_items=inventory_items,
        total_inventory_cost=total_inventory_cost,
        total_inventory_sale_value=total_inventory_sale_value,
        report_date=report_date
    )
# ==============================================================================
# In app.py, DELETE your old inventory report routes and REPLACE with this one.
# ==============================================================================
@app.route('/report/inventory')
@login_required
@permission_required('view_reports')
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
        'report_inventory.html', # <-- This is the final, correct filename.
        user=g.user,
        inventory_items=inventory_items,
        total_inventory_cost=total_inventory_cost,
        total_inventory_sale_value=total_inventory_sale_value,
        report_date=report_date,
        now=datetime.utcnow()
    )
@app.route('/report/daily-sales')
@login_required
@permission_required('view_reports')
def report_daily_sales():
    """
    Generates a report of all sales for a specific day, grouped by the user
    who made the sale, with subtotals and a grand total.
    """
    db = get_db()
    
    # Get the report date from the URL, defaulting to today if not provided.
    report_date_str = request.args.get('report_date', date.today().strftime('%Y-%m-%d'))
    
    # This is the query to get all sales for the selected date.
    # We define a "sale" as any journal entry that credits the 'Product Sales' account.
    # This is a robust way to isolate sales transactions.
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
    
    # --- Process the data to group by user ---
    sales_by_user = {}
    grand_total = 0

    for tx in transactions:
        username = tx['username']
        # If we haven't seen this user yet, create their entry in our dictionary
        if username not in sales_by_user:
            sales_by_user[username] = {
                'transactions': [],
                'total': 0
            }
        
        # Add the transaction to this user's list
        sales_by_user[username]['transactions'].append(dict(tx))
        # Add the amount to this user's subtotal
        sales_by_user[username]['total'] += tx['amount']
        # Add to the grand total for the day
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
@permission_required('view_reports')
def report_feed_movement():
    """Generates a report on feed usage across all farm sections."""
    db = get_db()
    start_date, end_date = _get_report_dates(request.args)
    
    # This query joins the inventory log with brooding and poultry tables
    # to show where every unit of feed went.
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

@app.route('/report/mortality')
@login_required
@permission_required('view_reports')
def report_mortality():
    """Generates a report on mortality in the brooding section."""
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
        now=datetime.utcnow()
    )

@app.route('/report/flock-movement')
@login_required
@permission_required('view_reports')
def report_flock_movement():
    """Shows a historical view of all flocks, both active and completed."""
    db = get_db()
    
    # Fetch all flocks, regardless of status, and calculate their costs
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
# ==============================================================================
# 12. DATA MODIFICATION & ACTION ROUTES (Called by Modals)
# ==============================================================================

@app.route('/inventory/item/add', methods=['POST'])
@login_required
@check_day_closed('date')
@permission_required('edit_inventory')
def add_inventory_item():
    """Handles creating a new inventory item type from the modal form."""
    try:
        # Extract data from the form
        name = request.form.get('name')
        category = request.form.get('category')
        quantity = float(request.form.get('quantity', 0))
        unit = request.form.get('unit')
        low_stock_threshold = float(request.form.get('low_stock_threshold', 0))
        unit_cost = float(request.form.get('unit_cost', 0))
        sale_price = float(request.form.get('sale_price', 0)) # Assuming you added this field to the modal
        expiry_date = request.form.get('expiry_date') or None

        # Basic validation
        if not all([name, category, unit]):
            flash('Item Name, Category, and Unit are required.', 'warning')
            return redirect(url_for('inventory_dashboard'))

        # Insert into the database
        db = get_db()
        db.execute("""
            INSERT INTO inventory (name, category, quantity, unit, low_stock_threshold, unit_cost, sale_price, expiry_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, category, quantity, unit, low_stock_threshold, unit_cost, sale_price, expiry_date))
        db.commit()

        flash(f"New inventory item '{name}' added successfully!", 'success')

    except (ValueError, TypeError) as e:
        flash(f"Invalid data provided. Please check your numbers. Error: {e}", 'danger')
    except sqlite3.IntegrityError:
        flash(f"An inventory item with that name might already exist.", 'danger')
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'danger')

    return redirect(url_for('inventory_dashboard'))
@app.route('/inventory/stock/add', methods=['POST'])
@login_required
@check_day_closed('date')
@permission_required('edit_inventory')
def add_inventory_stock():
    """Handles adding stock to an existing inventory item from the modal."""
    try:
        item_id = int(request.form.get('inventory_item_id'))
        quantity_added = float(request.form.get('quantity_added'))
        # purchase_date = request.form.get('purchase_date') # Can be used for detailed logging later

        if not item_id or quantity_added <= 0:
            flash('Invalid item or quantity provided. Quantity must be positive.', 'warning')
            return redirect(url_for('inventory_dashboard'))

        db = get_db()
        # Use a relative UPDATE to prevent race conditions
        db.execute("UPDATE inventory SET quantity = quantity + ? WHERE id = ?", (quantity_added, item_id))
        db.commit()

        flash('Stock added successfully!', 'success')

    except (ValueError, TypeError) as e:
        flash(f"Invalid data provided. Please check your numbers. Error: {e}", 'danger')
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'danger')

    return redirect(url_for('inventory_dashboard'))
@app.route('/inventory/usage/log', methods=['POST'])
@login_required
@permission_required('edit_inventory')
@check_day_closed('log_date')
def log_inventory_usage():
    """
    Handles logging the usage of an inventory item and calculates the cost.
    This single function can now link usage to a poultry flock, a water 
    production run, OR a brooding batch, making it highly flexible.
    """
    db = get_db()
    try:
        # --- Standard fields from the form ---
        item_id = int(request.form.get('inventory_item_id'))
        quantity_used = float(request.form.get('quantity_used'))
        log_date = request.form.get('log_date')

        # --- NEW: Optional Link Fields ---
        # The form will only send ONE of these. The others will be `None`.
        flock_id = request.form.get('flock_id') or None
        water_log_id = request.form.get('water_production_log_id') or None
        brooding_batch_id = request.form.get('brooding_batch_id') or None # <-- THE NEW FIELD

        if not all([item_id, quantity_used, log_date]) or quantity_used <= 0:
            flash('Invalid item, quantity, or date provided.', 'warning')
            return redirect(request.referrer or url_for('dashboard'))

        # --- Transaction Logic (Mostly Unchanged) ---
        item = db.execute("SELECT quantity, name, unit_cost FROM inventory WHERE id = ?", (item_id,)).fetchone()
        if not item or item['quantity'] < quantity_used:
            flash(f"Not enough stock for '{item['name'] if item else 'item'}'. Only {item['quantity'] if item else 0} available.", 'danger')
            return redirect(request.referrer or url_for('dashboard'))

        # Calculate the cost of this specific usage event
        cost_of_this_usage = quantity_used * (item['unit_cost'] or 0)
        
        # 1. Decrease the quantity in the main inventory table
        db.execute("UPDATE inventory SET quantity = quantity - ? WHERE id = ?", (quantity_used, item_id))

        # 2. Add a record to the inventory_log table with ALL possible link fields.
        #    SQLite will correctly handle the fields that are None.
        db.execute("""
            INSERT INTO inventory_log 
            (log_date, inventory_item_id, quantity_used, cost_of_usage, flock_id, water_production_log_id, brooding_batch_id, created_by_user_id) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (log_date, item_id, quantity_used, cost_of_this_usage, flock_id, water_log_id, brooding_batch_id, g.user.id))
        
        db.commit()

        flash(f'Usage of {item["name"]} logged successfully (Cost: ₦{cost_of_this_usage:,.2f})', 'success')

    except Exception as e:
        db.rollback()
        flash(f"An unexpected error occurred: {e}", 'danger')

    # `request.referrer` is a smart way to redirect the user back to the page they came from 
    # (e.g., back to the brooding dashboard or the poultry dashboard).
    return redirect(request.referrer or url_for('dashboard'))
# ==============================================================================
# 13. DATA MODIFICATION & ACTION ROUTES
# ==============================================================================
@app.route('/poultry/eggs/log', methods=['POST'])
@login_required
@permission_required('edit_poultry')
@check_day_closed('log_date')
def add_egg_log():
    db = get_db()
    try:
        # --- Get Data From the SIMPLER Form (no value_per_crate needed) ---
        log_date = request.form.get('log_date')
        flock_id = int(request.form.get('flock_id'))
        feed_item_id = int(request.form.get('feed_item_id'))
        feed_quantity_used = float(request.form.get('feed_quantity_used'))
        crates = int(request.form.get('crates', 0) or 0)
        pieces = int(request.form.get('pieces', 0) or 0)
        spoiled_count = int(request.form.get('spoiled_count', 0) or 0)

        # --- Get Current State of Inventory ---
        # 1. Get the "Eggs" inventory item to see current quantity and value
        eggs_item = db.execute("SELECT id, quantity, unit_cost FROM inventory WHERE name = 'Eggs'").fetchone()
        if not eggs_item:
            raise Exception("CRITICAL: Inventory item 'Eggs' not found. Please create it first.")
        
        current_egg_quantity = eggs_item['quantity'] or 0
        current_egg_unit_cost = eggs_item['unit_cost'] or 0
        current_total_value = current_egg_quantity * current_egg_unit_cost

        # 2. Get the feed item to calculate the cost of today's production
        feed_item = db.execute("SELECT unit_cost, quantity, name FROM inventory WHERE id = ?", (feed_item_id,)).fetchone()
        if not feed_item: raise Exception("Feed item not found.")
        if feed_quantity_used > feed_item['quantity']: raise Exception(f"Not enough {feed_item['name']} in stock.")
        
        # This is the cost of the raw materials (feed) used today
        cost_of_production_today = feed_quantity_used * (feed_item['unit_cost'] or 0)

        # --- Calculations ---
        EGGS_PER_CRATE = 30
        total_eggs_laid = (crates * EGGS_PER_CRATE) + pieces
        good_eggs_produced_today = total_eggs_laid - spoiled_count
        
        if good_eggs_produced_today < 0:
            raise Exception("Spoiled count cannot be greater than total eggs laid.")
            
        # --- THE AVERAGE COST CALCULATION ---
        new_total_value = current_total_value + cost_of_production_today
        new_total_quantity = current_egg_quantity + good_eggs_produced_today
        new_average_unit_cost = new_total_value / new_total_quantity if new_total_quantity > 0 else 0

        # --- Get Account IDs ---
        def get_account_id(name):
            account = db.execute("SELECT id FROM accounts WHERE name = ?", (name,)).fetchone()
            if not account:
                raise Exception(f"CRITICAL SETUP ERROR: Account '{name}' not found.")
            return account['id']

        feed_inventory_acc_id = get_account_id('Inventory - Feed')
        egg_inventory_acc_id = get_account_id('Inventory - Eggs')
        
        # --- DATABASE TRANSACTION ---
        
        # 1. Update the operational log
        db.execute("""
            INSERT INTO egg_log (log_date, flock_id, crates, pieces, quantity, spoiled_count, feed_cost)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (log_date, flock_id, crates, pieces, good_eggs_produced_today, spoiled_count, cost_of_production_today))

        # 2. Decrease feed stock
        db.execute("UPDATE inventory SET quantity = quantity - ? WHERE id = ?", (feed_quantity_used, feed_item_id))
        
        # 3. CRITICAL UPDATE: Update "Eggs" item with new quantity AND new average unit cost
        db.execute("UPDATE inventory SET quantity = ?, unit_cost = ? WHERE id = ?", 
                   (new_total_quantity, new_average_unit_cost, eggs_item['id']))

        # 4. Create a simpler, more accurate journal entry
        #    This entry reflects the conversion of one asset (Feed) into another (Eggs)
        description = f"Daily egg production cost for {log_date}"
        db.execute("""
            INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id) 
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (log_date, description, egg_inventory_acc_id, feed_inventory_acc_id, cost_of_production_today, g.user.id))
        
        # Note: Spoilage is now handled as a separate inventory adjustment, not in this production entry.

        db.commit()
        flash(f"Production logged. New average cost for eggs is now ₦{new_average_unit_cost:,.2f} per piece.", "success")

    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")
        
    return redirect(url_for('poultry_dashboard'))
@app.route('/poultry/flock/add', methods=['POST'])
@login_required
@check_day_closed('date')
@permission_required('edit_poultry')
def add_flock_post():
    """Handles creating a new flock from the modal form."""
    try:
        # Extract data from the form
        name = request.form.get('flock_name')
        breed = request.form.get('breed')
        acq_date = request.form.get('acquisition_date')
        bird_count = int(request.form.get('bird_count', 0))
        status = request.form.get('status')

        # Basic validation
        if not all([name, breed, acq_date, status]) or bird_count <= 0:
            flash('All fields are required and bird count must be positive.', 'warning')
            return redirect(url_for('poultry_dashboard'))

        # Insert into the database
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
@permission_required('edit_poultry') # Or a more specific permission
def deactivate_flock():
    """Calculates the final profit/loss for a flock and sets it to inactive."""
    db = get_db()
    try:
        flock_id = int(request.form.get('flock_id'))
        final_price = float(request.form.get('final_sale_price'))
        
        # --- CALCULATE TOTAL COSTS ---
        # Sum the cost of all inventory used by this specific flock
        cost_row = db.execute(
            "SELECT SUM(cost_of_usage) as total FROM inventory_log WHERE flock_id = ?",
            (flock_id,)
        ).fetchone()
        total_flock_cost = cost_row['total'] if cost_row and cost_row['total'] else 0

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
@permission_required('edit_inventory')
def update_inventory_item(item_id):
    """
    Handles updating an existing inventory item's details.
    Note: This function correctly does NOT update the current quantity on hand.
    That should be done via 'Add Stock' or 'Log Usage'.
    """
    db = get_db()
    try:
        # Extract all data from the edit form
        name = request.form.get('name')
        category = request.form.get('category')
        unit = request.form.get('unit')
        low_stock_threshold = float(request.form.get('low_stock_threshold', 0))
        unit_cost = float(request.form.get('unit_cost', 0))
        sale_price = float(request.form.get('sale_price', 0))
        expiry_date = request.form.get('expiry_date') or None

        # Basic validation
        if not all([name, category, unit]):
            flash('Item Name, Category, and Unit are required.', 'warning')
            return redirect(url_for('inventory_dashboard'))

        # Update the item in the database
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
@permission_required('edit_inventory') # Can reuse the same permission
def delete_inventory_item(item_id):
    """
    Handles deleting an inventory item ONLY if it has no transaction history.
    This protects data integrity.
    """
    db = get_db()
    try:
        # SECURITY CHECK: Before deleting, check if this item is used in any logs.
        usage_count = db.execute("SELECT COUNT(id) FROM inventory_log WHERE inventory_item_id = ?", (item_id,)).fetchone()[0]

        if usage_count > 0:
            flash("Cannot delete this item because it has a history of being used. Deleting it would corrupt your old reports.", "danger")
            return redirect(url_for('inventory_dashboard'))

        # If it has no history, it's safe to delete.
        db.execute("DELETE FROM inventory WHERE id = ?", (item_id,))
        db.commit()
        flash("Inventory item successfully deleted.", "success")

    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        db.rollback()

    return redirect(url_for('inventory_dashboard'))
# ==============================================================================
# 13B. BROODING MANAGEMENT ROUTES (NEW SECTION)
# ==============================================================================
@app.route('/brooding')
@login_required
@permission_required('view_poultry') # Reuse existing permission
def brooding_dashboard():
    """Displays the new Brooding Management dashboard."""
    db = get_db()
    
    # Get all active brooding batches and calculate their running costs
    active_batches = db.execute("""
        SELECT 
            b.*,
            (SELECT COALESCE(SUM(il.cost_of_usage), 0) FROM inventory_log il WHERE il.brooding_batch_id = b.id) as running_feed_cost,
            (SELECT COALESCE(SUM(bl.mortality_count), 0) FROM brooding_log bl WHERE bl.batch_id = b.id) as total_mortality
        FROM brooding_batches b
        WHERE b.status = 'Brooding'
        ORDER BY b.arrival_date DESC
    """).fetchall()

    # Get inventory items categorized as "Feed" or "Medication" for the modals
    brooding_supplies = db.execute("SELECT * FROM inventory WHERE category IN ('Feed', 'Medication') AND quantity > 0").fetchall()

    # Get a list of main "Active" flocks to transfer birds into
    active_flocks = db.execute("SELECT id, flock_name FROM poultry_flocks WHERE status = 'Active'").fetchall()

    # This is the return statement that sends all the data to your HTML file
    return render_template(
        'brooding.html',
        user=g.user,
        active_batches=active_batches,
        brooding_supplies=brooding_supplies,
        active_flocks=active_flocks,
        today_date=date.today().strftime('%Y-%m-%d')
    )

@app.route('/brooding/batch/add', methods=['POST'])
@login_required
@permission_required('edit_poultry')
@check_day_closed('arrival_date')
def add_brooding_batch():
    """Adds a new batch of day-old chicks."""
    db = get_db()
    try:
        name = request.form.get('batch_name')
        breed = request.form.get('breed')
        arrival_date = request.form.get('arrival_date')
        chick_count = int(request.form.get('initial_chick_count'))
        initial_cost = float(request.form.get('initial_cost'))

        db.execute("""
            INSERT INTO brooding_batches (batch_name, breed, arrival_date, initial_chick_count, initial_cost, current_chick_count)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, breed, arrival_date, chick_count, initial_cost, chick_count))
        db.commit()
        flash(f"New brooding batch '{name}' added successfully.", "success")
    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")
    return redirect(url_for('brooding_dashboard'))

@app.route('/brooding/log/mortality', methods=['POST'])
@login_required
@permission_required('edit_poultry')
@check_day_closed('log_date')
def log_brooding_mortality():
    """Logs daily mortality and updates the current chick count."""
    db = get_db()
    try:
        log_date = request.form.get('log_date')
        batch_id = int(request.form.get('batch_id'))
        mortality_count = int(request.form.get('mortality_count'))

        # Add the daily log entry
        db.execute("INSERT INTO brooding_log (log_date, batch_id, mortality_count) VALUES (?, ?, ?)",
                   (log_date, batch_id, mortality_count))
        
        # Update the master count in the brooding_batches table
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
@permission_required('edit_poultry')
def transfer_brooding_batch():
    db = get_db()
    try:
        # ... (Get form data: batch_id, transfer_date, target_flock_id) ...
        # ... (Calculate final_cost_per_bird as you did before) ...
        
        # --- NEW LOGIC: UPDATE THE TARGET FLOCK ---
        # 1. Get the target flock's current data
        target_flock = db.execute("SELECT bird_count, cost_per_bird FROM poultry_flocks WHERE id = ?", (target_flock_id,)).fetchone()
        
        # 2. Calculate the new average cost per bird for the flock
        current_total_value = (target_flock['bird_count'] or 0) * (target_flock['cost_per_bird'] or 0)
        new_birds_value = surviving_birds * final_cost_per_bird
        new_total_birds = (target_flock['bird_count'] or 0) + surviving_birds
        new_average_cost = (current_total_value + new_birds_value) / new_total_birds if new_total_birds > 0 else 0

        # --- UPDATE TABLES IN A TRANSACTION ---
        # Update the brooding batch (as before)
        db.execute("UPDATE brooding_batches SET ... WHERE id = ?", (..., batch_id))
        
        # Update the active flock with new bird count AND new average cost
        db.execute("""
            UPDATE poultry_flocks SET bird_count = ?, cost_per_bird = ? 
            WHERE id = ?
        """, (new_total_birds, new_average_cost, target_flock_id))
        
        db.commit()
        flash(f"{surviving_birds} birds successfully transferred. New flock average cost/bird: ₦{new_average_cost:,.2f}", "success")
    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")
    return redirect(url_for('brooding_dashboard'))
# Add this new route to app.py, e.g., in Section 13

@app.route('/poultry/flock/log-mortality', methods=['POST'])
@login_required
@permission_required('edit_poultry')
@check_day_closed('log_date')
def log_flock_mortality():
    db = get_db()
    try:
        flock_id = int(request.form.get('flock_id'))
        mortality_count = int(request.form.get('mortality_count'))
        log_date = request.form.get('log_date')
        
        # --- Get Flock and Account Details ---
        flock = db.execute("SELECT bird_count, cost_per_bird FROM poultry_flocks WHERE id = ?", (flock_id,)).fetchone()
        if not flock:
            raise Exception("Flock not found.")

        if mortality_count > flock['bird_count']:
            flash(f"Cannot log {mortality_count} mortalities. Only {flock['bird_count']} birds in flock.", "danger")
            return redirect(url_for('poultry_dashboard'))
        
        asset_account = db.execute("SELECT id FROM accounts WHERE name = 'Laying Flock Asset'").fetchone()
        expense_account = db.execute("SELECT id FROM accounts WHERE name = 'Livestock Loss Expense'").fetchone()
        if not asset_account or not expense_account:
            raise Exception("Required asset or expense accounts not found in Chart of Accounts.")

        # --- Calculate Financial Loss ---
        total_loss_value = mortality_count * (flock['cost_per_bird'] or 0)
        
        # --- DATABASE TRANSACTION ---
        # 1. Operationally: Reduce the bird count in the flock
        db.execute("UPDATE poultry_flocks SET bird_count = bird_count - ? WHERE id = ?", (mortality_count, flock_id))
        
        # 2. Financially: Create the journal entry
        if total_loss_value > 0:
            db.execute("""
                INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (log_date, f"Mortality loss of {mortality_count} bird(s) from flock ID {flock_id}", expense_account['id'], asset_account['id'], total_loss_value, g.user.id))

        db.commit()
        flash(f"{mortality_count} mortalities recorded. Financial loss of ₦{total_loss_value:,.2f} posted to expenses.", "success")

    except Exception as e:
        db.rollback()
        flash(f"An error occurred: {e}", "danger")

    return redirect(url_for('poultry_dashboard'))
# ==============================================================================
# 14. Table Water  route
# ==============================================================================
@app.route('/water/product/add', methods=['POST'])
@login_required
@permission_required('edit_water')
def add_water_product():
    """
    Handles creating a new water product type.
    FINAL CORRECTED LOGIC: Also creates a corresponding, sellable item in the 
    main inventory table. This is the crucial link.
    """
    db = get_db()
    try:
        name = request.form.get('name')
        price = float(request.form.get('price', 0))

        if not name or price <= 0:
            flash('Product Name and a positive Price are required.', 'warning')
            return redirect(url_for('water_dashboard'))

        # --- DATABASE TRANSACTION ---
        # 1. Create the product definition in the `water_products` table.
        cursor = db.cursor()
        cursor.execute("INSERT INTO water_products (name, price, quantity) VALUES (?, ?, 0)", (name, price))
        
        # 2. CRITICAL STEP: Create the matching item in the main `inventory` table.
        #    This makes it exist so it can be sold. The quantity starts at 0.
        db.execute("""
            INSERT INTO inventory (name, category, quantity, unit, sale_price, unit_cost)
            VALUES (?, 'Finished Goods', 0, 'Unit', ?, 0)
        """, (name, price))
        
        db.commit()
        flash(f"New water product '{name}' added and linked to inventory for sales!", 'success')

    except sqlite3.IntegrityError:
        db.rollback()
        flash(f"A product or inventory item with the name '{name}' already exists.", 'danger')
    except Exception as e:
        db.rollback()
        flash(f"An unexpected error occurred: {e}", 'danger')

    return redirect(url_for('water_dashboard'))

@app.route('/water/production/log', methods=['POST'])
@login_required
@permission_required('edit_water')
@check_day_closed('production_date')
def add_water_production_log():
    """
    Handles logging new water production.
    FINAL CORRECTED LOGIC: Updates stock in BOTH the `water_products` table (for KPIs)
    and the `inventory` table (for sales).
    """
    db = get_db()
    try:
        production_date = request.form.get('production_date')
        product_id = int(request.form.get('product_id'))
        quantity_produced = int(request.form.get('quantity_produced'))
        notes = request.form.get('notes')

        if not all([production_date, product_id, quantity_produced]) or quantity_produced <= 0:
            flash('Date, Product, and a positive Quantity are required.', 'warning')
            return redirect(url_for('water_dashboard'))

        # --- DATABASE TRANSACTION ---
        # 1. Add to the production log for history.
        db.execute("""
            INSERT INTO water_production_log (production_date, product_id, quantity_produced, notes)
            VALUES (?, ?, ?, ?)
        """, (production_date, product_id, quantity_produced, notes))
        
        # 2. Update the 'quantity' in the `water_products` table for the dashboard KPIs.
        db.execute("UPDATE water_products SET quantity = quantity + ? WHERE id = ?", (quantity_produced, product_id))

        # 3. CRITICAL STEP: Find the product's name and UPDATE THE MAIN INVENTORY STOCK.
        product_info = db.execute("SELECT name FROM water_products WHERE id = ?", (product_id,)).fetchone()
        if product_info:
            inventory_item_name = product_info['name']
            # This is the line that makes the items available for sale.
            db.execute("UPDATE inventory SET quantity = quantity + ? WHERE name = ?", 
                       (quantity_produced, inventory_item_name))
        
        db.commit()
        flash('Water production logged and stock updated successfully!', 'success')

    except Exception as e:
        db.rollback()
        flash(f"An unexpected error occurred: {e}", 'danger')
        
    return redirect(url_for('water_dashboard'))
@app.route('/water/product/update/<int:product_id>', methods=['POST'])
@login_required
@check_day_closed('date')
@permission_required('edit_water')
def update_water_product(product_id):
    """Handles updating an existing water product from the modal form."""
    try:
        name = request.form.get('name')
        price = float(request.form.get('price', 0))

        if not name or price <= 0:
            flash('Product Name and a positive Price are required.', 'warning')
            return redirect(url_for('water_dashboard'))

        db = get_db()
        db.execute("UPDATE water_products SET name = ?, price = ? WHERE id = ?", 
                   (name, price, product_id))
        db.commit()

        flash(f"Product '{name}' updated successfully!", 'success')

    except (ValueError, TypeError) as e:
        flash(f"Invalid price provided. Please enter a valid number. Error: {e}", 'danger')
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'danger')

    return redirect(url_for('water_dashboard'))
# Add this new route to app.py in Section 14

@app.route('/water/production/calculate-cost', methods=['POST'])
@login_required
@permission_required('edit_water') # Or a more specific permission
def calculate_water_cost():
    """
    Calculates the total cost and cost-per-unit for a specific water production run.
    """
    db = get_db()
    try:
        production_log_id = int(request.form.get('production_log_id'))

        # Get the production log details, especially the quantity produced
        prod_log = db.execute(
            "SELECT quantity_produced FROM water_production_log WHERE id = ?",
            (production_log_id,)
        ).fetchone()

        if not prod_log:
            flash("Production run not found.", "danger")
            return redirect(url_for('water_dashboard'))

        # --- CALCULATE TOTAL COSTS ---
        # Sum the cost of all inventory used by this specific production run
        cost_row = db.execute(
            "SELECT SUM(cost_of_usage) as total FROM inventory_log WHERE water_production_log_id = ?",
            (production_log_id,)
        ).fetchone()
        total_material_cost = cost_row['total'] if cost_row and cost_row['total'] else 0

        # --- CALCULATE COST PER UNIT ---
        quantity_produced = prod_log['quantity_produced']
        cost_per_unit = total_material_cost / quantity_produced if quantity_produced > 0 else 0

        # --- UPDATE THE WATER PRODUCTION LOG RECORD ---
        db.execute("""
            UPDATE water_production_log SET 
                total_cost = ?, 
                cost_per_unit = ?
            WHERE id = ?
        """, (total_material_cost, cost_per_unit, production_log_id))
        db.commit()

        flash(f"Costs calculated for production run. Cost per unit: ₦{cost_per_unit:,.2f}", "success")
    
    except Exception as e:
        db.rollback()
        flash(f"An error occurred while calculating costs: {e}", "danger")
        
    return redirect(url_for('water_dashboard'))
# ==============================================================================
# 15. CONTACT ROUTS
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
    
    # --- Get Contact Details ---
    contact = db.execute("SELECT * FROM contacts WHERE id = ?", (contact_id,)).fetchone()
    if not contact or not contact['account_id']:
        flash("Contact not found or does not have a linked ledger account.", "danger")
        return redirect(url_for('contacts_dashboard'))
    
    contact_account_id = contact['account_id']

    # --- Handle Date Range ---
    start_date, end_date = _get_report_dates(request.args)
    
    # --- Calculate Opening Balance ---
    opening_balance_row = db.execute("""
        SELECT (
            (SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE debit_account_id = ? AND transaction_date < ?) -
            (SELECT COALESCE(SUM(amount), 0) FROM journal_entries WHERE credit_account_id = ? AND transaction_date < ?)
        ) as opening_balance
    """, (contact_account_id, start_date, contact_account_id, start_date)).fetchone()
    opening_balance = opening_balance_row['opening_balance'] if opening_balance_row else 0

    # --- THIS IS THE CORRECTED QUERY ---
    # It now joins with the accounts table TWICE to get both debit and credit account names
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

    # --- Calculate Running Balance (logic is the same) ---
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
@check_day_closed('date')
@permission_required('edit_contacts')
def edit_contact(contact_id):
    """Displays the form to edit an existing contact."""
    user = User.get_by_id(session['user_id'])
    conn = get_db()
    contact = conn.execute("SELECT * FROM contacts WHERE id = ?", (contact_id,)).fetchone()
    conn.close()

    if not contact:
        flash("Contact not found.", "danger")
        return redirect(url_for('contacts_dashboard'))

    # This assumes you have a template named 'edit_contact.html'
    return render_template('edit_contact.html', user=user, contact=contact)

@app.route('/contacts/update/<int:contact_id>', methods=['POST'])
@login_required
@check_day_closed('date')
@permission_required('edit_contacts')
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
        finally:
            if conn:
                conn.close()
    
    return redirect(url_for('contacts_dashboard'))

@app.route('/contacts/delete/<int:contact_id>', methods=['POST'])
@login_required
@check_day_closed('date')
@permission_required('edit_contacts')
def delete_contact(contact_id):
    """Handles deleting a contact."""
    # In a real app, you should check if this contact has transactions first.
    conn = get_db()
    conn.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
    conn.commit()
    conn.close()
    flash("Contact successfully deleted.", "success")
    return redirect(url_for('contacts_dashboard'))
@app.route('/contacts/add', methods=['POST'])
@login_required
@permission_required('edit_contacts')
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
        # --- NEW, MORE ROBUST LOGIC ---
        if contact_type == 'Customer':
            # 1. Find the parent "Accounts Receivable" account
            parent_ar_acc = db.execute("SELECT code FROM accounts WHERE name = 'Accounts Receivable'").fetchone()
            if not parent_ar_acc:
                raise Exception("CRITICAL: Parent 'Accounts Receivable' account not found.")
            parent_code = parent_ar_acc['code']
            
            # 2. Find all existing sub-accounts for A/R
            # The pattern for the LIKE clause is passed as a parameter.
            like_pattern = f"{parent_code}.%"
            sub_accounts = db.execute("SELECT code FROM accounts WHERE code LIKE ?", (like_pattern,)).fetchall()

            # 3. Find the highest existing sub-account number numerically
            highest_sub_num = 0
            for acc in sub_accounts:
                try:
                    # Split the code (e.g., "1200.01") and get the part after the dot
                    sub_num = int(acc['code'].split('.')[1])
                    if sub_num > highest_sub_num:
                        highest_sub_num = sub_num
                except (IndexError, ValueError):
                    # Ignore any codes that don't match the "parent.sub" format
                    continue

            # 4. Create the new code by adding 1 to the highest found number
            new_sub_num = highest_sub_num + 1
            new_code = f"{parent_code}.{new_sub_num:02d}" # Formats as "1200.01", "1200.02", etc.
            account_name = f"A/R - {name}"

            # 5. Insert the new account
            cursor = db.cursor()
            cursor.execute("INSERT INTO accounts (code, name, type) VALUES (?, ?, 'Asset')", (new_code, account_name))
            new_account_id = cursor.lastrowid

        # 6. Insert the contact and link their new account_id
        db.execute("INSERT INTO contacts (name, type, phone, email, account_id) VALUES (?, ?, ?, ?, ?)",
                     (name, contact_type, phone, email, new_account_id))
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
    # This handler no longer needs to know about the user.
    return render_template('404.html'), 404
# ==============================================================================
# 17. API ROUTES FOR OFFLINE SYNC
# ==============================================================================
from flask import jsonify

@app.route('/api/sync/expense', methods=['POST'])
@login_required 
def sync_expense():
    """API endpoint to receive offline expense data."""
    data = request.get_json()
    db = get_db()

    try:
        # We find the accounts based on the IDs sent from the form
        payment_account = db.execute("SELECT * FROM accounts WHERE id = ?", (data['credit_account_id'],)).fetchone()
        expense_account = db.execute("SELECT * FROM accounts WHERE id = ?", (data['debit_account_id'],)).fetchone()

        if not payment_account or not expense_account:
            return jsonify({'status': 'error', 'message': 'Account not found'}), 404

        # Create the journal entry
        db.execute("""
            INSERT INTO journal_entries (transaction_date, description, debit_account_id, credit_account_id, amount, created_by_user_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (data['date'], data['description'], expense_account['id'], payment_account['id'], float(data['amount']), g.user.id))

        db.commit()
        print(f"Successfully synced offline expense: {data['description']}")
        return jsonify({'status': 'success', 'message': 'Synced'}), 200

    except Exception as e:
        db.rollback()
        print(f"Error syncing expense: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
