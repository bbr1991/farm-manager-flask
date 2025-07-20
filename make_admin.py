# make_admin.py
import sqlite3

DATABASE = 'farm_data.db'
# IMPORTANT: Change this to the exact username you want to make an admin
USERNAME_TO_MAKE_ADMIN = 'Admin' 

def make_user_admin():
    """Finds a user by username and updates their role to 'admin'."""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        print(f"Attempting to find user: '{USERNAME_TO_MAKE_ADMIN}'...")

        # The SQL command to update the 'role' column for a specific user
        sql_update = "UPDATE users SET role = 'admin' WHERE username = ?"
        
        # Execute the command
        cursor.execute(sql_update, (USERNAME_TO_MAKE_ADMIN,))

        # Check if any rows were changed
        if cursor.rowcount == 0:
            print(f"ERROR: No user found with the username '{USERNAME_TO_MAKE_ADMIN}'. Please check the spelling.")
        else:
            # If a row was changed, commit the change to the database
            conn.commit()
            print(f"SUCCESS: User '{USERNAME_TO_MAKE_ADMIN}' has been promoted to 'admin'.")

    except sqlite3.Error as e:
        print(f"DATABASE ERROR: {e}")
    finally:
        if conn:
            conn.close()
            print("Database connection closed.")
            

# This makes the script run when you call it from the terminal
if __name__ == '__main__':
    make_user_admin()