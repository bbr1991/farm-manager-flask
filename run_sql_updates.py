# run_sql_updates.py
import sqlite3
import os

DATABASE_FILE = 'farm_data.db'
SQL_SCRIPT_FILE = 'update_live_db.sql'

def run_sql_script(db_file, sql_script):
    if not os.path.exists(db_file):
        print(f"Error: Database file '{db_file}' not found.")
        return

    if not os.path.exists(sql_script):
        print(f"Error: SQL script file '{sql_script}' not found.")
        return

    conn = None
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        with open(sql_script, 'r') as f:
            sql_commands = f.read()
        
        # Execute all SQL commands from the script
        cursor.executescript(sql_commands)
        conn.commit()
        print(f"Successfully executed '{sql_script}' on '{db_file}'.")

    except sqlite3.Error as e:
        print(f"SQLite error during script execution: {e}")
        if conn:
            conn.rollback()
            print("Transaction rolled back.")
    except Exception as e:
        print(f"An unexpected Python error occurred: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    print(f"Attempting to run SQL updates on {DATABASE_FILE} using {SQL_SCRIPT_FILE}...")
    run_sql_script(DATABASE_FILE, SQL_SCRIPT_FILE)