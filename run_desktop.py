import webview
import threading
from app import app # Import your Flask app object from your app.py file

# We need to run the Flask server in a separate thread.
# This is because the GUI window (webview) will block the main thread.
def run_server():
    # Running with debug=False is important for a production app.
    # The host '127.0.0.1' and a random port is a secure default.
    app.run(host='127.0.0.1', port=5000, debug=False) 

if __name__ == '__main__':
    # Start the Flask server in a background thread
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True  # Allows the main app to exit even if the thread is running
    server_thread.start()

    # Create the pywebview window
    # This window will load the URL of our running Flask app.
    webview.create_window(
        'Babura Farm Manager',  # This is the title of the window
        'http://127.0.0.1:5000/login', # The entry point of your app
        width=1280,
        height=800,
        resizable=True,
        confirm_close=True # Asks the user "Are you sure?" before closing
    )
    
    # Start the GUI. This will block until the window is closed.
    webview.start()