try:
    import webview
    print(f"\n--- SUCCESS ---")
    print(f"Successfully imported pywebview version: {webview.__version__}")
    print(f"The library is installed and working correctly in this environment.")
    print(f"-----------------\n")
except Exception as e:
    print(f"\n--- FAILURE ---")
    print(f"Could not import pywebview. The error is: {e}")
    print(f"The library is NOT installed correctly in this environment.")
    print(f"-----------------\n")