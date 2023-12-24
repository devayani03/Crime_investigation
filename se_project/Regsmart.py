from tkinter import Tk
import logging
import datetime as dt
from Interface import UserInterface  # Assuming Interface is the module containing UserInterface

try:
    # Get the current date and time for creating the log file
    date = dt.datetime.now()
    
    # Extract the date portion of the current date for the log file name
    logfile = str(date)[0:10]
    
    # Configure logging to write logs to a file named with the current date
    logging.basicConfig(filename='data/log/' + logfile + '.log', level=logging.DEBUG,
                        format='%(asctime)s - [%(levelname)s] --> %(message)s')
    
    # Log the start of the application
    logging.info('[RegSmart] RegSmart Started', extra={'investigator': 'RegSmart'})

    # Create the main Tkinter window
    root = Tk()
    root.withdraw()  # Hide the root window initially
    root.title("RegSmart")
    root.iconbitmap("data/img/icon.ico")

    # Create an instance of the UserInterface class from the Interface module
    b = UserInterface(root)

    # Set the background color of the main window
    root.configure(background='lightblue')

    # Configure a function to be called when the window is closed
    root.protocol('WM_DELETE_WINDOW', b.confirm_quit)
    
    # Center the window on the screen with dimensions 800x450
    b.center_window(root, 800, 450)
    
    # Set the system encoding to UTF-8
    root.tk.call('encoding', 'system', 'utf-8')
    
    # Start the Tkinter event loop
    root.mainloop()
    
    # Log the end of the application
    logging.info('[RegSmart] Ended', extra={'investigator': 'RegSmart'})

except Exception as e:
    # Print the exception message to the console
    print(str(e))
    
    # Log the error with the exception details
    logging.error('[RegSmart] An error occurred', exc_info=True, extra={'investigator': 'RegSmart'})
