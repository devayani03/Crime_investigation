# Import necessary modules and classes
from Interface import *
try:
    # Get the current date for creating log file
    date = dt.datetime.now()
    logfile = str(date)[0:10]

    # Configure logging to write logs to a file
    logging.basicConfig(filename='data/log/' + logfile + '.log', level=logging.DEBUG,
                        format='%(asctime)s - [%(levelname)s] --> %(message)s')
    logging.info('[RegAnalyser] RegAnalyser Started', extra={'investigator': 'RegAnalyser'})
    # Log the start of the RegAnalyser application

    # Create and configure the main application window
    root = Tk()
    root.withdraw()
    root.title("RegAnalyser")
    root.iconbitmap("data/img/icon.ico")

    # Instantiate the UserInterface class
    b = UserInterface(root)

    # Configure window closing behavior and set window position
    root.protocol('WM_DELETE_WINDOW', b.confirm_quit)
    b.center_window(root, 800, 450)
    # Set system encoding to utf-8
    root.tk.call('encoding', 'system', 'utf-8')
    # Start the main event loop
    root.mainloop()
    # Log the end of the RegAnalyser application
    logging.info('[RegAnalyser] Ended', extra={'investigator': 'RegAnalyser'})

except Exception as e:
    # Print and log any exceptions that occur
    print(str(e))
    logging.error('[RegAnalyser] An error occurred', exc_info=True, extra={'investigator': 'RegAnalyser'})