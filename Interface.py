import datetime as dt
import logging
import os
import shutil
import subprocess
import threading as thread
import time
import tkinter.filedialog as fd
import tkinter.messagebox as mb
import tkinter.simpledialog as sd
import tkinter.ttk as tkk
import webbrowser
from tkinter import *
from tkinter import filedialog
import requests
from time import sleep

from Registry import Registry

# importing functions from other files
import Parse
import Reports
import Verification

class VirusTotal_API:
    # Initializing the class with an API key
    def __init__(self, apiKey):
        self.apiKey = apiKey  # Storing the API key as an instance variable

    # Uploading a file to VirusTotal for scanning
    def uploadFile(self, fileName):
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'  # URL for file scanning
        files = {'file': open(fileName, 'rb')}  # File to be uploaded
        params = {'apikey': self.apiKey}  # API key parameter
        r = requests.post(url, data=params, files=files)  # Making a POST request to upload the file

        r.raise_for_status()  # Checking for any HTTP errors
        if r.headers['Content-Type'] == 'application/json':
            return r.json()['resource']  # Returning the resource identifier for the uploaded file
        else:
            raise Exception('Unable to locate result')  # Raise an exception if unable to locate the result

    # Retrieving the report for a file using its resource identifier
    def retrieveReport(self, resourceId):
        url = 'https://www.virustotal.com/vtapi/v2/file/report'  # URL for retrieving file report
        params = {'apikey': self.apiKey, 'resource': resourceId}  # Parameters for the request
        while True:
            r = requests.get(url, params=params)  # Making a GET request to retrieve the report
            r.raise_for_status()  # Checking for any HTTP errors

            if r.headers['Content-Type'] == 'application/json':
                if r.json()['response_code'] == 1:
                    break  # Break the loop if the report is ready (response_code = 1)
                else:
                    delay = 25  # If the report is not ready, set a delay
                    sleep(delay)  # Wait for the specified delay before trying again
            else:
                raise Exception('Invalid content type')  # Raise an exception for an invalid content type

        report = r.json()  # Store the retrieved report
        self.report = report  # Storing the report within the class instance
        positives = []
        # Gathering information about detected positive scans
        for engine, result in report['scans'].items():
            if result['detected'] == True:
                positives.append(engine)  # Append the scanning engine to the positives list if detected

        return positives  # Return the list of engines where the file was detected

class UserInterface:
    # Initialization method for the UserInterface class
    def __init__(self, master):
        self.master = master
        self.report_log = ""
        self.timeline_log = []
        self.investigator = "RegAnalyser"
        self.intro()

        # Declarations
        # Variables for various settings and configurations
        self.directory = ""
        # Flags for process control
        self.stop_processing = False
        self.finished_parse = [False, False, False, False, False]
        self.current_user = None
        self.current_config = None
        self.local_machine = None
        self.users = None
        self.session = ""

        self.session_name = StringVar()

        # Variables for different session attributes
        self.full_session = ""
        self.location = ""
        self.business = ""
        self.hash_gui = ""
        self.has_report = ""

        # Settings variables
        self.business_setting = ""
        self.location_setting = ""
        self.settings = ""

        # Database initialization with default values and hashes
        self.db = {
            "services": IntVar(),
            "user_registered": IntVar(),
            "user_start": IntVar(),
            "user_installed": IntVar(),
            "system_registered": IntVar(),
            "system_start": IntVar(),
            "system_installed": IntVar(),
            "services_hash": "a4a40a3e5b91043137b5072da9a70832",
            "user_registered_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "user_start_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "user_installed_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "system_registered_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "system_start_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "system_installed_hash": "d41d8cd98f00b204e9800998ecf8427e"
        }

        # Various report variables
        self.report = ""
        self.system_report = IntVar()
        self.os_report = IntVar()
        self.app_report = IntVar()
        self.network_report = IntVar()
        self.device_report = IntVar()
        self.user_app_report = IntVar()

        # Hives variables for different registry hives
        self.default = ""
        self.ntuser = ""
        self.sam = ""
        self.security = ""
        self.software = ""
        self.system = ""

        self.control_set = ""
        self.sa_windir = ""
        self.sa_processor = ""
        self.sa_computer_name = ""
        self.sa_process_num = 0
        self.sa_path = ""
        self.sa_curr_version = ""
        self.sa_shutdown = ""
        self.sa_bios_vendor = "Processing ..."
        self.sa_bios_version = "Processing ..."
        self.sa_system_manufacturer = "Processing ..."
        self.sa_system_product_name = "Processing ..."
        self.os = {}

        # Function initializations
        # Function to create the toolbar
        self.toolbar()
        # Function to create the main menu
        self.main_menu()
        # Function to load settings from a configuration file
        self.load_settings()

        # Status and progress bar initialization
        self.status = Label(self.master, text="STATUS: Ready", bd=1, relief=SUNKEN, anchor=W)
        self.progress = tkk.Progressbar(self.master, orient="horizontal", length=200, mode="indeterminate")
        self.progress.step(5)
        self.progress["value"] = 0

        self.status.pack(side=BOTTOM, fill=X, anchor=S, expand=True)
        self.progress.pack(side=RIGHT, fill=X, anchor=S, padx=2, in_=self.status)

        # Frame initialization
        self.frame = Frame(self.master, width=800, height=500)

        self.root_tree = tkk.Treeview(self.master, height=400, columns=('Created', 'Modified'),
                                      selectmode='extended')

        self.session_frame = Frame(self.frame, width=300, height=500)
        self.session_frame.grid_rowconfigure(0, weight=1)
        self.session_frame.grid_columnconfigure(0, weight=1)
        self.session_frame.pack(side=LEFT, fill=BOTH, expand=True)

        xscrollbar = Scrollbar(self.session_frame, orient=HORIZONTAL)
        xscrollbar.grid(row=1, column=0, sticky=E + W)

        yscrollbar = Scrollbar(self.session_frame)
        yscrollbar.grid(row=0, column=1, sticky=N + S)

        self.canvas = Canvas(self.session_frame, bg='white', width=300, height=500)
        self.canvas_frame = Frame(self.canvas)
        self.canvas.config(xscrollcommand=xscrollbar.set, yscrollcommand=xscrollbar.set)
        yscrollbar.config(command=self.canvas.yview)
        xscrollbar.config(command=self.canvas.xview)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.canvas.create_window((0, 0), window=self.canvas_frame, anchor=N + W, width=1200)

        self.canvas_frame.bind("<Configure>", lambda event, canvas=self.canvas: self.onFrameConfigure(self.canvas))
        r = 0
        Label(self.canvas_frame, text="Sessions", font="Arial 14 bold", fg="white", bg="#013220").pack(fill=BOTH,
                                                                                                       expand=True,
                                                                                                       side="top")
        # Error handling for loading sessions
        try:
            if not os.path.exists(os.getcwd() + "\\data\\sessions"):
                os.makedirs(os.getcwd() + "\\data\\sessions")

            for filename in os.listdir(os.getcwd() + "\\data\\sessions"):
                r += 1
                image = PhotoImage(file="data/img/regticksession.png", height=50, width=50)
                image.zoom(50, 50)
                tmp = filename

                session_info = self.get_config(filename)
                b = Button(self.canvas_frame, image=image, compound=LEFT, text=session_info, anchor=W, justify=LEFT,
                           command=lambda tmp=tmp: self.load_session(tmp))
                b.image = image
                b.pack(fill=BOTH, expand=True)
        except Exception:
            # Logging errors if session loading fails
            logging.error('[RegAnalyser] An error occurred in (Session loading)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})
            self.display_message('error', 'An error occurred while Loading sessions.\nPlease try again.')

        # Tool frame with buttons for different analyses
        tool_frame = Frame(self.frame, width=500, height=500)
        tool_frame.pack(side=RIGHT)
        tool_frame.columnconfigure(0, weight=1)

        Label(tool_frame, textvariable=self.session_name, font="Arial 14 bold") \
            .grid(row=0, column=0, columnspan=6, sticky="nsew")

        image = PhotoImage(file="data/img/os.png", height=47, width=50)
        image.zoom(80, 80)
        b = Button(tool_frame, text="OS Analysis", image=image, compound=TOP, command=self.os_analysis)
        b.image = image
        b.grid(row=0, column=4, sticky="nsew")

        image = PhotoImage(file="data/img/network.png", height=47, width=50)
        image.zoom(80, 80)
        b = Button(tool_frame, text="Network Analysis", image=image, compound=TOP, command=self.network_analysis)
        b.image = image
        b.grid(row=2, column=4, sticky="nsew")

        image = PhotoImage(file="data/img/device.png", height=47, width=50)
        image.zoom(80, 80)
        b = Button(tool_frame, text="Device Analysis", image=image, compound=TOP, command=self.device_analysis)
        b.image = image
        b.grid(row=4, column=4, sticky="nsew")

        image = PhotoImage(file="data/img/regview.png", height=47, width=50)
        image.zoom(80, 80)
        b = Button(tool_frame, text="Registry Viewer", image=image, compound=TOP, command=self.regview)
        b.image = image
        b.grid(row=6, column=4, sticky="nsew")

        image = PhotoImage(file="data/img/application.png", height=47, width=50)
        image.zoom(80, 80)
        b = Button(tool_frame, text="Application Analysis", image=image, compound=TOP,
                   command=self.application_analysis)
        b.image = image
        b.grid(row=8, column=4, sticky="nsew")

        image = PhotoImage(file="data/img/virustotal.png", height=47, width=50)
        image.zoom(80, 80)
        b = Button(tool_frame, text="VirusTotal check", image=image, compound=TOP, command=self.virustotal_gui)
        b.image = image
        b.grid(row=12, column=4, sticky="nsew")

        self.frame.pack(expand=True, fill=BOTH)

        self.master.update()

    # Function to load settings from a configuration file
    def load_settings(self):
        try:
            i = 0
            # Open the configuration file for reading
            with open(os.getcwd() + "\\data\\config\\RegAnalyser.conf", 'r') as file:
                # Iterate through each line in the file
                for line in file:
                    if i < 7:  # Handle the first 7 lines
                        # Split each line into key-value pairs
                        (key, val) = line.split()
                        key = key.strip(":")  # Remove any trailing colons
                        self.db[str(key)].set(int(val))  # Set the value as an integer in the db dictionary

                    elif i > 6 and i < 14:  # Handle lines 8 to 13
                        # Split each line into key-value pairs
                        (key, val) = line.split()
                        key = key.strip(":")  # Remove any trailing colons
                        self.db[str(key)] = val  # Assign the value directly to the db dictionary

                    elif i == 14:  # Handle line 14
                        # Extract the business setting from the line
                        self.business_setting = line.split(":")[1]

                    elif i == 15:  # Handle line 15
                        # Extract and split the location setting
                        self.location_setting = line.split(":")[1].split(",")

                    i += 1  # Increment the counter for line tracking

        except Exception as ee:
            print(ee)  # Print the exception if any occurs
            logging.error('[RegAnalyser] An error occurred in (load_settings)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})
            return "Error occurred"  # Return an error message if an exception occurs

    # Function to update and save settings to a configuration file
    def update_settings(self, display=None):
        # Log that settings have been saved
        self.rep_log("Saved settings")
        try:
            # Open the configuration file for writing
            with open(os.getcwd() + "\\data\\config\\RegAnalyser.conf", 'w') as file:
                final = ""  # Initialize a string to hold the final settings
                b = self.business_setting.strip("\n")  # Retrieve and clean the business setting

                loc = ""  # Initialize an empty string for location settings
                # Concatenate location settings into a string
                for i in self.location_setting:
                    if i != "":
                        loc += i.strip("\n") + ","
                loc = loc[:-1]  # Remove the last comma

                j = 0  # Counter to track the number of settings processed
                # Iterate through the settings in self.db dictionary
                for i, k in self.db.items():
                    if j < 7:  # Handle the first 7 settings differently
                        final += i + ": " + str(k.get()) + "\n"  # Construct settings with their values
                    else:
                        final += i + ": " + k + "\n"  # Handle subsequent settings
                    j += 1  # Increment the counter

                # Append business and location settings to the final settings string
                final += "business_name:" + b + "\n"
                final += "business_address:" + loc

                # Write the final settings to the configuration file
                file.write(final)

            # Display a success message if not explicitly told otherwise
            if not display:
                self.display_message("info", "Your settings have been updated successfully")
                self.settings.destroy()  # Close settings window if it exists

        except Exception as ee:
            # Log any exceptions that occur during the process
            logging.error('[RegAnalyser] An error occurred in (Update settings)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

    # Function to calculate and display hash for a selected folder
    def hash_folder(self):
        try:
            # Open a folder selection dialog and retrieve the selected folder's path
            filename = fd.askdirectory()

            # Get the hash of the selected folder using a method from Verification class
            hash = Verification.get_hash(filename)

            # Display information about the selected folder and its hash in the GUI
            self.display_message("info", "Filename: " + filename + "\n\nHash: " + hash
                                 + "\n\nNote: Contents copied to clipboard!")

            # Clear the clipboard and append folder information for easy copying
            self.hash_gui.clipboard_clear()
            self.hash_gui.clipboard_append("Filename: " + filename + "\nHash: " + hash)

            # Ensure the GUI window gets focus after copying to clipboard
            self.hash_gui.focus_force()

        except Exception as ee:
            # Log any exceptions that occur during the process
            logging.error('[RegAnalyser] An error occurred in (hash folder)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

    # Function to calculate and display hash for a selected file
    def hash_file(self):
        try:
            # Open a file selection dialog and retrieve the selected file's path
            filename = fd.askopenfilename()

            # Get the hash of the selected file using a method from Verification class
            hash = Verification.hash_file(filename)

            # Display information about the selected file and its hash in the GUI
            self.display_message("info", "Filename: " + filename + "\n\nHash: " + hash
                                 + "\n\nNote: Contents copied to clipboard!")

            # Clear the clipboard and append file information for easy copying
            self.hash_gui.clipboard_clear()
            self.hash_gui.clipboard_append("Filename: " + filename + "\nHash: " + hash)

            # Ensure the GUI window gets focus after copying to clipboard
            self.hash_gui.focus_force()

        except Exception as ee:
            # Log any exceptions that occur during the process
            logging.error('[RegAnalyser] An error occurred in (hash file)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

    # Function to create the Hash Generator window
    def hash_checker(self):
        # Log that Hash Generator has been opened
        self.rep_log("Opened Hash Generator")

        # Create a new GUI window (Toplevel) for the Hash Generator
        self.hash_gui = Toplevel()

        # Center the Hash Generator window on the screen with dimensions 353x150
        self.center_window(self.hash_gui, 353, 150)

        # Configure the title and icon for the Hash Generator window
        self.hash_gui.title("RegAnalyser: Hash Generator")
        self.hash_gui.iconbitmap("data/img/icon.ico")

        # Row counter initialization for widget placement
        r = 1

        # Create a label indicating the purpose of the Hash Generator
        Label(self.hash_gui, font="Arial 16 bold", fg="black", bg="orange",
              text="Hash Generator") \
            .grid(row=0, column=0, columnspan=2, sticky="nsew")
        r += 1

        # Create a button to hash a folder
        image = PhotoImage(file="data/img/folder.png", height=50, width=50)
        image.zoom(50, 50)
        b = Button(self.hash_gui, text="Hash Folder", image=image, compound=TOP, command=self.hash_folder)
        b.image = image  # Retain image reference to prevent garbage collection
        b.grid(row=1, column=0, pady=10, sticky="nsew")

        # Create a button to hash a file
        image = PhotoImage(file="data/img/file.png", height=50, width=50)
        image.zoom(50, 50)
        b = Button(self.hash_gui, text="Hash File", image=image, compound=TOP, command=self.hash_file)
        b.image = image  # Retain image reference to prevent garbage collection
        b.grid(row=1, column=1, pady=10, sticky="nsew")

        # Display a message about automatic clipboard copying of hash information
        Label(self.hash_gui, font="Arial 10 bold", fg="black", bg="grey",
              text="Hash information is automatically copied to clipboard!") \
            .grid(row=2, column=0, columnspan=2, sticky="nsew")

    def virustotal_gui(self):
        # Create a new Tkinter window for the File Scanner
        root = Tk()
        root.title("File Scanner")

        # Label to prompt user to select a file for scanning
        api_key_label = Label(root, text="Select a file to scan")
        api_key_label.pack()

        # Function to browse and select a file for scanning
        def browse_file(api_key_label):
            file_path = filedialog.askopenfilename()
            api_key_label['text'] = file_path  # Update the label text to display the selected file path
            return file_path

        # Function to display the scan results in a separate window
        def display_results(positives, filename):
            result_window = Tk()
            result_window.title("Scan Results")

            frame = Frame(result_window)
            frame.pack()

            scrollbar = Scrollbar(frame)
            scrollbar.pack(side='right', fill='y')

            result_text = Text(frame, wrap='word', yscrollcommand=scrollbar.set)
            result_text.insert('end', f"Scanned file: {filename}\n\n")

            # Display the scan results based on positives (threats detected)
            if len(positives) > 0:
                result_text.insert('end', f'Positives: {len(positives)}\n')
                result_text.insert('end', "Alerts:\n")
                for alert in positives:
                    result_text.insert('end', f"- {alert}\n")
            else:
                result_text.insert('end', "No threats detected.\n")

            result_text.pack(side='left', fill='both', expand=True)
            scrollbar.config(command=result_text.yview)

            result_window.mainloop()

        # Function to initiate the scan using the selected file
        def scan_file(api_key_label):
            file_path = api_key_label['text']  # Retrieve the selected file path

            # Replace the API key with your actual VirusTotal API key
            api = VirusTotal_API("788912950ab73ac48ec575a041351e944cda861eaf1c90f2cf38a2aad5cf2b38")

            # Upload the file and get the resource ID
            resource_id = api.uploadFile(file_path)

            # Retrieve scan results using the resource ID
            positives = api.retrieveReport(resource_id)
            filename = file_path

            # Display the results in a separate window
            display_results(positives, filename)

        # Button to browse and select a file for scanning
        browse_button = Button(root, text="Browse", command=lambda: browse_file(api_key_label))
        browse_button.pack()

        # Button to initiate the scan using the selected file
        scan_button = Button(root, text="Scan", command=lambda: scan_file(api_key_label))
        scan_button.pack()

        root.mainloop()  # Start the main event loop for the File Scanner window

    # Function to convert bytes to human-readable format
    def human_bytes(self, B):
        B = float(B)
        KB = float(1024)
        MB = float(KB ** 2)  # 1,048,576
        GB = float(KB ** 3)  # 1,073,741,824
        TB = float(KB ** 4)  # 1,099,511,627,776

        if B < KB:
            return '{0} {1}'.format(B, 'Bytes' if 0 == B > 1 else 'Byte')
        elif KB <= B < MB:
            return '{0:.2f} KB'.format(B / KB)
        elif MB <= B < GB:
            return '{0:.2f} MB'.format(B / MB)
        elif GB <= B < TB:
            return '{0:.2f} GB'.format(B / GB)
        elif TB <= B:
            return '{0:.2f} TB'.format(B / TB)

    # Function to retrieve configuration information from a file
    def get_config(self, filename):
        filename = "data\\sessions\\" + filename + "\\RegAnalyser.session"
        try:
            with open(filename, 'r') as file:
                return file.read()
        except Exception:
            return "Error occurred"

    # Function to calculate the total size of a directory
    def get_size(self, start_path='.'):
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(start_path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                total_size += os.path.getsize(fp)
        return total_size

    # Adjusts the scroll region of the canvas when the frame is configured
    def onFrameConfigure(self, t=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    # Creates the main menu with options like New Session, Close Session, and more
    def main_menu(self):
        menubar = Menu(self.master)
        self.master.config(menu=menubar)
        filemenu = Menu(menubar, tearoff=0)
        filemenu.add_command(label="New Session", command=self.open_directory)
        filemenu.add_command(label="Close Session", command=self.close_session)

        filemenu.add_separator()

        filemenu.add_command(label="Exit", command=self.confirm_quit)
        menubar.add_cascade(label="File", menu=filemenu)
        editmenu = Menu(menubar, tearoff=0)

        editmenu.add_separator()

        editmenu.add_command(label="Device Analysis", command=self.device_analysis)
        editmenu.add_command(label="Application Analysis", command=self.application_analysis)
        editmenu.add_command(label="OS Analysis", command=self.os_analysis)
        editmenu.add_command(label="Network Analysis", command=self.network_analysis)
        editmenu.add_command(label="Registry Viewer", command=self.regview)
        # editmenu.add_command(label="Hash Generator", command=self.hash_checker)
        editmenu.add_command(label="Report", command=self.make_report)

        menubar.add_cascade(label="Tools", menu=editmenu)
        helpmenu = Menu(menubar, tearoff=0)
        # helpmenu.add_command(label="Help", command=self.help)
        # helpmenu.add_command(label="About...", command=self.intro)
        # menubar.add_cascade(label="Help", menu=helpmenu)

    # Displays different types of messages (info, error, warning, success) after importing a dump
    def display_message(self, types, message):
        if types == "info":
            mb.showinfo("RegAnalyser", message)
        if types == "error":
            mb.showerror("RegAnalyser", message)
        if types == "warning":
            mb.showwarning("RegAnalyser", message)
        if types == "success":
            tmp = Toplevel()
            tmp.title("RegAnalyser")
            tmp.iconbitmap("data/img/icon.ico")
            Frame(tmp, width=200, height=8).pack()
            photo = PhotoImage(file="data/img/regticksmall.png", height=100, width=100)
            label = Label(tmp, image=photo)
            label.image = photo
            label.pack(side=LEFT, padx=20, pady=10)
            Label(tmp, text="Successfully verified dumps!", font="Bold", pady=20).pack()
            Button(tmp, text="OK", command=tmp.destroy).pack(side=RIGHT, padx=100, pady=20, ipadx=20, ipady=2)
            self.center_window(tmp, 400, 150)
            tmp.focus_force()

    # Displays a question message in a dialogue box and returns the user's answer
    def get_answer(self, message):
        return mb.askquestion("RegAnalyser", message)

    # Creates a toolbar
    def toolbar(self):
        toolbar = Frame(self.master, bg="gray")
        toolbar.pack(side=TOP, fill=X)

    # Sets the status label with the given message in the bottom right corner
    def set_status(self, msg):
        self.status['text'] = "STATUS: " + msg

    # Displays the welcome message and gets investigator details
    def intro(self):
        # Log opening of about window
        self.rep_log("Opened about window")
        logging.info("Initiated about window", extra={'investigator': self.investigator})

        # Create a Toplevel window for the about section
        about = Toplevel(bg='white')
        about.title("RegAnalyser")
        about.iconbitmap("data/img/icon.ico")

        # Create a frame within the about window
        frame = Frame(about, width=400, height=100, bg='white')

        # Display the RegAnalyser logo
        reg = PhotoImage(file="data/img/RegAnalyser.png")
        label = Label(about, image=reg)
        label.image = reg
        label.pack()

        # Load and display welcome message
        welcome = open("data/info/welcome", 'r').read()
        Label(about, text=welcome, bd=1, wraplength=500, bg='white').pack(fill=X)

        # Load and display copyright information and disclaimer
        disclaimer = open("data/info/disclaimer", 'r').read()
        year = dt.datetime.now().year
        Label(about, text="Copyright@" + str(year), bd=1, relief=SUNKEN, anchor=E, wraplength=200) \
            .pack(side=BOTTOM, fill=X)
        Label(about, text=disclaimer, bd=1, bg="lightgrey", relief=SUNKEN, anchor=S).pack(side=BOTTOM, fill=X)
        frame.pack()

        # Center the about window and focus on it
        self.center_window(about, 750, 400)
        about.focus_force()

        # Log getting investigator information
        self.rep_log("Getting Investigator information")

        # If the investigator is not set, prompt for investigator's name and ID
        if self.investigator == "RegAnalyser":
            # Prompt for investigator's name
            self.investigator = sd.askstring("RegAnalyser", "Investigators Name:")
            if not self.investigator or self.investigator == "" or self.investigator == " ":
                # If no name is provided, display a warning and prompt again
                self.investigator = "RegAnalyser"
                self.rep_log("User failed to enter their name on the first try.")
                self.display_message("warning", "Please enter your name")
                self.investigator = sd.askstring("RegAnalyser", "Investigators Name:")
                if not self.investigator or self.investigator == "" or self.investigator == " ":
                    # If still no name provided, log and display error, then exit
                    logging.info('Failed to get investigator name exiting ...', extra={'investigator': 'RegAnalyser'})
                    mb.showerror("RegAnalyser", "Failed to get Investigator Name.\nExiting ...")
                    exit(0)

            # Prompt for investigator's ID
            id = sd.askstring("RegAnalyser", "Investigators ID: ")
            if not id or id == "" or id == " ":
                # If no ID is provided, display a warning and prompt again
                self.rep_log("User failed to enter their ID on the first try.")
                self.display_message("warning", "Please enter your ID")
                id = sd.askstring("RegAnalyser", "Investigators ID:")
                if not id or id == "" or id == " ":
                    # If still no ID provided, log and display error, then exit
                    logging.info('Failed to get investigator id exiting ...', extra={'investigator': 'RegAnalyser'})
                    mb.showerror("RegAnalyser", "Failed to get Investigator ID.\nExiting ...")
                    exit(0)

            # Log investigator's name and ID
            self.rep_log("Investigator entered name: " + self.investigator)
            self.rep_log("Investigator entered id: " + id)

            # Display a message to the investigator and update the ID
            self.display_message("info", "Hello " + self.investigator + ".\nPlease wait while sessions are loading.")
            self.investigator += " (" + id + ")"

        else:
            about.focus_force()

        # Show the main application window and focus on the about window
        self.master.deiconify()
        about.focus_force()

    def confirm_quit(self):
        tmp = self.get_answer("Do you want to quit?")
        if tmp == "yes":
            logging.info("Exiting RegAnalyser ...", extra={'investigator': self.investigator})
            self.master.destroy()
            exit(0)

    # Updates the loading progress and verifies dumps
    def update_loading(self):
        # Check if directory path is not empty
        if self.directory != "":
            # Start the progress bar animation and set status message
            self.progress.start()
            self.set_status("Verifying dumps ...")
            self.display_message("info", "Verifying dumps for session. \nPress OK to continue.")

            # Verify the dump's integrity using Verification.verify_dump method
            tmp = Verification.verify_dump(self.directory)
            # tmp = 1

            # Check the verification result
            if tmp == 2:
                # If no dumps found, display a warning message and set status
                self.display_message("warning", "No dumps were found in this directory please choose another.")
                self.set_status("No dumps found")
            elif tmp:
                # If verification successful, display success message and start processing dumps in a new thread
                self.display_message("info", "Successfully verified integrity of dumps")
                self.set_status("Processing ...")
                thread.Thread(target=self.read_dumps).start()
            else:
                # If verification fails, display error messages and update status
                self.set_status("Dumps are not authentic")
                self.display_message("error", "The integrity of the dumps is not valid.")
                self.display_message("error", "RegAnalyser cannot process due to difference in original file "
                                              "and forensic copy.")
                self.display_message("info", "Please get new dumps and make sure that the dumps were "
                                             "successfully acquired.")

            # Reset progress bar values and stop the progress animation
            self.progress['value'] = 0
            self.progress.stop()

            # Start a thread to reset the progress bar to its initial state
            thread.Thread(target=self.reset_progress).start()

    # Reads dumps and parses registry information
    def read_dumps(self):
        # Check if directory path is not empty
        if self.directory != "":
            # Set status message indicating processing of dumps
            self.set_status("Processing dumps ...")
            # Start the progress bar animation
            self.progress.start()
            self.master.update()

            try:
                # Loop through files in the specified directory
                for filename in os.listdir(self.directory):
                    # Create Registry objects for specific files found in the directory
                    if filename == "DEFAULT":
                        self.default = Registry.Registry(self.directory + "/" + filename)
                    elif filename == "NTUSER.DAT":
                        self.ntuser = Registry.Registry(self.directory + "/" + filename)
                    elif filename == "SAM":
                        self.sam = Registry.Registry(self.directory + "/" + filename)
                    elif filename == "SECURITY":
                        self.security = Registry.Registry(self.directory + "/" + filename)
                    elif filename == "SOFTWARE":
                        self.software = Registry.Registry(self.directory + "/" + filename)
                    elif filename == "SYSTEM":
                        self.system = Registry.Registry(self.directory + "/" + filename)

                # Open the SYSTEM registry hive to retrieve specific information
                key = self.system.open("Select")
                for v in key.values():
                    if v.name() == "Current":
                        self.control_set = str(v.value())

                # Access specific registry keys to retrieve system information
                key = self.system.open("ControlSet00" + self.control_set + "\\Control\\Session Manager\\Environment")
                for v in key.values():
                    if v.name() == "PROCESSOR_ARCHITECTURE":
                        self.sa_processor = v.value()

            except Exception as ee:
                # Catch any exceptions that might occur during registry parsing
                logging.error('An error occurred in (parsing registry)', exc_info=True,
                              extra={'investigator': 'RegAnalyser'})
                # Display error message and close the session
                self.display_message("error", "Failed to Parse registry dumps.\nSession is now closing.")
                self.close_session()

        # Set status message to 'Ready' once processing is complete or if the directory is empty
        self.set_status("Ready")

    # Resets the progress bar after a delay
    def reset_progress(self):
        time.sleep(2)
        self.progress['value'] = 0
        self.progress.stop()

    # Closes the current session and resets various attributes
    def close_session(self):
        self.rep_log("Session closed [" + self.full_session + "]")
        logging.info("Closed session [" + self.full_session + "]", extra={'investigator': self.investigator})
        self.stop_processing = False
        self.finished_parse = [False, False, False, False, False]
        self.current_user = None
        self.current_config = None
        self.local_machine = None
        self.users = None
        self.session = ""
        self.full_session = ""
        self.session_name.set("")

        # Hives
        self.default = ""
        self.ntuser = ""
        self.sam = ""
        self.security = ""
        self.software = ""
        self.system = ""
        self.session_name.set("")

        self.control_set = ""
        self.sa_windir = ""
        self.sa_processor = ""
        self.sa_computer_name = ""
        self.sa_process_num = 0
        self.sa_path = ""
        self.sa_curr_version = ""
        self.sa_shutdown = ""
        self.sa_bios_vendor = "Processing ..."
        self.sa_bios_version = "Processing ..."
        self.sa_system_manufacturer = "Processing ..."
        self.sa_system_product_name = "Processing ..."
        self.os = {}
        self.directory = ""
        self.master.title("RegAnalyser")

    # Loads a session by setting the directory and updating loading progress
    def load_session(self, dir):
        # Close any existing session before loading a new one
        self.close_session()

        # Define the session directory path
        sess = os.getcwd() + "\\data\\sessions\\" + dir

        # Confirm user action before proceeding with loading the session
        if self.get_answer("Are you sure you want to load this session?\n" + dir) == "yes":
            # Log the action of loading the session
            self.rep_log("Loading session: " + dir)

            # Set the directory path to the session being loaded
            self.directory = sess

            # Extract session name from the directory path
            tmp = self.directory.split("\\")
            self.full_session = tmp[len(tmp) - 1]

            # Check for session validity through configuration
            if self.get_config(self.full_session) == "Error occurred":
                self.display_message("error", "Invalid session selected. Please re-import the session.")
                return

            # Set session name and update GUI title with loaded session information
            self.session_name.set(self.full_session.split("_")[0])
            self.master.title("RegAnalyser: [" + tmp[len(tmp) - 1] + "]")

            # Trigger the loading process for the session
            self.update_loading()

            # Log the loaded session and its details
            logging.info("Loaded session [" + self.full_session + "]", extra={'investigator': self.investigator})

    # Reloads the session information and updates the canvas
    def reload_sessions(self):
        # Clear and hide canvas and session frame
        self.canvas.delete("all")
        self.canvas.pack_forget()
        self.session_frame.pack_forget()

        # Create a new session frame
        self.session_frame = Frame(self.frame, width=300, height=500)
        self.session_frame.grid_rowconfigure(0, weight=1)
        self.session_frame.grid_columnconfigure(0, weight=1)
        self.session_frame.pack(side=LEFT, fill=BOTH, expand=True)

        # Create scrollbars for the canvas
        xscrollbar = Scrollbar(self.session_frame, orient=HORIZONTAL)
        xscrollbar.grid(row=1, column=0, sticky=E + W)

        yscrollbar = Scrollbar(self.session_frame)
        yscrollbar.grid(row=0, column=1, sticky=N + S)

        # Create a canvas to hold session frames
        self.canvas = Canvas(self.session_frame, bg='white', width=300, height=500)
        self.canvas_frame = Frame(self.canvas)
        self.canvas.config(xscrollcommand=xscrollbar.set, yscrollcommand=xscrollbar.set)
        yscrollbar.config(command=self.canvas.yview)
        xscrollbar.config(command=self.canvas.xview)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.canvas.create_window((0, 0), window=self.canvas_frame, anchor=N + W, width=1200)

        # Update canvas on frame configuration changes
        self.canvas_frame.bind("<Configure>", lambda event, canvas=self.canvas: self.onFrameConfigure(self.canvas))

        # Display session labels/buttons
        r = 0
        Label(self.canvas_frame, text="Sessions", font="Arial 14 bold", fg="white", bg="blue").pack(fill=BOTH,
                                                                                                    expand=True)
        try:
            # Iterate through session directories and display buttons
            for filename in os.listdir(os.getcwd() + "\\data\\sessions"):
                r += 1
                image = PhotoImage(file="data/img/regticksession.png", height=50, width=50)
                image.zoom(50, 50)
                tmp = filename

                session_info = self.get_config(filename)
                b = Button(self.canvas_frame, image=image, compound=LEFT, text=session_info, anchor=W, justify=LEFT,
                           command=lambda tmp=tmp: self.load_session(tmp))
                b.image = image
                b.pack(fill=BOTH, expand=True)
        except Exception:
            # Error handling for session loading failure
            logging.error('[RegAnalyser] An error occurred in (Session loading)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})
            self.display_message('error', 'An error occurred while Loading sessions.\nPlease try again.')

    # Copies files and directories from source to destination, creating a new session
    def copy_dumps(self, src, dst, symlinks=False, ignore=None):
        # Iterate through items in the source directory
        for item in os.listdir(src):
            # Create full paths for source and destination
            s = os.path.join(src, item)
            d = os.path.join(dst, item)

            # Check if the item is a directory
            if os.path.isdir(s):
                # Recursively copy directory contents preserving symlinks and ignoring specified patterns
                shutil.copytree(s, d, symlinks, ignore)
            else:
                # Copy the file metadata and contents from source to destination
                shutil.copy2(s, d)

    # Creates a configuration file for a session based on the provided case, destination, and folder name, displayed on the main window
    def create_config(self, case, dest, folder_name):
        # Splitting folder_name by underscore to extract case details
        folder_name = folder_name.split("_")

        # Create or open a file in the specified destination
        file = open(dest + "\\RegAnalyser.session", 'w')

        # Writing case details to the file
        file.write("  Case: " + str(case) + "\n")  # Writing case number
        file.write("\n")  # Empty line for formatting
        file.write("  Name: " + folder_name[0] + "\n")  # Writing name extracted from folder_name
        file.write("  Machine: " + folder_name[1] + "\n")  # Writing machine details
        file.write("  Date: " + folder_name[2] + "\t\t\t\t")  # Writing date
        file.write("  Size: " + self.human_bytes(self.get_size(dest)))  # Writing size of the folder

        # Closing the file after writing
        file.close()

    # Imports a session concurrently, copying dumps and creating a configuration file
    def import_concurrent(self, dest, case, name):
        # Check if the destination directory exists
        if not os.path.exists(dest):
            # If it doesn't exist, create the directory, copy dumps, create config, reload sessions, and update loading
            os.makedirs(dest)  # Create the destination directory
            self.copy_dumps(self.directory, dest)  # Copy dumps from the current directory to the destination
            self.create_config(case, dest, name)  # Create a configuration file for the session
            self.reload_sessions()  # Reload the sessions to update the UI
            self.update_loading()  # Update loading state for the new session
        else:
            # If the destination directory exists, prompt for replacement
            if self.get_answer("Session already exists.\nDo you want to replace it?") == "yes":
                try:
                    # If confirmed, remove the directory, create a new one, copy dumps, and update the session
                    shutil.rmtree(dest)  # Remove existing directory
                    os.makedirs(dest)  # Create a new directory
                    self.copy_dumps(self.directory, dest)  # Copy dumps to the new destination
                    self.reload_sessions()  # Reload sessions to reflect changes
                    self.update_loading()  # Update the loading state for the new session
                except Exception:
                    # Handle exception if there's an issue overwriting the session due to access denial
                    self.display_message("error", "Failed to overwrite session.\nAccess is denied.\n"
                                                  "Please delete the folder from data/sessions/[session]")
            else:
                # If user chooses not to replace, show a warning message
                self.display_message("warning", "Please note that this new session is not going to be created.")

    # Opens a directory dialog to select a new session directory and initiates the import process
    def open_directory(self):
        # Log the creation of a new session
        self.rep_log("Creating new session")
        # Set the status to 'Ready'
        self.set_status("Ready")

        # Prompt the user to select a directory
        self.directory = fd.askdirectory()

        # Check if a directory has been selected
        if self.directory != "":
            # Check if the selected directory is a valid RegAcquire folder
            if Verification.is_valid_regacquire(self.directory):
                # Ask the user to input a case number
                case = sd.askstring("RegAnalyser", "Enter Case Number:")
                if not case or case == "" or case == " ":
                    # Prompt again if case number is not provided
                    self.display_message("warning", "Please enter case number")
                    case = sd.askstring("RegAnalyser", "Enter Case Number:")
                    if not case or case == "" or case == " ":
                        # Show an error message and return if case number is still not provided
                        self.display_message("error", "Failed to get case number, session will not be imported.")
                        return

                # Extract session details from the selected directory
                tmp = self.directory.split("/")
                self.master.title("RegAnalyser: [" + tmp[len(tmp) - 1] + "]")
                self.session = tmp[len(tmp) - 1].split("_")[0]
                self.full_session = tmp[len(tmp) - 1]
                self.rep_log("New session [" + tmp[len(tmp) - 1] + "]")
                self.rep_log("Case number [" + case + "]")
                self.session_name.set(self.session)

                # Set status and initiate import of dumps
                self.set_status("Importing dumps...")
                self.progress.start()
                self.display_message("info", "Importing dumps...\nPlease wait\n\nYou will be notified when it's done.")

                # Prepare destination and session name
                dest = os.getcwd() + "\\data\\sessions\\" + tmp[len(tmp) - 1]
                name = tmp[len(tmp) - 1]

                # Start concurrent thread for session import
                thread.Thread(target=self.import_concurrent, args=(dest, case, name,)).start()
            else:
                # Close session and display error for invalid RegAcquire folder
                self.close_session()
                self.display_message("error", "This is not a valid RegAcquire folder!")
        else:
            # Close session and show warning if failed to create a new session
            self.close_session()
            self.display_message("warning", "Failed to create new session!")

    # Centers a tkinter window on the screen
    def center_window(self, tmp, width=300, height=200):
        # get screen width and height
        screen_width = tmp.winfo_screenwidth()
        screen_height = tmp.winfo_screenheight()

        # calculate position x and y coordinates
        x = (screen_width / 2) - (width / 2)
        y = (screen_height / 2) - (height / 2)
        tmp.geometry('%dx%d+%d+%d' % (width, height, x, y))

    # Gathers data for OS analysis, including product details, user profiles, and user accounts
    def os_analysis_data(self):
        try:
            self.os['RegisteredOrganization'] = "N/A"
            self.os['RegisteredOwner'] = "N/A"
            self.os['ReleaseId'] = ""
            key = self.software.open("Microsoft\\Windows NT\\CurrentVersion") #hive path
            for v in key.values():
                if v.name() == "ReleaseId":
                    self.os['ReleaseId'] = v.value()
                if v.name() == "ProductName":
                    self.os['ProductName'] = v.value()
                if v.name() == "ProductId":
                    self.os['ProductId'] = v.value()
                if v.name() == "PathName":
                    self.os['PathName'] = v.value()
                if v.name() == "InstallDate":
                    self.os['InstallDate'] = time.strftime('%a %b %d %H:%M:%S %Y (UTC)', time.gmtime(v.value()))
                if v.name() == "RegisteredOrganization":
                    self.os['RegisteredOrganization'] = v.value()
                    if self.os['RegisteredOrganization'] == "":
                        self.os['RegisteredOrganization'] = "N/A"
                if v.name() == "RegisteredOwner":
                    self.os['RegisteredOwner'] = v.value()
                if v.name() == "CurrentBuild":
                    self.os['CurrentBuild'] = v.value()
        except Exception:
            logging.error('An error occurred in (OS_analysis - Current Version)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

        try:
            key = self.system.open("ControlSet00" + self.control_set + "\\Control\\Session Manager\\Environment")
            for v in key.values():
                if v.name() == "windir":
                    self.sa_windir = v.value()
        except Exception:
            logging.error('An error occurred in (OS_analysis - WinDir)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

        sid_list = []
        users_paths_list = []
        mapping_list = []
        accounts = []

        try:
            key = self.software.open("Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
            for v in key.subkeys():
                sid_list.append(v.name())
        except Exception:
            logging.error('An error occurred in (OS_analysis - SID)', exc_info=True, extra={'investigator': 'RegAnalyser'})

        try:
            for sid in sid_list:
                k = self.software.open("Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + sid)
                for v in k.values():
                    if v.name() == "ProfileImagePath":
                        name = v.value().split("\\")
                        mapping_list.append(name[len(name) - 1])
                        users_paths_list.append(v.value())
        except Exception:
            logging.error('An error occurred in (OS_analysis - Profile)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

        try:
            key = self.sam.open("SAM\\Domains\\Account\\Users\\Names")
            for v in key.subkeys():
                accounts.append(v.name())
        except Exception:
            logging.error('An error occurred in (OS_analysis - User accounts)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

        return self.os, sid_list, users_paths_list, mapping_list, accounts

    # Displays an OS analysis window with relevant information
    def os_analysis(self):
        self.rep_log("Viewed os analysis")
        try:
            if self.directory != "" and self.software != "":
                logging.info("OS Analysis on [" + self.full_session + "]", extra={'investigator': self.investigator})
                tk = Tk()
                tk.grid_columnconfigure(0, weight=1)
                tk.grid_columnconfigure(1, weight=1)
                tk.grid_columnconfigure(2, weight=1)
                tk.grid_columnconfigure(3, weight=1)
                tk.grid_rowconfigure(0, weight=1)
                tk.grid_rowconfigure(1, weight=1)
                self.center_window(tk, 500, 520)
                tk.title("RegAnalyser: OS Analysis")
                tk.iconbitmap("data/img/icon.ico")

                self.os, sid_list, users_paths_list, mapping_list, accounts = self.os_analysis_data()

                r = 1
                Label(tk, font="Arial 14 bold", fg="white", bg="cyan", text="OS Analysis \n[" + self.full_session + "]") \
                    .grid(row=0, columnspan=4, sticky="nsew")
                r += 1
                r += 1

                Label(tk, text='Product Name: ').grid(row=r, column=0)
                Label(tk, font="Helvetica 10 bold italic", text=self.os['ProductName']).grid(row=r, column=1)
                r += 1

                Label(tk, text='Release Id: ').grid(row=r, column=0)
                Label(tk, font="Helvetica 10 bold italic", text=self.os['ReleaseId']).grid(row=r, column=1)
                r += 1

                Label(tk, text='Current Build: ').grid(row=r, column=0)
                Label(tk, font="Helvetica 10 bold italic", text=self.os['CurrentBuild']).grid(row=r, column=1)
                r += 1

                Label(tk, text='Product Id: ').grid(row=r, column=0)
                Label(tk, font="Helvetica 10 bold italic", text=self.os['ProductId']).grid(row=r, column=1)
                r += 1

                Label(tk, text='Path Name: ').grid(row=r, column=0)
                Label(tk, font="Helvetica 10 bold italic", text=self.os['PathName']).grid(row=r, column=1)
                r += 1

                Label(tk, text="Install Date: ").grid(row=r, column=0)
                v = Label(tk, font="Helvetica 10 bold italic", text=self.os['InstallDate'])
                v.grid(row=r, column=1)
                r += 1

                Label(tk, text="Registered Organization: ").grid(row=r, column=0)
                vv = Label(tk, font="Helvetica 10 bold italic", text=self.os['RegisteredOrganization'])
                vv.grid(row=r, column=1)
                r += 1

                Label(tk, text="Registered Owner: ").grid(row=r, column=0)
                m = Label(tk, font="Helvetica 10 bold italic", text=self.os['RegisteredOwner'])
                m.grid(row=r, column=1)
                r += 1

                Label(tk, text="Windows Directory: ").grid(row=r, column=0)
                m = Label(tk, font="Helvetica 10 bold italic", text=self.sa_windir)
                m.grid(row=r, column=1)
                r += 1

                txt_frm = Frame(tk, width=350, height=150)
                txt_frm.grid(row=r, column=1, sticky="nsew")
                txt_frm.grid_propagate(False)
                txt_frm.grid_rowconfigure(0, weight=1)
                txt_frm.grid_columnconfigure(0, weight=1)
                tv = tkk.Treeview(txt_frm)
                tv['columns'] = ('MAP', 'PATH')
                tv.heading("#0", text='USERNAME')
                tv.column('#0', stretch=True)
                tv.heading('MAP', text='SID')
                tv.column('MAP', stretch=True)
                tv.heading('PATH', text='PATH')
                tv.column('PATH', stretch=True)

                tv.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
                scrollb = Scrollbar(txt_frm, command=tv.yview)
                scrollb.grid(row=0, column=1, sticky='nsew')
                tv['yscrollcommand'] = scrollb.set
                scrollbx = Scrollbar(txt_frm, command=tv.xview, orient=HORIZONTAL)
                scrollbx.grid(row=1, column=0, sticky='nsew')
                tv['xscrollcommand'] = scrollbx.set
                Label(tk, text='User Profiles: ').grid(row=r, column=0)

                for i in range(0, len(sid_list)):
                    tv.insert('', 'end', text=mapping_list[i], values=(sid_list[i], users_paths_list[i]))
                r += 1

                Label(tk, text='User Accounts: ').grid(row=r, column=0)
                lb_frm = Frame(tk, width=350, height=110)
                lb_frm.grid(row=r, column=1, sticky="nsew")
                lb_frm.grid_propagate(False)
                lb_frm.grid_rowconfigure(0, weight=1)
                lb_frm.grid_columnconfigure(0, weight=1)
                lb = Listbox(lb_frm)
                for a in accounts:
                    lb.insert(END, a)
                lb.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
                scrollb = Scrollbar(lb_frm, command=lb.yview)
                scrollb.grid(row=0, column=1, sticky='nsew')
                lb['yscrollcommand'] = scrollb.set
                scrollbx = Scrollbar(lb_frm, command=lb.xview, orient=HORIZONTAL)
                scrollbx.grid(row=1, column=0, sticky='nsew')
                lb['xscrollcommand'] = scrollbx.set
                tk.lift()

            else:
                self.rep_log("No session loaded")
                self.display_message('error', 'Please click on a session to load!')
        except Exception:
            logging.error('An error occurred in (OS_analysis)', exc_info=True, extra={'investigator': 'RegAnalyser'})
            self.display_message('error', 'An error occurred while processing\n Please try again.')

    # Opens the Registry Viewer tool to browse registry hives
    def regview(self):

        self.rep_log("Browsing Registry with Registry Viewer")
        try:
            if self.directory != "" and self.software != "":
                hives = ""
                path = os.getcwd() + "\\data\\sessions\\" + self.full_session + "\\"

                hives += " " + path + "DEFAULT"
                hives += " " + path + "NTUSER.DAT"
                hives += " " + path + "SAM"
                hives += " " + path + "SECURITY"
                hives += " " + path + "SOFTWARE"
                hives += " " + path + "SYSTEM"

                python3_command = os.getcwd() + "\\data\\lib\\regview\\RegView.exe " + hives
                # os.system(python3_command)
                process = subprocess.Popen(python3_command, stdin=None, stdout=None,
                                           close_fds=False, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)

            else:
                self.display_message('error', 'Please click on a session to load!')

        except Exception as ee:
            print(ee)
            logging.error('An error occurred in (regview)', exc_info=True, extra={'investigator': 'RegAnalyser'})
            self.display_message('error', 'An error occurred while opening regview\n Please try again.')

    # Gathers data for network analysis, including network cards, intranets, wireless networks, and profiles
    def network_analysis_data(self):
        cards = []
        intranet = []
        wireless = []
        matched = []

        try:
            key = self.software.open("Microsoft\\Windows NT\\CurrentVersion\\NetworkCards")
            for v in key.subkeys():
                for n in v.values():
                    if n.name() == "Description":
                        cards.append(n.value())
        except Exception:
            logging.error('An error occurred in (network_analysis - Cards)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

        try:
            key = self.software.open("Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Nla\\Cache\\Intranet")
            for v in key.subkeys():
                intranet.append(v.name())
        except Exception:
            logging.error('An error occurred in (network_analysis - Intranets)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

        try:
            key = self.software.open("Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Nla\\Wireless")
            for v in key.subkeys():
                wireless.append(v.name())
        except Exception:
            logging.error('An error occurred in (network_analysis - Wireless)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

        try:
            key = self.software.open("Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles")
            for v in key.subkeys():
                tmp = {}
                tmp["ID"] = v.name()
                for s in v.values():
                    if s.name() == "Description":
                        tmp["Description"] = s.value()
                    if s.name() == "DateCreated":
                        tmp["Created"] = Parse.parse_date(s.value().hex())
                    if s.name() == "DateLastConnected":
                        tmp["Modified"] = Parse.parse_date(s.value().hex())
                matched.append(tmp)
        except Exception:
            logging.error('An error occurred in (network_analysis - Extracting Wireless profiles)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

        return cards, intranet, wireless, matched

    def application_analysis_data(self):
        start_applications = []
        registered_applications = []
        installed_applications = []
        user_start_applications = []
        user_registered_applications = []
        user_installed_applications = []

        try:
            key = self.software.open("Microsoft\\Windows\\CurrentVersion\\Run")
            for v in key.values():
                start_applications.append(v.name())
        except Exception:
            logging.error('An error occurred in (application_analysis - Run)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

        try:
            key = self.software.open("RegisteredApplications")
            for v in key.values():
                registered_applications.append(v.name())
        except Exception:
            logging.error('An error occurred in (application_analysis - Registered)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

        try:
            key = self.software.open("Microsoft\\Windows\\CurrentVersion\\Uninstall")
            for v in key.subkeys():
                installed_applications.append(v.name())
        except Exception:
            logging.error('An error occurred in (application_analysis - Installed)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

        # ===
        try:
            key = self.ntuser.open("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
            for v in key.values():
                user_start_applications.append(v.name())
        except Exception:
            logging.error('An error occurred in (application_analysis - User Run)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

        try:
            key = self.ntuser.open("Software\\RegisteredApplications")
            for v in key.values():
                user_registered_applications.append(v.name())
        except Exception:
            logging.error('An error occurred in (application_analysis - User Registerd)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

        try:
            key = self.ntuser.open("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
            for v in key.subkeys():
                user_installed_applications.append(v.name())
        except Exception:
            logging.error('An error occurred in (application_analysis - User Installed)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

        try:
            if "64" in self.sa_processor:
                key = self.software.open("WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
                for v in key.subkeys():
                    installed_applications.append(v.name())

                key = self.software.open("WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run")
                for v in key.values():
                    start_applications.append(v.name())
        except Exception:
            logging.error('An error occurred in (application_analysis - 64 Run and Installed)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

        return start_applications, registered_applications, installed_applications, user_start_applications, \
            user_registered_applications, user_installed_applications

    # Perform application analysis
    def application_analysis(self):
        self.rep_log("Viewed application analysis")
        try:
            if self.directory != "" and self.software != "":
                logging.info("Application Analysis on [" + self.full_session + "]",
                             extra={'investigator': self.investigator})
                tk = Tk()
                tk.grid_columnconfigure(0, weight=1)
                tk.grid_columnconfigure(1, weight=1)
                tk.grid_columnconfigure(2, weight=1)
                tk.grid_columnconfigure(3, weight=1)
                tk.grid_rowconfigure(0, weight=1)
                tk.grid_rowconfigure(1, weight=1)
                self.center_window(tk, 850, 520)
                tk.title("RegAnalyser: Application Analysis")
                tk.iconbitmap("data/img/icon.ico")

                start_applications, registered_applications, installed_applications, user_start_applications, \
                    user_registered_applications, user_installed_applications = self.application_analysis_data()

                r = 1
                Label(tk, font="Arial 14 bold", fg="white", bg="brown",
                      text="Application Analysis \n[" + self.full_session + "]") \
                    .grid(row=0, columnspan=4, sticky="nsew")
                r += 1
                r += 1
                Label(tk, font="Arial 12 bold", text="System").grid(row=r, column=1)
                Label(tk, font="Arial 12 bold", text="User [" + self.session_name.get() + "]").grid(row=r, column=3)
                r += 2
                Label(tk, text='StartUp Programs: ').grid(row=r, column=0)
                lb_frm = Frame(tk, width=350, height=110)
                lb_frm.grid(row=r, column=1, sticky="nsew")
                lb_frm.grid_propagate(False)
                lb_frm.grid_rowconfigure(0, weight=1)
                lb_frm.grid_columnconfigure(0, weight=1)
                lb = Listbox(lb_frm)
                for a in start_applications:
                    lb.insert(END, a)
                lb.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
                scrollb = Scrollbar(lb_frm, command=lb.yview)
                scrollb.grid(row=0, column=1, sticky='nsew')
                lb['yscrollcommand'] = scrollb.set
                scrollbx = Scrollbar(lb_frm, command=lb.xview, orient=HORIZONTAL)
                scrollbx.grid(row=1, column=0, sticky='nsew')
                lb['xscrollcommand'] = scrollbx.set

                lb_frm = Frame(tk, width=350, height=110, )
                lb_frm.grid(row=r, column=3, sticky="nsew")
                lb_frm.grid_propagate(False)
                lb_frm.grid_rowconfigure(0, weight=1)
                lb_frm.grid_columnconfigure(0, weight=1)
                lb = Listbox(lb_frm)
                for a in user_start_applications:
                    lb.insert(END, a)
                lb.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
                scrollb = Scrollbar(lb_frm, command=lb.yview)
                scrollb.grid(row=0, column=1, sticky='nsew')
                lb['yscrollcommand'] = scrollb.set
                scrollbx = Scrollbar(lb_frm, command=lb.xview, orient=HORIZONTAL)
                scrollbx.grid(row=1, column=0, sticky='nsew')
                lb['xscrollcommand'] = scrollbx.set
                r += 2

                Label(tk, text='Registered Programs: ').grid(row=r, column=0)
                lbr_frm = Frame(tk, width=350, height=110)
                lbr_frm.grid(row=r, column=1, sticky="nsew")
                lbr_frm.grid_propagate(False)
                lbr_frm.grid_rowconfigure(0, weight=1)
                lbr_frm.grid_columnconfigure(0, weight=1)
                lbr = Listbox(lbr_frm)
                for a in registered_applications:
                    lbr.insert(END, a)
                lbr.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
                scrollbr = Scrollbar(lbr_frm, command=lbr.yview)
                scrollbr.grid(row=0, column=1, sticky='nsew')
                lbr['yscrollcommand'] = scrollbr.set
                scrollbxr = Scrollbar(lbr_frm, command=lbr.xview, orient=HORIZONTAL)
                scrollbxr.grid(row=1, column=0, sticky='nsew')
                lbr['xscrollcommand'] = scrollbxr.set

                lbr_frm = Frame(tk, width=350, height=110)
                lbr_frm.grid(row=r, column=3, sticky="nsew")
                lbr_frm.grid_propagate(False)
                lbr_frm.grid_rowconfigure(0, weight=1)
                lbr_frm.grid_columnconfigure(0, weight=1)
                lbr = Listbox(lbr_frm)
                for a in user_registered_applications:
                    lbr.insert(END, a)
                lbr.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
                scrollbr = Scrollbar(lbr_frm, command=lbr.yview)
                scrollbr.grid(row=0, column=1, sticky='nsew')
                lbr['yscrollcommand'] = scrollbr.set
                scrollbxr = Scrollbar(lbr_frm, command=lbr.xview, orient=HORIZONTAL)
                scrollbxr.grid(row=1, column=0, sticky='nsew')
                lbr['xscrollcommand'] = scrollbxr.set
                r += 2

                Label(tk, text='Installed Programs: ').grid(row=r, column=0)
                lbr_frm = Frame(tk, width=350, height=220)
                lbr_frm.grid(row=r, column=1, sticky="nsew")
                lbr_frm.grid_propagate(False)
                lbr_frm.grid_rowconfigure(0, weight=1)
                lbr_frm.grid_columnconfigure(0, weight=1)
                lbr = Listbox(lbr_frm)
                for i in installed_applications:
                    lbr.insert(END, i)
                lbr.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
                scrollbr = Scrollbar(lbr_frm, command=lbr.yview)
                scrollbr.grid(row=0, column=1, sticky='nsew')
                lbr['yscrollcommand'] = scrollbr.set
                scrollbxr = Scrollbar(lbr_frm, command=lbr.xview, orient=HORIZONTAL)
                scrollbxr.grid(row=1, column=0, sticky='nsew')
                lbr['xscrollcommand'] = scrollbxr.set

                lbr_frm = Frame(tk, width=350, height=220)
                lbr_frm.grid(row=r, column=3, sticky="nsew")
                lbr_frm.grid_propagate(False)
                lbr_frm.grid_rowconfigure(0, weight=1)
                lbr_frm.grid_columnconfigure(0, weight=1)
                lbr = Listbox(lbr_frm)
                for i in user_installed_applications:
                    lbr.insert(END, i)
                lbr.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
                scrollbr = Scrollbar(lbr_frm, command=lbr.yview)
                scrollbr.grid(row=0, column=1, sticky='nsew')
                lbr['yscrollcommand'] = scrollbr.set
                scrollbxr = Scrollbar(lbr_frm, command=lbr.xview, orient=HORIZONTAL)
                scrollbxr.grid(row=1, column=0, sticky='nsew')
                lbr['xscrollcommand'] = scrollbxr.set

                tk.lift()

            else:
                self.rep_log("No session loaded")
                self.display_message('error', 'Please click on a session to load!')
        except Exception:
            logging.error('An error occurred in (OS_analysis)', exc_info=True, extra={'investigator': 'RegAnalyser'})
            self.display_message('error', 'An error occurred while processing\n Please try again.')

    # Perform network analysis on the loaded session, displaying relevant information in a Tkinter window.
    def network_analysis(self):
        self.rep_log("Viewed network analysis")
        try:
            if self.directory != "" and self.software != "":
                logging.info("Network Analysis on [" + self.full_session + "]",
                             extra={'investigator': self.investigator})
                tk = Tk()
                tk.grid_columnconfigure(0, weight=1)
                tk.grid_columnconfigure(1, weight=1)
                tk.grid_columnconfigure(2, weight=1)
                tk.grid_columnconfigure(3, weight=1)
                tk.grid_rowconfigure(0, weight=1)
                tk.grid_rowconfigure(1, weight=1)
                self.center_window(tk, 800, 520)
                tk.title("RegAnalyser: Application Analysis")
                tk.iconbitmap("data/img/icon.ico")

                cards, intranet, wireless, matched = self.network_analysis_data()

                r = 1
                Label(tk, font="Arial 14 bold", fg="white", bg="green",
                      text="Network Analysis \n[" + self.full_session + "]") \
                    .grid(row=0, columnspan=4, sticky="nsew")
                r += 1

                Label(tk, text='Network Cards: ').grid(row=r, column=0)
                lb_frm = Frame(tk, width=350, height=110)
                lb_frm.grid(row=r, column=1, sticky="nsew")
                lb_frm.grid_propagate(False)
                lb_frm.grid_rowconfigure(0, weight=1)
                lb_frm.grid_columnconfigure(0, weight=1)
                lb = Listbox(lb_frm)
                for a in cards:
                    lb.insert(END, a)
                lb.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
                scrollb = Scrollbar(lb_frm, command=lb.yview)
                scrollb.grid(row=0, column=1, sticky='nsew')
                lb['yscrollcommand'] = scrollb.set
                scrollbx = Scrollbar(lb_frm, command=lb.xview, orient=HORIZONTAL)
                scrollbx.grid(row=1, column=0, sticky='nsew')
                lb['xscrollcommand'] = scrollbx.set
                r += 1

                Label(tk, text='Intranet Networks: ').grid(row=r, column=0)
                lb_frm = Frame(tk, width=350, height=110)
                lb_frm.grid(row=r, column=1, sticky="nsew")
                lb_frm.grid_propagate(False)
                lb_frm.grid_rowconfigure(0, weight=1)
                lb_frm.grid_columnconfigure(0, weight=1)
                lb = Listbox(lb_frm)
                for a in intranet:
                    lb.insert(END, a)
                lb.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
                scrollb = Scrollbar(lb_frm, command=lb.yview)
                scrollb.grid(row=0, column=1, sticky='nsew')
                lb['yscrollcommand'] = scrollb.set
                scrollbx = Scrollbar(lb_frm, command=lb.xview, orient=HORIZONTAL)
                scrollbx.grid(row=1, column=0, sticky='nsew')
                lb['xscrollcommand'] = scrollbx.set
                r += 1

                txt_frm = Frame(tk, width=650, height=250)
                txt_frm.grid(row=r, column=1, sticky="nsew")
                txt_frm.grid_propagate(False)
                txt_frm.grid_rowconfigure(0, weight=1)
                txt_frm.grid_columnconfigure(0, weight=1)
                tv = tkk.Treeview(txt_frm)
                tv['columns'] = ('Created', 'LastConnected', 'ID')
                tv.heading("#0", text='Description')
                tv.column('#0', stretch=True)
                tv.heading('Created', text='Created')
                tv.column('Created', stretch=True)
                tv.heading('LastConnected', text='LastConnected')
                tv.column('LastConnected', stretch=True)
                tv.heading('ID', text='ID')
                tv.column('ID', stretch=True)

                tv.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
                scrollb = Scrollbar(txt_frm, command=tv.yview)
                scrollb.grid(row=0, column=1, sticky='nsew')
                tv['yscrollcommand'] = scrollb.set
                scrollbx = Scrollbar(txt_frm, command=tv.xview, orient=HORIZONTAL)
                scrollbx.grid(row=1, column=0, sticky='nsew')
                tv['xscrollcommand'] = scrollbx.set
                Label(tk, text='Wireless: ').grid(row=r, column=0)

                for u in matched:
                    tv.insert('', 'end', text=u["Description"], values=(u["Created"], u["Modified"], u["ID"]))
                r += 1

                tk.lift()

            else:
                self.rep_log("No session loaded")
                self.display_message('error', 'Please click on a session to load!')
        except Exception:
            logging.error('An error occurred in (OS_analysis)', exc_info=True, extra={'investigator': 'RegAnalyser'})
            self.display_message('error', 'An error occurred while processing\n Please try again.')

    # Retrieve device analysis data, specifically information about printers and USB devices.
    def device_analysis_data(self):
        logging.info("Device Analysis on [" + self.full_session + "]", extra={'investigator': self.investigator})
        printer = []
        usb = []

        try:
            key = self.system.open("ControlSet00" + self.control_set + "\\Control\\Print\\Environments")
            for v in key.subkeys():
                for s in v.subkeys():
                    if s.name() == "Drivers":
                        for ss in s.subkeys():
                            if "Version" in ss.name():
                                for d in ss.subkeys():
                                    printer.append(d.name())
        except Exception:
            logging.error('An error occurred in (device_analysis - Print Drivers)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})

        try:
            key = self.system.open("ControlSet00" + self.control_set + "\\Enum\\USBSTOR")
            for v in key.subkeys():
                name = v.name().split("&")
                tmp = {}
                serial = []
                tmp["Type"] = name[0]
                tmp["Vendor"] = name[1].split("_")[1]
                tmp["Product"] = name[2].split("_")[1]
                tmp["Revision"] = name[3].split("_")[1]

                for s in v.subkeys():
                    serial_data = {}
                    serial_data["ID"] = s.name()
                    serial_data["InstallDate"] = "N/A"
                    serial_data["LastArrivalDate"] = "N/A"
                    serial_data["LastRemovalDate"] = "N/A"
                    for ss in s.subkeys():
                        if ss.name() == "Properties":
                            for sss in ss.subkeys():
                                for ssss in sss.subkeys():
                                    if ssss.name() == "0064":
                                        for ssssv in ssss.values():
                                            serial_data["InstallDate"] = ssssv.value().replace(microsecond=0)
                                    if ssss.name() == "0066":
                                        for ssssv in ssss.values():
                                            serial_data["LastArrivalDate"] = ssssv.value().replace(microsecond=0)
                                    if ssss.name() == "0067":
                                        for ssssv in ssss.values():
                                            serial_data["LastRemovalDate"] = ssssv.value().replace(microsecond=0)
                            serial.append(serial_data)
                tmp["Serial"] = serial
                usb.append(tmp)
        except Exception:
            logging.error('An error occurred in (device_analysis - USB)', exc_info=True,
                          extra={'investigator': 'RegAnalyser'})
        return printer, usb

    # Display device analysis information in a Tkinter window
    def device_analysis(self):
        self.rep_log("Viewed device analysis")
        try:
            if self.directory != "" and self.system != "":
                tk = Tk()
                tk.grid_columnconfigure(0, weight=1)
                tk.grid_columnconfigure(1, weight=2)
                tk.grid_columnconfigure(2, weight=2)
                tk.grid_columnconfigure(3, weight=2)
                tk.grid_rowconfigure(0, weight=1)
                tk.grid_rowconfigure(1, weight=1)
                self.center_window(tk, 950, 520)
                tk.title("RegAnalyser: Application Analysis")
                tk.iconbitmap("data/img/icon.ico")

                printer, usb = self.device_analysis_data()

                r = 1
                Label(tk, font="Arial 14 bold", fg="white", bg="Black",
                      text="Device Analysis \n[" + self.full_session + "]") \
                    .grid(row=0, columnspan=4, sticky="nsew")
                r += 1

                Label(tk, text='Printers: ').grid(row=r, column=0)
                lb_frm = Frame(tk, width=850, height=210)
                lb_frm.grid(row=r, column=1, sticky="nsew")
                lb_frm.grid_propagate(False)
                lb_frm.grid_rowconfigure(0, weight=1)
                lb_frm.grid_columnconfigure(0, weight=1)
                lb = Listbox(lb_frm)
                for a in printer:
                    lb.insert(END, a)
                lb.grid(row=0, column=0, sticky="nsew")
                scrollb = Scrollbar(lb_frm, command=lb.yview)
                scrollb.grid(row=0, column=1, sticky='nsew')
                lb['yscrollcommand'] = scrollb.set
                scrollbx = Scrollbar(lb_frm, command=lb.xview, orient=HORIZONTAL)
                scrollbx.grid(row=1, column=0, sticky='nsew')
                lb['xscrollcommand'] = scrollbx.set
                r += 1

                txt_frm = Frame(tk, width=850, height=250)
                txt_frm.grid(row=r, column=1, sticky="nsew")
                txt_frm.grid_propagate(False)
                txt_frm.grid_rowconfigure(0, weight=1)
                txt_frm.grid_columnconfigure(0, weight=1)
                tv = tkk.Treeview(txt_frm)
                tv['columns'] = ('Vendor', 'Product', 'Revision')
                tv.heading("#0", text='Type')
                tv.column('#0', stretch=True)
                tv.heading('Vendor', text='#Vendor')
                tv.column('Vendor', stretch=True)
                tv.heading('Product', text='#Product')
                tv.column('Product', stretch=True)
                tv.heading('Revision', text='#Revision')
                tv.column('Revision', stretch=True)

                tv.grid(row=0, column=0, sticky="nsew")
                scrollb = Scrollbar(txt_frm, command=tv.yview)
                scrollb.grid(row=0, column=1, sticky='nsew')
                tv['yscrollcommand'] = scrollb.set
                scrollbx = Scrollbar(txt_frm, command=tv.xview, orient=HORIZONTAL)
                scrollbx.grid(row=1, column=0, sticky='nsew')
                tv['xscrollcommand'] = scrollbx.set
                Label(tk, text='USB: ').grid(row=r, column=0)
                tv.tag_configure('new_serials', background='lightgrey')

                for u in usb:
                    tmp = tv.insert('', 'end', text=u["Type"], values=(u["Vendor"], u["Product"], u["Revision"]))
                    ser = tv.insert(tmp, 'end', text='#Serials', values=('#Installed Date', '#Plugged Date',
                                                                         '#Unplugged Date'), tags=('new_serials',))
                    for z in u["Serial"]:
                        tv.insert(ser, 'end', text=z['ID'], values=(z['InstallDate'], z['LastArrivalDate'],
                                                                    z['LastRemovalDate']))
                r += 1
                tk.lift()

            else:
                self.rep_log("No session loaded")
                self.display_message('error', 'Please click on a session to load!')
        except Exception:
            logging.error('An error occurred in (OS_analysis)', exc_info=True, extra={'investigator': 'RegAnalyser'})
            self.display_message('error', 'An error occurred while processing\n Please try again.')

    # Open a window for generating a report, allowing the user to customize and choose report options.
    def make_report(self):

        try:
            if self.directory != "" and self.system != "":
                self.rep_log("Opened the report menu")
                self.has_report = "True"
                self.report = Toplevel()
                self.center_window(self.report, 400, 450)
                self.report.title("RegAnalyser: Report")
                self.report.iconbitmap("data/img/icon.ico")

                r = 1
                Label(self.report, font="Arial 10 bold", fg="blue", bg="yellow",
                      text="Reporting Information") \
                    .grid(row=0, column=0, columnspan=2, sticky="nsew")
                r += 1

                Label(self.report, text="Enter Organization name: ") \
                    .grid(row=r, column=0, sticky="nsew")
                r += 1
                tmp_business = self.business_setting
                self.business = Entry(self.report)
                self.business.insert(0, tmp_business)
                self.business.grid(row=r, column=0, columnspan=2)
                r += 1
                Label(self.report, text="Enter Organization Location (Line separated): ") \
                    .grid(row=r, column=0, sticky="nsew")
                r += 1
                tmp_loc = self.location_setting
                self.location = Text(self.report, height=10, width=10)
                for i in tmp_loc:
                    self.location.insert(END, i + '\n')
                self.location.grid(row=r, column=0, sticky="nsew", columnspan=2)
                r += 1

                self.system_report.set(1)
                self.os_report.set(1)
                self.user_app_report.set(1)
                self.app_report.set(1)
                self.network_report.set(1)
                self.device_report.set(1)

                Checkbutton(
                    self.report, text="System Analysis", variable=self.system_report, anchor=W, justify=LEFT
                ).grid(row=r, column=0, sticky=W)

                Checkbutton(
                    self.report, text="OS Analysis", variable=self.os_report, anchor=W, justify=LEFT
                ).grid(row=r, column=1, sticky=W)
                r += 1
                Checkbutton(
                    self.report, text="User Application Analysis", variable=self.user_app_report, anchor=W, justify=LEFT
                ).grid(row=r, column=0, sticky=W)
                Checkbutton(
                    self.report, text="System Application Analysis", variable=self.app_report, anchor=W, justify=LEFT
                ).grid(row=r, column=1, sticky=W)
                r += 1
                Checkbutton(
                    self.report, text="Network Analysis", variable=self.network_report, anchor=W, justify=LEFT
                ).grid(row=r, column=0, sticky=W)

                Checkbutton(
                    self.report, text="Device Analysis", variable=self.device_report, anchor=W, justify=LEFT
                ).grid(row=r, column=1, sticky=W)
                r += 6

                rep = Button(self.report, compound=LEFT, text="Generate Report", anchor=W, justify=LEFT,
                             command=self.generate_report)

                rep.grid(row=r, columnspan=2, pady=20)

            else:
                self.rep_log("No session loaded, not showing report menu")
                self.display_message('error', 'Please select a valid session')
        except Exception as ee:
            print(ee)
            self.display_message("error", "Failed to create report.\nThis could be due to several reasons, "
                                          "PDF file is already opened or incorrect options choosed.")
            logging.error('Report failed to be created', extra={'investigator': 'RegAnalyser'})

    # Generate a report based on the selected options and save it to a user-specified location.
    def generate_report(self):
        try:
            self.set_status("Verifying dumps ...")
            self.progress.start()
            self.rep_log("Generating report")
            self.display_message("info",
                                 "Creating report\nPlease wait while dumps are being verified ...\nPress OK to continue.")

            tmp = Verification.verify_dump(self.directory)
            # tmp = 1
            case = self.get_config(self.full_session)
            self.progress.stop()
            self.set_status("Done")
            if case == "Error occurred":
                self.display_message("error", "Session is not valid. Report cannot be created.")
                return

            case = case.split(":")[5]

            if tmp:
                b = [self.business.get()]
                tmp = self.location.get(1.0, END).split('\n')
                self.business_setting = self.business.get().strip("\n")
                self.location_setting = tmp
                for i in tmp:
                    b.append(i)
                self.rep_log("Updating the business information.")
                self.update_settings(True)
                data = {}

                if self.os_report.get():
                    data["os"] = self.os_analysis_data()

                if self.network_report.get():
                    data["network"] = self.network_analysis_data()

                if self.user_app_report.get():
                    data["user_application"] = self.application_analysis_data()

                if self.app_report.get():
                    data["application"] = self.application_analysis_data()

                if self.device_report.get():
                    data["device"] = self.device_analysis_data()

                file = fd.asksaveasfilename(defaultextension=".pdf", initialfile=self.full_session,
                                            filetypes=[("PDF Document", "*.pdf")])

                if not file or file == "" or file == " ":
                    self.rep_log("Failed to set the saving destination.")
                    file = fd.asksaveasfilename(defaultextension=".pdf", initialfile=self.full_session,
                                                filetypes=[("PDF Document", "*.pdf")])
                if not file or file == "" or file == " ":
                    self.rep_log("Failed to set the saving destination for the second time. Not making the report.")
                    self.display_message("error", "Failed to get report target file. Report cannot be created.")
                    self.report.destroy()
                    return

                self.progress.start()
                self.set_status("Generating report ...")
                self.display_message("info", "Generating Report\nPlease click OK to continue.")
                Reports.standard_report(file, self.full_session + "@" + case, self.investigator, b, self.db,
                                        self.report_log, self.timeline_log, data)
                self.display_message('info', 'Your report has been saved.')

                self.report.destroy()
                self.progress.stop()
                self.set_status("DONE")

            else:
                self.display_message('error', 'Integrity of the session violated, Report cannot be created.')

        except Exception as ee:
            print(ee)
            self.display_message("error", "Failed to create report.\nThis could be due to several reasons, "
                                          "PDF file is already opened or incorrect options choosed.")
            logging.error('Report failed to be created', exc_info=True, extra={'investigator': 'RegAnalyser'})

    # Log a message to the report log, including a timestamp and investigator information.

    tmp = dt.datetime.now().replace(microsecond=0)

    def rep_log(self, msg):
        tmp = dt.datetime.now().replace(microsecond=0)
        self.report_log += str(tmp) + " - [" + self.investigator + "] => " + msg + "<br/>"
        self.timeline_log.append(tmp.time())