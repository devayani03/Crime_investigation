import sys
import os
import winreg
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QTreeWidget, QTreeWidgetItem, QHeaderView, QPushButton
from PyQt5.QtCore import QFile, QTextStream


class CrimeInvestigationWebsite(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Crime Investigation Website")
        self.setGeometry(100, 100, 800, 600)

        self.load_css("styles.css")

        # Create a central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Create a navigation bar (horizontal layout)
        navbar = QVBoxLayout()

        # Buttons for navigation
        home_button = QPushButton("Home")
        registry_upload_button = QPushButton("Registry Upload")
        malware_detection_button = QPushButton("Malware Detection")
        analysis_options_button = QPushButton("Analysis Options")

        # Set the stylesheet for the buttons
        home_button.setStyleSheet("QPushButton")
        registry_upload_button.setStyleSheet("QPushButton")
        malware_detection_button.setStyleSheet("QPushButton")
        analysis_options_button.setStyleSheet("QPushButton")

        # Connect the "Registry Upload" button to display the registry viewer
        registry_upload_button.clicked.connect(self.display_registry_viewer)

        # Add buttons to the navbar
        navbar.addWidget(home_button)
        navbar.addWidget(registry_upload_button)
        navbar.addWidget(malware_detection_button)
        navbar.addWidget(analysis_options_button)

        # Create a horizontal layout for the cards
        card_layout = QHBoxLayout()

        # Create three cards with outline
        card1 = QLabel("Card 1")
        card1.setObjectName("card")  # Apply the .card style to this widget
        card1.setStyleSheet("border: 1px solid #000; padding: 10px;")

        html_content = """
        <html>
    <head>
        <style>
            ul {
                list-style-type: disc;
                padding-left: 20px;
            }

            li {
                font-size: 16px;
                margin-bottom: 10px;
            }

            h1 {
                font-size: 24px;
                margin-bottom: 20px;
            }
        </style>
    </head>
    <body>
        <h1>Registry Forensics</h1>
        <ul>
            <li style="font-size: 20px;">Click on registry upload button</li>
            <li style="font-size: 20px;">You will find three columns: key, value, and data</li>
            <li style="font-size: 20px;">A registry key is a container in the Windows Registry <br> that can store various types of information, including subkeys <br> and values.</li>
            <li style="font-size: 20px;">Registry values are used to hold various types of information, <br>such as strings, numbers, binary data, and more. Each value<br> within a key typically has a name that distinguishes it from other<br> values within the same key.</li>
            <li style="font-size: 20px;">The type of data stored in a registry value can vary depending on <br>the value's purpose. Common data types include strings (text), <br>binary data, DWORD (double word, typically used for integers)</li>
        </ul>
    </body>
</html>

    """

        card1.setText(html_content)

        card2 = QLabel("Card 2")
        card2.setObjectName("card")  # Apply the .card style to this widget
        card2.setStyleSheet("border: 1px solid #000; padding: 10px;")

        html_content2 = """
        <html>
    <head>
        <style>
            ul {
                list-style-type: disc;
                padding-left: 20px;
            }

            li {
                font-size: 16px;
                margin-bottom: 10px;
            }

            h1 {
                font-size: 24px;
                margin-bottom: 20px;
            }
        </style>
    </head>
    <body>
        <h1>Malware detection</h1>
        <ul>
            <li style="font-size: 20px;">Click on malware detection option</li>
            <li style="font-size: 20px;">Choose the type of scan you want to perform. Common options<br> include quick scans, full system scans, or custom scans focusing<br> on specific areas.</li>
            <li style="font-size: 20px;">If the software allows, select the Windows Registry as the <br>target of the scan. Ensure you have the appropriate permissions to <br>access and scan the Registry.</li>
            <li style="font-size: 20px;">Initiate the scan process. The software will start analyzing<br> the Registry for any signs of malware.</li>
            <li style="font-size: 20px;">Once the scan is complete, review the results. The software will<br> provide a list of detected items, which may include malware or<br> suspicious Registry entries.</li>
        </ul>
    </body>
</html>

    """

        card2.setText(html_content2)

        card3 = QLabel("Card 3")
        card3.setObjectName("card")  # Apply the .card style to this widget
        card3.setStyleSheet("border: 1px solid #000; padding: 10px;")

        html_content3 = """
        <html>
    <head>
        <style>
            ul {
                list-style-type: disc;
                padding-left: 20px;
            }

            li {
                font-size: 16px;
                margin-bottom: 10px;
            }

            h1 {
                font-size: 24px;
                margin-bottom: 20px;
            }
        </style>
    </head>
    <body>
        <h1>Analysis Options</h1>
        <ul>
            <li style="font-size: 20px;">Click on registry upload button</li>
            <li style="font-size: 20px;">You will find three columns: key, value, and data</li>
            <li style="font-size: 20px;">A registry key is a container in the Windows Registry <br> that can store various types of information, including subkeys <br> and values.</li>
            <li style="font-size: 20px;">Registry values are used to hold various types of information, <br>such as strings, numbers, binary data, and more. Each value<br> within a key typically has a name that distinguishes it from other<br> values within the same key.</li>
            <li style="font-size: 20px;">The type of data stored in a registry value can vary depending on <br>the value's purpose. Common data types include strings (text), <br>binary data, DWORD (double word, typically used for integers)</li>
        </ul>
    </body>
</html>

    """

        card3.setText(html_content3)

        # Create a vertical layout for the content
        content_layout = QVBoxLayout()
        content_layout.addLayout(navbar)

        central_widget.setLayout(content_layout)

        card_layout.addWidget(card1)
        card_layout.addWidget(card2)
        card_layout.addWidget(card3)

        # Add the card layout to the central layout
        content_layout.addLayout(card_layout)

        # Initialize a placeholder for the registry viewer
        self.registry_viewer = None

    def load_css(self, file_name):
        file = QFile(file_name)
        if file.open(QFile.ReadOnly | QFile.Text):
            stream = QTextStream(file)
            self.setStyleSheet(stream.readAll())
            file.close()

    def display_registry_viewer(self):
        # Create and display the RegistryViewer widget
        if not self.registry_viewer:
            self.registry_viewer = RegistryViewer()
        self.setCentralWidget(self.registry_viewer)


class RegistryViewer(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()

        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabels(
            ["Registry Key", "Value Name", "Value Data"])
        layout.addWidget(self.tree_widget)

        self.load_registry_data()

        self.setLayout(layout)

    def load_registry_data(self):
        root = winreg.HKEY_LOCAL_MACHINE
        subkey = r"SOFTWARE\Microsoft\Windows\CurrentVersion"

        try:
            with winreg.OpenKey(root, subkey) as key:
                self.recursive_tree_view(key, self.tree_widget)

        except FileNotFoundError:
            error_label = QLabel("Registry key not found.")
            layout.addWidget(error_label)  # Use layout directl

    def recursive_tree_view(self, key, tree_widget, parent_item=None):
        for i in range(0, winreg.QueryInfoKey(key)[1]):
            subkey_name = winreg.EnumKey(key, i)
            subkey_path = os.path.join(
                str(winreg.QueryInfoKey(key)[0]), subkey_name)

            child_item = QTreeWidgetItem(parent_item, [subkey_path, "", ""])
            tree_widget.addTopLevelItem(child_item)

            try:
                with winreg.OpenKey(key, subkey_name) as subkey:
                    self.recursive_tree_view(subkey, tree_widget, child_item)
            except OSError:
                # Handle registry errors or exceptions here
                pass


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CrimeInvestigationWebsite()
    window.show()
    sys.exit(app.exec_())
