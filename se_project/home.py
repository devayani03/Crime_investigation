import sys
import os
import winreg
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QTreeWidget, QTreeWidgetItem, QHeaderView, QPushButton
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

        # Label for website description
        description_label = QLabel("This website will help the forensic department find cyber criminals.")

        # Create a vertical layout for the content
        content_layout = QVBoxLayout()
        content_layout.addLayout(navbar)
        content_layout.addWidget(description_label)

        central_widget.setLayout(content_layout)

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
        self.tree_widget.setHeaderLabels(["Registry Key", "Value Name", "Value Data"])
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
            layout().addWidget(error_label)

    def recursive_tree_view(self, key, tree_widget, parent_item=None):
        for i in range(0, winreg.QueryInfoKey(key)[1]):
            subkey_name = winreg.EnumKey(key, i)
            subkey_path = os.path.join(str(winreg.QueryInfoKey(key)[0]), subkey_name)

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