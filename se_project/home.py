import sys
import chardet
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QFileDialog, QTextEdit, QTreeWidget, QTreeWidgetItem
from datetime import datetime

class ScannerApp(QWidget):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        # Create main layout
        main_layout = QVBoxLayout()

        # Create button layout
        button_layout = QHBoxLayout()

        # Buttons
        upload_button = QPushButton('Upload File', self)
        scan_button = QPushButton('Start Scanning', self)
        export_button = QPushButton('Export File', self)
        help_button = QPushButton('Help', self)

        # QTreeWidget for displaying .reg file content in a tree structure
        reg_tree_widget = QTreeWidget(self)
        reg_tree_widget.setColumnCount(5)  # Set the number of columns

        # Set header labels for columns
        reg_tree_widget.setHeaderLabels(['Path', 'Name', 'Type', 'Data', 'Timestamp'])

        # Button click events
        upload_button.clicked.connect(lambda: self.upload_file())
        scan_button.clicked.connect(self.start_scanning)
        export_button.clicked.connect(self.export_file)
        help_button.clicked.connect(self.show_help)

        # Add buttons to the button layout
        button_layout.addWidget(upload_button)
        button_layout.addWidget(scan_button)
        button_layout.addWidget(export_button)
        button_layout.addWidget(help_button)

        # Add the button layout, .reg contents edit, and QTreeWidget to the main layout
        main_layout.addLayout(button_layout)
        main_layout.addWidget(reg_tree_widget)

        # Set the main layout for the main window
        self.setLayout(main_layout)

        # Set window properties
        self.setWindowTitle('Scanner App')
        self.setGeometry(100, 100, 800, 600)  # Adjust the window size as needed

        # Set the QTreeWidget instance as a class attribute
        self.reg_tree_widget = reg_tree_widget

    def upload_file(self):
        # Open file dialog for file selection
        file_dialog = QFileDialog(self)
        file_path, _ = file_dialog.getOpenFileName(self, 'Upload File', '', 'Registry Files (*.reg)')

        if file_path:
            # Detect the encoding of the .reg file
            with open(file_path, 'rb') as reg_file:
                result = chardet.detect(reg_file.read())
                encoding = result['encoding']

            # Read and display the contents of the .reg file with detected encoding
            with open(file_path, 'r', encoding=encoding) as reg_file:
                reg_contents = reg_file.read()

            # Parse and display the .reg file content in a tree structure
            self.display_reg_content(reg_contents)

    def display_reg_content(self, reg_contents):
        # Parse the .reg file content
        reg_data = self.parse_reg_content(reg_contents)

        # Clear existing items in the tree widget
        reg_tree_widget = self.reg_tree_widget
        reg_tree_widget.clear()

        # Display the parsed .reg file content in a tree structure
        self.populate_tree_widget(reg_tree_widget, reg_data)

    def parse_reg_content(self, reg_contents):
        reg_data = {}

        lines = [line.strip() for line in reg_contents.splitlines() if line.strip()]

        key_stack = []  # Keep track of the current registry key

        for line in lines:
            if line.startswith('[') and line.endswith(']'):
                # Handle registry key entries
                key_path = line[1:-1]
                key_stack = key_path.split('\\')
                current_key = reg_data
                for key_part in key_stack:
                    current_key = current_key.setdefault(key_part, {})
            else:
                # Handle registry value entries
                parts = line.split('=', 1)
                if len(parts) == 2:
                    value_name, value_data = parts
                    current_key[value_name.strip()] = value_data.strip()

        return reg_data

    def populate_tree_widget(self, tree_widget, data, parent_item=None):
        for key, value in data.items():
            if isinstance(value, dict):
                # Recursive call for subkeys
                key_item = QTreeWidgetItem(parent_item if parent_item else tree_widget)
                key_item.setText(0, key)
                key_item.setText(1, '')  # Empty string for Name column
                key_item.setText(2, '')  # Empty string for Type column
                key_item.setText(3, '')  # Empty string for Data column
                key_item.setText(4, '')  # Empty string for Timestamp column
                self.populate_tree_widget(tree_widget, value, key_item)
            else:
                # Display registry value
                value_item = QTreeWidgetItem(parent_item if parent_item else tree_widget)
                value_item.setText(0, key)

                # Retrieve additional info for specific keys
                name, value_type, value_data, timestamp, additional_info = self.get_value_info(parent_item, key, value)
                
                value_item.setText(1, name)
                value_item.setText(2, value_type)
                value_item.setText(3, value_data)
                value_item.setText(4, timestamp + ' ' + additional_info)

    def get_value_info(self, parent_item, key, value):
        # Add logic here to retrieve Name, Type, Data, and Timestamp based on key or value
        name = key
        value_type = 'String'  # Placeholder, you need to determine the type based on your data
        value_data = str(value)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Placeholder timestamp
        additional_info = ''  # Placeholder for additional info

        # Add more conditions for other keys or values as needed
        if parent_item is not None and parent_item.text(0) == 'Software' and key == 'Publisher':
            # Example: Retrieve additional info for the 'Publisher' key under 'Software'
            additional_info = 'Example Publisher Info'

        return name, value_type, value_data, timestamp, additional_info

    def start_scanning(self):
        # Placeholder for scanning functionality
        pass

    def export_file(self):
        # Placeholder for export functionality
        pass

    def show_help(self):
        # Placeholder for help functionality
        pass


if __name__ == '__main__':
    app = QApplication(sys.argv)
    scanner_app = ScannerApp()
    scanner_app.show()
    sys.exit(app.exec_())
