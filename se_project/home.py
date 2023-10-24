import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QPushButton, QVBoxLayout, QHBoxLayout, QLabel
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
        navbar = QHBoxLayout()

        # Buttons for navigation
        home_button = QPushButton("Home")
        registry_upload_button = QPushButton("Registry Upload")
        malware_detection_button = QPushButton("Malware Detection")
        analysis_options_button = QPushButton("Analysis Options")

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

    def load_css(self, file_name):
        file = QFile(file_name)
        if file.open(QFile.ReadOnly | QFile.Text):
            stream = QTextStream(file)
            self.setStyleSheet(stream.readAll())
            file.close()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CrimeInvestigationWebsite()
    window.show()
    sys.exit(app.exec_())
