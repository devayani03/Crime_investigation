import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget
from PyQt5.QtCore import QUrl
from PyQt5.QtGui import QDesktopServices


class BasicWebsite(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Basic Website with PyQt")
        self.setGeometry(100, 100, 400, 100)

        # Create a central widget and a layout
        central_widget = QWidget()
        layout = QVBoxLayout(central_widget)

        # Create a button to open the website
        open_button = QPushButton("Open Website in Browser")
        open_button.clicked.connect(self.open_website)

        layout.addWidget(open_button)
        self.setCentralWidget(central_widget)

    def open_website(self):
        # Specify the URL you want to open in the user's default web browser
        url = QUrl("https://www.example.com")

        # Use QDesktopServices to open the URL in the default web browser
        QDesktopServices.openUrl(url)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = BasicWebsite()
    window.show()
    sys.exit(app.exec_())
