import sys
import cv2
from Crypto.Cipher import DES,AES
from Crypto.Random import get_random_bytes
from PyQt5 import QtWidgets, QtCore,QtGui
from PyQt5.QtWidgets import QFileDialog, QComboBox, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout
from despycryprtodome import encrypt_image,decrypt_image,save_image,load_image,display_image
import qdarkstyle
global key
global current_stylesheet
current_stylesheet = "dark"
mode_names = {
    DES.MODE_CBC: "DES.MODE_CBC",
    DES.MODE_ECB: "DES.MODE_ECB",
}
cipher_names={
    DES: "DES",
    AES: "AES"
}

class MyApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        #self.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())

        self.theme_toggle_button = QPushButton("Toggle Theme")
        self.theme_toggle_button.setObjectName("theme_toggle_button")
        self.key_label = QLabel("Enter Key:")
        self.key_entry = QLineEdit()
        self.set_key_button = QPushButton("Set Key")
        self.generate_key_button = QPushButton("Generate Random Key")
        self.save_key_button = QPushButton("Save Key to File")
        self.read_key_button = QPushButton("Read Key from File")


        self.cipher_label= QLabel("Selected Cipher: None")
        #self.cipher_label.setFixedHeight(10)
        self.cipher_combobox = QComboBox()
        self.cipher_combobox.setFixedHeight(13)
        self.cipher_combobox.addItem("None", None)
        for cipher_value, cipher_name in cipher_names.items():
            self.cipher_combobox.addItem(cipher_name, cipher_value)
        self.mode_label = QLabel("Selected Mode: None")
        self.mode_combobox = QComboBox()
        self.mode_combobox.addItem("None", None)
        for mode_value, mode_name in mode_names.items():
            self.mode_combobox.addItem(mode_name, mode_value)

        self.encrypt_button = QPushButton("Encrypt Image")
        self.decrypt_button = QPushButton("Decrypt Image")
        self.default_stylesheet = self.styleSheet()

        self.init_ui()

    def init_ui(self):
        # Create layouts for left and right sections
        vbox_left = QVBoxLayout()
        vbox_right = QVBoxLayout()

        # Set alignment and spacing for both layouts
        vbox_left.setAlignment(QtCore.Qt.AlignBottom)
        vbox_right.setAlignment(QtCore.Qt.AlignBottom)
        #vbox_left.setSpacing(10)  # Adjust the spacing as needed
        #vbox_right.setSpacing(10)  # Adjust the spacing as needed

        # Add widgets to left layout
        vbox_left.addWidget(self.theme_toggle_button)
        vbox_left.addWidget(self.key_label)
        vbox_left.addWidget(self.key_entry)
        vbox_left.addWidget(self.set_key_button)
        vbox_left.addWidget(self.generate_key_button)
        vbox_left.addWidget(self.save_key_button)
        vbox_left.addWidget(self.read_key_button)

        # Add widgets to right layout
        vbox_right.addWidget(self.cipher_label)
        vbox_right.addWidget(self.cipher_combobox)
        vbox_right.addWidget(self.mode_label)
        vbox_right.addWidget(self.mode_combobox)
        vbox_right.addWidget(self.encrypt_button)
        vbox_right.addWidget(self.decrypt_button)

        # Create a horizontal layout for the entire window
        hbox = QHBoxLayout()

        # Add the left and right layouts to the horizontal layout with stretches
        hbox.addLayout(vbox_left, stretch=1)  # Adjust the stretch factor as needed
        hbox.addLayout(vbox_right, stretch=1)  # Adjust the stretch factor as needed

        # Set the horizontal layout as the main layout for your window
        self.setLayout(hbox)

        self.set_key_button.clicked.connect(self.set_key)
        self.generate_key_button.clicked.connect(self.generate_random_key)
        self.save_key_button.clicked.connect(self.save_key_to_file)
        self.read_key_button.clicked.connect(self.read_key_from_file)
        self.mode_combobox.currentIndexChanged.connect(self.set_mode)
        self.encrypt_button.clicked.connect(self.encrypt_button_click)
        self.decrypt_button.clicked.connect(self.decrypt_button_click)
        self.theme_toggle_button.clicked.connect(self.toggle_theme)



    def set_mode(self, index):
        mode_var = self.mode_combobox.itemData(index)
        self.mode_label.setText(f"Selected Mode: {mode_names.get(mode_var)}")

    def set_key(self):
        global key

        key_str = self.key_entry.text()
        key_bytes = key_str.encode('utf-8')

        if len(key_bytes) != 8:
            self.key_entry.clear()
            self.key_entry.insert("Key must be 8 bytes")
        else:
            key = key_bytes

    def generate_random_key(self):
        global key
        key = get_random_bytes(8)
        self.key_entry.clear()
        self.key_entry.insert("Generated Random Key")

    def save_key_to_file(self):
        global key

        file_path, _ = QFileDialog.getSaveFileName(filter="Text files (*.txt)")

        if file_path:
            try:
                with open(file_path, "wb") as key_file:
                    key_file.write(key)
                self.key_entry.clear()
                self.key_entry.insert( "Key was written to file")
            except Exception as e:
                print(f"Error saving key to file: {str(e)}")
        else:
            print("No file selected for saving the key.")

    def read_key_from_file(self):
        global key

        file_path, _ = QFileDialog.getOpenFileName(filter="Text files (*.txt)")
        if file_path:
            try:
                with open(file_path, "rb") as key_file:
                    key = key_file.read()
                    self.key_entry.clear()
                    self.key_entry.insert(0, "Key was read from file")
            except FileNotFoundError:
                self.key_entry.clear()
                self.key_entry.insert(0, "File Not Found")

    def encrypt_button_click(self):
        mode = self.mode_combobox.currentData()
        if mode != DES.MODE_CBC and mode != DES.MODE_ECB:
            print('Only CBC and ECB mode supported...')
            sys.exit()

        file_path, _ = QFileDialog.getOpenFileName()
        if not file_path:
            return

        imageOrig = load_image(file_path)
        display_image(imageOrig, "Original image")

        encryptedImage = encrypt_image(imageOrig, key, mode)

        # Display encrypted image (consider using QLabel to display images in PyQt)
        # display_image(encryptedImage, "Encrypted image")
        display_image(encryptedImage,"Encrypted image")
        encrypted_filename = f'{mode_names.get(mode, "unknown")}_encrypted_{file_path.split("/")[-1]}.bmp'
        print(encrypted_filename)
        save_image(encryptedImage, encrypted_filename)

    def decrypt_button_click(self):
        mode = self.mode_combobox.currentData()
        if mode != DES.MODE_CBC and mode != DES.MODE_ECB:
            print('Only CBC and ECB mode supported...')
            sys.exit()

        file_path, _ = QFileDialog.getOpenFileName()
        if not file_path:
            return

        encryptedImage = load_image(file_path)

        decryptedImage = decrypt_image(encryptedImage, key, mode)
        display_image(decryptedImage,"Decrypted image")

    def toggle_theme(self):
        global current_stylesheet

        print(type(current_stylesheet))
        print(self.default_stylesheet)
        print(current_stylesheet, "now")

        # Check if the current theme is dark
        if 'white' in current_stylesheet:
            print("not dark")
            self.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
            print(self.styleSheet())
            current_stylesheet = "dark"
            for button in self.findChildren(QPushButton):
                button.setStyleSheet(  """
                           background-color: #455364;
                           color: #E0E1E3;
                           border-radius: 4px;
                           padding: 2px;
                           outline: none;
                           border: none;
                           """)

        elif 'dark' == current_stylesheet:
            print(current_stylesheet, "Nofuck123")
            print(self.styleSheet())
            # Switch to the light theme
            print(self.default_stylesheet)
            self.setStyleSheet(self.default_stylesheet + """
                /* Custom light theme styles */
                background-color: white; /* Set background color to white */
                color: black; /* Set text color to black */
            """)

            # Set the style for all QPushButton widgets
            for button in self.findChildren(QPushButton):
                button.setStyleSheet("""
                    background-color: light gray;
                    color: black;
                    border-radius: 4px;
                    padding: 2px;
                    outline: none;
                    border: 1px solid black;
                """)



            # Remove any existing stylesheet

            # Set your custom light theme stylesheet
            current_stylesheet="white"
            print(current_stylesheet)




        # Display decrypted image (consider using QLabel to display images in PyQt)
        # display_image(decryptedImage, "Decrypted Image")

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    app.setStyle("Fusion")  # Optional: Use the Fusion style for a more modern look
    window = MyApp()
    window.setWindowTitle("Image Encryption/Decryption")
    window.setGeometry(100,100,800, 400)  # Adjust the window size
    window.show()
    sys.exit(app.exec_())
