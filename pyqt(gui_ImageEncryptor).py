import os
import sys
from Crypto.Cipher import DES,AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon,QPixmap
from PyQt5.QtWidgets import QFileDialog, QComboBox, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QFrame, \
    QApplication, QMessageBox, QCheckBox
import qdarkstyle
import datetime
from ImageEncryptor import ImageEncryptor
import qdarktheme



current_stylesheet = "dark"

mode_des_names = {
    DES.MODE_CBC: "CBC",
    DES.MODE_ECB: "ECB",
}

mode_aes_names={
    AES.MODE_ECB: "ECB",
    AES.MODE_CBC: "CBC",
    AES.MODE_CTR: "CTR",
    AES.MODE_GCM: "GCM",
}
cipher_names={
    DES: "DES",
    AES: "AES",
}


def show_alert(message):
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Critical)
    msg.setText(message)
    msg.setWindowTitle("Error")
    msg.exec_()
class MyApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.encryptor= ImageEncryptor()
        self.use_rsa_encryption = False
        self.rsa_public_key = None
        self.rsa_private_key = None
        #self.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())

        self.theme_toggle_button = QPushButton()
        self.theme_toggle_button.setObjectName("theme_toggle_button")
        self.theme_toggle_button.setIcon(QIcon("image (1).png"))  # Replace with the path to your dark theme image
        self.theme_toggle_button.setIconSize(QtCore.QSize(50, 50))
        self.theme_toggle_button.setFixedSize(50, 50)
        self.theme_toggle_button.setStyleSheet("background-color: transparent;")# Replace with the path to your dark theme image

        self.separator = QFrame()
        self.separator.setFrameShape(QFrame.VLine)
        self.separator.setFrameShadow(QFrame.Sunken)


        self.mode_display_label = QLabel("Current Mode: Educational")  # Default text
        self.mode_display_label.setStyleSheet("""
            font-size: 20px;
            font-weight: bold;
            color: rgba(255, 255, 255, 150);  /* White with transparency */
            text-align: center;
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
        """)
        # Purpose label styling
        # Purpose label styling
        self.purpose_label = QLabel("Select Purpose:")
        self.purpose_label.setStyleSheet("""
            font-size: 16px;
            font-weight: bold;
            color: #4CAF50;  /* Green color to make it stand out */
            margin-bottom: 5px;
        """)

        # Purpose combo box styling
        self.purpose_combobox = QComboBox()
        self.purpose_combobox.addItem("Educational purpose")
        self.purpose_combobox.addItem("Intended purpose")
        self.purpose_combobox.setStyleSheet("""
            font-size: 14px;  
            border: 2px solid #4CAF50;  /* Green border to match the label */
            padding: 5px;
            border-radius: 5px;
        """)

        self.rsa_checkbox = QCheckBox("Use RSA to Encrypt/Decrypt symmetric key")
        self.rsa_key_status_label = QLabel("RSA key status:")
        self.rsa_key_status_entry = QLineEdit()

        self.generate_rsa_keys_button = QPushButton("Generate RSA pair of keys and save to files")
        self.read_private_key_button = QPushButton("Read Private Key from File")
        self.read_public_key_button = QPushButton("Read Public Key from File")

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

        self.encrypt_button = QPushButton("Encrypt Image")
        self.decrypt_button = QPushButton("Decrypt Image")
        self.default_stylesheet = self.styleSheet()

        self.init_ui()


    def init_ui(self):
        # Create layouts for left and right sections
        vbox_left = QVBoxLayout()
        vbox_right = QVBoxLayout()

        # Create a QLabel for displaying the current mode in the center


        # Update mode text when combo box selection changes
        self.purpose_combobox.currentIndexChanged.connect(self.update_mode_display)

        # Set alignment and spacing for both layouts
        vbox_left.setAlignment(QtCore.Qt.AlignBottom)
        vbox_right.setAlignment(QtCore.Qt.AlignBottom)
        #vbox_left.setSpacing(10)  # Adjust the spacing as needed
        #vbox_right.setSpacing(10)  # Adjust the spacing as needed

        # Add widgets to left layout
        vbox_left.addWidget(self.purpose_label)
        vbox_left.addWidget(self.purpose_combobox)


        spacer_item = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)

        vbox_left.addItem(spacer_item)
        vbox_left.addWidget(self.mode_display_label)

        vbox_left.addItem(spacer_item)
        vbox_left.addWidget(self.rsa_key_status_label)
        vbox_left.addWidget(self.rsa_key_status_entry)
        vbox_left.addWidget(self.generate_rsa_keys_button)
        vbox_left.addWidget(self.read_private_key_button)
        vbox_left.addWidget(self.read_public_key_button)

        vbox_left.addWidget(self.key_label)
        vbox_left.addWidget(self.rsa_checkbox)  # Add the checkbox to the layout
        vbox_left.addWidget(self.key_entry)
        vbox_left.addWidget(self.set_key_button)
        vbox_left.addWidget(self.generate_key_button)
        vbox_left.addWidget(self.save_key_button)
        vbox_left.addWidget(self.read_key_button)

        # Add widgets to right layout
        spacer = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)




        vbox_right.addWidget(self.theme_toggle_button,alignment=Qt.AlignmentFlag.AlignRight)
        vbox_right.addSpacerItem(spacer)

        vbox_right.addWidget(self.separator)

        vbox_right.addWidget(self.cipher_label)
        vbox_right.addWidget(self.cipher_combobox)
        vbox_right.addWidget(self.mode_label)
        vbox_right.addWidget(self.mode_combobox)
        vbox_right.addWidget(self.encrypt_button)
        vbox_right.addWidget(self.decrypt_button)


        # Create a horizontal layout for the entire window
        hbox = QHBoxLayout()

        # Add the left and right layouts to the horizontal layout with stretches
        hbox.addLayout(vbox_left, stretch=1)
        hbox.addWidget(self.separator)        # Adjust the stretch factor as needed
        hbox.addLayout(vbox_right, stretch=1)  # Adjust the stretch factor as needed

        # Set the horizontal layout as the main layout for your window
        self.setLayout(hbox)
        # Add the mode display label at the center of the window

        #DES,AES
        self.set_key_button.clicked.connect(self.set_key)
        self.generate_key_button.clicked.connect(self.generate_random_key)
        self.save_key_button.clicked.connect(self.save_key_to_file)
        self.read_key_button.clicked.connect(self.read_key_from_file)
        self.mode_combobox.currentIndexChanged.connect(self.set_mode)
        self.cipher_combobox.currentIndexChanged.connect(self.set_cipher)
        self.encrypt_button.clicked.connect(self.encrypt_button_click)
        self.decrypt_button.clicked.connect(self.decrypt_button_click)

        self.theme_toggle_button.clicked.connect(self.toggle_theme)
        self.cipher_combobox.currentIndexChanged.connect(self.update_mode_combobox)
        self.generate_rsa_keys_button.clicked.connect(self.generate_rsa_keys_values)
        #self.read_private_key_button.clicked.connect(self.read_private_key_from_file)

        self.read_private_key_button.clicked.connect(self.read_private_key_from_file)
        self.read_public_key_button.clicked.connect(self.read_public_key_from_file)
        self.rsa_checkbox.stateChanged.connect(self.toggle_rsa_encryption)

        self.update_mode_combobox()

    def update_mode_display(self):
        selected_mode = self.purpose_combobox.currentText()
        if selected_mode == "Educational purpose":
            self.mode_display_label.setText("Current Mode: Educational")
        else:
            self.mode_display_label.setText("Current Mode: Real Use")
    def toggle_rsa_encryption(self, state):
        # Update the flag based on the checkbox state
        self.encryptor.use_rsa_encryption = state == Qt.Checked


    def generate_rsa_keys_values(self):
        # Generate a new RSA key pair
        rsa_keys = RSA.generate(2048)

        # Save the private key to a file
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        filenameprivate = f"privatekey_{timestamp}.pem"

        folder_path = "rsa_keys"
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
            print(f"Folder '{folder_path}' created successfully.")
        with open(f"rsa_keys\\{filenameprivate}", "wb") as private_file:
            private_file.write(rsa_keys.export_key("PEM"))

        # Save the public key to a file
        filenamepublic = f"publickey_{timestamp}.pem"
        with open(f"rsa_keys\\{filenamepublic}", "wb") as public_file:
            public_file.write(rsa_keys.publickey().export_key("PEM"))

        self.rsa_key_status_entry.setText("Keys were generated and saved to files")

    def read_private_key_from_file(self):
        file_path, _ = QFileDialog.getOpenFileName(filter="PEM files (*.pem)")
        if file_path:
            try:
                with open(file_path, "rb") as file:
                    self.encryptor.rsa_private_key = RSA.import_key(file.read())
                    self.rsa_key_status_entry.setText("Private key loaded successfully")
            except Exception as e:
                print(f"Error reading private key: {str(e)}")



    def read_public_key_from_file(self):
        file_path, _ = QFileDialog.getOpenFileName(filter="PEM files (*.pem)")
        print(file_path, "file path")
        if file_path:
            try:
                with open(file_path, "rb") as file:
                    self.encryptor.rsa_public_key= RSA.import_key(file.read())
                    self.rsa_key_status_entry.setText("Public key loaded successfully")
            except Exception as e:
                print(f"Error reading public key: {str(e)}")


    def update_mode_combobox(self):
        self.encryptor.cipher = self.cipher_combobox.currentData()
        print(self.encryptor.cipher)# Get the selected cipher value
        print(DES)
        # Clear the mode combobox
        self.mode_combobox.clear()

        # Add "None" option to the mode combobox
        self.mode_combobox.addItem("None", None)

        if self.encryptor.cipher == DES:
            # Add DES modes if DES is selected
            for mode_val, mode_name in mode_des_names.items():
                self.mode_combobox.addItem(mode_name, mode_val)

        elif self.encryptor.cipher == AES:
            for mode_val, mode_name in mode_aes_names.items():
                self.mode_combobox.addItem(mode_name, mode_val)

    def set_mode(self, index):
        mode_var = self.mode_combobox.itemData(index)

        self.encryptor.cipher = self.cipher_combobox.currentData()
        if self.encryptor.cipher == DES:
            mode_name = mode_des_names.get(mode_var)
        elif self.encryptor.cipher == AES:
            mode_name = mode_aes_names.get(mode_var)
        else:
            mode_name = None

        self.mode_label.setText(f"Selected Mode: {mode_name if mode_name else 'None'}")
    def set_cipher(self, index):
        cipher_var = self.cipher_combobox.itemData(index)
        self.cipher_label.setText(f"Selected Cipher: {cipher_names.get(cipher_var)}")




    def set_key(self):

        key_str = self.key_entry.text()
        self.encryptor.cipher = self.cipher_combobox.currentData()

        if self.encryptor.cipher == DES:
            if len(key_str) != 8:
                self.key_entry.clear()
                self.key_entry.insert("Key must be 8 bytes")
        elif self.encryptor.cipher == AES:
            if len(key_str) != 32:
                self.key_entry.clear()
                show_alert("No cipher selected. Select a cipher first.")
                self.key_entry.insert("Key must be 32 bytes")
        else:
            self.key_entry.clear()
            show_alert("Key is not set. Please set the key first.")
            self.key_entry.insert("No cipher selected")


        key_bytes = key_str.encode('utf-8')
        self.encryptor.key = key_bytes

    def generate_random_key(self):
        self.encryptor.cipher = self.cipher_combobox.currentData()
        #print(self.encryptor.cipher, "check")
        if self.encryptor.cipher == DES:
            self.encryptor.key = get_random_bytes(8)
            self.key_entry.clear()
            self.key_entry.insert("Generated Random Key for DES")
        elif self.encryptor.cipher == AES:
            self.encryptor.key = get_random_bytes(32)
            self.key_entry.clear()
            self.key_entry.insert("Generated Random Key for AES")
        else:
            self.key_entry.clear()
            show_alert("No cipher selected. Select a cipher first.")
            self.key_entry.insert("No cipher selected")



    def save_key_to_file(self):

        file_path, _ = QFileDialog.getSaveFileName(filter="Text files (*.txt)")


        if file_path:
            try:
                with open(file_path, "wb") as key_file:
                    key_file.write(self.encryptor.key)
                self.key_entry.clear()
                self.key_entry.insert( "Key was written to file")
            except Exception as e:
                print(f"Error saving key to file: {str(e)}")
        else:
            print("No file selected for saving the key.")

    def read_key_from_file(self):

        file_path, _ = QFileDialog.getOpenFileName(filter="Text files (*.txt)")
        if file_path:
            try:
                with open(file_path, "rb") as key_file:
                    self.encryptor.key = key_file.read()
                    self.key_entry.clear()
                    self.key_entry.insert("Key was read from file")
            except FileNotFoundError:
                self.key_entry.clear()
                self.key_entry.insert( "File Not Found")

    def encrypt_button_click(self):

        self.encryptor.cipher = self.cipher_combobox.currentData()
        self.encryptor.mode = self.mode_combobox.currentData()
        print(self.encryptor.cipher,self.encryptor.mode)
        if self.encryptor.cipher is None or self.encryptor.mode is None:
            show_alert("Cipher and mode must be selected.")
            return

        self.encryptor.mode = self.mode_combobox.currentData()
        self.encryptor.cipher=self.cipher_combobox.currentData()
        print(self.encryptor.mode)
        print(self.encryptor.cipher)
        # Ensure the RSA public key is read if RSA encryption is selected
        if self.encryptor.use_rsa_encryption and self.encryptor.rsa_public_key is None:
            show_alert("RSA encryption of symmetric key is  selected but public key not read. Please read the public key first.")
            return
        print(self.encryptor.use_rsa_encryption, "use rsa encryption" )
        if not self.encryptor.use_rsa_encryption and self.encryptor.key is None:
            show_alert("Key is not set. Please set the key first.")
            return

        file_filter = "Image Files (*.png *.jpg *.jpeg *.bmp);"
        file_path, _ = QFileDialog.getOpenFileName(None, "Select Image", "", file_filter)
        #print(file_path)
        if not file_path:
            return
        #print(file_path, "file path")
        try:
            imageOrig = ImageEncryptor.load_image(file_path)
            ImageEncryptor.display_image(imageOrig, "Original image")
        except Exception as e:
            show_alert(f"Error loading image: {str(e)}")
            return None
        #print(imageOrig)


        try:
            encryptedImage = self.encryptor.encrypt(imageOrig)
        except ValueError as e:
            show_alert(f"Encryption failed: {str(e)}")
            return None

        if encryptedImage is None:
            print("Encryption failed. Please check the key and mode.")
        else:
            ImageEncryptor.display_image(encryptedImage, "Encrypted image")
        # Display encrypted image (consider using QLabel to display images in PyQt)
        # display_image(encryptedImage, "Encrypted image")
            encrypted_images_folder_path= "encrypted_images"
            if not os.path.exists(encrypted_images_folder_path):
                os.makedirs(encrypted_images_folder_path)
                print(f"Folder '{encrypted_images_folder_path}' created successfully.")
            encrypted_filename = f'{encrypted_images_folder_path}\\{cipher_names.get(self.encryptor.cipher, "unknown")}_{mode_aes_names.get(self.encryptor.mode, "unknown")}_encrypted_{file_path.split("/")[-1]}.png'
            print(encrypted_filename)
            ImageEncryptor.save_image(encryptedImage, encrypted_filename)


    def decrypt_button_click(self):

        self.encryptor.cipher = self.cipher_combobox.currentData()
        self.encryptor.mode = self.mode_combobox.currentData()

        if self.encryptor.cipher is None or self.encryptor.mode is None:
            show_alert("Cipher and mode must be selected.")
            return

        self.encryptor.cipher = self.cipher_combobox.currentData()
        self.encryptor.mode = self.mode_combobox.currentData()
        print(self.encryptor.use_rsa_encryption, "use rsa encryption")
        if not self.encryptor.use_rsa_encryption and self.encryptor.key is None:
            show_alert("Key is not set. Please set the key first.")
            return

        if self.encryptor.use_rsa_encryption and self.encryptor.rsa_private_key is None:
            show_alert("RSA decryption of symmetric key is  selected but private key not read. Please read the private key first.")
            return
        file_filter = "Image Files (*.png *.jpg *.jpeg *.bmp);"
        file_path, _ = QFileDialog.getOpenFileName(None, "Select Image", "", file_filter)
        if not file_path:
            return

        try:
            encryptedImage = ImageEncryptor.load_image(file_path)
        except ValueError as e:
            show_alert(f"Error loading image: {str(e)}")
            return None

        try:
            decryptedImage = self.encryptor.decrypt(encryptedImage)
        except Exception as e:
            show_alert(f"Decryption failed: {str(e)}")
            return None
        if decryptedImage is None:
            print("Decryption failed. Please check the key and mode.")
        else:
            decrypted_images_folder_path = "decrypted_images"
            if not os.path.exists(decrypted_images_folder_path):
                os.makedirs(decrypted_images_folder_path)
                print(f"Folder '{decrypted_images_folder_path}' created successfully.")
            ImageEncryptor.display_image(decryptedImage,"Decrypted image")
            decrypted_filename = f'{decrypted_images_folder_path}\\{cipher_names.get(self.encryptor.cipher, "unknown")}_{mode_aes_names.get(self.encryptor.mode, "unknown")}_decrypted_{file_path.split("/")[-1]}.png'
            print(decrypted_filename)
            ImageEncryptor.save_image(decryptedImage, decrypted_filename)


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
            self.theme_toggle_button.setIcon(QIcon("image (1).png"))
            self.theme_toggle_button.setStyleSheet("background-color: transparent;")
            self.separator.setStyleSheet("""
                        background-color:#455364;
                        """)


        elif 'dark' == current_stylesheet:

            print(self.styleSheet())
            # Switch to the light theme
            print(self.default_stylesheet)
            self.setStyleSheet(self.default_stylesheet + """
                /* Custom light theme styles */
                background-color: white; /* Set background color to white */
                color: black; /* Set text color to black */
                
            """)
            self.theme_toggle_button.setIcon(QIcon("output-onlinepngtools.png"))


            # Set the style for all QPushButton widgets

            for button in self.findChildren(QPushButton):
                button.setStyleSheet("""
                    background-color: light gray;
                    color: black;
                    border-radius: 4px;
                    padding: 1px;
                    outline: none;
                    border: 1px solid black;
                """)

            self.separator.setStyleSheet("""
            background-color:#455364;
            """)

            self.theme_toggle_button.setStyleSheet("background-color: transparent;")






            # Set your custom light theme stylesheet
            current_stylesheet="white"
            #print(current_stylesheet)





if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    #app.setStyle("Breeze")  # Optional: Use the Fusion style for a more modern look
    window = MyApp()
    window.setWindowTitle("Image Encryption/Decryption")
    window.setGeometry(100,100,800, 600)  # Adjust the window size
    window.show()
    sys.exit(app.exec_())
