import math
import sys
import cv2
from Crypto.Cipher import DES,AES
from Crypto.Random import get_random_bytes
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon,QPixmap
from PyQt5.QtWidgets import QFileDialog, QComboBox, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout,QFrame
from despycryprtodome import encrypt_image,decrypt_image,save_image,load_image,display_image
from bbs_class import BBS_Stream_Cipher
from blum_goldwasser import BGWCryptosystem
from math import gcd
import qdarkstyle
import datetime
global key
global current_stylesheet
current_stylesheet = "dark"

mode_des_names = {
    DES.MODE_CBC: "CBC",
    DES.MODE_ECB: "ECB",
}

mode_aes_names={
    AES.MODE_ECB: "ECB",
    AES.MODE_CBC: "CBC",
    AES.MODE_OFB: "OFB",
    AES.MODE_CFB: "CFB",
    AES.MODE_CTR: "CTR",
    AES.MODE_CCM: "CCM",
    AES.MODE_EAX: "EAX",
    AES.MODE_GCM: "GCM",
    AES.MODE_SIV: "SIV",
    AES.MODE_OCB: "OCB",
    AES.MODE_OPENPGP: "OPENPGP",
}
cipher_names={
    DES: "DES",
    AES: "AES",
    BBS_Stream_Cipher: "BBS Stream Cipher"
}



class MyApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        #self.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
        self.blum_goldwasser = BGWCryptosystem()

        self.theme_toggle_button = QPushButton()
        self.theme_toggle_button.setObjectName("theme_toggle_button")
        self.theme_toggle_button.setIcon(QIcon("image (1).png"))  # Replace with the path to your dark theme image
        self.theme_toggle_button.setIconSize(QtCore.QSize(50, 50))
        self.theme_toggle_button.setFixedSize(50, 50)
        self.theme_toggle_button.setStyleSheet("background-color: transparent;")# Replace with the path to your dark theme image

        self.separator = QFrame()
        self.separator.setFrameShape(QFrame.VLine)
        self.separator.setFrameShadow(QFrame.Sunken)

        self.p_blum_goldwasser_label = QLabel("Enter p:")
        self.p_blum_goldwasser_entry = QLineEdit()
        self.q_blum_goldwasser_label = QLabel("Enter q:")
        self.q_blum_goldwasser_entry = QLineEdit()
        self.n_blum_goldwasser_label = QLabel("Enter n:")
        self.n_blum_goldwasser_entry = QLineEdit()
        self.x0_blum_goldwasser_label = QLabel("Enter seed:")
        self.x0_blum_goldwasser_entry = QLineEdit()
        self.xt_blum_goldwasser_label = QLabel("Enter x_t:")
        self.xt_blum_goldwasser_entry = QLineEdit()
        self.generate_blum_goldwasser_values_button = QPushButton("Generate p, q, seed for Blum-Goldwasser")
        self.read_private_key_button = QPushButton("Read Private Key from File")
        self.read_public_key_button = QPushButton("Read Public Key from File")

        self.p_label = QLabel("Enter p:")
        self.p_entry = QLineEdit()
        self.q_label = QLabel("Enter q:")
        self.q_entry = QLineEdit()
        self.seed_label = QLabel("Enter seed:")
        self.seed_entry = QLineEdit()
        self.generate_bbs_values_button = QPushButton("Generate p, q, seed for BBS")
        self.key_label = QLabel("Enter Key:")
        self.key_entry = QLineEdit()
        self.set_key_button = QPushButton("Set Key")
        self.generate_key_button = QPushButton("Generate Random Key")
        self.save_key_button = QPushButton("Save Key to File")
        self.read_key_button = QPushButton("Read Key from File")

        self.h_label = QLabel("h (block size):")
        self.plaintext_label = QLabel("Enter message bits or encrypted bits:")
        self.plaintext_entry = QLineEdit()
        self.encrypt_blum_goldwasser_button = QPushButton("Encrypt")
        self.decrypt_blum_goldwasser_button = QPushButton("Decrypt")
        self.decrypt_from_file_button = QPushButton("Decrypt from File")
        self.result_label = QLabel("Result:")

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



        # Set alignment and spacing for both layouts
        vbox_left.setAlignment(QtCore.Qt.AlignBottom)
        vbox_right.setAlignment(QtCore.Qt.AlignBottom)
        #vbox_left.setSpacing(10)  # Adjust the spacing as needed
        #vbox_right.setSpacing(10)  # Adjust the spacing as needed

        # Add widgets to left layout
        vbox_left.addWidget(self.p_blum_goldwasser_label)
        vbox_left.addWidget(self.p_blum_goldwasser_entry)
        vbox_left.addWidget(self.q_blum_goldwasser_label)
        vbox_left.addWidget(self.q_blum_goldwasser_entry)
        vbox_left.addWidget(self.n_blum_goldwasser_label)
        vbox_left.addWidget(self.n_blum_goldwasser_entry)
        vbox_left.addWidget(self.x0_blum_goldwasser_label)
        vbox_left.addWidget(self.x0_blum_goldwasser_entry)
        vbox_left.addWidget(self.xt_blum_goldwasser_label)
        vbox_left.addWidget(self.xt_blum_goldwasser_entry)
        vbox_left.addWidget(self.generate_blum_goldwasser_values_button)
        vbox_left.addWidget(self.read_private_key_button)
        vbox_left.addWidget(self.read_public_key_button)
        vbox_left.addWidget(self.p_label)
        vbox_left.addWidget(self.p_entry)
        vbox_left.addWidget(self.q_label)
        vbox_left.addWidget(self.q_entry)
        vbox_left.addWidget(self.seed_label)
        vbox_left.addWidget(self.seed_entry)
        vbox_left.addWidget(self.generate_bbs_values_button)
        vbox_left.addWidget(self.key_label)
        vbox_left.addWidget(self.key_entry)
        vbox_left.addWidget(self.set_key_button)
        vbox_left.addWidget(self.generate_key_button)
        vbox_left.addWidget(self.save_key_button)
        vbox_left.addWidget(self.read_key_button)

        # Add widgets to right layout
        spacer = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        # Add widgets for Blum-Goldwasser cryptosystem




        vbox_right.addWidget(self.theme_toggle_button,alignment=Qt.AlignmentFlag.AlignRight)
        vbox_right.addSpacerItem(spacer)
        vbox_right.addWidget(QLabel("Blum-Goldwasser Cryptosystem"))
        vbox_right.addWidget(self.h_label)
        vbox_right.addWidget(self.plaintext_label)
        vbox_right.addWidget(self.plaintext_entry)
        vbox_right.addWidget(self.encrypt_blum_goldwasser_button)
        vbox_right.addWidget(self.decrypt_blum_goldwasser_button)
        vbox_right.addWidget(self.decrypt_from_file_button)
        vbox_right.addWidget(self.result_label)
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
        #Blum-goldwasser
        self.encrypt_blum_goldwasser_button.clicked.connect(self.encrypt_blum_goldwasser)
        self.decrypt_blum_goldwasser_button.clicked.connect(self.decrypt_blum_goldwasser)
        self.generate_blum_goldwasser_values_button.clicked.connect(self.generate_random_blum_goldwasser_values)
        self.read_private_key_button.clicked.connect(self.read_private_key_from_file)
        self.read_public_key_button.clicked.connect(self.read_public_key_from_file)
        self.n_blum_goldwasser_entry.textChanged.connect(self.update_h_label)
        self.p_blum_goldwasser_entry.textChanged.connect(self.update_n_label)
        self.q_blum_goldwasser_entry.textChanged.connect(self.update_n_label)
        self.decrypt_from_file_button.clicked.connect(self.decrypt_from_file_blum_goldwasser)
        #BBS
        self.generate_bbs_values_button.clicked.connect(self.generate_random_bbs_values)
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


        self.update_mode_combobox()


    def update_h_label(self):
        n_str = self.n_blum_goldwasser_entry.text()
        if n_str:
            try:
                n = int(n_str)
                h_value = round(math.log2(math.log2(n)))
                self.h_label.setText(f"h (block size): {h_value}")
            except ValueError:
                # Handle the case when the input is not a valid integer
                pass

    def update_n_label(self):
        p_str = self.p_blum_goldwasser_entry.text()
        q_str = self.q_blum_goldwasser_entry.text()

        if p_str and q_str:
            try:
                p = int(p_str)
                q = int(q_str)
                n_value = p * q
                self.n_blum_goldwasser_entry.setText(str(n_value))
                self.update_h_label()  # Update the h label as well
            except ValueError:
                # Handle the case when the input is not a valid integer
                pass
    def encrypt_blum_goldwasser(self):
        n_str = self.n_blum_goldwasser_entry.text()
        if n_str =='':
            n_str = int(self.p_blum_goldwasser_entry.text()) * int(self.q_blum_goldwasser_entry.text())
        x0_str = self.x0_blum_goldwasser_entry.text()
        plaintext = self.plaintext_entry.text()
        result_text,xt = self.blum_goldwasser.encrypt(int(n_str),int(x0_str),plaintext)
        self.result_label.setText(f"Encrypted message: {result_text} xt={xt}")

        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"encrypt_result_{timestamp}.txt"
        with open(f"blum-goldwasser_results\\{filename}", "w") as file:
            file.write(f"encrypted={result_text}\nxt={xt}")

    def decrypt_blum_goldwasser(self):
        p_str = int(self.p_blum_goldwasser_entry.text())
        q_str = int(self.q_blum_goldwasser_entry.text())
        xt_str = int(self.xt_blum_goldwasser_entry.text())
        ciphertext = self.plaintext_entry.text()

        result_text = self.blum_goldwasser.decrypt(p_str, q_str, xt_str, ciphertext)
        self.result_label.setText(f"Decrypted message: {result_text}")

    def decrypt_from_file_blum_goldwasser(self):
        encrypted_filename, _ = QFileDialog.getOpenFileName(filter="Text files (*.txt)")
        if encrypted_filename:
            try:
                with open(encrypted_filename, "r") as file:
                    lines = file.readlines()
                    encrypted_text = lines[0].split("=")[1].strip()
                    x_t_value = int(lines[1].split("=")[1].strip())

                    # Update the corresponding QLineEdit widgets
                    self.plaintext_entry.clear()# Clear the previous plaintext entry
                    self.plaintext_entry.setText(encrypted_text)
                    self.xt_blum_goldwasser_entry.setText(str(x_t_value))

                    # Decrypt the message
                    p_value = int(self.p_blum_goldwasser_entry.text())
                    q_value = int(self.q_blum_goldwasser_entry.text())
                    decrypted_text = self.blum_goldwasser.decrypt(p_value, q_value, x_t_value, encrypted_text)

                    # Display the decrypted message
                    self.result_label.setText(f"Decrypted message: {decrypted_text}")

            except Exception as e:
                print(f"Error decrypting from file: {str(e)}")
    def generate_random_bbs_values(self):
        p, q, seed = BBS_Stream_Cipher.find_prime_congruent_number_x0()
        self.p_entry.setText(str(p))
        self.q_entry.setText(str(q))
        self.seed_entry.setText(str(seed))

    def generate_random_blum_goldwasser_values(self):
        p, q, seed = BGWCryptosystem.find_prime_congruent_number_x0()
        n=p*q
        h_value = round(math.log2(math.log2(n)))
        # Save p and q to a file with the current timestamp
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        filenameprivate = f"privatekey_{timestamp}.txt"
        with open(f"blum-goldwasser_keys\\{filenameprivate}", "w") as file:
            file.write(f"p={p}\nq={q}")
        filenamepublic = f"publickey_{timestamp}.txt"
        with open(f"blum-goldwasser_keys\\{filenamepublic}", "w") as file:
            file.write(f"n={n}")
        self.p_blum_goldwasser_entry.setText(str(p))
        self.q_blum_goldwasser_entry.setText(str(q))
        self.x0_blum_goldwasser_entry.setText(str(seed))
        self.n_blum_goldwasser_entry.setText(str(n))
        self.h_label.setText(f"h (block size): {h_value}")

    def update_mode_combobox(self):
        selected_cipher = self.cipher_combobox.currentData()
        print(selected_cipher)# Get the selected cipher value
        print(DES)
        # Clear the mode combobox
        self.mode_combobox.clear()

        # Add "None" option to the mode combobox
        self.mode_combobox.addItem("None", None)

        if selected_cipher == DES:
            # Add DES modes if DES is selected
            for mode_val, mode_name in mode_des_names.items():
                self.mode_combobox.addItem(mode_name, mode_val)

        elif selected_cipher == AES:
            for mode_val, mode_name in mode_aes_names.items():
                self.mode_combobox.addItem(mode_name, mode_val)

    def set_mode(self, index):
        mode_var = self.mode_combobox.itemData(index)

        selected_cipher = self.cipher_combobox.currentData()
        if selected_cipher == DES:
            mode_name = mode_des_names.get(mode_var)
        elif selected_cipher == AES:
            mode_name = mode_aes_names.get(mode_var)
        else:
            mode_name = None

        self.mode_label.setText(f"Selected Mode: {mode_name if mode_name else 'None'}")
    def set_cipher(self, index):
        cipher_var = self.cipher_combobox.itemData(index)
        self.cipher_label.setText(f"Selected Cipher: {cipher_names.get(cipher_var)}")

    def read_private_key_from_file(self):
        file_path, _ = QFileDialog.getOpenFileName(filter="Text files (*.txt)")
        if file_path:
            try:
                with open(file_path, "r") as file:
                    lines = file.readlines()
                    p_value = int(lines[0].split("=")[1])
                    q_value = int(lines[1].split("=")[1])

                    # Update the corresponding QLineEdit widgets
                    self.p_blum_goldwasser_entry.setText(str(p_value))
                    self.q_blum_goldwasser_entry.setText(str(q_value))

                    # Calculate and set the value of n
                    n_value = p_value * q_value
                    self.n_blum_goldwasser_entry.setText(str(n_value))

                    # Update the h label
                    self.update_h_label()
            except Exception as e:
                print(f"Error reading private key: {str(e)}")

    def read_public_key_from_file(self):
        file_path, _ = QFileDialog.getOpenFileName(filter="Text files (*.txt)")
        if file_path:
            try:
                with open(file_path, "r") as file:
                    lines = file.readlines()
                    n_value = int(lines[0].split("=")[1])

                    # Update the corresponding QLineEdit widget
                    self.n_blum_goldwasser_entry.setText(str(n_value))

                    # Update the h label
                    self.update_h_label()
            except Exception as e:
                print(f"Error reading public key: {str(e)}")
    def set_key(self):
        global key

        key_str = self.key_entry.text()
        selected_cipher = self.cipher_combobox.currentData()

        if selected_cipher == DES:
            if len(key_str) != 8:
                self.key_entry.clear()
                self.key_entry.insert("Key must be 8 bytes")
        elif selected_cipher == AES:
            if len(key_str) != 16:
                self.key_entry.clear()
                self.key_entry.insert("Key must be 16 bytes")
        else:
            self.key_entry.clear()
            self.key_entry.insert("No cipher selected")

        key_bytes = key_str.encode('utf-8')
        key = key_bytes

    def generate_random_key(self):
        global key
        selected_cipher = self.cipher_combobox.currentData()
        print(selected_cipher, "check")
        if selected_cipher == DES:
            key = get_random_bytes(8)
            self.key_entry.clear()
            self.key_entry.insert("Generated Random Key for DES")
        elif selected_cipher == AES:
            key = get_random_bytes(16)
            self.key_entry.clear()
            self.key_entry.insert("Generated Random Key for AES")
        else:
            self.key_entry.clear()
            self.key_entry.insert("No cipher selected")



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
                    self.key_entry.insert("Key was read from file")
            except FileNotFoundError:
                self.key_entry.clear()
                self.key_entry.insert( "File Not Found")

    def encrypt_button_click(self,index):
        selected_cipher = self.cipher_combobox.currentData()
        mode = self.mode_combobox.currentData()

        if selected_cipher is None:
            print("Cipher and mode must be selected.")
            return




        if selected_cipher == BBS_Stream_Cipher:
            #p, q, seed = BBS_Stream_Cipher.find_prime_congruent_number_x0()
            file_path, _ = QFileDialog.getOpenFileName()
            print(file_path)
            if not file_path:
                return
            print(file_path, "file path")
            imageOrig = load_image(file_path)
            print(imageOrig)
            display_image(imageOrig, "Original image")

            p_str = self.p_entry.text()
            q_str = self.q_entry.text()
            seed_str = self.seed_entry.text()

            try:
                p = int(p_str)
                q = int(q_str)
                seed = int(seed_str)
                if gcd(seed, p*q) != 1:
                    print("seed and p*q are not coprime")
                    return

            except ValueError:
                print("Invalid input for p, q, or seed. Please enter valid integers.")
                return
            print(p,q,seed)
            cipher = BBS_Stream_Cipher(p, q, seed)
            keystream = cipher.blum_blum_shub_generator(imageOrig.nbytes * 8)

            encryptedImage = cipher.encrypt_image(imageOrig, keystream,istext=False)
            display_image(encryptedImage, "Encrypted image")
            encrypted_filename = f'{cipher_names.get(selected_cipher, "unknown")}_encrypted_{file_path.split("/")[-1]}.bmp'
            save_image(encryptedImage, encrypted_filename)
        else:
            mode = self.mode_combobox.currentData()
            selected_cipher=self.cipher_combobox.currentData()
            print(mode)
            print(selected_cipher)
            """if mode != DES.MODE_CBC and mode != DES.MODE_ECB:
                print('Only CBC and ECB mode supported...')
                sys.exit()"""

            file_path, _ = QFileDialog.getOpenFileName()
            print(file_path)
            if not file_path:
                return
            print(file_path, "file path")
            imageOrig = load_image(file_path)
            print(imageOrig)
            display_image(imageOrig, "Original image")


            encryptedImage = encrypt_image(imageOrig, key, mode,selected_cipher)

            # Display encrypted image (consider using QLabel to display images in PyQt)
            # display_image(encryptedImage, "Encrypted image")
            display_image(encryptedImage,"Encrypted image")
            encrypted_filename = f'{cipher_names.get(selected_cipher, "unknown")}_{mode_des_names.get(mode, "unknown")}_encrypted_{file_path.split("/")[-1]}.bmp'
            print(encrypted_filename)
            save_image(encryptedImage, encrypted_filename)


    def decrypt_button_click(self):

        selected_cipher = self.cipher_combobox.currentData()
        mode = self.mode_combobox.currentData()

        if selected_cipher is None:
            print("Cipher and mode must be selected.")
            return



        if selected_cipher == BBS_Stream_Cipher:

            #p, q, seed = BBS_Stream_Cipher.find_prime_congruent_number_x0()

            p_str = self.p_entry.text()
            q_str = self.q_entry.text()
            seed_str = self.seed_entry.text()

            try:
                p = int(p_str)
                q = int(q_str)
                seed = int(seed_str)
            except ValueError:
                print("Invalid input for p, q, or seed. Please enter valid integers.")
                return
            print(p,q,seed)
            file_path, _ = QFileDialog.getOpenFileName()
            if not file_path:
                return
            cipher = BBS_Stream_Cipher(p, q, seed)
            keystream = cipher.blum_blum_shub_generator(len(load_image(file_path).tobytes()) * 8)

            encryptedImage = load_image(file_path)
            decryptedImage = cipher.decrypt_image(encryptedImage, keystream,istext=False)
            display_image(decryptedImage, "Decrypted image")
        else:
            selected_cipher = self.cipher_combobox.currentData()
            mode = self.mode_combobox.currentData()
            """if mode != DES.MODE_CBC and mode != DES.MODE_ECB:
                print('Only CBC and ECB mode supported...')
                sys.exit()"""

            file_path, _ = QFileDialog.getOpenFileName()
            if not file_path:
                return

            encryptedImage = load_image(file_path)

            decryptedImage = decrypt_image(encryptedImage, key, mode,selected_cipher)
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
    window.setGeometry(100,100,800, 600)  # Adjust the window size
    window.show()
    sys.exit(app.exec_())
