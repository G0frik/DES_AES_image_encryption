import os
import sys
import tempfile
import traceback

import cv2
import numpy as np
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from PySide6 import QtWidgets, QtCore  #
from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QFileDialog, QComboBox, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QFrame, QApplication, QMessageBox, QCheckBox,
    QWidget, QButtonGroup, QDialog, QDialogButtonBox, QGroupBox, QFormLayout
)
import datetime
from ImageEncryptor import ImageEncryptor
import qdarktheme
import json,copy




current_theme_mode = "dark"


mode_des_names = {DES.MODE_CBC: "CBC", DES.MODE_ECB: "ECB"}
mode_aes_names = {AES.MODE_ECB: "ECB", AES.MODE_CBC: "CBC", AES.MODE_CTR: "CTR", AES.MODE_GCM: "GCM"}
cipher_names = {DES: "DES", AES: "AES"}




def load_stylesheet(file_path="styles.qss"):
    try:
        with open(file_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Warning: Stylesheet file not found at {os.path.abspath(file_path)}")
        return ""
    except Exception as e:
        print(f"Error loading stylesheet: {e}")
        return ""


def show_alert(message):
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Icon.Critical)
    msg.setText(message)
    msg.setWindowTitle("Error")
    msg.exec()


class SettingsDialog(QDialog):
    def __init__(self, parent=None, current_settings=None):
        super().__init__(parent)
        self.setWindowTitle("Application Settings")
        self.setMinimumWidth(500)
        self.current_settings = current_settings if current_settings else self._get_default_settings_structure()

        # Main layout for the dialog
        main_layout = QVBoxLayout(self)

        # Educational Mode Settings
        edu_groupbox = QGroupBox("Educational Mode Defaults")
        edu_layout = QFormLayout(edu_groupbox)

        self.edu_public_key_path_edit = QLineEdit()
        self.edu_browse_public_btn = QPushButton("Browse...")
        edu_public_key_layout = QHBoxLayout()
        edu_public_key_layout.addWidget(self.edu_public_key_path_edit)
        edu_public_key_layout.addWidget(self.edu_browse_public_btn)
        edu_layout.addRow("Default Public Key:", edu_public_key_layout)

        self.edu_private_key_path_edit = QLineEdit()
        self.edu_browse_private_btn = QPushButton("Browse...")
        edu_private_key_layout = QHBoxLayout()
        edu_private_key_layout.addWidget(self.edu_private_key_path_edit)
        edu_private_key_layout.addWidget(self.edu_browse_private_btn)
        edu_layout.addRow("Default Private Key:", edu_private_key_layout)

        self.edu_cipher_combo = QComboBox()
        self.edu_cipher_combo.addItem("None", None)
        for val, name in cipher_names.items():
            self.edu_cipher_combo.addItem(name, val)
        edu_layout.addRow("Default Cipher:", self.edu_cipher_combo)

        self.edu_mode_combo = QComboBox()  # Cryptographic mode
        edu_layout.addRow("Default Crypto Mode:", self.edu_mode_combo)

        self.edu_use_rsa_checkbox = QCheckBox("Use RSA by default")
        edu_layout.addRow(self.edu_use_rsa_checkbox)

        self.edu_use_lsb_checkbox = QCheckBox("Use LSB by default (requires RSA)")
        edu_layout.addRow(self.edu_use_lsb_checkbox)
        main_layout.addWidget(edu_groupbox)

        # Fully-Secure Mode Settings
        sec_groupbox = QGroupBox("Fully-Secure Mode Defaults")
        sec_layout = QFormLayout(sec_groupbox)

        self.sec_public_key_path_edit = QLineEdit()
        self.sec_browse_public_btn = QPushButton("Browse...")
        sec_public_key_layout = QHBoxLayout()
        sec_public_key_layout.addWidget(self.sec_public_key_path_edit)
        sec_public_key_layout.addWidget(self.sec_browse_public_btn)
        sec_layout.addRow("Default Public Key:", sec_public_key_layout)

        self.sec_private_key_path_edit = QLineEdit()
        self.sec_browse_private_btn = QPushButton("Browse...")
        sec_private_key_layout = QHBoxLayout()
        sec_private_key_layout.addWidget(self.sec_private_key_path_edit)
        sec_private_key_layout.addWidget(self.sec_browse_private_btn)
        sec_layout.addRow("Default Private Key:", sec_private_key_layout)

        self.sec_cipher_combo = QComboBox()
        # In secure mode, only AES
        self.sec_cipher_combo.addItem(cipher_names[AES], AES)  # Default to AES
        sec_layout.addRow("Default Cipher:", self.sec_cipher_combo)

        self.sec_mode_combo = QComboBox()  # Cryptographic mode
        sec_layout.addRow("Default Crypto Mode:", self.sec_mode_combo)

        self.sec_use_rsa_checkbox = QCheckBox("Use RSA by default")
        sec_layout.addRow(self.sec_use_rsa_checkbox)

        self.sec_use_lsb_checkbox = QCheckBox("Use LSB by default (requires RSA)")
        sec_layout.addRow(self.sec_use_lsb_checkbox)
        main_layout.addWidget(sec_groupbox)

        # Dialog Buttons (OK, Cancel)
        self.button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        main_layout.addWidget(self.button_box)

        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)

        # Connect signals for dynamic updates within the dialog
        self.edu_cipher_combo.currentIndexChanged.connect(
            lambda: self._update_crypto_modes(self.edu_cipher_combo, self.edu_mode_combo, "educational"))
        self.sec_cipher_combo.currentIndexChanged.connect(
            lambda: self._update_crypto_modes(self.sec_cipher_combo, self.sec_mode_combo, "fully_secure"))

        self.edu_use_rsa_checkbox.stateChanged.connect(
            lambda state: self.edu_use_lsb_checkbox.setEnabled(state == Qt.CheckState.Checked.value))
        self.sec_use_rsa_checkbox.stateChanged.connect(
            lambda state: self.sec_use_lsb_checkbox.setEnabled(state == Qt.CheckState.Checked.value))

        # Connect browse buttons
        self.edu_browse_public_btn.clicked.connect(
            lambda: self._browse_file(self.edu_public_key_path_edit, "Select Default Public Key"))
        self.edu_browse_private_btn.clicked.connect(
            lambda: self._browse_file(self.edu_private_key_path_edit, "Select Default Private Key"))
        self.sec_browse_public_btn.clicked.connect(
            lambda: self._browse_file(self.sec_public_key_path_edit, "Select Default Public Key"))
        self.sec_browse_private_btn.clicked.connect(
            lambda: self._browse_file(self.sec_private_key_path_edit, "Select Default Private Key"))

        self.load_settings()  # Populate dialog with current settings

        # Initialize crypto mode comboboxes
        self._update_crypto_modes(self.edu_cipher_combo, self.edu_mode_combo, "educational")
        self._update_crypto_modes(self.sec_cipher_combo, self.sec_mode_combo, "fully_secure")
        self.restore_crypto_mode_selections()  # Restore after population

    def _get_default_settings_structure(self):
        # Helper to ensure current_settings has the right keys if passed as None
        return {
            "educational": {"public_key_path": "", "private_key_path": "", "cipher": None, "crypto_mode": None,
                            "use_rsa": False, "use_lsb": False},
            "fully_secure": {"public_key_path": "", "private_key_path": "", "cipher": AES, "crypto_mode": AES.MODE_GCM,
                             "use_rsa": True, "use_lsb": False}
        }

    def _browse_file(self, line_edit_widget, dialog_title="Select File"):
        file_path, _ = QFileDialog.getOpenFileName(self, dialog_title, "", "PEM files (*.pem);;All Files (*)")
        if file_path:
            line_edit_widget.setText(file_path)

    def _update_crypto_modes(self, cipher_combo, mode_combo, app_mode_type):
        mode_combo.blockSignals(True)
        mode_combo.clear()
        mode_combo.addItem("None", None)

        selected_cipher_val = cipher_combo.currentData()

        allowed_modes_to_add = {}
        if selected_cipher_val == DES:  # DES only for educational
            if app_mode_type == "educational":
                allowed_modes_to_add = mode_des_names.copy()
        elif selected_cipher_val == AES:
            if app_mode_type == "fully_secure":  # Fully-secure specific AES modes
                if AES.MODE_GCM in mode_aes_names: allowed_modes_to_add[AES.MODE_GCM] = mode_aes_names[AES.MODE_GCM]
                if AES.MODE_CTR in mode_aes_names: allowed_modes_to_add[AES.MODE_CTR] = mode_aes_names[AES.MODE_CTR]
            else:  # Educational AES modes
                allowed_modes_to_add = mode_aes_names.copy()

        for mode_val, mode_name_str in allowed_modes_to_add.items():
            mode_combo.addItem(mode_name_str, mode_val)
        mode_combo.blockSignals(False)

    # Inside SettingsDialog.load_settings(self):
    def load_settings(self):
        # Educational
        edu_cfg = self.current_settings.get("educational", self._get_default_settings_structure()["educational"])
        self.edu_public_key_path_edit.setText(edu_cfg.get("public_key_path", ""))
        self.edu_private_key_path_edit.setText(edu_cfg.get("private_key_path", ""))

        loaded_edu_cipher = edu_cfg.get("cipher")
        if loaded_edu_cipher is not None:
            idx = self.edu_cipher_combo.findData(loaded_edu_cipher)
            if idx != -1:
                self.edu_cipher_combo.setCurrentIndex(idx)
            else:
                self.edu_cipher_combo.setCurrentIndex(0)  # Default to "None" if not found
        else:
            self.edu_cipher_combo.setCurrentIndex(0)  # Default to "None"

        # Call _update_crypto_modes before trying to set crypto_mode index
        self._update_crypto_modes(self.edu_cipher_combo, self.edu_mode_combo, "educational")
        loaded_edu_crypto_mode = edu_cfg.get("crypto_mode")
        if loaded_edu_crypto_mode is not None:
            idx = self.edu_mode_combo.findData(loaded_edu_crypto_mode)
            if idx != -1:
                self.edu_mode_combo.setCurrentIndex(idx)
            elif self.edu_mode_combo.count() > 0:
                self.edu_mode_combo.setCurrentIndex(0)  # Default to its "None"
        elif self.edu_mode_combo.count() > 0:
            self.edu_mode_combo.setCurrentIndex(0)

        self.edu_use_rsa_checkbox.setChecked(edu_cfg.get("use_rsa", False))
        self.edu_use_lsb_checkbox.setChecked(
            edu_cfg.get("use_lsb", False) and self.edu_use_rsa_checkbox.isChecked())  # LSB depends on RSA
        self.edu_use_lsb_checkbox.setEnabled(self.edu_use_rsa_checkbox.isChecked())

        # Fully-Secure (similar logic for loading and defaulting)
        sec_cfg = self.current_settings.get("fully_secure", self._get_default_settings_structure()["fully_secure"])
        self.sec_public_key_path_edit.setText(sec_cfg.get("public_key_path", ""))
        self.sec_private_key_path_edit.setText(sec_cfg.get("private_key_path", ""))

        loaded_sec_cipher = sec_cfg.get("cipher", AES)  # Default to AES if not found
        idx_sec_cipher = self.sec_cipher_combo.findData(loaded_sec_cipher)
        if idx_sec_cipher != -1:
            self.sec_cipher_combo.setCurrentIndex(idx_sec_cipher)
        else:  # Should not happen if AES is always in this combo
            if self.sec_cipher_combo.count() > 0: self.sec_cipher_combo.setCurrentIndex(0)

        self._update_crypto_modes(self.sec_cipher_combo, self.sec_mode_combo, "fully_secure")
        loaded_sec_crypto_mode = sec_cfg.get("crypto_mode", AES.MODE_GCM)  # Default to GCM
        idx_sec_mode = self.sec_mode_combo.findData(loaded_sec_crypto_mode)
        if idx_sec_mode != -1:
            self.sec_mode_combo.setCurrentIndex(idx_sec_mode)
        elif self.sec_mode_combo.count() > 0:
            self.sec_mode_combo.setCurrentIndex(0)

        self.sec_use_rsa_checkbox.setChecked(sec_cfg.get("use_rsa", True))
        self.sec_use_lsb_checkbox.setChecked(
            sec_cfg.get("use_lsb", False) and self.sec_use_rsa_checkbox.isChecked())
        self.sec_use_lsb_checkbox.setEnabled(self.sec_use_rsa_checkbox.isChecked())

    def restore_crypto_mode_selections(self):
        # Call this *after* _update_crypto_modes has run for both sections based on loaded cipher
        edu_cfg = self.current_settings.get("educational", {})
        if edu_cfg.get("crypto_mode") is not None:
            idx = self.edu_mode_combo.findData(edu_cfg.get("crypto_mode"))
            if idx != -1: self.edu_mode_combo.setCurrentIndex(idx)

        sec_cfg = self.current_settings.get("fully_secure", {})
        if sec_cfg.get("crypto_mode") is not None:
            idx = self.sec_mode_combo.findData(sec_cfg.get("crypto_mode"))
            if idx != -1: self.sec_mode_combo.setCurrentIndex(idx)
        elif self.sec_cipher_combo.currentData() == AES:
            idx = self.sec_mode_combo.findData(AES.MODE_GCM)
            if idx != -1: self.sec_mode_combo.setCurrentIndex(idx)

    def get_settings(self):
        settings = {
            "educational": {
                "public_key_path": self.edu_public_key_path_edit.text(),
                "private_key_path": self.edu_private_key_path_edit.text(),
                "cipher": self.edu_cipher_combo.currentData(),
                "crypto_mode": self.edu_mode_combo.currentData(),
                "use_rsa": self.edu_use_rsa_checkbox.isChecked(),
                "use_lsb": self.edu_use_lsb_checkbox.isChecked() and self.edu_use_rsa_checkbox.isChecked(),
            },
            "fully_secure": {
                "public_key_path": self.sec_public_key_path_edit.text(),
                "private_key_path": self.sec_private_key_path_edit.text(),
                "cipher": self.sec_cipher_combo.currentData(),  # Should be AES
                "crypto_mode": self.sec_mode_combo.currentData(),
                "use_rsa": self.sec_use_rsa_checkbox.isChecked(),
                "use_lsb": self.sec_use_lsb_checkbox.isChecked() and self.sec_use_rsa_checkbox.isChecked(),
            }
        }
        return settings
class MyApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.settings_file = "app_settings.json"

        self.cipher_to_name = {DES: "DES", AES: "AES"}
        self.name_to_cipher = {v: k for k, v in self.cipher_to_name.items()}

        self.mode_to_name_map = {  # Helper map for all modes
            DES: {v: k for k, v in mode_des_names.items()},
            AES: {v: k for k, v in mode_aes_names.items()}
        }

        self.name_to_mode_map = {
            DES: {name: val for val, name in mode_des_names.items()},
            AES: {name: val for val, name in mode_aes_names.items()}
        }

        self.all_cipher_items = list(cipher_names.items())  # Used by SettingsDialog if passed
        self.all_cipher_items_for_combobox = [(name, val) for val, name in self.all_cipher_items]

        self.default_settings = {
            "educational": {
                "public_key_path": "", "private_key_path": "",
                "cipher": None, "crypto_mode": None,
                "use_rsa": False, "use_lsb": False
            },
            "fully_secure": {
                "public_key_path": "", "private_key_path": "",
                "cipher": AES, "crypto_mode": AES.MODE_GCM,
                "use_rsa": True, "use_lsb": False
            }
        }
        self._load_app_settings_from_file()
        self.all_cipher_items = list(cipher_names.items())
        self.all_cipher_items_for_combobox = [(name, val) for val, name in self.all_cipher_items]
        self.encryptor = ImageEncryptor()
        self.use_rsa_encryption = False
        self.rsa_public_key = None
        self.rsa_private_key = None
        self.current_app_mode = "Educational Mode"


        # Main structural widgets
        self.header_widget = QWidget()
        self.header_widget.setObjectName("appHeader")

        self.sidebar_container_widget = QWidget()
        self.sidebar_container_widget.setObjectName("sidebarContainer")

        self.right_panel_widget = QWidget()  # New container for header + main_content

        self.main_content_area_widget = QWidget()
        self.main_content_area_widget.setObjectName("mainContentArea")

        # Header content
        self.mode_display_label = QLabel(f"Current Mode: {self.current_app_mode.replace(' Mode', '')}")
        self.mode_display_label.setObjectName("modeDisplayLabel")

        self.theme_toggle_button = QPushButton()
        self.theme_toggle_button.setObjectName("theme_toggle_button")
        # Icon will be set by apply_theme_and_styles
        self.theme_toggle_button.setIconSize(QtCore.QSize(32, 32))
        self.theme_toggle_button.setFixedSize(40, 40)

        # Sidebar content
        self.hamburger_button = QPushButton("☰")
        self.hamburger_button.setObjectName("hamburgerButton")
        self.hamburger_button.setFixedSize(40, 40)

        self.mode_selection_panel = QWidget()
        self.mode_selection_panel.setObjectName("modeSelectionPanel")
        # ... (mode_buttons_layout, educational_mode_button, fully_secure_mode_button, mode_button_group setup) ...
        self.mode_buttons_layout = QVBoxLayout(self.mode_selection_panel)
        self.mode_buttons_layout.setContentsMargins(10, 10, 10, 10)
        self.mode_buttons_layout.setSpacing(8)
        self.educational_mode_button = QPushButton("Educational Mode")
        self.educational_mode_button.setCheckable(True)
        self.educational_mode_button.setObjectName("modeOptionButton")
        self.educational_mode_button.setIconSize(QtCore.QSize(20, 20))
        self.fully_secure_mode_button = QPushButton("Fully-Secure Mode")
        self.fully_secure_mode_button.setCheckable(True)
        self.fully_secure_mode_button.setObjectName("modeOptionButton")
        self.fully_secure_mode_button.setIconSize(QtCore.QSize(20, 20))
        self.settings_button = QPushButton("Settings")
        self.settings_button.setObjectName("modeOptionButton")
        self.settings_button.setIcon(QIcon("icons/settings_icon.png"))
        self.settings_button.setIconSize(QtCore.QSize(20, 20))

        self.mode_button_group = QButtonGroup(self)
        self.mode_button_group.addButton(self.educational_mode_button)
        self.mode_button_group.addButton(self.fully_secure_mode_button)
        self.mode_button_group.setExclusive(True)
        self.mode_buttons_layout.addWidget(self.educational_mode_button)
        self.mode_buttons_layout.addWidget(self.fully_secure_mode_button)
        self.mode_buttons_layout.addWidget(self.settings_button)
        self.mode_buttons_layout.addStretch()
        self.mode_selection_panel.setVisible(True)
        self.educational_mode_button.setChecked(True)


        self.is_sidebar_expanded = True  # Sidebar starts expanded



        self.sidebar_full_width = 220

        self.sidebar_collapsed_width = 50


        self.sidebar_container_animation = QPropertyAnimation(self.sidebar_container_widget, b"maximumWidth")
        self.sidebar_container_animation.setDuration(250)
        self.sidebar_container_animation.setEasingCurve(QEasingCurve.InOutCubic)
        self.sidebar_container_animation.finished.connect(self._on_sidebar_container_animation_finished)

        # Main content widgets
        self.main_content_separator = QFrame()
        self.main_content_separator.setObjectName("mainContentSeparator")
        self.main_content_separator.setFrameShape(QFrame.Shape.VLine)
        self.main_content_separator.setFrameShadow(QFrame.Shadow.Sunken)

        #  RSA Widgets
        self.rsa_checkbox = QCheckBox("Use RSA to Encrypt/Decrypt symmetric key")
        self.lsb_checkbox = QCheckBox("Use LSB Steganography (hide in/extract from image; RSA REQUIRED)")


        # Create a container for RSA-specific options
        self.rsa_options_container = QWidget()
        self.rsa_options_container.setObjectName("rsaOptionsContainer") # Optional for styling

        self.rsa_key_status_label = QLabel("RSA key status:")
        self.rsa_key_status_entry = QLineEdit()
        self.generate_rsa_keys_button = QPushButton("Generate RSA pair of keys and save to files")
        self.read_private_key_button = QPushButton("Read Private Key from File")
        self.read_public_key_button = QPushButton("Read Public Key from File")

        # RSA Options Animation attributes
        self.is_rsa_options_expanded = False  # Start collapsed
        self.rsa_options_target_height = 0  # To be captured
        self.rsa_options_animation = QPropertyAnimation(self.rsa_options_container, b"maximumHeight")
        self.rsa_options_animation.setDuration(200)  # Animation duration
        self.rsa_options_animation.setEasingCurve(QEasingCurve.InOutQuad)
        self.rsa_options_animation.finished.connect(self._on_rsa_options_animation_finished)

        # Set initial collapsed state for RSA options container
        self.rsa_options_container.setMaximumHeight(0)
        self.rsa_options_container.setVisible(False)

        self.key_label = QLabel("Enter Key:")
        self.key_entry = QLineEdit()
        self.set_key_button = QPushButton("Set Key")
        self.generate_key_button = QPushButton("Generate Random Key")
        self.save_key_button = QPushButton("Save Key to File")
        self.read_key_button = QPushButton("Read Key from File")
        self.cipher_label = QLabel("Selected Cipher: None")
        self.cipher_combobox = QComboBox()
        self.cipher_combobox.setFixedHeight(30)
        self.cipher_combobox.addItem("None", None)
        for cipher_value, cipher_name in cipher_names.items():
            self.cipher_combobox.addItem(cipher_name, cipher_value)
        self.mode_label = QLabel("Selected Mode: None")  # Cryptographic mode
        self.mode_combobox = QComboBox()
        self.mode_combobox.setFixedHeight(30)
        self.mode_combobox.addItem("None", None)
        self.encrypt_button = QPushButton("Encrypt Image / Video")
        self.decrypt_button = QPushButton("Decrypt Image")
        # Set initial dependent states

        self.init_ui()
        self.apply_theme_and_styles(initial_setup=True)
        self._apply_defaults_to_ui()

    def init_ui(self):
        #  Overall Horizontal Layout for the Window (Sidebar | RightPanel)
        overall_h_layout = QHBoxLayout(self)
        overall_h_layout.setContentsMargins(0, 0, 0, 0)
        overall_h_layout.setSpacing(0)

        # Sidebar Area
        sidebar_main_layout = QVBoxLayout(self.sidebar_container_widget)
        sidebar_main_layout.setContentsMargins(8, 8, 8, 8)
        sidebar_main_layout.setSpacing(10)
        sidebar_main_layout.addWidget(self.hamburger_button, alignment=Qt.AlignmentFlag.AlignLeft)
        sidebar_main_layout.addWidget(self.mode_selection_panel)



        sidebar_main_layout.addStretch(1)


        self.sidebar_container_widget.setMinimumWidth(self.sidebar_collapsed_width)
        if self.is_sidebar_expanded:
            self.sidebar_container_widget.setMaximumWidth(self.sidebar_full_width)
            self.mode_selection_panel.setVisible(True)
        else:
            self.sidebar_container_widget.setMaximumWidth(self.sidebar_collapsed_width)
            self.mode_selection_panel.setVisible(False)

        overall_h_layout.addWidget(self.sidebar_container_widget)

        overall_h_layout.addWidget(self.sidebar_container_widget)

        # Right Panel (Header + Main Content Area)
        right_panel_v_layout = QVBoxLayout(self.right_panel_widget)
        right_panel_v_layout.setContentsMargins(0, 0, 0, 0)
        right_panel_v_layout.setSpacing(0)

        # Header Widget
        header_internal_h_layout = QHBoxLayout(self.header_widget)
        header_internal_h_layout.setContentsMargins(10, 8, 10, 8)
        header_internal_h_layout.setSpacing(10)
        header_internal_h_layout.addWidget(self.mode_display_label)
        header_internal_h_layout.addStretch(1)
        header_internal_h_layout.addWidget(self.theme_toggle_button)

        right_panel_v_layout.addWidget(self.header_widget)

        # Main Content Area Widget
        main_content_internal_h_layout = QHBoxLayout(self.main_content_area_widget)
        main_content_internal_h_layout.setContentsMargins(15, 15, 15, 15)
        main_content_internal_h_layout.setSpacing(10)

        vbox_left = QVBoxLayout()
        vbox_left.addStretch(1)  # Push content to bottom

        # Symmetric Key Section
        vbox_left.addWidget(self.key_label)
        vbox_left.addWidget(self.key_entry)
        vbox_left.addWidget(self.set_key_button)
        vbox_left.addWidget(self.generate_key_button)
        vbox_left.addWidget(self.save_key_button)
        vbox_left.addWidget(self.read_key_button)
        vbox_left.addSpacing(20)

        # RSA Control Section
        vbox_left.addWidget(self.rsa_checkbox)

        # Layout for the RSA options container
        rsa_options_layout = QVBoxLayout(self.rsa_options_container)
        rsa_options_layout.setContentsMargins(0, 5, 0, 0)
        rsa_options_layout.setSpacing(5)
        rsa_options_layout.addWidget(self.rsa_key_status_label)
        rsa_options_layout.addWidget(self.rsa_key_status_entry)
        rsa_options_layout.addWidget(self.generate_rsa_keys_button)
        rsa_options_layout.addWidget(self.read_private_key_button)
        rsa_options_layout.addWidget(self.read_public_key_button)

        vbox_left.addWidget(self.rsa_options_container)
        vbox_left.addSpacing(10) # Spacer
        vbox_left.addWidget(self.lsb_checkbox)
        vbox_left.addSpacing(10) # Spacer
        vbox_right = QVBoxLayout()
        vbox_right.addStretch(1)
        vbox_right.addWidget(self.cipher_label)
        vbox_right.addWidget(self.cipher_combobox)
        vbox_right.addWidget(self.mode_label)
        vbox_right.addWidget(self.mode_combobox)
        vbox_right.addSpacing(20)
        vbox_right.addWidget(self.encrypt_button)
        vbox_right.addWidget(self.decrypt_button)

        main_content_internal_h_layout.addLayout(vbox_left, stretch=1)
        main_content_internal_h_layout.addWidget(self.main_content_separator)
        main_content_internal_h_layout.addLayout(vbox_right, stretch=1)

        right_panel_v_layout.addWidget(self.main_content_area_widget, stretch=1)

        overall_h_layout.addWidget(self.right_panel_widget, stretch=1)

        # Connect signals
        self.hamburger_button.clicked.connect(self.toggle_sidebar_animation)
        self.educational_mode_button.toggled.connect(self.handle_mode_button_toggled)
        self.fully_secure_mode_button.toggled.connect(self.handle_mode_button_toggled)
        self.set_key_button.clicked.connect(self.set_key)
        self.generate_key_button.clicked.connect(self.generate_random_key)
        self.save_key_button.clicked.connect(self.save_key_to_file)
        self.read_key_button.clicked.connect(self.read_key_from_file)
        self.mode_combobox.currentIndexChanged.connect(self.set_mode)
        self.cipher_combobox.currentIndexChanged.connect(self.set_cipher)
        self.encrypt_button.clicked.connect(self.encrypt_button_click)
        self.decrypt_button.clicked.connect(self.decrypt_button_click)
        self.theme_toggle_button.clicked.connect(self.toggle_theme)
        self.generate_rsa_keys_button.clicked.connect(self.generate_rsa_keys_values)
        self.read_private_key_button.clicked.connect(self.read_private_key_from_file)
        self.read_public_key_button.clicked.connect(self.read_public_key_from_file)

        self.rsa_checkbox.stateChanged.connect(self.toggle_rsa_encryption)
        self.rsa_checkbox.stateChanged.connect(self.toggle_rsa_options_visibility_animated)


        self.rsa_checkbox.stateChanged.connect(self.update_lsb_checkbox_state)
        self.update_lsb_checkbox_state(self.rsa_checkbox.checkState().value)
        self.settings_button.clicked.connect(self.open_settings_dialog)

        self.update_mode_combobox()

    def showEvent(self, event):
        """Override showEvent to ensure initial UI states are correct, especially for animations."""
        super().showEvent(event)

        # Sidebar initial width setup
        if self.is_sidebar_expanded:
            self.sidebar_container_widget.setMaximumWidth(self.sidebar_full_width)
            self.mode_selection_panel.setVisible(True)
        else:
            self.sidebar_container_widget.setMaximumWidth(self.sidebar_collapsed_width)
            self.mode_selection_panel.setVisible(False)



    def apply_theme_and_styles(self, initial_setup=False, new_theme=None):
        global current_theme_mode
        theme_to_set = current_theme_mode
        if new_theme:
            theme_to_set = new_theme

        qdarktheme.setup_theme(theme_to_set)
        current_theme_mode = theme_to_set

        base_stylesheet = QApplication.instance().styleSheet()
        additional_stylesheet = load_stylesheet()
        QApplication.instance().setStyleSheet(base_stylesheet + additional_stylesheet)

        for button in self.findChildren(QPushButton):
            button.setCursor(Qt.CursorShape.PointingHandCursor)


        self.header_widget.setProperty("theme", current_theme_mode)
        self.sidebar_container_widget.setProperty("theme", current_theme_mode)
        self.mode_display_label.setProperty("theme", current_theme_mode)
        self.main_content_separator.setProperty("theme", current_theme_mode)


        widgets_to_repolish = [
            self.header_widget,
            self.sidebar_container_widget,
            self.mode_display_label,
            self.main_content_separator,
        ]
        for widget in widgets_to_repolish:
            widget.style().unpolish(widget)
            widget.style().polish(widget)

        self.update_mode_display_label_text()

        if current_theme_mode == "dark":
            self.theme_toggle_button.setIcon(QIcon("icons/change_theme_dark_theme.png"))
            self.educational_mode_button.setIcon(QIcon("icons/edu_icon_dark_theme.png"))
            self.fully_secure_mode_button.setIcon(QIcon("icons/sec_icon_dark_theme.png"))
            self.settings_button.setIcon(QIcon("icons/settings_icon_dark_theme.png"))
        else:  # light theme
            self.theme_toggle_button.setIcon(QIcon("icons/change_theme_light_theme.png"))
            self.educational_mode_button.setIcon(QIcon("icons/edu_icon_light_theme.png"))
            self.fully_secure_mode_button.setIcon(QIcon("icons/sec_icon_light_theme.png"))
            self.settings_button.setIcon(QIcon("icons/settings_icon_light_theme.png"))

    def _apply_defaults_to_ui(self):
        mode_key = "educational" if self.current_app_mode == "Educational Mode" else "fully_secure"
        settings_for_current_mode = self.default_settings.get(mode_key)

        if not settings_for_current_mode:
            print(f"No default settings found for mode: {self.current_app_mode}")
            return
        print(f"Applying UI defaults for mode: {self.current_app_mode}")

        #  Temporarily block signals for direct setting
        self.cipher_combobox.blockSignals(True)
        self.mode_combobox.blockSignals(True)
        self.rsa_checkbox.blockSignals(True)  # Block during direct set
        self.lsb_checkbox.blockSignals(True)

        # 1. Apply Cipher
        default_cipher_obj = settings_for_current_mode.get("cipher")
        idx = self.cipher_combobox.findData(default_cipher_obj) if default_cipher_obj is not None else -1
        self.cipher_combobox.setCurrentIndex(idx if idx != -1 else 0)

        self.cipher_combobox.blockSignals(False)  # Unblock before calling set_cipher
        self.set_cipher(self.cipher_combobox.currentIndex())  # This updates mode_combobox

        # 2. Apply Crypto Mode (after mode_combobox is populated)
        self.mode_combobox.blockSignals(True)
        default_crypto_mode_obj = settings_for_current_mode.get("crypto_mode")
        idx_mode = self.mode_combobox.findData(default_crypto_mode_obj) if default_crypto_mode_obj is not None else -1
        if idx_mode != -1:
            self.mode_combobox.setCurrentIndex(idx_mode)
        # If not found, update_mode_combobox's default logic (e.g. GCM for secure AES) takes precedence
        # or it stays at "None" or the first item if "None" was the only one.
        current_mode_idx = self.mode_combobox.currentIndex()
        if current_mode_idx != -1: self.set_mode(current_mode_idx)  # Ensure encryptor state is updated
        self.mode_combobox.blockSignals(False)

        # 3. Apply RSA checkbox state
        use_rsa_default = settings_for_current_mode.get("use_rsa", False)
        self.rsa_checkbox.setChecked(use_rsa_default)
        # Manually call the handlers because we blocked signals on rsa_checkbox
        self.toggle_rsa_encryption(self.rsa_checkbox.checkState().value)  # Update encryptor flag
        self.update_lsb_checkbox_state(self.rsa_checkbox.checkState().value)  # Update LSB enabled state

        # Crucially, now call the animation/visibility toggle directly with the new state
        # This bypasses relying on the signal if it was blocked or if state didn't "change" from widget's perspective
        self.toggle_rsa_options_visibility_animated(self.rsa_checkbox.checkState().value)

        self.rsa_checkbox.blockSignals(False)  # Unblock RSA checkbox

        # Load keys if RSA is now set to true by default
        if self.encryptor.use_rsa_encryption:  # Check the flag
            pub_path = settings_for_current_mode.get("public_key_path", "")
            priv_path = settings_for_current_mode.get("private_key_path", "")
            self.encryptor.rsa_public_key = self._load_key_from_path(pub_path, "public") if pub_path else None
            self.encryptor.rsa_private_key = self._load_key_from_path(priv_path, "private") if priv_path else None
        else:
            self.encryptor.rsa_public_key = None
            self.encryptor.rsa_private_key = None
        self._update_rsa_key_status_display()

        # 4. Apply LSB checkbox state
        use_lsb_default = settings_for_current_mode.get("use_lsb", False)
        if self.lsb_checkbox.isEnabled():
            self.lsb_checkbox.setChecked(use_lsb_default)
        else:
            self.lsb_checkbox.setChecked(False)
        self.lsb_checkbox.blockSignals(False)

        print(f"UI defaults applied for {self.current_app_mode}.")


    def _settings_to_serializable(self, settings_dict):
        """Converts cipher/mode objects in settings to string names for JSON."""
        serializable_settings = {}
        for mode_type, config in settings_dict.items():  # "educational", "fully_secure"
            s_config = config.copy()
            if s_config.get("cipher"):
                s_config["cipher_name"] = self.cipher_to_name.get(s_config["cipher"])
            del s_config["cipher"]  # Remove original object

            if s_config.get("crypto_mode") and s_config.get("cipher_name"):
                cipher_obj = self.name_to_cipher.get(s_config["cipher_name"])
                if cipher_obj and cipher_obj in self.mode_to_name_map:
                    # Get the string name for the mode value
                    mode_val_to_name_map_for_cipher = {v: k for k, v in self.name_to_mode_map[cipher_obj].items()}
                    s_config["crypto_mode_name"] = mode_val_to_name_map_for_cipher.get(s_config["crypto_mode"])
            del s_config["crypto_mode"]  # Remove original object
            serializable_settings[mode_type] = s_config
        return serializable_settings

    def _serializable_to_settings(self, loaded_data_dict):
        """Converts cipher/mode string names from JSON back to objects."""
        restored_settings = {}
        for mode_type, s_config in loaded_data_dict.items():
            config = s_config.copy()
            cipher_obj = None
            if "cipher_name" in config and config["cipher_name"]:
                cipher_obj = self.name_to_cipher.get(config["cipher_name"])
                config["cipher"] = cipher_obj
            else:
                config["cipher"] = None  # Default if no cipher name
            del config["cipher_name"]

            if "crypto_mode_name" in config and config["crypto_mode_name"] and cipher_obj:
                if cipher_obj in self.name_to_mode_map:
                    config["crypto_mode"] = self.name_to_mode_map[cipher_obj].get(config["crypto_mode_name"])
                else:
                    config["crypto_mode"] = None
            else:
                config["crypto_mode"] = None
            del config["crypto_mode_name"]
            restored_settings[mode_type] = config
        return restored_settings

    def _save_app_settings_to_file(self):
        try:
            serializable_data = self._settings_to_serializable(self.default_settings)
            with open(self.settings_file, 'w') as f:
                json.dump(serializable_data, f, indent=4)
            print(f"Settings saved to {self.settings_file}")
        except Exception as e:
            print(f"Error saving settings: {e}")
            show_alert(f"Could not save settings: {e}")

    def _load_app_settings_from_file(self):
        try:
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    loaded_data = json.load(f)
                    # Ensure loaded structure matches expected structure before assigning
                    processed_settings = self._serializable_to_settings(loaded_data)

                    # Merge loaded settings with defaults to ensure all keys are present
                    for mode_key in self.default_settings:
                        if mode_key in processed_settings:
                            self.default_settings[mode_key].update(processed_settings[mode_key])

                    print(f"Settings loaded from {self.settings_file}")
            else:
                print(f"Settings file not found ({self.settings_file}). Using default settings.")
        except json.JSONDecodeError:
            print(f"Error decoding settings file ({self.settings_file}). Using default settings.")
        except Exception as e:
            print(f"Error loading settings: {e}. Using default settings.")

    def open_settings_dialog(self):

        dialog_settings_input = {
            "educational": self.default_settings["educational"].copy(),  # Shallow copy of inner dict is fine
            "fully_secure": self.default_settings["fully_secure"].copy()  # Shallow copy of inner dict
        }


        dialog = SettingsDialog(self, current_settings=dialog_settings_input)
        if dialog.exec() == QDialog.Accepted:
            new_settings = dialog.get_settings()


            self.default_settings = new_settings

            self._save_app_settings_to_file()
            print("Settings saved via dialog:", self.default_settings)
            # Optionally apply defaults to current UI
            self._apply_defaults_to_ui()
        else:
            print("Settings dialog cancelled.")
    def toggle_sidebar_animation(self):
        if self.sidebar_container_animation.state() == QPropertyAnimation.State.Running:
            return

        if self.is_sidebar_expanded:
            target_width = self.sidebar_collapsed_width
        else:
            self.mode_selection_panel.setVisible(True)  #
            target_width = self.sidebar_full_width

        self.sidebar_container_animation.setStartValue(self.sidebar_container_widget.maximumWidth())
        self.sidebar_container_animation.setEndValue(target_width)
        self.sidebar_container_animation.start()

        # Toggle state to reflect the target of the animation
        self.is_sidebar_expanded = not self.is_sidebar_expanded

    def _on_sidebar_container_animation_finished(self):
        if not self.is_sidebar_expanded:
            self.mode_selection_panel.setVisible(False)
            self.sidebar_container_widget.setMaximumWidth(self.sidebar_collapsed_width)
        else:  # If animation just finished and target was expanded
            self.sidebar_container_widget.setMaximumWidth(self.sidebar_full_width)
            self.mode_selection_panel.setVisible(True)

    def handle_mode_button_toggled(self, checked):
        sender_button = self.sender()
        if checked:
            previous_cipher_data_before_filter = self.cipher_combobox.currentData()

            # Set current_app_mode and UI texts
            if sender_button == self.educational_mode_button:
                self.current_app_mode = "Educational Mode"
                self.encryptor.preserve_headers = True
                self.encrypt_button.setText("Encrypt Image / Video")
                self.decrypt_button.setText("Decrypt Image")
            elif sender_button == self.fully_secure_mode_button:
                self.current_app_mode = "Fully-Secure Mode"
                self.encryptor.preserve_headers = False
                self.encrypt_button.setText("Encrypt File")
                self.decrypt_button.setText("Decrypt File")

            self.update_mode_display_label_text()  #

            # Filter/Repopulate Cipher ComboBox based on the new self.current_app_mode
            self.cipher_combobox.blockSignals(True)
            self.cipher_combobox.clear()
            self.cipher_combobox.addItem("None", None)

            if self.current_app_mode == "Educational Mode":
                for cipher_name_str, cipher_value in self.all_cipher_items_for_combobox:
                    self.cipher_combobox.addItem(cipher_name_str, cipher_value)

                # Try to restore previous selection if it's valid in the full list
                idx = self.cipher_combobox.findData(previous_cipher_data_before_filter)
                if idx != -1:
                    self.cipher_combobox.setCurrentIndex(idx)
                else:
                    self.cipher_combobox.setCurrentIndex(0)

            elif self.current_app_mode == "Fully-Secure Mode":
                self.cipher_combobox.addItem(cipher_names[AES], AES)
                idx = self.cipher_combobox.findData(AES)
                if idx != -1:  # Should always find AES unless only "None" exists
                    self.cipher_combobox.setCurrentIndex(idx)  # Default to AES
                else:
                    self.cipher_combobox.setCurrentIndex(0)

            self.cipher_combobox.blockSignals(False)


            self.set_cipher(self.cipher_combobox.currentIndex())


            self._apply_defaults_to_ui()

    def update_mode_display_label_text(self):
        display_text = self.current_app_mode.replace(" Mode", "")
        self.mode_display_label.setText(f"Current Mode: {display_text}")

    def toggle_theme(self):
        global current_theme_mode
        new_theme = "light" if current_theme_mode == "dark" else "dark"
        self.apply_theme_and_styles(new_theme=new_theme)

    def update_lsb_checkbox_state(self, rsa_checkbox_state_int: int):
        """
        Enables or disables the LSB checkbox based on the RSA checkbox state.
        If RSA is unchecked, LSB is disabled and also unchecked.
        """
        is_rsa_checked = (rsa_checkbox_state_int == Qt.CheckState.Checked.value)

        self.lsb_checkbox.setEnabled(is_rsa_checked)
        if not is_rsa_checked:
            # If RSA is disabled, LSB cannot be used, so ensure it's unchecked.
            if self.lsb_checkbox.isChecked():
                self.lsb_checkbox.setChecked(False)

    def toggle_rsa_options_visibility_animated(self, state_int: int):
        target_expanded_state = (state_int == Qt.CheckState.Checked.value)

        if self.rsa_options_animation.state() == QPropertyAnimation.State.Running:
            return

        # Only proceed if the target state is different from the current logical state,
        # OR if the target is to be expanded and height hasn't been set (first time).
        if target_expanded_state == self.is_rsa_options_expanded and \
                not (target_expanded_state and self.rsa_options_target_height == 0):
            if self.is_rsa_options_expanded and self.rsa_options_target_height > 0:
                self.rsa_options_container.setVisible(True)
                self.rsa_options_container.setMaximumHeight(self.rsa_options_target_height)
            elif not self.is_rsa_options_expanded:
                self.rsa_options_container.setVisible(False)
                self.rsa_options_container.setMaximumHeight(0)
            return

        if target_expanded_state:
            if self.rsa_options_target_height == 0:
                self.rsa_options_container.setVisible(True)
                self.rsa_options_container.setMaximumHeight(16777215)
                QApplication.processEvents()
                layout_sh = self.rsa_options_container.layout().sizeHint()
                self.rsa_options_target_height = layout_sh.height()
                if self.rsa_options_target_height <= 10:
                    self.rsa_options_target_height = 150
                print(f"RSA options target height captured: {self.rsa_options_target_height}")
                if not self.is_rsa_options_expanded:
                    self.rsa_options_container.setMaximumHeight(0)

            if self.rsa_options_target_height > 0:
                self.rsa_options_container.setVisible(True)
                self.rsa_options_animation.setStartValue(self.rsa_options_container.maximumHeight())
                self.rsa_options_animation.setEndValue(self.rsa_options_target_height)
                self.rsa_options_animation.start()
            else:
                self.rsa_options_container.setVisible(True)
                self.rsa_options_container.setMaximumHeight(150)

            self.is_rsa_options_expanded = True

        else:
            start_height = self.rsa_options_container.maximumHeight()
            # If it was logically expanded but  visually collapsed, animate from full known height
            if self.is_rsa_options_expanded and self.rsa_options_target_height > 0 and start_height == 0:
                start_height = self.rsa_options_target_height

            self.rsa_options_animation.setStartValue(start_height)
            self.rsa_options_animation.setEndValue(0)
            self.rsa_options_animation.start()
            self.is_rsa_options_expanded = False

    def _on_rsa_options_animation_finished(self):
        # This state variable should now accurately reflect the state POST-animation intent
        if not self.is_rsa_options_expanded:
            if self.rsa_options_container.maximumHeight() == 0:  # Check if animation completed to 0
                self.rsa_options_container.setVisible(False)
        else:  # Finished expanding
            if self.rsa_options_target_height > 0:  # Ensure it is set to its full height
                self.rsa_options_container.setMaximumHeight(self.rsa_options_target_height)
            self.rsa_options_container.setVisible(True)  # Ensure visible
    def toggle_rsa_encryption(self, state):
        self.encryptor.use_rsa_encryption = state == Qt.CheckState.Checked.value


    def _load_key_from_path(self, key_path, key_type="public"):
        """Attempts to load an RSA key from a given path."""
        if not key_path or not os.path.exists(key_path):
            show_alert(f"Key path for {key_type} not provided or does not exist: {key_path}")
            return None
        try:
            with open(key_path, "rb") as f:
                key_data = f.read()
            key_obj = RSA.import_key(key_data)


            if key_type == "public":

                try:
                    key_obj.export_key(format='PEM', pkcs=8)

                    if hasattr(key_obj, 'n') and hasattr(key_obj, 'e') and not key_obj.has_private():
                        pass  # Looks like a public key
                except ValueError:  # Expected if it's a pure public key from some export formats
                    pass

            elif key_type == "private":
                if not key_obj.has_private():
                    print(f"Warning: Loaded key from {key_path} is not a private key.")
                    return None
            return key_obj
        except Exception as e:
            print(f"Failed to load {key_type} key from {key_path}: {e}")
            show_alert(f"Failed to auto-load {key_type} key from default path:\n{key_path}\nError: {e}")
            return None

    def _update_rsa_key_status_display(self):
        """Updates the rsa_key_status_entry text based on loaded keys."""
        pub_loaded = self.encryptor.rsa_public_key is not None
        priv_loaded = self.encryptor.rsa_private_key is not None

        if pub_loaded and priv_loaded:
            self.rsa_key_status_entry.setText("Public & Private keys loaded.")
        elif pub_loaded:
            self.rsa_key_status_entry.setText("Public key loaded; Private key NOT loaded.")
        elif priv_loaded:
            self.rsa_key_status_entry.setText("Private key loaded; Public key NOT loaded.")
        else:
            self.rsa_key_status_entry.setText("No RSA keys loaded.")
    def generate_rsa_keys_values(self):
        rsa_keys = RSA.generate(2048)
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        filenameprivate = f"privatekey_{timestamp}.pem"
        folder_path = "rsa_keys"
        os.makedirs(folder_path, exist_ok=True)
        try:
            with open(os.path.join(folder_path, filenameprivate), "wb") as f:
                f.write(rsa_keys.export_key("PEM"))
            with open(os.path.join(folder_path, f"publickey_{timestamp}.pem"), "wb") as f:
                f.write(rsa_keys.publickey().export_key("PEM"))
            self.rsa_key_status_entry.setText("Keys were generated and saved to files")
        except Exception as e:
            self.rsa_key_status_entry.setText(f"Error: {str(e)}")
            show_alert(f"Error: {str(e)}")

    def read_private_key_from_file(self):
        fp, _ = QFileDialog.getOpenFileName(self, "Read Private Key", "", "PEM files (*.pem)")
        if fp:
            try:
                with open(fp, "rb") as f:
                    self.encryptor.rsa_private_key = RSA.import_key(f.read())
                self.rsa_key_status_entry.setText("Private key loaded")
            except Exception as e:
                self.rsa_key_status_entry.setText(f"Error: {str(e)}")
                show_alert(f"Error: {str(e)}")

    def read_public_key_from_file(self):
        fp, _ = QFileDialog.getOpenFileName(self, "Read Public Key", "", "PEM files (*.pem)")
        if fp:
            try:
                with open(fp, "rb") as f:
                    self.encryptor.rsa_public_key = RSA.import_key(f.read())
                self.rsa_key_status_entry.setText("Public key loaded")
            except Exception as e:
                self.rsa_key_status_entry.setText(f"Error: {str(e)}")
                show_alert(f"Error: {str(e)}")

    def update_mode_combobox(self):
        current_crypto_mode_selection = self.mode_combobox.currentData()
        selected_cipher_val = self.encryptor.cipher

        self.mode_combobox.blockSignals(True)
        self.mode_combobox.clear()
        self.mode_combobox.addItem("None", None)

        allowed_modes_to_add = {}

        if selected_cipher_val == DES:
            if self.current_app_mode == "Educational Mode":
                allowed_modes_to_add = mode_des_names.copy()


        elif selected_cipher_val == AES:
            if self.current_app_mode == "Fully-Secure Mode":
                # Only GCM and CTR for AES in Fully-Secure Mode
                if AES.MODE_GCM in mode_aes_names:
                    allowed_modes_to_add[AES.MODE_GCM] = mode_aes_names[AES.MODE_GCM]
                if AES.MODE_CTR in mode_aes_names:
                    allowed_modes_to_add[AES.MODE_CTR] = mode_aes_names[AES.MODE_CTR]
            else:  # Educational Mode, show all standard AES modes
                allowed_modes_to_add = mode_aes_names.copy()

        for mode_val, mode_name_str in allowed_modes_to_add.items():
            self.mode_combobox.addItem(mode_name_str, mode_val)

        self.mode_combobox.blockSignals(False)

        # Attempt to restore selection or set a sensible default
        idx = self.mode_combobox.findData(current_crypto_mode_selection)
        # Check if the restored mode is actually in the (now possibly filtered) list
        is_restored_item_still_valid = False
        if idx != -1:
            if current_crypto_mode_selection in allowed_modes_to_add:
                is_restored_item_still_valid = True

        if idx != -1 and is_restored_item_still_valid:
            self.mode_combobox.setCurrentIndex(idx)
        elif self.current_app_mode == "Fully-Secure Mode" and selected_cipher_val == AES:
            # Default to GCM if available in Fully-Secure AES, then CTR, then None
            gcm_idx = self.mode_combobox.findData(AES.MODE_GCM)
            if gcm_idx != -1:
                self.mode_combobox.setCurrentIndex(gcm_idx)
            else:
                ctr_idx = self.mode_combobox.findData(AES.MODE_CTR)
                self.mode_combobox.setCurrentIndex(ctr_idx if ctr_idx != -1 else 0)
        elif self.mode_combobox.count() > 0:  # If any items (at least "None")
            self.mode_combobox.setCurrentIndex(0)  # Default to "None"

        self.set_mode(self.mode_combobox.currentIndex())  # Update labels and encryptor state

    def set_mode(self, index):
        if index == -1 and self.mode_combobox.count() > 0:
            index = 0
        elif index == -1:
            self.encryptor.mode = None
            self.mode_label.setText("Selected Mode: None")
            return
        mode_var = self.mode_combobox.itemData(index)
        self.encryptor.mode = mode_var
        name_disp = "None"
        if self.encryptor.cipher == DES:
            name_disp = mode_des_names.get(mode_var, "None")
        elif self.encryptor.cipher == AES:
            name_disp = mode_aes_names.get(mode_var, "None")
        self.mode_label.setText(f"Selected Mode: {name_disp}")

    def set_cipher(self, index):
        cipher_var = self.cipher_combobox.currentData()
        self.encryptor.cipher = cipher_var
        self.cipher_label.setText(f"Selected Cipher: {cipher_names.get(cipher_var, 'None')}")
        self.update_mode_combobox()

    def set_key(self):
        key_str = self.key_entry.text()
        if self.encryptor.cipher is None:
            show_alert("No cipher selected.")
            self.key_entry.setText("No cipher selected")
            return
        try:
            key_bytes = key_str.encode('utf-8')
        except Exception as e:
            show_alert(f"Key encoding error: {e}")
            return
        valid_len = False
        c_name = cipher_names.get(self.encryptor.cipher)
        if self.encryptor.cipher == DES and len(key_bytes) == 8:
            valid_len = True
        elif self.encryptor.cipher == AES and len(key_bytes) in [16, 24, 32]:
            valid_len = True

        if not valid_len:
            if self.encryptor.cipher == DES:
                error_string=f"Error: DES key must be 8 bytes. Your key is {len(key_bytes)} bytes."
                show_alert(error_string)
            elif self.encryptor.cipher == AES:
                error_string=f"Error: AES key must be 16, 24, or 32 bytes. Your key is {len(key_bytes)} bytes."
                show_alert(error_string)
            self.key_entry.setText(error_string)
            return
        self.encryptor.key = key_bytes
        self.key_entry.setText("Key set successfully")

    def generate_random_key(self):
        if self.encryptor.cipher is None:
            show_alert("No cipher selected.")
            self.key_entry.setText("No cipher selected")
            return
        key_len, c_name = (0, "Unknown")
        if self.encryptor.cipher == DES:
            key_len, c_name = (8, "DES")
        elif self.encryptor.cipher == AES:
            key_len, c_name = (32, "AES")

        if key_len == 0:
            self.key_entry.setText("Error: Unknown cipher.")
            return
        self.encryptor.key = get_random_bytes(key_len)
        self.key_entry.setText(f"Generated {key_len}-byte key for {c_name}")

    def save_key_to_file(self):
        if self.encryptor.key is None:
            show_alert("No key to save.")
            return
        fp, _ = QFileDialog.getSaveFileName(self, "Save Key", "", "Key Files (*.key);;All Files (*)")
        if fp:
            try:
                with open(fp, "wb") as f:
                    f.write(self.encryptor.key)
                self.key_entry.setText("Key saved.")
            except Exception as e:
                show_alert(f"Error saving key: {str(e)}")
                self.key_entry.setText("Error saving.")
        else:
            self.key_entry.setText("Save cancelled.")

    def read_key_from_file(self):
        fp, _ = QFileDialog.getOpenFileName(self, "Read Key", "", "Key Files (*.key);;All Files (*)")
        if fp:
            try:
                with open(fp, "rb") as f:
                    key_bytes = f.read()
                c_name = cipher_names.get(self.encryptor.cipher)
                valid_len = False
                if self.encryptor.cipher == DES and len(key_bytes) == 8:
                    valid_len = True
                elif self.encryptor.cipher == AES and len(key_bytes) in [16, 24, 32]:
                    valid_len = True
                elif self.encryptor.cipher is None: # Allow reading key before cipher selection
                    valid_len = True
                if not valid_len:
                    show_alert(f"Invalid key length in file for {c_name}.")
                    return
                self.encryptor.key = key_bytes
                self.key_entry.setText(f"Key read ({len(key_bytes)} bytes).")
            except FileNotFoundError:
                show_alert("File Not Found.")
                self.key_entry.setText("File Not Found.")
            except Exception as e:
                show_alert(f"Error reading key: {str(e)}")
                self.key_entry.setText(f"Error: {str(e)}")



    def encrypt_button_click(self):
        self.encryptor.cipher = self.cipher_combobox.currentData()
        self.encryptor.mode = self.mode_combobox.currentData()

        if self.encryptor.key is None:
            show_alert("Symmetric key is not set.")
            return

        if self.encryptor.cipher is None or self.encryptor.mode is None:
            show_alert("Cipher and cryptographic mode must be selected.")
            return
        if self.encryptor.use_rsa_encryption and self.encryptor.rsa_public_key is None:
            show_alert("RSA encryption selected but public key not read.")
            return
        if not self.encryptor.use_rsa_encryption and self.encryptor.key is None:
            show_alert("Symmetric key is not set when RSA is not in use.")
            return

        encrypted_data_for_lsb = None
        intermediate_encrypted_filepath_for_lsb = None  # Used in Fully-Secure + LSB
        original_input_fp_for_naming = None
        encrypted_image_obj_for_direct_save = None



        if self.current_app_mode == "Educational Mode":
            file_filter = "Media Files (*.png *.jpg *.jpeg *.bmp *.mp4 *.avi *.mov *.mkv);;" \
                          "Image Files (*.png *.jpg *.jpeg *.bmp);;" \
                          "Video Files (*.mp4 *.avi *.mov *.mkv);;" \
                          "All Files (*.*)"
            fp, _ = QFileDialog.getOpenFileName(self, "Select Image or Video to Encrypt (Educational)", "", file_filter)
            if not fp: return
            original_input_fp_for_naming = fp

            file_extension = os.path.splitext(fp)[1].lower()
            image_extensions = ['.png', '.jpg', '.jpeg', '.bmp']
            video_extensions = ['.mp4', '.avi', '.mov', '.mkv']

            if file_extension in image_extensions:
                try:
                    img_orig = ImageEncryptor.load_image(fp)
                    ImageEncryptor.display_image(img_orig, "Original Image")
                    enc_img_obj = self.encryptor.encrypt(img_orig)
                    if enc_img_obj is None: raise ValueError("Image encryption returned None.")

                    if self.lsb_checkbox.isChecked() and self.encryptor.use_rsa_encryption:
                        is_success_encode, buffer = cv2.imencode(".png", enc_img_obj)  # Encode to lossless PNG bytes
                        if not is_success_encode: raise ValueError("Failed to encode encrypted image to bytes for LSB.")
                        encrypted_data_for_lsb = buffer.tobytes()
                    elif not self.lsb_checkbox.isChecked():
                        encrypted_image_obj_for_direct_save = enc_img_obj  # Save for normal processing
                    # If LSB checked but RSA not, encrypted_data_for_lsb remains None, handled later
                except Exception as e:
                    show_alert(f"Educational Image encryption process failed: {str(e)}")
                    return

            elif file_extension in video_extensions:
                if self.lsb_checkbox.isChecked() and self.encryptor.use_rsa_encryption:
                    show_alert(
                        "LSB Steganography for direct video output is not applied in this step for Educational Mode. "
                        "The video will be encrypted. You can then LSB the *encrypted video file* using Fully-Secure Mode if desired.")
                    # Proceed to encrypt video without LSB for now

                print(f"Starting Educational Video Encryption for: {fp}")
                try:

                    self.encryptor.encrypt_video_frames(input_video=fp)
                    QMessageBox.information(self, "Video Encryption (Educational)",
                                            f"Educational video encryption for '{os.path.basename(fp)}' processed.\n"
                                            "Check console for details. Encrypted video is in 'encrypted_videos' folder.")
                except AttributeError:
                    show_alert("Error: 'encrypt_video_frames' method not found in ImageEncryptor.")
                except Exception as e:
                    traceback.print_exc()
                    show_alert(f"Educational Video encryption failed: {str(e)}")
                return  # Video processing ends here for Educational Mode, LSB step is skipped for video output.

            else:
                show_alert(f"Unsupported file type for Educational Mode encryption: {file_extension}")
                return

        elif self.current_app_mode == "Fully-Secure Mode":
            # File encryption logic (can be image, video, or any file)
            input_fp, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt (Fully-Secure)", "",
                                                      "All Files (*.*)")
            if not input_fp: return
            original_input_fp_for_naming = input_fp

            try:
                if self.lsb_checkbox.isChecked() and self.encryptor.use_rsa_encryption:
                    # Encrypt to a temporary file first, then read its bytes for LSB
                    temp_fd, intermediate_encrypted_filepath_for_lsb = tempfile.mkstemp(suffix=".enc")
                    os.close(temp_fd)
                    if not self.encryptor.encrypt_file(input_fp,
                                                       intermediate_encrypted_filepath_for_lsb):  # Assuming returns True/False
                        raise ValueError("Core file encryption step (for LSB) failed.")
                    with open(intermediate_encrypted_filepath_for_lsb, 'rb') as f_temp:
                        encrypted_data_for_lsb = f_temp.read()
                elif not self.lsb_checkbox.isChecked():
                    # Normal file encryption, ask for output path directly
                    suggested_out_name = f"{os.path.basename(input_fp)}.enc"
                    output_fp, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File As...",
                                                               os.path.join(os.path.dirname(input_fp),
                                                                            suggested_out_name),
                                                               "All Files (*.*)")
                    if not output_fp: return
                    if not self.encryptor.encrypt_file(input_fp, output_fp):  # Assuming returns True/False
                        raise ValueError("File encryption and saving failed.")
                    QMessageBox.information(self, "Success", f"File encrypted and saved to:\n{output_fp}")
                    return  # Done for non-LSB Fully-Secure file encryption
                # If LSB checked but RSA not, encrypted_data_for_lsb remains None, handled below
            except Exception as e:
                show_alert(f"Fully-Secure File encryption process failed: {str(e)}")
                if intermediate_encrypted_filepath_for_lsb and os.path.exists(intermediate_encrypted_filepath_for_lsb):
                    os.remove(intermediate_encrypted_filepath_for_lsb)
                return


        #  LSB Steganography Hiding Step
        if self.lsb_checkbox.isChecked():
            if not self.encryptor.use_rsa_encryption:  # Should be prevented by UI logic already
                show_alert("LSB Steganography requires RSA to be active. Please check the RSA option.")
                if intermediate_encrypted_filepath_for_lsb and os.path.exists(
                    intermediate_encrypted_filepath_for_lsb): os.remove(intermediate_encrypted_filepath_for_lsb)
                return

            if not encrypted_data_for_lsb:
                show_alert(
                    "No valid encrypted data available to hide with LSB (ensure RSA is used and previous encryption step succeeded).")
                if intermediate_encrypted_filepath_for_lsb and os.path.exists(
                    intermediate_encrypted_filepath_for_lsb): os.remove(intermediate_encrypted_filepath_for_lsb)
                return

            container_img_path, _ = QFileDialog.getOpenFileName(self, "Select Container Image for LSB Steganography",
                                                                "",
                                                                "Image Files (*.png *.bmp)")  # Lossless formats recommended
            if not container_img_path:
                show_alert("LSB Steganography cancelled: No container image selected.")
                if intermediate_encrypted_filepath_for_lsb and os.path.exists(
                    intermediate_encrypted_filepath_for_lsb): os.remove(intermediate_encrypted_filepath_for_lsb)
                return
            try:
                container_image_obj = ImageEncryptor.load_image(container_img_path)
                # Assuming hide_data_in_image_seeded returns (bool_success, result_or_error_msg)
                lsb_success, lsb_result = self.encryptor.hide_data_in_image_seeded(container_image_obj,
                                                                                   encrypted_data_for_lsb)

                if not lsb_success:
                    show_alert(f"LSB Hiding Failed: {lsb_result}")  # Display specific error from ImageEncryptor
                    # Cleanup is in finally
                else:
                    stego_image_obj = lsb_result  # If successful, lsb_result is the stego image NumPy array
                    if stego_image_obj is None:  # Should be caught by lsb_success=False, but defensive
                        raise ValueError("LSB hiding reported success but returned no image.")

                    default_stego_name = f"stego_{os.path.splitext(os.path.basename(container_img_path))[0]}.png"  # Suggest .png
                    stego_save_path, _ = QFileDialog.getSaveFileName(self, "Save Steganographic Image As...",
                                                                     os.path.join(os.path.dirname(container_img_path),
                                                                                  default_stego_name),
                                                                     "PNG Image (*.png);;BMP Image (*.bmp)")
                    if not stego_save_path:
                        show_alert("Save steganographic image cancelled.")
                        # Cleanup in finally
                        return

                    ImageEncryptor.save_image(stego_image_obj, stego_save_path)
                    ImageEncryptor.display_image(stego_image_obj, "Steganographic Image (Encrypted Output)")
                    QMessageBox.information(self, "Success",
                                            f"Encrypted data hidden in image and saved to:\n{stego_save_path}")
            except Exception as e:
                show_alert(f"An error occurred during LSB Steganography: {str(e)}")
            finally:
                if intermediate_encrypted_filepath_for_lsb and os.path.exists(intermediate_encrypted_filepath_for_lsb):
                    os.remove(intermediate_encrypted_filepath_for_lsb)
            return  # LSB processing complete or failed

        # Normal Save for Educational Mode IMAGE if LSB was NOT checked
        if encrypted_image_obj_for_direct_save is not None and self.current_app_mode == "Educational Mode" and not self.lsb_checkbox.isChecked():
            ImageEncryptor.display_image(encrypted_image_obj_for_direct_save, "Encrypted Image")
            save_dir = "encrypted_images"
            os.makedirs(save_dir, exist_ok=True)
            c_name = cipher_names.get(self.encryptor.cipher, "unknown_cipher")
            m_name = "unknown_mode"
            if self.encryptor.cipher == DES:
                m_name = mode_des_names.get(self.encryptor.mode, "unknown_mode")
            elif self.encryptor.cipher == AES:
                m_name = mode_aes_names.get(self.encryptor.mode, "unknown_mode")

            original_basename = os.path.basename(
                original_input_fp_for_naming if original_input_fp_for_naming else "output")
            encrypted_filename_stem = f"{c_name}_{m_name}_encrypted_{original_basename}"
            # Ensure the saved file has a .png extension if enc_img_obj is an image
            base_name_without_ext = os.path.splitext(encrypted_filename_stem)[0]
            save_path = os.path.join(save_dir, f"{base_name_without_ext}.png")

            ImageEncryptor.save_image(encrypted_image_obj_for_direct_save, save_path)
            QMessageBox.information(self, "Success", f"Image encrypted and saved to:\n{save_path}")

    def decrypt_button_click(self):
        self.encryptor.cipher = self.cipher_combobox.currentData()
        self.encryptor.mode = self.mode_combobox.currentData()

        if self.encryptor.cipher is None or self.encryptor.mode is None:
            show_alert("Cipher and cryptographic mode must be selected.")
            return
        if self.encryptor.use_rsa_encryption and self.encryptor.rsa_private_key is None:
            show_alert("RSA decryption selected but private key not read.")
            return
        if not self.encryptor.use_rsa_encryption and self.encryptor.key is None:
            show_alert("Symmetric key is not set.")
            return

        extracted_encrypted_bytes = None
        stego_input_fp = None

        if self.lsb_checkbox.isChecked():
            if not self.encryptor.use_rsa_encryption:
                show_alert("LSB Steganography requires RSA decryption to be active to retrieve the key.")
                return
            stego_fp, _ = QFileDialog.getOpenFileName(self, "Select Steganographic Image to Extract Data From", "",
                                                      "Image Files (*.png *.bmp)")
            if not stego_fp: return
            stego_input_fp = stego_fp
            try:
                stego_image_obj = ImageEncryptor.load_image(stego_fp)
                ImageEncryptor.display_image(stego_image_obj, "Steganographic Image (Input)")
                extracted_encrypted_bytes = self.encryptor.extract_data_from_image_seeded(stego_image_obj)
                if extracted_encrypted_bytes is None or len(extracted_encrypted_bytes) == 0:
                    raise ValueError("No data extracted or extraction failed.")
                print(f"Successfully extracted {len(extracted_encrypted_bytes)} bytes using LSB.")
            except Exception as e:
                show_alert(f"LSB Data Extraction failed: {str(e)}")
                return



        if self.current_app_mode == "Educational Mode":
            dec_img = None
            try:
                if self.lsb_checkbox.isChecked():
                    if extracted_encrypted_bytes:

                        enc_img_data = cv2.imdecode(np.frombuffer(extracted_encrypted_bytes, np.uint8),
                                                    cv2.IMREAD_UNCHANGED)
                        if enc_img_data is None:
                            raise ValueError("Could not decode extracted bytes into an image.")
                        ImageEncryptor.display_image(enc_img_data, "Extracted Encrypted Image")
                        dec_img = self.encryptor.decrypt(enc_img_data)
                    else:
                        show_alert("LSB was checked, but no data was extracted to decrypt.")
                        return
                else:  # Normal image decryption (LSB not checked)
                    fp, _ = QFileDialog.getOpenFileName(self, "Select Encrypted Image to Decrypt", "",
                                                        "Image Files (*.png *.jpg *.jpeg *.bmp)")
                    if not fp: return
                    stego_input_fp = fp  # For consistent naming if saving
                    enc_img_data = ImageEncryptor.load_image(fp)
                    ImageEncryptor.display_image(enc_img_data, "Encrypted Image (to be decrypted)")
                    dec_img = self.encryptor.decrypt(enc_img_data)

                if dec_img is None:
                    show_alert("Image decryption resulted in None.")
                    return

                ImageEncryptor.display_image(dec_img, "Decrypted Image")
                save_dir = "decrypted_images"
                os.makedirs(save_dir, exist_ok=True)
                c_name = cipher_names.get(self.encryptor.cipher, "unk_cipher")
                m_name = mode_des_names.get(self.encryptor.mode,
                                            "unk_mode") if self.encryptor.cipher == DES else mode_aes_names.get(
                    self.encryptor.mode, "unk_mode")

                base_name_for_decrypted = "output"
                if stego_input_fp:  # Use the name of the input (stego or encrypted) image for context
                    base_name_for_decrypted = os.path.splitext(os.path.basename(stego_input_fp))[0]
                    if self.lsb_checkbox.isChecked():
                        base_name_for_decrypted = f"{base_name_for_decrypted}_extracted"

                dec_stem = f"{c_name}_{m_name}_decrypted_{base_name_for_decrypted}"
                save_path = os.path.join(save_dir, f"{dec_stem}.png")
                ImageEncryptor.save_image(dec_img, save_path)
                QMessageBox.information(self, "Success", f"Image decrypted and saved to:\n{save_path}")

            except Exception as e:
                show_alert(f"Image decryption process failed: {str(e)}")
                return

        elif self.current_app_mode == "Fully-Secure Mode":
            output_fp = None  # To store the final output path
            try:
                if self.lsb_checkbox.isChecked():
                    if extracted_encrypted_bytes:
                        import tempfile
                        temp_fd, temp_encrypted_input_path = tempfile.mkstemp(suffix=".enc.lsb.tmp")
                        try:
                            with os.fdopen(temp_fd, 'wb') as tmp_file:
                                tmp_file.write(extracted_encrypted_bytes)

                            # Now decrypt this temporary file
                            input_dir = os.path.dirname(stego_input_fp) if stego_input_fp else os.getcwd()
                            suggested_out_name = f"{os.path.splitext(os.path.basename(stego_input_fp))[0] if stego_input_fp else 'extracted_file'}.dec"
                            output_fp, _ = QFileDialog.getSaveFileName(self, "Save Extracted & Decrypted File As...",
                                                                       os.path.join(input_dir, suggested_out_name),
                                                                       "All Files (*.*)")
                            if not output_fp: return  # User cancelled save dialog
                            self.encryptor.decrypt_file(temp_encrypted_input_path, output_fp)
                        finally:
                            if os.path.exists(temp_encrypted_input_path):
                                os.remove(temp_encrypted_input_path)
                    else:
                        show_alert("LSB was checked, but no data was extracted to decrypt.")
                        return
                else:  # Normal file decryption (LSB not checked)
                    input_fp, _ = QFileDialog.getOpenFileName(self, "Select Encrypted File to Decrypt", "",
                                                              "All Files (*.*)")
                    if not input_fp: return

                    suggested_out_name = os.path.basename(input_fp)
                    if suggested_out_name.lower().endswith(".enc"):
                        suggested_out_name = suggested_out_name[:-4]
                    else:
                        suggested_out_name += ".dec"
                    output_fp, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File As...",
                                                               os.path.join(os.path.dirname(input_fp), suggested_out_name),
                                                               "All Files (*.*)")
                    if not output_fp: return
                    self.encryptor.decrypt_file(input_fp, output_fp)

                QMessageBox.information(self, "Success", f"File decrypted and saved to:\n{output_fp}")
            except Exception as e:
                show_alert(f"File decryption process failed: {str(e)}")
                return


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = MyApp()
    window.setWindowTitle("Image Encryption/Decryption")
    window.setGeometry(100, 100, 950, 700)
    window.show()
    sys.exit(app.exec())