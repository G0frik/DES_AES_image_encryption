import sys
import cv2
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import filedialog
from despycryprtodome import encrypt_image,decrypt_image
import time

key = None
mode_names = {
    DES.MODE_CBC: "DES.MODE_CBC",
    DES.MODE_ECB: "DES.MODE_ECB",
}
def load_image(filename):
    return cv2.imread(filename)

def display_image(image, title):
    cv2.imshow(title, image)
    cv2.waitKey()

def save_image(image, filename):
    cv2.imwrite(filename, image)


# Rest of your code remains the same

def encrypt_button_click():
    mode = mode_var.get()
    if mode != DES.MODE_CBC and mode != DES.MODE_ECB:
        print('Only CBC and ECB mode supported...')
        sys.exit()

    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    imageOrig = load_image(file_path)
    display_image(imageOrig, "Original image")
    start_time = time.time()
    encryptedImage = encrypt_image(imageOrig, key, mode)
    stop_time=time.time()
    print(f"{stop_time-start_time} encrypt")
    #print(key.decode('utf-8'))
    display_image(encryptedImage, "Encrypted image")

    encrypted_filename = f'{mode_names.get(mode, "unknown")}_encrypted_{file_path.split("/")[-1]}.bmp'
    print(encrypted_filename)
    save_image(encryptedImage, encrypted_filename)

def decrypt_button_click():
    mode = mode_var.get()
    if mode != DES.MODE_CBC and mode != DES.MODE_ECB:
        print('Only CBC and ECB mode supported...')
        sys.exit()

    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    encryptedImage = load_image(file_path)
    start_time=time.time()
    decryptedImage = decrypt_image(encryptedImage, key, mode)
    stop_time = time.time()
    print(f"{stop_time - start_time} decrypt")
    #print(key.decode())


    display_image(decryptedImage, "Decrypted Image")

def set_mode():
    mode = mode_var.get()
    mode_label.config(text=f"Selected Mode: {mode_names.get(mode, 'Unknown')}")

def set_key():
    global key
    key_str = key_entry.get()
    key_bytes = key_str.encode('utf-8')

    if len(key_bytes) != 8:
        key_entry.delete(0, tk.END)  # Clear any existing text in the Entry widget
        key_entry.insert(0, "Key must be 8 bytes")
    else:
        key = key_bytes
def generate_random_key():
    global key
    key = get_random_bytes(8)
    key_entry.delete(0, tk.END)  # Clear any existing text in the Entry widget
    key_entry.insert(0, "Generated Random Key")

def save_key_to_file():
    global key
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "wb") as key_file:
            key_file.write(key)
            key_entry.delete(0, tk.END)  # Clear any existing text in the Entry widget
            key_entry.insert(0, "Key was written to file")

# Function to read the key from a text file
def read_key_from_file():
    global key
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        try:
            with open(file_path, "rb") as key_file:
                key = key_file.read()
                key_entry.delete(0, tk.END)  # Clear any existing text in the Entry widget
                key_entry.insert(0, "Key was readed from file")
        except FileNotFoundError:
            key_entry.delete(0, tk.END)  # Clear any existing text in the Entry widget
            key_entry.insert(0, "File Not Found")


root = tk.Tk()
root.title("Image Encryption/Decryption")


root.geometry("500x400")
title_label = tk.Label(root, text="DES Image Encryption", font=("Helvetica", 16))
title_label.pack(pady=10)
title_label.pack(anchor=tk.N)

# Create two frames to separate the button groups
mode_var = tk.IntVar()
mode_var.set(DES.MODE_CBC)

key_frame = tk.Frame(root)
key_frame.pack(side=tk.LEFT, padx=10)

action_frame = tk.Frame(root)
action_frame.pack(side=tk.RIGHT, padx=10)

# Entry widget for key input
key_label = tk.Label(key_frame, text="Enter Key:")
key_label.pack()
key_entry = tk.Entry(key_frame, width=40)
key_entry.pack()
set_key_button = tk.Button(key_frame, text="Set Key", command=set_key)
set_key_button.pack()
generate_key_button = tk.Button(key_frame, text="Generate Random Key", command=generate_random_key)
generate_key_button.pack()
save_key_button = tk.Button(key_frame, text="Save Key to File", command=save_key_to_file)
save_key_button.pack()
read_key_button = tk.Button(key_frame, text="Read Key from File", command=read_key_from_file)
read_key_button.pack()

mode_label = tk.Label(action_frame, text="Selected Mode: None")
mode_label.pack()
for mode_value, mode_name in mode_names.items():
    mode_radio = tk.Radiobutton(action_frame, text=mode_name, variable=mode_var, value=mode_value, command=set_mode)
    mode_radio.pack(anchor=tk.W)


line_canvas = tk.Canvas(root, width=2, height=600, bg="black")
line_canvas.pack(side=tk.LEFT)

encrypt_button = tk.Button(action_frame, text="Encrypt Image", command=encrypt_button_click)
encrypt_button.pack(side=tk.TOP, fill=tk.BOTH, anchor=tk.N)

decrypt_button = tk.Button(action_frame, text="Decrypt Image", command=decrypt_button_click)
decrypt_button.pack(side=tk.TOP, fill=tk.BOTH, anchor=tk.N)



root.mainloop()

