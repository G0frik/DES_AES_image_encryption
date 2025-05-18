import numpy as np
import cv2
import struct
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import traceback
# Before hiding
import hashlib
import time
from functools import wraps

def timeit(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        print(f"[⏱️] Running '{func.__name__}'...")
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"[✅] '{func.__name__}' completed in {end_time - start_time:.4f} seconds\n")
        return result
    return wrapper

class ImageEncryptorlsb:
    SEED_LENGTH_BITS_RSA_SIZE = 2048
    CHANNELS = 3
    SEED_HEADER_PIXELS  = int((SEED_LENGTH_BITS_RSA_SIZE / CHANNELS) + ((SEED_LENGTH_BITS_RSA_SIZE % CHANNELS) != 0))

    def __init__(self, cipher=None, mode=None, key=None, rsa_public_key=None, rsa_private_key=None,
                 use_rsa_encryption=False):
        self.cipher = cipher
        self.mode = mode
        self.key = key
        self.use_rsa_encryption = use_rsa_encryption
        self.rsa_public_key = rsa_public_key
        self.rsa_private_key = rsa_private_key

    def rsa_encrypt(self, data: bytes) -> bytes:
        cipher_rsa = PKCS1_OAEP.new(self.rsa_public_key)
        return cipher_rsa.encrypt(data)

    def rsa_decrypt(self, encrypted_data: bytes) -> bytes:
        cipher_rsa = PKCS1_OAEP.new(self.rsa_private_key)
        return cipher_rsa.decrypt(encrypted_data)

    def hide_data_in_image_seeded(self, image_path, binary_data, output_path, seed):
        """
        Hide binary data in an image using seeded LSB steganography

        Args:
            image_path (str): Path to the cover image
            binary_data (bytes): Binary data to hide
            output_path (str): Path to save the image with hidden data
            seed (int): Seed for random bit placement

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Open the image with OpenCV
            img = cv2.imread(image_path)
            if img is None:
                print(f"Error: Could not open image {image_path}")
                return False

            height, width, channels = img.shape

            # Calculate maximum data capacity (in bytes)
            # We're using 1 bit per color channel, so 3 bits per pixel
            max_bytes = (width * height * channels) // 8

            # Encrypt the seed if using RSA
            len_data = len(binary_data)
            len_bytes = len_data.to_bytes(4,byteorder="big")
            if self.use_rsa_encryption:
                if self.rsa_public_key is None:
                    print("RSA public key not provided.")
                    return False
                seed_bytes = seed.to_bytes(4, byteorder='big')
                plain_header=seed_bytes + len_bytes
                encrypted_header = self.rsa_encrypt(plain_header)
                print("Hash of plaintext seed (before encrypting):", hashlib.sha256(seed_bytes).hexdigest())

                # After extracting

                if len(encrypted_header)*8 != self.SEED_LENGTH_BITS_RSA_SIZE:
                    print("Encrypted seed has unexpected length.")
                    return False
            else:
                encrypted_header = b''
            # Prepend encrypted seed to image in fixed pixel range

            print(len_data,"len_Data")
            data_to_hide = binary_data
            binary_bits = [int(bit) for byte in data_to_hide for bit in format(byte, '08b')]

            #seed_data_bits = [int(bit) for byte in encrypted_seed for bit in format(byte, '08b')]
            header_bits = [int(bit) for byte in encrypted_header for bit in format(byte, '08b')]

            if (len(header_bits) + len(binary_bits)) > height * width * channels:
                print("Data + seed too large for image.")
                return False


            # Step 1: Embed encrypted seed at fixed pixel range
            for i, bit in enumerate(header_bits):
                pixel_idx = i // 3
                ch = i % 3
                y = pixel_idx // width
                x = pixel_idx % width
                img[y, x, ch] = (img[y, x, ch] & 0xFE) | bit

            # Step 2: Use seed (not encrypted) to randomize rest of embedding

# The original value is known at embedding time
            if len(str(seed)) < 8:
                print("Seed must be at least 8 digits long.")
                return False
            random.seed(seed)

            data_start_index = self.SEED_HEADER_PIXELS * 3
            available_indices = list(range(data_start_index, height * width * channels))
            positions = random.sample(available_indices, len(binary_bits))
            #print(available_indices,"available_indices",len(binary_bits),"len_binary_bits")

            for i, pos in enumerate(positions):
                pixel_idx = pos // channels
                ch = pos % channels
                y = pixel_idx // width
                x = pixel_idx % width
                img[y, x, ch] = (img[y, x, ch] & 0xFE) | binary_bits[i]

            cv2.imwrite(output_path, img)
            print("Data hidden successfully.")
            return img

        except Exception as e:
            print(f"Error hiding data: {e}")
            return False


    def extract_data_from_image_seeded(self, image_path):
        """
        Extract hidden binary data from an image using the same seed

        Args:
            image_path (str): Path to the image with hidden data

        Returns:
            bytes: Extracted binary data or None if failed
        """
        try:
            img = cv2.imread(image_path)
            if img is None:
                print(f"Error: Could not open image {image_path}")
                return None

            height, width, channels = img.shape

            flat_img = img.reshape(-1)

            # Step 1: Extract the encrypted seed (assumed fixed in first pixels)
            encrypted_seed_bits = flat_img[:self.SEED_LENGTH_BITS_RSA_SIZE] & 1
            encrypted_seed_bytes = np.packbits(encrypted_seed_bits).tobytes()

            if self.use_rsa_encryption:
                if self.rsa_private_key is None:
                    print("RSA private key not provided.")
                    return None

                #print(type(encrypted_seed_bytes),len(encrypted_seed_bytes),encrypted_seed_bytes)
                seed_bytes = self.rsa_decrypt(encrypted_seed_bytes)
                seed_value = int.from_bytes(seed_bytes[:4], 'big')
                print("Hash of extracted seed:", hashlib.sha256(seed_bytes[:4]).hexdigest())
                len_data= int.from_bytes(seed_bytes[4:], 'big')

                if len_data <= 0:
                    print("Invalid extracted data length.")
                    return None
            else:
                print("RSA decryption required but disabled.")
                return None

            random.seed(seed_value)
            total_pixels = height * width * channels
            data_start_index = self.SEED_HEADER_PIXELS * 3
            print(total_pixels,data_start_index,"total_pixels","data_start_index")
            len_bits= len_data * 8
            positions = random.sample(range(data_start_index, total_pixels), len_bits)

            positions_arr = np.array(positions)
            ys = (positions_arr // channels) // width
            xs = (positions_arr // channels) % width
            chs = positions_arr % channels

            bits = img[ys, xs, chs] & 1

            # Read length field

            #length_bits = bits[:32]
            #length = int(''.join(str(bit) for bit in length_bits), 2)
            length=len_data
            #print("Extracted length:", length)

            if length <= 0:
                print("Invalid extracted length.")
                return None
            print("Extracted length:", type(length),length,length*8)
            # Extract actual message
            message_bits = bits[32:32 + length * 8]
            output = bytearray()
            #print("Extracted message bits:", message_bits)
            for i in range(0, len(message_bits), 8):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | message_bits[i + j]
                output.append(byte)

            return bytes(output)

        except Exception as e:
            print(f"Error extracting data: {e}")
            traceback.print_exc()
            return None

    @timeit
    def hide_file_in_image_seeded(self, image_path, file_path, output_path, seed):
        """
        Hide a file in an image using seeded LSB steganography

        Args:
            image_path (str): Path to the cover image
            file_path (str): Path to the file to hide
            output_path (str): Path to save the image with hidden file
            seed (int): Seed for the random bit placement

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Read the file to hide
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Hide the file data in the image
            return self.hide_data_in_image_seeded(image_path, file_data, output_path, seed)

        except FileNotFoundError:
            print(f"Error: File {file_path} not found")
            return False
        except Exception as e:
            print(f"Error hiding file: {e}")
            return False

    @timeit
    def extract_file_from_image_seeded(self, image_path, output_file_path):
        """
        Extract a hidden file from an image using seeded LSB steganography

        Args:
            image_path (str): Path to the image with hidden file
            output_file_path (str): Path to save the extracted file

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Extract the hidden data
            extracted_data = self.extract_data_from_image_seeded(image_path)

            if extracted_data:
                # Write the extracted data to a file
                with open(output_file_path, 'wb') as f:
                    f.write(extracted_data)
                return True
            else:
                return False

        except Exception as e:
            print(f"Error extracting file: {e}")
            return False

        # The original methods are kept for compatibility

    def hide_data_in_image(self, image_path, binary_data, output_path):

        try:
            # Open the image with OpenCV
            img = cv2.imread(image_path)
            if img is None:
                print(f"Error: Could not open image {image_path}")
                return False

            height, width, channels = img.shape

            # Calculate maximum data capacity (in bytes)
            # We're using 1 bit per color channel, so 3 bits per pixel
            max_bytes = (width * height * channels) // 8

            # Prepare the data - first 4 bytes store data length
            data_len = len(binary_data)

            if data_len > max_bytes - 4:
                print(f"Data too large. Maximum capacity: {max_bytes - 4} bytes")
                return False

            # Convert data length to bytes (4 bytes, big-endian)
            len_bytes = struct.pack('>I', data_len)

            # Combine length and actual data
            data_to_hide = len_bytes + binary_data

            # Convert data to bits
            binary_bits = []
            for byte in data_to_hide:
                binary_bits.extend([int(bit) for bit in format(byte, '08b')])

            # Ensure binary_bits doesn't exceed image capacity
            binary_bits = binary_bits[:height * width * channels]

            # Convert image to numpy array for processing
            img_array = np.array(img)

            # Process each color channel separately to prevent data type issues
            data_index = 0
            for i in range(height):
                for j in range(width):
                    for k in range(channels):
                        if data_index < len(binary_bits):
                            # Clear the LSB and set it to the data bit
                            img_array[i, j, k] = (img_array[i, j, k] & 0xFE) | binary_bits[data_index]
                            data_index += 1
                        else:
                            # No more data to hide
                            break

            # Save the image with hidden data
            cv2.imwrite(output_path, img_array)

            return True

        except Exception as e:
            print(f"Error hiding data: {e}")
            return False

    def extract_data_from_image(self, image_path):

        try:
            # Open the image with OpenCV
            img = cv2.imread(image_path)
            if img is None:
                print(f"Error: Could not open image {image_path}")
                return None

            height, width, channels = img.shape

            # Extract LSB from each byte in the image
            extracted_bits = []
            for i in range(height):
                for j in range(width):
                    for k in range(channels):
                        # Extract the LSB
                        extracted_bits.append(img[i, j, k] & 1)

            # Convert bits to bytes
            extracted_bytes = bytearray()
            for i in range(0, len(extracted_bits), 8):
                if i + 8 <= len(extracted_bits):
                    byte = 0
                    for j in range(8):
                        byte = (byte << 1) | extracted_bits[i + j]
                    extracted_bytes.append(byte)

            # First 4 bytes contain the length of actual data
            if len(extracted_bytes) < 4:
                print("Error: Image doesn't contain enough data")
                return None

            data_len = struct.unpack('>I', extracted_bytes[:4])[0]

            # Validate data length to avoid potential issues
            if data_len <= 0 or data_len > len(extracted_bytes) - 4:
                print(f"Error: Invalid data length detected: {data_len}")
                return None

            # Extract the actual data
            extracted_data = extracted_bytes[4:4 + data_len]

            return bytes(extracted_data)

        except Exception as e:
            print(f"Error extracting data: {e}")
            return None

    @timeit
    def hide_file_in_image(self, image_path, file_path, output_path):

        try:
            # Read the file to hide
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Hide the file data in the image
            return self.hide_data_in_image(image_path, file_data, output_path)

        except FileNotFoundError:
            print(f"Error: File {file_path} not found")
            return False
        except Exception as e:
            print(f"Error hiding file: {e}")
            return False

    @timeit
    def extract_file_from_image(self, image_path, output_file_path):

        try:
            # Extract the hidden data
            extracted_data = self.extract_data_from_image(image_path)

            if extracted_data:
                # Write the extracted data to a file
                with open(output_file_path, 'wb') as f:
                    f.write(extracted_data)
                return True
            else:
                return False

        except Exception as e:
            print(f"Error extracting file: {e}")
            return False

encryptor = ImageEncryptorlsb()
encryptor.use_rsa_encryption = True
encryptor.rsa_public_key = RSA.import_key(open("rsa_keys//publickey_20250424113120.pem").read())
print(encryptor.rsa_public_key)
encryptor.rsa_private_key = RSA.import_key(open("rsa_keys//privatekey_20250424113120.pem").read())

# Example with standard LSB steganography
#binary_data = b"This is a secret message"
#encryptor.hide_data_in_image("tux_clear.bmp", binary_data, "hidden_data.png")

#extracted = encryptor.extract_data_from_image("hidden_data.png")
#if extracted:
#    print("Standard LSB message:", extracted.decode('utf-8'))

# Example with seeded LSB steganography
seed_value = 99999999  # Can be any integer
print("Seed value:", len(str(seed_value)),"text")

#encryptor.hide_data_in_image_seeded("tux_clear.bmp", binary_data, "hidden_data_seeded.png", seed_value)

#extracted_seeded = encryptor.extract_data_from_image_seeded("hidden_data_seeded.png")
#if extracted_seeded:
#    print("Seeded LSB message:", extracted_seeded.decode('utf-8'))

#encryptor.hide_file_in_image("SamplePNGImage_30mbmb.png","SamplePNGImage_5mbmb.png","hidden_file_5mb_in_30mb.png")
#encryptor.extract_file_from_image("hidden_file_5mb_in_30mb.png", "extracted_5mb_file.png")
#encryptor.hide_file_in_image_seeded("SamplePNGImage_30mbmb.png","SamplePNGImage_5mbmb.png","hidden_file_5mb_in_30mb_seeded.png", seed_value)
#extracted_file_seeded = encryptor.extract_file_from_image_seeded("hidden_file_5mb_in_30mb_seeded.png", "extracted_5mb_file_seeded.png")

encryptor.hide_file_in_image_seeded("SamplePNGImage_20mbmb.png","SamplePNGImage_1mbmb.png","hidden_file_1mb_in_20mb_seeded.png", seed_value)
extracted_file_seeded = encryptor.extract_file_from_image_seeded("hidden_file_1mb_in_20mb_seeded.png", "extracted_1mb_file_seeded.png")

