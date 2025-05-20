from os import times_result

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
from Crypto.Random import get_random_bytes

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
    HEADER_LENGTH_BITS_RSA = 2048
    SEED_SIZE= 4
    LEN_DATA_POSITION = SEED_SIZE + 4
    EXPECTED_SEED_HASH_POSITION = SEED_SIZE + 4 + 32
    EXPECTED_DATA_HASH_POSITION = SEED_SIZE + 4 + 32 + 32


    def __init__(self, cipher=None, mode=None, key=None, rsa_public_key=None, rsa_private_key=None,
                 use_rsa_encryption=False):
        self.use_rsa_encryption = use_rsa_encryption
        self.rsa_public_key = rsa_public_key
        self.rsa_private_key = rsa_private_key


    def rsa_encrypt(self, data: bytes) -> bytes:
        cipher_rsa = PKCS1_OAEP.new(self.rsa_public_key)
        return cipher_rsa.encrypt(data)

    def rsa_decrypt(self, encrypted_data: bytes) -> bytes:
        cipher_rsa = PKCS1_OAEP.new(self.rsa_private_key)
        return cipher_rsa.decrypt(encrypted_data)

    def hide_data_in_image_seeded(self, image_path, binary_data, output_path):




        time_start_start=time.time()
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
            img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
            height, width, channels = img.shape
            flat_img = img.reshape(-1)  # flatten
            HEADER_PIXELS = int((self.HEADER_LENGTH_BITS_RSA / channels) + ((self.HEADER_LENGTH_BITS_RSA % channels) != 0))

            if img is None:
                print(f"Error: Could not open image {image_path}")
                return False


            # Calculate maximum data capacity (in bytes)
            # We're using 1 bit per color channel, so 3 bits per pixel
            #max_bytes = (width * height * channels) // 8

            # Encrypt the seed if using RSA
            len_data = len(binary_data)
            len_bytes = len_data.to_bytes(4,byteorder="big")

            if self.use_rsa_encryption:
                if self.rsa_public_key is None:
                    print("Error: RSA public key not provided.")
                    return False

                data_hash = hashlib.sha256(binary_data).digest()
                #seed_bytes = seed.to_bytes(4, byteorder='big')
                seed_bytes = get_random_bytes(self.SEED_SIZE)
                seed_value= int.from_bytes(seed_bytes, 'big')
                seed_hash=hashlib.sha256(seed_bytes).digest()
                print(type(seed_hash),len(seed_hash),seed_hash)

                plain_header=seed_bytes + len_bytes + seed_hash + data_hash
                encrypted_header = self.rsa_encrypt(plain_header)
                print("Hash of plaintext seed (before encrypting):",seed_hash.hex(),seed_value )

                # After extracting
                if len(encrypted_header)*8 != self.HEADER_LENGTH_BITS_RSA:
                    print("Error: Encrypted seed has unexpected length.")
                    return False


            #print(len_data,"len_Data")

            data_to_hide = binary_data
            #binary_bits = [int(bit) for byte in data_to_hide for bit in format(byte, '08b')]
            binary_bits = np.unpackbits(np.frombuffer(data_to_hide, dtype=np.uint8))

            #seed_data_bits = [int(bit) for byte in encrypted_seed for bit in format(byte, '08b')]

            #header_bits = [int(bit) for byte in encrypted_header for bit in format(byte, '08b')]
            header_bits = np.unpackbits(np.frombuffer(encrypted_header, dtype=np.uint8))

            if (len(header_bits) + len(binary_bits)) > height * width * channels:
                print("Error: Data + seed too large for image.")
                return False

            len_header_bits=len(header_bits)
            # Step 1: Embed encrypted seed at fixed pixel range
            """for i, bit in enumerate(header_bits):
                pixel_idx = i // 3
                ch = i % 3
                y = pixel_idx // width
                x = pixel_idx % width
                img[y, x, ch] = (img[y, x, ch] & 0xFE) | bit"""
            flat_img[:len_header_bits] = (flat_img[:len_header_bits] & 0xFE) | header_bits

            # Step 2: Use seed (not encrypted) to randomize rest of embedding

# The original value is known at embedding time


            data_start_index = HEADER_PIXELS * channels

            time_start=time.time()
            rng = np.random.default_rng(seed_value)
            positions= rng.choice(np.arange(data_start_index, height * width * channels), size=len(binary_bits), replace=False)
            time_end=time.time()
            print("Execution time rng.choice_hide:", time_end - time_start)
            print(positions[0:10], "positions", len(positions))

            time_start=time.time()
            # Changing code below to flattened array instead of 2D
            """for i, pos in enumerate(positions):
                pixel_idx = pos // channels
                ch = pos % channels
                y = pixel_idx // width
                x = pixel_idx % width
                img[y, x, ch] = (img[y, x, ch] & 0xFE) | binary_bits[i]"""

            #positions_arr = np.array(positions)
            """
            pixel_idx = positions_arr // channels
            ch = positions_arr % channels
            y = pixel_idx // width
            x = pixel_idx % width
"""
            # Flatten the image to 1D to modify easily:
            flat_img = img.reshape(-1)

            # Calculate flat positions in the flattened array
            #flat_positions = y * (width * channels) + x * channels + ch

            # Clear LSB and set bit in one go:
            flat_img[positions] = (flat_img[positions] & 0xFE) | binary_bits

            # Reshape back to original shape
            img = flat_img.reshape(height, width, channels)
            time_end_end = time.time()

            print("Execution time from the start of method :", time_end_end - time_start_start)
            time_end = time.time()
            cv2.imwrite(output_path, img)

            print("Execution time hiding bits:", time_end - time_start)
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
            img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
            if img is None:
                print(f"Error: Could not open image {image_path}")
                return None

            height, width, channels = img.shape
            HEADER_PIXELS = int((self.HEADER_LENGTH_BITS_RSA / channels) + ((self.HEADER_LENGTH_BITS_RSA % channels) != 0))
            #print(HEADER_PIXELS)
            flat_img = img.reshape(-1)

            # Step 1: Extract the encrypted seed (assumed fixed in first pixels)
            encrypted_seed_bits = flat_img[:self.HEADER_LENGTH_BITS_RSA] & 1
            encrypted_seed_bytes = np.packbits(encrypted_seed_bits).tobytes()

            if self.use_rsa_encryption:
                if self.rsa_private_key is None:
                    print("Error: RSA private key not provided.")
                    return None

                #print(type(encrypted_seed_bytes),len(encrypted_seed_bytes),encrypted_seed_bytes)
                seed_bytes = self.rsa_decrypt(encrypted_seed_bytes)
                seed_value = int.from_bytes(seed_bytes[:self.SEED_SIZE], 'big')
                len_data = int.from_bytes(seed_bytes[self.SEED_SIZE:self.LEN_DATA_POSITION], 'big')


                actual_seed_hash= hashlib.sha256(seed_bytes[:self.SEED_SIZE]).digest()
                #print(seed_value,"seed_value")
                #print(actual_seed_hash,"actual_seed_hash")
                expected_seed_hash = seed_bytes[self.LEN_DATA_POSITION:self.EXPECTED_SEED_HASH_POSITION]

                if actual_seed_hash != expected_seed_hash:
                    print("Error: Hash mismatch! Extracted seed may be corrupted or tampered with.")
                    return None
                elif actual_seed_hash == expected_seed_hash:
                    print("Hash match: seed integrity verified.")
                print("Hash of extracted seed:", hashlib.sha256(seed_bytes[:self.SEED_SIZE]).hexdigest())


                expected_data_hash = seed_bytes[self.EXPECTED_SEED_HASH_POSITION:self.EXPECTED_DATA_HASH_POSITION]

                if len_data <= 0:
                    print("Error: Invalid extracted data length.")
                    return None
            else:
                print("Error: RSA decryption required but disabled.")
                return None

            #random.seed(seed_value)
            total_pixels = height * width * channels
            data_start_index = HEADER_PIXELS * channels
            print(total_pixels,data_start_index,"total_pixels","data_start_index")
            len_bits= len_data * 8
            #get execution time
            #positions = random.sample(range(data_start_index, total_pixels), len_bits)

            rng = np.random.default_rng(seed_value)
            time.start1=time.time()
            print("data_start_index",data_start_index,"total_pixels",total_pixels,"len_bits",len_bits,"rng.choice")
            positions = rng.choice(np.arange(data_start_index, total_pixels), size=len_bits, replace=False)
            time.end1=time.time()
            print("Execution time rng.choice:", time.end1 - time.start1)
            print(positions[0:10],"positions",len(positions),"len_bits",len_bits)
            print(positions)

            # Changing code below to flattened array instead of 2D
            #positions_arr = np.array(positions)
            """
            
            ys = (positions_arr // channels) // width
            xs = (positions_arr // channels) % width
            chs = positions_arr % channels

            bits = img[ys, xs, chs] & 1"""
            bits = flat_img[positions] & 1

            # Read length field

            #length_bits = bits[:32]
            #length = int(''.join(str(bit) for bit in length_bits), 2)
            length=len_data
            #print("Extracted length:", length)

            if length <= 0:
                print("Error: Invalid extracted length.")
                return None
            print("Extracted length:", type(length),length,length*8)
            # Extract actual message
            message_bits = bits[: len_bits]
            # Convert bits (0/1) to a NumPy array if not already
            message_bits_np = np.array(message_bits, dtype=np.uint8)

            # Pack bits into bytes (8 bits per byte, MSB first)
            output = np.packbits(message_bits_np).tobytes()

            actual_data_hash = hashlib.sha256(output).digest()

            if actual_data_hash != expected_data_hash:
                print("Error: Hash mismatch! Extracted data may be corrupted or tampered with.")
                return None
            else:
                print("Hash match: data integrity verified.")

            return bytes(output)

        except Exception as e:
            print(f"Error extracting data: {e}")
            traceback.print_exc()
            return None

    @timeit
    def hide_file_in_image_seeded(self, image_path, file_path, output_path):
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
            return self.hide_data_in_image_seeded(image_path, file_data, output_path)

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


#encryptor.hide_data_in_image_seeded("tux_clear.bmp", binary_data, "hidden_data_seeded.png", seed_value)

#extracted_seeded = encryptor.extract_data_from_image_seeded("hidden_data_seeded.png")
#if extracted_seeded:
#    print("Seeded LSB message:", extracted_seeded.decode('utf-8'))

#encryptor.hide_file_in_image("SamplePNGImage_30mbmb.png","SamplePNGImage_5mbmb.png","hidden_file_5mb_in_30mb.png")
#encryptor.extract_file_from_image("hidden_file_5mb_in_30mb.png", "extracted_5mb_file.png")
encryptor.hide_file_in_image_seeded("SamplePNGImage_30mbmb.png","SamplePNGImage_5mbmb.png","hidden_file_5mb_in_30mb_seeded.png")
extracted_file_seeded = encryptor.extract_file_from_image_seeded("hidden_file_5mb_in_30mb_seeded.png", "extracted_5mb_file_seeded.png")


"""

encryptor.hide_file_in_image_seeded("SamplePNGImage_20mbmb.png","SamplePNGImage_1mbmb.png","hidden_file_1mb_in_20mb_seeded.png", seed_value)
extracted_file_seeded = encryptor.extract_file_from_image_seeded("hidden_file_1mb_in_20mb_seeded.png", "extracted_1mb_file_seeded.png")
"""

