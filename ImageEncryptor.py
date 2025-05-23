import hashlib
import struct
import time
import traceback
import uuid
from functools import wraps

import cv2
import numpy as np
import os
import tempfile
import shutil
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad



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

class ImageEncryptor:
    HEADER_LENGTH_BITS_RSA = 2048
    SEED_SIZE= 4
    LEN_DATA_POSITION = SEED_SIZE + 4
    EXPECTED_SEED_HASH_POSITION = SEED_SIZE + 4 + 32
    EXPECTED_DATA_HASH_POSITION = SEED_SIZE + 4 + 32 + 32
    CHUNK_SIZE = 64 * 1024  # 64 KB

    def __init__(self, cipher=None, mode=None, key=None, rsa_public_key=None, rsa_private_key=None, use_rsa_encryption=False):
        self.cipher = cipher
        self.mode = mode
        self.key = key
        self.use_rsa_encryption = use_rsa_encryption
        self.rsa_public_key = rsa_public_key
        self.rsa_private_key = rsa_private_key
    @staticmethod
    def generate_uuid(length=8):
        """Generate a UUID and return the first 'length' characters as a string."""
        return str(uuid.uuid4()).replace('-', '')[:length]

    @staticmethod
    def extract_frames_to_temp(video_path, duration_sec=15):
        cap = cv2.VideoCapture(video_path)

        if not cap.isOpened():
            raise IOError(f"Failed to open video: {video_path}")

        # Get FPS from video
        fps = cap.get(cv2.CAP_PROP_FPS)
        print(f"FPS: {fps}")
        if fps == 0:
            raise ValueError("Could not determine FPS of the video.")

        temp_dir = tempfile.mkdtemp(prefix="frames_")
        max_frames = int(duration_sec * fps)
        print(f"Extracting frames for {duration_sec} seconds (up to {max_frames} frames)...")
        frame_count = 0

        while frame_count < max_frames:
            ret, frame = cap.read()
            if not ret:
                break
            frame_path = os.path.join(temp_dir, f"frame_{frame_count:04d}.png")
            ImageEncryptor.save_image(frame,frame_path)
            frame_count += 1

        cap.release()
        print(f"Extracted {frame_count} frames at {fps:.2f} FPS to temporary directory '{temp_dir}'")
        return temp_dir, int(fps)  # Also return the detected FPS
    @staticmethod
    def reassemble_video_from_frames(frame_dir, output_video_path, fps=30, compare_mode=False):
        try:
            # Use '.png' if compare_mode is True, otherwise only 'encrypted.png'
            frame_files = sorted([
                f for f in os.listdir(frame_dir)
                if (f.endswith('.png') if compare_mode else f.endswith('encrypted.png'))
            ])

            if not frame_files:
                raise ValueError("No suitable PNG frames found in the directory.")

            # Read first frame to get video dimensions
            first_frame_path = os.path.join(frame_dir, frame_files[0])
            first_frame = ImageEncryptor.load_image(first_frame_path)
            if first_frame is None:
                raise ValueError(f"Could not read the first frame: {first_frame_path}")
            height, width, _ = first_frame.shape

            fourcc = cv2.VideoWriter_fourcc(*'mp4v')  # Use 'mp4v' for compatibility
            out = cv2.VideoWriter(output_video_path, fourcc, fps, (width, height))

            for file_name in frame_files:
                frame_path = os.path.join(frame_dir, file_name)
                frame = ImageEncryptor.load_image(frame_path)
                if frame is None:
                    print(f"Warning: Skipping unreadable frame: {frame_path}")
                    continue
                out.write(frame)

            out.release()
            shutil.rmtree(frame_dir)
            print(f"Video saved to '{output_video_path}' and temporary directory removed.")
        except Exception as e:
            print(f"[ERROR] Failed to reassemble video: {e}")
            if 'out' in locals():
                out.release()
            if os.path.exists(frame_dir):
                shutil.rmtree(frame_dir, ignore_errors=True)

    def generate_key(self, cipher_type):
        if cipher_type == DES:
            self.key = get_random_bytes(8)
        elif cipher_type == AES:
            self.key = get_random_bytes(32)
        else:
            raise ValueError("Unsupported cipher for key generation.")

        return self.key
    @staticmethod
    def load_image(filename):
        return cv2.imread(filename,cv2.IMREAD_UNCHANGED)

    @staticmethod
    def save_image(image, filename):
        cv2.imwrite(filename, image)

    @staticmethod
    def display_image(image, title):
        cv2.imshow(title, image)
        cv2.waitKey()
        cv2.destroyAllWindows()

    def rsa_encrypt(self, data: bytes) -> bytes:
        """
        Encrypts the given data using RSA public key encryption.
        Args:
            data (bytes): The data to encrypt.
        Returns:
            bytes: The encrypted data
        """
        cipher_rsa = PKCS1_OAEP.new(self.rsa_public_key)
        return cipher_rsa.encrypt(data)

    def rsa_decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypts the given data using RSA private key decryption.
        Args:
            encrypted_data (bytes): The data to decrypt.
        Returns:
            bytes: The decrypted data
        """
        cipher_rsa = PKCS1_OAEP.new(self.rsa_private_key)
        return cipher_rsa.decrypt(encrypted_data)

    def encrypt(self, image):
        if self.cipher is None or self.mode is None:
            raise ValueError("Cipher and mode must be set before encryption.")

        rowOrig, columnOrig, depthOrig = image.shape
        imageBytes = image.tobytes()

        if self.cipher == DES:
            ivSize = DES.block_size if self.mode == DES.MODE_CBC else 0
            iv = get_random_bytes(ivSize)
            cipher = DES.new(self.key, self.mode, iv) if self.mode == DES.MODE_CBC else DES.new(self.key, self.mode)
        elif self.cipher == AES:
            ivSize = AES.block_size if self.mode == AES.MODE_CBC else 0
            iv = get_random_bytes(ivSize)
            if self.mode == AES.MODE_CBC:
                cipher = AES.new(self.key, AES.MODE_CBC, iv)
            elif self.mode == AES.MODE_GCM:
                nonce = get_random_bytes(12)
                cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
                ciphertext, tag = cipher.encrypt_and_digest(imageBytes)

                nonceSize = len(nonce)
                tagSize = len(tag)
                rsa_key_size = 256 if self.rsa_public_key else 0

                void = columnOrig * depthOrig - nonceSize - tagSize - rsa_key_size
                parts = [nonce, tag]

                if self.use_rsa_encryption and self.rsa_public_key:
                    parts.append(self.rsa_encrypt(self.key))

                parts.append(ciphertext)
                buffer = b''.join(parts) + bytes(void)
                encryptedImage = np.frombuffer(buffer, dtype=image.dtype).reshape(rowOrig + 1, columnOrig, depthOrig)
                return encryptedImage

            elif self.mode == AES.MODE_CTR:
                nonce = get_random_bytes(12)
                cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
                ciphertext = cipher.encrypt(imageBytes)

                nonceSize = 12
                rsa_key_size = 256 if self.rsa_public_key else 0

                void = columnOrig * depthOrig - nonceSize - rsa_key_size
                parts = [nonce]

                if self.use_rsa_encryption and self.rsa_public_key:
                    parts.append(self.rsa_encrypt(self.key))

                parts.append(ciphertext)
                buffer = b''.join(parts) + bytes(void)
                encryptedImage = np.frombuffer(buffer, dtype=image.dtype).reshape(rowOrig + 1, columnOrig, depthOrig)
                return encryptedImage

            else:
                cipher = AES.new(self.key, self.mode)
                iv = None
        else:
            raise ValueError("Unsupported cipher.")

        # Standard CBC / ECB encryption
        imageBytesPadded = pad(imageBytes, cipher.block_size)
        ciphertext = cipher.encrypt(imageBytesPadded)

        paddedSize = len(imageBytesPadded) - len(imageBytes)
        rsa_key_size = 256 if self.rsa_public_key else 0

        void = columnOrig * depthOrig - ivSize - paddedSize - rsa_key_size
        parts = []
        if iv:
            parts.append(iv)
        if self.use_rsa_encryption and self.rsa_public_key:
            parts.append(self.rsa_encrypt(self.key))

        parts.append(ciphertext)

        buffer = b''.join(parts) + bytes(void)
        encryptedImage = np.frombuffer(buffer, dtype=image.dtype).reshape(rowOrig + 1, columnOrig, depthOrig)
        return encryptedImage

    def decrypt(self, encrypted_image):
        if self.cipher is None or self.mode is None:
            raise ValueError("Cipher and mode must be set before decryption.")

        rowEncrypted, columnOrig, depthOrig = encrypted_image.shape
        rowOrig = rowEncrypted - 1
        encryptedBytes = encrypted_image.tobytes()

        if self.cipher == DES:
            block_size = DES.block_size
        elif self.cipher == AES:
            block_size = AES.block_size
        else:
            raise ValueError("Unsupported cipher.")

        rsa_key_size = 256 if self.use_rsa_encryption and self.rsa_private_key else 0
        nonceSize = 12 if self.mode in [AES.MODE_CTR, AES.MODE_GCM] else 0
        ivSize = block_size if self.mode == self.cipher.MODE_CBC else 0
        tagSize = 16 if self.mode == AES.MODE_GCM else 0

        iv = encryptedBytes[:ivSize] if ivSize else None
        nonce = encryptedBytes[:nonceSize] if nonceSize else None
        tag = encryptedBytes[nonceSize: nonceSize + tagSize] if self.mode == AES.MODE_GCM else None

        # Decrypt the RSA-encrypted key if RSA private key is provided
        if self.use_rsa_encryption and self.rsa_private_key:
            if self.mode == AES.MODE_GCM:
                rsa_encrypted_key = encryptedBytes[nonceSize + tagSize: nonceSize + tagSize + rsa_key_size]
            elif self.mode == AES.MODE_CTR:
                rsa_encrypted_key = encryptedBytes[nonceSize: nonceSize + rsa_key_size]
            elif self.mode == self.cipher.MODE_CBC:
                rsa_encrypted_key = encryptedBytes[ivSize: ivSize + rsa_key_size]
            elif self.mode == self.cipher.MODE_ECB:
                rsa_encrypted_key = encryptedBytes[:rsa_key_size]
            else:
                raise ValueError("Unsupported mode for RSA key decryption")

            self.key = self.rsa_decrypt(rsa_encrypted_key)
        elif self.key is None:
            raise ValueError("Either key or rsa_private_key must be provided")

        imageOrigBytesSize = rowOrig * columnOrig * depthOrig
        paddedSize = (imageOrigBytesSize // block_size + 1) * block_size - imageOrigBytesSize

        if self.mode == AES.MODE_GCM:
            encrypted_start = nonceSize + tagSize + rsa_key_size
        elif self.mode == AES.MODE_CTR:
            encrypted_start = nonceSize + rsa_key_size
        else:
            encrypted_start = ivSize + rsa_key_size

        encrypted = encryptedBytes[encrypted_start: encrypted_start + imageOrigBytesSize + paddedSize]

        # Decrypt image
        if self.mode == self.cipher.MODE_CBC:
            cipher = self.cipher.new(self.key, self.mode, iv)
            decryptedImageBytesPadded = cipher.decrypt(encrypted)
            decryptedImageBytes = unpad(decryptedImageBytesPadded, block_size)
        elif self.mode == AES.MODE_CTR:
            encrypted = encryptedBytes[encrypted_start: encrypted_start + imageOrigBytesSize]
            cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
            decryptedImageBytes = cipher.decrypt(encrypted)
        elif self.mode == AES.MODE_GCM:
            encrypted = encryptedBytes[encrypted_start: encrypted_start + imageOrigBytesSize]
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            decryptedImageBytes = cipher.decrypt_and_verify(encrypted, tag)
        else:
            cipher = self.cipher.new(self.key, self.mode)
            decryptedImageBytesPadded = cipher.decrypt(encrypted)
            decryptedImageBytes = unpad(decryptedImageBytesPadded, block_size)

        # Shared conversion step
        decryptedImage = np.frombuffer(decryptedImageBytes, dtype=encrypted_image.dtype).reshape(rowOrig, columnOrig,
                                                                                                 depthOrig)
        return decryptedImage

    def encrypt_file(self, input_path, output_path):
        print(self.cipher,self.mode)
        if self.cipher != AES or self.mode not in [AES.MODE_GCM, AES.MODE_CTR]:
            raise ValueError("Only AES with GCM or CTR mode is supported.")

        # Generate IV or nonce
        iv = get_random_bytes(12 if self.mode == 'GCM' else 16)

        # Initialize AES cipher
        if self.mode == AES.MODE_GCM:
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        elif self.mode == AES.MODE_CTR:
            cipher = AES.new(self.key, AES.MODE_CTR, nonce=iv, initial_value=int.from_bytes(iv, 'big'))
        else:
            raise ValueError("Unsupported mode")

        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            # 1. Write IV or Nonce
            fout.write(iv)

            # 2. If RSA is used, encrypt and write the symmetric key
            if self.use_rsa_encryption and self.rsa_public_key:
                encrypted_key = self.rsa_encrypt(self.key)
                encrypted_key_size = len(encrypted_key)
                fout.write(struct.pack('H', encrypted_key_size))  # 2 bytes for key size
                fout.write(encrypted_key)
            else:
                fout.write(struct.pack('H', 0))  # 0-length marker

            # 3. Encrypt file in chunks
            while chunk := fin.read(self.CHUNK_SIZE):
                encrypted_chunk = cipher.encrypt(chunk)
                fout.write(encrypted_chunk)

            # 4. Write GCM tag if needed
            if self.mode == 'GCM':
                fout.write(cipher.digest())

    def decrypt_file(self, input_path, output_path):
        if self.cipher != AES or self.mode not in [AES.MODE_GCM, AES.MODE_CTR]:
            raise ValueError("Only AES with GCM or CTR mode is supported.")

        with open(input_path, 'rb') as fin:
            # 1. Read IV or nonce
            iv = fin.read(12 if self.mode == AES.MODE_GCM else 16)

            # 2. Read and decrypt symmetric key (if RSA was used)
            encrypted_key_size = struct.unpack('H', fin.read(2))[0]

            if encrypted_key_size > 0:
                encrypted_key = fin.read(encrypted_key_size)
                if not self.rsa_private_key:
                    raise ValueError("RSA private key required for decryption.")
                key = self.rsa_decrypt(encrypted_key)
            else:
                key = self.key

            # 3. Initialize AES cipher
            if self.mode == AES.MODE_GCM:
                # Reserve last 16 bytes for the GCM tag
                fin.seek(0, 2)
                file_size = fin.tell()
                tag_size = 16
                encrypted_data_len = file_size - (len(iv) + 2 + encrypted_key_size + tag_size)

                # Seek back to start of encrypted data
                fin.seek(len(iv) + 2 + encrypted_key_size)

                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

                with open(output_path, 'wb') as fout:
                    total_read = 0
                    while total_read < encrypted_data_len:
                        to_read = min(self.CHUNK_SIZE, encrypted_data_len - total_read)
                        chunk = fin.read(to_read)
                        if not chunk:
                            break
                        fout.write(cipher.decrypt(chunk))
                        total_read += len(chunk)

                    tag = fin.read(tag_size)
                    try:
                        cipher.verify(tag)
                    except ValueError:
                        raise ValueError("GCM tag verification failed! Decryption corrupted or tampered.")
            else:  # CTR mode
                cipher = AES.new(key, AES.MODE_CTR, initial_value=int.from_bytes(iv, 'big'))
                with open(output_path, 'wb') as fout:
                    while chunk := fin.read(self.CHUNK_SIZE):
                        fout.write(cipher.decrypt(chunk))

    # GCM tag at end

    def encrypt_video_frames(self,input_video,compare_mode=False):
        os.makedirs("encrypted_videos", exist_ok=True)
        video_filename = os.path.basename(input_video)
        print(f"Encrypting video: {video_filename}")

        # Step 1: Extract frames from video
        temp_frame_dir = ImageEncryptor.extract_frames_to_temp(input_video)
        output_video_name = os.path.join("encrypted_videos",
                                         f"encrypted_{os.path.splitext(video_filename)[0]}_{ImageEncryptor.generate_uuid()}.mp4")
        # Step 2: Encrypt each frame
        frame_files = [f for f in os.listdir(temp_frame_dir[0]) if f.endswith('.png')]
        for frame_file in frame_files:
            frame_path = os.path.join(temp_frame_dir[0], frame_file)
            encrypted_frame_path = frame_path.replace('.png', '_encrypted.png')

            frame_image = self.load_image(frame_path)
            encrypted_image = self.encrypt(frame_image)
            self.save_image(encrypted_image, encrypted_frame_path)

        print(f"Frames extracted from '{input_video}' and encrypted to '{temp_frame_dir[0]}' using {self.mode}.")
        print(f"Encrypted frames ready for reassembly into '{output_video_name}'.")
        ImageEncryptor.reassemble_video_from_frames(temp_frame_dir[0], output_video_name, fps=temp_frame_dir[1],
                                     compare_mode=compare_mode)

    def hide_data_in_image_seeded(self, img, binary_data, output_path=None):
        """
        Hide binary data in an image using seeded LSB steganography

        Args:
            img (ndarray): Image to hide data in
            binary_data (bytes): Binary data to hide
            output_path (str): Path to save the image with hidden data

        Returns:
            bytes: Modified image with hidden data or None if failed
        """
        time_start_start = time.time()
        try:
            # Step 1: Read the image using OpenCV
            #img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
            if img is None:
                print(f"Error: Could not open image") # {image_path}")
                return False
            height, width, channels = img.shape

            # flatten the image to 1D to modify easily
            flat_img = img.reshape(-1)
            # calculate the number of pixels needed for the header
            HEADER_PIXELS = int(
                (self.HEADER_LENGTH_BITS_RSA / channels) + ((self.HEADER_LENGTH_BITS_RSA % channels) != 0))



            len_data = len(binary_data)
            len_bytes = len_data.to_bytes(4, byteorder="big")

            # Step 2: Encrypt the header using RSA
            if self.use_rsa_encryption:
                if self.rsa_public_key is None:
                    print("Error: RSA public key not provided.")
                    return False

                data_hash = hashlib.sha256(binary_data).digest()

                seed_bytes = get_random_bytes(self.SEED_SIZE)
                seed_value = int.from_bytes(seed_bytes, 'big')
                seed_hash = hashlib.sha256(seed_bytes).digest()

                plain_header = seed_bytes + len_bytes + seed_hash + data_hash
                encrypted_header = self.rsa_encrypt(plain_header)
                print("Hash of plaintext seed (before encrypting):", seed_hash.hex())

                # After extracting
                if len(encrypted_header) * 8 != self.HEADER_LENGTH_BITS_RSA:
                    print("Error: Encrypted seed has unexpected length.")
                    return False
            else:
                print("Error: RSA encryption required but disabled.")
                return False

            data_to_hide = binary_data

            # converting data to be hidden bytes to bits
            binary_bits = np.unpackbits(np.frombuffer(data_to_hide, dtype=np.uint8))

            # converting encrypted header bytes to bits
            header_bits = np.unpackbits(np.frombuffer(encrypted_header, dtype=np.uint8))

            # Calculate maximum data capacity
            max_data_capacity = height * width * channels - self.HEADER_LENGTH_BITS_RSA
            if (self.HEADER_LENGTH_BITS_RSA + len(binary_bits)) > max_data_capacity:
                print("Error: Data + seed too large for image.")
                return False

            # Step 3: Embed encrypted header at fixed pixel range of constant header length

            flat_img[:self.HEADER_LENGTH_BITS_RSA] = (flat_img[:self.HEADER_LENGTH_BITS_RSA] & 0xFE) | header_bits

            # calculating the starting index for hiding data
            data_start_index = HEADER_PIXELS * channels

            time_start = time.time()

            # Step 4: Using seed to randomize rest of embedding
            rng = np.random.default_rng(seed_value)
            positions = rng.choice(np.arange(data_start_index, height * width * channels), size=len(binary_bits),
                                   replace=False)
            time_end = time.time()
            print("Execution time rng.choice_hide:", time_end - time_start)

            time_start = time.time()
            # Changing code below to flattened array instead of 2D
            """for i, pos in enumerate(positions):
                pixel_idx = pos // channels
                ch = pos % channels
                y = pixel_idx // width
                x = pixel_idx % width
                img[y, x, ch] = (img[y, x, ch] & 0xFE) | binary_bits[i]"""

            # Step 5: Embed binary data at randomized positions
            flat_img[positions] = (flat_img[positions] & 0xFE) | binary_bits

            # Step 6: Reshape back to original shape
            img = flat_img.reshape(height, width, channels)
            time_end_end = time.time()

            print("Execution time from the start of method :", time_end_end - time_start_start)
            time_end = time.time()
            # Step 7: return the modified image
            if output_path:
                cv2.imwrite(output_path, img)


            print("Execution time hiding bits:", time_end - time_start)
            print("Data hidden successfully.")
            return img

        except Exception as e:
            print(f"Error hiding data: {e}")
            return False

    def extract_data_from_image_seeded(self, img):

        """
        Extract hidden binary data from an image using the same seed used in hiding which is the RSA encrypted

        Args:
            image_path (str): Path to the image with hidden data

        Returns:
            bytes: Extracted binary data or None if failed
        """
        try:
            # Step 1: Read the image using OpenCV
            #img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
            #if img is None:
            #    print(f"Error: Could not open image {image_path}")
            #    return None

            height, width, channels = img.shape
            # calculate the number of pixels needed for the header
            HEADER_PIXELS = int(
                (self.HEADER_LENGTH_BITS_RSA / channels) + ((self.HEADER_LENGTH_BITS_RSA % channels) != 0))

            # flatten the image to 1D to modify easily
            flat_img = img.reshape(-1)

            # Step 1: Extract the encrypted seed (assumed fixed in first pixels)
            encrypted_seed_bits = flat_img[:self.HEADER_LENGTH_BITS_RSA] & 1
            encrypted_seed_bytes = np.packbits(encrypted_seed_bits).tobytes()

            # Step 2: Decrypt the header using RSA
            if self.use_rsa_encryption:
                if self.rsa_private_key is None:
                    print("Error: RSA private key not provided.")
                    return None

                seed_bytes = self.rsa_decrypt(encrypted_seed_bytes)
                # extract the seed value and length of data from the decrypted bytes
                seed_value = int.from_bytes(seed_bytes[:self.SEED_SIZE], 'big')

                len_data = int.from_bytes(seed_bytes[self.SEED_SIZE:self.LEN_DATA_POSITION], 'big')

                actual_seed_hash = hashlib.sha256(seed_bytes[:self.SEED_SIZE]).digest()

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

            total_pixels = height * width * channels
            data_start_index = HEADER_PIXELS * channels

            len_bits = len_data * 8
            # Step 3: Generate random positions using the seed
            rng = np.random.default_rng(seed_value)
            time_start1 = time.time()

            positions = rng.choice(np.arange(data_start_index, total_pixels), size=len_bits, replace=False)
            time_end1 = time.time()
            print("Execution time rng.choice:", time_end1 - time_start1)

            # Step 4: Extract binary data from randomized positions
            message_bits = flat_img[positions] & 1

            length = len_data
            if length <= 0:
                print("Error: Invalid extracted length.")
                return None
            print("Extracted length:", length, length * 8)
            # Extract actual message

            # Pack bits into bytes (8 bits per byte, MSB first)
            output = np.packbits(message_bits).tobytes()

            actual_data_hash = hashlib.sha256(output).digest()
            # Step 5 : Check if the extracted data matches the expected length and return bytes
            if actual_data_hash != expected_data_hash:
                print("Error: Hash mismatch! Extracted data may be corrupted or tampered with.")
                return None
            else:
                print("Hash match: data integrity verified.")

            return output

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
            image_data = ImageEncryptor.load_image(image_path)
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Hide the file data in the image
            return self.hide_data_in_image_seeded(image_data, file_data, output_path)

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
            image_data=ImageEncryptor.load_image(image_path)
            extracted_data = self.extract_data_from_image_seeded(image_data)

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


# Generate AES key
aes_key = get_random_bytes(32)  # AES-256

# Optional RSA keys
rsa_key = RSA.generate(2048)
public_key = rsa_key.publickey()
private_key = rsa_key

encryptor = ImageEncryptor(
    cipher=AES,
    mode=AES.MODE_GCM,
    key=aes_key,
    rsa_public_key=public_key,
    rsa_private_key=private_key,
    use_rsa_encryption=True
)


test_input_path="SamplePNGImage_30mbmb.png"
encrypted_path = 'encrypted_output.bin'
encryptor.encrypt_file(test_input_path, encrypted_path)
print(f"Encrypted file saved to {encrypted_path}")



decrypted_path = 'decrypted_output.bin'
encryptor.decrypt_file(encrypted_path, decrypted_path)
print(f"Decrypted file saved to {decrypted_path}")
