import uuid

import cv2
import numpy as np
import os
import tempfile
import shutil
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class ImageEncryptor:
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

    @staticmethod
    def load_image(filename):
        return cv2.imread(filename)

    @staticmethod
    def save_image(image, filename):
        cv2.imwrite(filename, image)

    @staticmethod
    def display_image(image, title):
        cv2.imshow(title, image)
        cv2.waitKey()
        cv2.destroyAllWindows()

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
                    rsa_cipher = PKCS1_OAEP.new(self.rsa_public_key)
                    encrypted_key = rsa_cipher.encrypt(self.key)
                    parts.append(encrypted_key)

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
                    rsa_cipher = PKCS1_OAEP.new(self.rsa_public_key)
                    encrypted_key = rsa_cipher.encrypt(self.key)
                    parts.append(encrypted_key)

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
            rsa_cipher = PKCS1_OAEP.new(self.rsa_public_key)
            encrypted_key = rsa_cipher.encrypt(self.key)
            parts.append(encrypted_key)

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

            rsa_cipher = PKCS1_OAEP.new(self.rsa_private_key)
            self.key = rsa_cipher.decrypt(rsa_encrypted_key)
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

        # Decrypt
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


    def generate_key(self, cipher_type):
        if cipher_type == DES:
            self.key = get_random_bytes(8)
        elif cipher_type == AES:
            self.key = get_random_bytes(32)
        else:
            raise ValueError("Unsupported cipher for key generation.")

        return self.key

