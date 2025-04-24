import cv2
import numpy as np
from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA


class ImageEncryptor:
    def __init__(self, cipher=None, mode=None, key=None, rsa_public_key=None, rsa_private_key=None, use_rsa_encryption=False):
        self.cipher = cipher
        self.mode = mode
        self.key = key
        self.use_rsa_encryption = use_rsa_encryption
        self.rsa_public_key = rsa_public_key
        self.rsa_private_key = rsa_private_key

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

    def generate_key(self, cipher_type):
        if cipher_type == DES:
            self.key = get_random_bytes(8)
        elif cipher_type == AES:
            self.key = get_random_bytes(32)
        else:
            raise ValueError("Unsupported cipher for key generation.")

        return self.key



