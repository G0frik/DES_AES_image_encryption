import sys
import cv2
import numpy as np
from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA


def load_image(filename):
    return cv2.imread(filename)

def display_image(image, title):
    cv2.imshow(title, image)
    cv2.waitKey()
def encrypt_image(image, key, mode, algorithm,rsa_public_key=None):
    rowOrig, columnOrig, depthOrig = image.shape

    # Convert original image data to bytes
    imageBytes = image.tobytes()

    # Determine block size based on the algorithm

    if algorithm == DES:
        ivSize = DES.block_size if mode in [DES.MODE_CBC] else 0
        iv=get_random_bytes(ivSize)
        if mode == DES.MODE_CBC:
            cipher = DES.new(key, DES.MODE_CBC, iv)
        else:
            cipher = DES.new(key, DES.MODE_ECB)
    elif algorithm == AES:
        ivSize = AES.block_size if mode in [AES.MODE_CBC] else 0
        iv = get_random_bytes(ivSize)
        if mode == AES.MODE_CBC:
            cipher = AES.new(key, AES.MODE_CBC, iv)
        elif mode == AES.MODE_GCM:
            nonce = get_random_bytes(12)
            # Initialize the AES-GCM cipher with the key and nonce
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            # Pad the image bytes to the AES block size
            imageBytesPadded = pad(imageBytes, AES.block_size)

            # Encrypt the padded image bytes and get the authentication tag
            ciphertext, tag = cipher.encrypt_and_digest(imageBytesPadded)

            # Convert the ciphertext, nonce, and tag to a single buffer
            # Calculate sizes for padding and void space
            nonceSize = len(nonce)
            tagSize = len(tag)
            paddedSize = len(imageBytesPadded) - len(imageBytes)
            rsa_key_size=256
            void = columnOrig * depthOrig - nonceSize - tagSize - paddedSize
            if rsa_public_key:
                void = columnOrig * depthOrig - nonceSize - tagSize - paddedSize - rsa_key_size
                rsa_cipher = PKCS1_OAEP.new(rsa_public_key)
                encrypted_key = rsa_cipher.encrypt(key)
                # Combine nonce, ciphertext, tag, and void space into one buffer
                nonceTagKeyCiphertextVoid = nonce + tag + encrypted_key + ciphertext + bytes(void)
                encryptedImage = np.frombuffer(nonceTagKeyCiphertextVoid, dtype=image.dtype).reshape(rowOrig + 1,
                                                                                                  columnOrig,
                                                                                                  depthOrig)
            else:
                nonceTagCiphertextVoid = nonce + tag + ciphertext + bytes(void)
                encryptedImage = np.frombuffer(nonceTagCiphertextVoid, dtype=image.dtype).reshape(rowOrig + 1, columnOrig,
                                                                                              depthOrig)
            # Convert the buffer to the encrypted image data format

            return encryptedImage
        elif mode == AES.MODE_CTR:
            nonce = get_random_bytes(12)
            # For CTR mode, we need to specify a counter object
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
            imageBytesPadded = pad(imageBytes, cipher.block_size)
            ciphertext = cipher.encrypt(imageBytesPadded)
            nonceSize = 12
            # Convert ciphertext bytes to encrypted image data
            paddedSize = len(imageBytesPadded) - len(imageBytes)
            void = columnOrig * depthOrig - nonceSize - paddedSize
            rsa_key_size= 256
            if rsa_public_key:
                void = columnOrig * depthOrig - nonceSize  - paddedSize - rsa_key_size
                rsa_cipher = PKCS1_OAEP.new(rsa_public_key)
                encrypted_key = rsa_cipher.encrypt(key)
                # Combine nonce, ciphertext, tag, and void space into one buffer
                nonceKeyCiphertextVoid = nonce + encrypted_key + ciphertext + bytes(void)
                encryptedImage = np.frombuffer(nonceKeyCiphertextVoid, dtype=image.dtype).reshape(rowOrig + 1,
                                                                                                  columnOrig,
                                                                                                  depthOrig)
            else:
                nonceCiphertextVoid = nonce + ciphertext + bytes(void)
                encryptedImage = np.frombuffer(nonceCiphertextVoid, dtype=image.dtype).reshape(rowOrig + 1, columnOrig,
                                                                                              depthOrig)

            return encryptedImage
        else:
            cipher = AES.new(key, AES.MODE_ECB)
    else:
        raise ValueError("Unsupported algorithm")

    # Pad and encrypt
    imageBytesPadded = pad(imageBytes, cipher.block_size)
    ciphertext = cipher.encrypt(imageBytesPadded)

    # Convert ciphertext bytes to encrypted image data
    paddedSize = len(imageBytesPadded) - len(imageBytes)
    void = columnOrig * depthOrig - ivSize - paddedSize
    rsa_key_size= 256
    if rsa_public_key:
        void = columnOrig * depthOrig - ivSize - paddedSize - rsa_key_size
        rsa_cipher = PKCS1_OAEP.new(rsa_public_key)
        encrypted_key = rsa_cipher.encrypt(key)
        # Combine nonce, ciphertext, tag, and void space into one buffer
        ivKeyCiphertextVoid = iv + encrypted_key + ciphertext + bytes(void)
        encryptedImage = np.frombuffer(ivKeyCiphertextVoid, dtype=image.dtype).reshape(rowOrig + 1,
                                                                                          columnOrig,
                                                                                          depthOrig)
    else:
        ivCiphertextVoid = iv + ciphertext + bytes(void)
        encryptedImage = np.frombuffer(ivCiphertextVoid, dtype=image.dtype).reshape(rowOrig + 1, columnOrig, depthOrig)

    return encryptedImage

def save_image(image, filename):
    cv2.imwrite(filename, image)

def decrypt_image(encrypted_image, key, mode, algorithm):
    rowEncrypted, columnOrig, depthOrig = encrypted_image.shape
    rowOrig = rowEncrypted - 1
    encryptedBytes = encrypted_image.tobytes()
    #print(encryptedBytes)

    if algorithm == DES:
        block_size = DES.block_size
    elif algorithm == AES:
        block_size = AES.block_size
    else:
        raise ValueError("Unsupported algorithm")

    print(block_size)

    nonceSize = 12 if mode in [AES.MODE_CTR,AES.MODE_GCM] else 0
    ivSize = block_size if mode in [algorithm.MODE_CBC] else 0
    tagsize = 16 if mode in [AES.MODE_GCM] else 0
    iv = encryptedBytes[:ivSize]

    nonce=encryptedBytes[:nonceSize]

    tag = encryptedBytes[nonceSize: nonceSize + 16] if mode in [AES.MODE_GCM] else None

    print(ivSize)

    imageOrigBytesSize = rowOrig * columnOrig * depthOrig
    paddedSize = (imageOrigBytesSize // block_size + 1) * block_size - imageOrigBytesSize
    print(ivSize, imageOrigBytesSize, paddedSize)

    if mode in [algorithm.MODE_CTR]:
        encrypted = encryptedBytes[nonceSize: nonceSize + imageOrigBytesSize + paddedSize]
    elif mode in [AES.MODE_GCM]:
        encrypted = encryptedBytes[nonceSize + tagsize: nonceSize + tagsize + imageOrigBytesSize + paddedSize]
    else:
        encrypted = encryptedBytes[ivSize: ivSize + imageOrigBytesSize + paddedSize]

    # Decrypt
    if mode == algorithm.MODE_CBC:
        cipher = algorithm.new(key, algorithm.MODE_CBC, iv)
    elif mode == algorithm.MODE_OFB:
        cipher = algorithm.new(key, algorithm.MODE_OFB, iv)
    elif mode == algorithm.MODE_CFB:
        cipher = algorithm.new(key, algorithm.MODE_CFB, iv)
    elif mode == algorithm.MODE_CTR:
        cipher = algorithm.new(key, algorithm.MODE_CTR, nonce=nonce)
    elif mode == AES.MODE_GCM:
        cipher = algorithm.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            decryptedImageBytesPadded = cipher.decrypt_and_verify(encrypted, tag)
            decryptedImageBytes = unpad(decryptedImageBytesPadded, block_size)

            decryptedImage = np.frombuffer(decryptedImageBytes, encrypted_image.dtype).reshape(rowOrig, columnOrig,
                                                                                               depthOrig)
            return decryptedImage
        except ValueError as e:
            raise ValueError(f"{str(e)}")
            #sys.exit(1)

    else:
        cipher = algorithm.new(key, algorithm.MODE_ECB)

    if mode not in [AES.MODE_GCM]:

        decryptedImageBytesPadded = cipher.decrypt(encrypted)
        decryptedImageBytes = unpad(decryptedImageBytesPadded, block_size)

        # Convert bytes to decrypted image data
        decryptedImage = np.frombuffer(decryptedImageBytes, encrypted_image.dtype).reshape(rowOrig, columnOrig, depthOrig)

        return decryptedImage


def main():
    mode_names = {
        DES.MODE_CBC: "DES.MODE_CBC",
        DES.MODE_ECB: "DES.MODE_ECB",
        DES.MODE_CFB: "DES.MODE_CFB"
        # Add other modes as needed
    }
    # Set mode
    mode = DES.MODE_CBC
    print(str(mode))
    # mode = DES.MODE_ECB


    # Set sizes
    keySize = 8

    # Load original image
    image_path="tux_clear.bmp"
    imageOrig = load_image(image_path)

    # Display original image
    display_image(imageOrig, "Original image")

    # Encrypt
    key = get_random_bytes(keySize)
    encryptedImage = encrypt_image(imageOrig, key, DES.MODE_CFB)

    # Display encrypted image
    display_image(encryptedImage, "Encrypted image")
    save_image(encryptedImage,f'{mode_names.get(mode, "unknown")}_encrypted{image_path}.bmp')

    # Save the encrypted image (optional)
    # save_image(encryptedImage, "topsecretEnc.bmp")

    # Decrypt
    decryptedImage = decrypt_image(load_image(f"{mode_names.get(mode, 'unknown')}_encrypted{image_path}.bmp"), key, mode)

    # Display decrypted image
    display_image(decryptedImage, "Decrypted Image")

    # Close all windows
    cv2.destroyAllWindows()

if __name__ == "__main__":
    main()
