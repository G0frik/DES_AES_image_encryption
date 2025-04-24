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


            ciphertext, tag = cipher.encrypt_and_digest(imageBytes)

            # Convert the ciphertext, nonce, and tag to a single buffer
            # Calculate sizes for padding and void space
            nonceSize = len(nonce)
            tagSize = len(tag)
            rsa_key_size=256
            void = columnOrig * depthOrig - nonceSize - tagSize
            if rsa_public_key:
                void = columnOrig * depthOrig - nonceSize - tagSize - rsa_key_size
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
            # No padding needed for CTR mode
            ciphertext = cipher.encrypt(imageBytes)
            nonceSize = 12
            # Convert ciphertext bytes to encrypted image data
            void = columnOrig * depthOrig - nonceSize #- len(ciphertext)
            print("void",void)
            rsa_key_size = 256
            if rsa_public_key:
                void = columnOrig * depthOrig - nonceSize - rsa_key_size
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

def decrypt_image(encrypted_image, mode, algorithm,rsa_private_key=None,key=None):
    rowEncrypted, columnOrig, depthOrig = encrypted_image.shape
    rowOrig = rowEncrypted - 1
    encryptedBytes = encrypted_image.tobytes()

    if algorithm == DES:
        block_size = DES.block_size
    elif algorithm == AES:
        block_size = AES.block_size
    else:
        raise ValueError("Unsupported algorithm")

    print(block_size)
    rsa_key_size=256 if rsa_private_key else 0
    nonceSize = 12 if mode in [AES.MODE_CTR,AES.MODE_GCM] else 0
    ivSize = block_size if mode in [algorithm.MODE_CBC] else 0
    tagsize = 16 if mode in [AES.MODE_GCM] else 0
    iv = encryptedBytes[:ivSize]

    nonce=encryptedBytes[:nonceSize]

    tag = encryptedBytes[nonceSize: nonceSize + tagsize] if mode in [AES.MODE_GCM] else None

    # Decrypt the RSA-encrypted key if RSA private key is provided
    if rsa_private_key:
        if mode == AES.MODE_GCM:
            rsa_encrypted_key = encryptedBytes[nonceSize + tagsize: nonceSize + tagsize + rsa_key_size]
        elif mode == AES.MODE_CTR:
            rsa_encrypted_key = encryptedBytes[nonceSize: nonceSize + rsa_key_size]
        elif mode == algorithm.MODE_CBC:
            rsa_encrypted_key = encryptedBytes[ivSize: ivSize + rsa_key_size]
        elif mode == algorithm.MODE_ECB:
            rsa_encrypted_key = encryptedBytes[:rsa_key_size]
        else:
            raise ValueError("Unsupported mode for RSA key decryption")

        rsa_cipher = PKCS1_OAEP.new(rsa_private_key)
        key = rsa_cipher.decrypt(rsa_encrypted_key)
        print("decrypted_rsa_key",key)
    elif key is None:
        raise ValueError("Either key or rsa_private_key must be provided")


    imageOrigBytesSize = rowOrig * columnOrig * depthOrig
    paddedSize = (imageOrigBytesSize // block_size + 1) * block_size - imageOrigBytesSize
    print(ivSize, imageOrigBytesSize, paddedSize)

    if mode == AES.MODE_GCM:
        encrypted_start = nonceSize + tagsize + rsa_key_size
    elif mode == AES.MODE_CTR:
        encrypted_start = nonceSize + rsa_key_size
    else:
        encrypted_start = ivSize + rsa_key_size

    encrypted = encryptedBytes[encrypted_start: encrypted_start + imageOrigBytesSize + paddedSize]

    # Decrypt
    if mode == algorithm.MODE_CBC:
        cipher = algorithm.new(key, algorithm.MODE_CBC, iv)
    elif mode == algorithm.MODE_OFB:
        cipher = algorithm.new(key, algorithm.MODE_OFB, iv)
    elif mode == algorithm.MODE_CFB:
        cipher = algorithm.new(key, algorithm.MODE_CFB, iv)
    elif mode == algorithm.MODE_CTR:
        encrypted = encryptedBytes[encrypted_start: encrypted_start + imageOrigBytesSize]
        cipher = algorithm.new(key, algorithm.MODE_CTR, nonce=nonce)

        print("check")
        decryptedImageBytes = cipher.decrypt(encrypted)
        decryptedImage = np.frombuffer(decryptedImageBytes, encrypted_image.dtype).reshape(rowOrig, columnOrig, depthOrig)

        return decryptedImage
    elif mode == AES.MODE_GCM:
        encrypted = encryptedBytes[encrypted_start: encrypted_start + imageOrigBytesSize ]
        print("check")
        cipher = algorithm.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            decryptedImageBytes = cipher.decrypt_and_verify(encrypted, tag)
            #decryptedImageBytes = unpad(decryptedImageBytesPadded, block_size)

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
        AES.MODE_CBC: "AES.MODE_CBC",
        DES.MODE_ECB: "DES.MODE_ECB",
        DES.MODE_CFB: "DES.MODE_CFB"
        # Add other modes as needed
    }
    # Set mode
    mode = AES.MODE_CBC
    print(str(mode))
    # mode = DES.MODE_ECB


    # Set sizes
    keySize = 32

    # Load original image
    image_path="tux_clear.bmp"
    imageOrig = load_image(image_path)

    # Display original image
    display_image(imageOrig, "Original image")

    # Encrypt
    key = get_random_bytes(keySize)
    encryptedImage = encrypt_image(imageOrig, key, AES.MODE_CBC,AES)

    # Display encrypted image
    display_image(encryptedImage, "Encrypted image")
    save_image(encryptedImage,f'{mode_names.get(mode, "unknown")}_encrypted{image_path}.bmp')

    # Save the encrypted image (optional)
    # save_image(encryptedImage, "topsecretEnc.bmp")

    # Decrypt
    decryptedImage = decrypt_image(load_image(f"{mode_names.get(mode, 'unknown')}_encrypted{image_path}.bmp"),mode=AES.MODE_CBC, algorithm=AES, key=key )

    # Display decrypted image
    display_image(decryptedImage, "Decrypted Image")

    # Close all windows
    cv2.destroyAllWindows()

if __name__ == "__main__":
    main()
