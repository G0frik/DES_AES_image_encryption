import sys
import cv2
import numpy as np
from Crypto.Cipher import DES,AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter

def load_image(filename):
    return cv2.imread(filename)

def display_image(image, title):
    cv2.imshow(title, image)
    cv2.waitKey()
def encrypt_image(image, key, mode, algorithm=DES):
    rowOrig, columnOrig, depthOrig = image.shape

    # Convert original image data to bytes
    imageBytes = image.tobytes()

    # Determine block size based on the algorithm

    if algorithm == DES:
        ivSize = DES.block_size if mode in [DES.MODE_CBC, DES.MODE_OFB, DES.MODE_CFB] else 0
        iv=get_random_bytes(ivSize)
        if mode == DES.MODE_CBC:
            cipher = DES.new(key, DES.MODE_CBC, iv)
        elif mode == DES.MODE_OFB:
            cipher = DES.new(key, DES.MODE_OFB, iv)
        elif mode == DES.MODE_CFB:
            cipher = DES.new(key, DES.MODE_CFB, iv, segment_size=64)
        elif mode == DES.MODE_CTR:
            # For CTR mode, we need to specify a counter object
            counter = Counter.new(DES.block_size * 8)
            cipher = DES.new(key, DES.MODE_CTR, counter=counter)
        else:
            cipher = DES.new(key, DES.MODE_ECB)
    elif algorithm == AES:
        ivSize = AES.block_size if mode in [AES.MODE_CBC, AES.MODE_OFB, AES.MODE_CFB] else 0
        iv = get_random_bytes(ivSize)
        if mode == AES.MODE_CBC:
            cipher = AES.new(key, AES.MODE_CBC, iv)
        elif mode == AES.MODE_OFB:
            cipher = AES.new(key, AES.MODE_OFB, iv)
        elif mode == AES.MODE_CFB:
            cipher = AES.new(key, AES.MODE_CFB, iv)
        elif mode == AES.MODE_CTR:
            nonce = get_random_bytes(8)
            # For CTR mode, we need to specify a counter object
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
            imageBytesPadded = pad(imageBytes, cipher.block_size)
            ciphertext = cipher.encrypt(imageBytesPadded)
            nonceSize = 8
            # Convert ciphertext bytes to encrypted image data
            paddedSize = len(imageBytesPadded) - len(imageBytes)
            void = columnOrig * depthOrig - nonceSize - paddedSize
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
    ivCiphertextVoid = iv + ciphertext + bytes(void)
    encryptedImage = np.frombuffer(ivCiphertextVoid, dtype=image.dtype).reshape(rowOrig + 1, columnOrig, depthOrig)

    return encryptedImage

def save_image(image, filename):
    cv2.imwrite(filename, image)

def decrypt_image(encrypted_image, key, mode, algorithm=DES):
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
    nonceSize = 8 if mode in [algorithm.MODE_CTR] else 0
    ivSize = block_size if mode in [algorithm.MODE_CBC, algorithm.MODE_OFB, algorithm.MODE_CFB] else 0
    iv = encryptedBytes[:ivSize]
    nonce=encryptedBytes[:nonceSize]
    print(ivSize)
    imageOrigBytesSize = rowOrig * columnOrig * depthOrig
    paddedSize = (imageOrigBytesSize // block_size + 1) * block_size - imageOrigBytesSize
    print(ivSize, imageOrigBytesSize, paddedSize)
    if mode in [algorithm.MODE_CTR]:
        encrypted = encryptedBytes[nonceSize: nonceSize + imageOrigBytesSize + paddedSize]
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
    else:
        cipher = algorithm.new(key, algorithm.MODE_ECB)

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
