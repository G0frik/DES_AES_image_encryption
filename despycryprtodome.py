import sys
import cv2
import numpy as np
from Crypto.Cipher import DES,AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def load_image(filename):
    return cv2.imread(filename)

def display_image(image, title):
    cv2.imshow(title, image)
    cv2.waitKey()
def encrypt_image(image, key, mode):
    print(image)
    rowOrig, columnOrig, depthOrig = image.shape

    # Convert original image data to bytes
    imageBytes = image.tobytes()

    # Encrypt
    block_size = DES.block_size if mode == DES.MODE_CBC or DES.MODE_ECB else AES.block_size
    ivSize = block_size if mode == DES.MODE_CBC or mode == AES.MODE_CBC else 0
    print(ivSize)

    iv = get_random_bytes(ivSize)
    cipher = DES.new(key, mode, iv) if mode == DES.MODE_CBC else DES.new(key, DES.MODE_ECB)
    imageBytesPadded = pad(imageBytes, DES.block_size)
    ciphertext = cipher.encrypt(imageBytesPadded)

    # Convert ciphertext bytes to encrypted image data
    paddedSize = len(imageBytesPadded) - len(imageBytes)

    void = columnOrig * depthOrig - ivSize - paddedSize
    ivCiphertextVoid = iv + ciphertext + bytes(void)
    print(image.shape, void)
    print(image.shape,image.dtype)
    encryptedImage = np.frombuffer(ivCiphertextVoid, dtype=image.dtype).reshape(rowOrig + 1, columnOrig, depthOrig)

    return encryptedImage

def save_image(image, filename):
    cv2.imwrite(filename, image)

def decrypt_image(encrypted_image, key, mode):
    rowEncrypted, columnOrig, depthOrig = encrypted_image.shape # cv2
    rowOrig = rowEncrypted - 1
    encryptedBytes = encrypted_image.tobytes()
    ivSize = DES.block_size if mode == DES.MODE_CBC else 0
    iv = encryptedBytes[:ivSize]
    imageOrigBytesSize = rowOrig * columnOrig * depthOrig
    paddedSize = (imageOrigBytesSize // DES.block_size + 1) * DES.block_size - imageOrigBytesSize
    print(ivSize,imageOrigBytesSize,paddedSize)
    encrypted = encryptedBytes[ivSize: ivSize + imageOrigBytesSize + paddedSize]

    # Decrypt
    cipher = DES.new(key, mode, iv) if mode == DES.MODE_CBC else DES.new(key, DES.MODE_ECB)
    decryptedImageBytesPadded = cipher.decrypt(encrypted)
    decryptedImageBytes = unpad(decryptedImageBytesPadded, DES.block_size)

    # Convert bytes to decrypted image data
    decryptedImage = np.frombuffer(decryptedImageBytes, encrypted_image.dtype).reshape(rowOrig, columnOrig, depthOrig)

    return decryptedImage

def main():
    mode_names = {
        DES.MODE_CBC: "DES.MODE_CBC",
        DES.MODE_ECB: "DES.MODE_ECB",
        # Add other modes as needed
    }
    # Set mode
    mode = DES.MODE_CBC
    print(str(mode))
    # mode = DES.MODE_ECB
    if mode != DES.MODE_CBC and mode != DES.MODE_ECB:
        print('Only CBC and ECB mode supported...')
        sys.exit()

    # Set sizes
    keySize = 8

    # Load original image
    image_path="Tux-with-tablet.jpg"
    imageOrig = load_image(image_path)

    # Display original image
    display_image(imageOrig, "Original image")

    # Encrypt
    key = get_random_bytes(keySize)
    encryptedImage = encrypt_image(imageOrig, key, AES.MODE_CBC)

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
