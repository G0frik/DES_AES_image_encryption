import random
import time
import re
import cv2
import numpy as np
from math import gcd

class BBS_Stream_Cipher:
    def __init__(self, p, q, seed):
        self.p = p
        self.q = q
        self.seed = seed

    @staticmethod
    def generate_random_odd():
        number = random.randint(1, 2**31 - 1)
        if number % 2 == 0:
            number += 1
        return number

    @staticmethod
    def congruence_check(num, modulo=4):
        if num % modulo == 3:
            return True
        else:
            return False

    @staticmethod
    def is_prime(num, k=5):
        for i in range(2, k):
            n = pow(i, num - 1, num)
            if n != 1:
                return False
        return True


    @staticmethod
    def find_prime_congruent_number_x0():
        while True:
            p = BBS_Stream_Cipher.generate_random_odd()
            q = BBS_Stream_Cipher.generate_random_odd()

            if BBS_Stream_Cipher.is_prime(p) and BBS_Stream_Cipher.congruence_check(p) and BBS_Stream_Cipher.is_prime(q) and BBS_Stream_Cipher.congruence_check(q):
                n = p * q
                seed = random.randint(2, n)
                while gcd(seed, n) != 1:
                    print("seed and p*q are not coprime")
                    seed = random.randint(2, n)
                return p, q, seed

    def blum_blum_shub_generator(self, num_bits=6):
        if BBS_Stream_Cipher.is_prime(self.p) and BBS_Stream_Cipher.congruence_check(self.p) and BBS_Stream_Cipher.is_prime(self.q) and BBS_Stream_Cipher.congruence_check(self.q):

            n = self.p * self.q
            xi = self.seed

            random_bits = []

            for _ in range(num_bits):
                xi = xi * xi % n
                random_bits.append(str(xi % 2))
            random_bits = ''.join(random_bits)
            return re.findall("........", random_bits)
        else:
            print("p and q are not prime or congruent to 3 modulo 4")

    @staticmethod
    def encrypt(plaintext, keystream, istext=True):
        if isinstance(plaintext, bytes):
            if istext:
                ciphertext = [plaintext[i] ^ int(keystream[i], 2) for i in range(len(plaintext))]
                decoded_string = ''.join(chr(code_point) for code_point in ciphertext)
                return ciphertext, decoded_string
            else:
                ciphertext = [plaintext[i] ^ int(keystream[i], 2) for i in range(len(plaintext))]
                return ciphertext
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
            if istext:
                ciphertext = [plaintext[i] ^ int(keystream[i], 2) for i in range(len(plaintext))]
                decoded_string = ''.join(chr(code_point) for code_point in ciphertext)
                return ciphertext, decoded_string
            else:
                ciphertext = [plaintext[i] ^ int(keystream[i], 2) for i in range(len(plaintext))]
                return ciphertext

    @staticmethod
    def decrypt(ciphertext, keystream, istext=True):
        if istext:
            plaintext = [ciphertext[i] ^ int(keystream[i], 2) for i in range(len(ciphertext))]
            decoded_string = ''.join(chr(code_point) for code_point in plaintext)
            return decoded_string
        else:
            plaintext = [ciphertext[i] ^ int(keystream[i], 2) for i in range(len(ciphertext))]
            return bytes(plaintext)

    @staticmethod
    def encrypt_file(input_file, output_file, p, q, seed):
        with open(input_file, 'rb') as file:
            file_content = file.read()

        num_bits = len(file_content) * 8
        keystream = BBS_Stream_Cipher.blum_blum_shub_generator(p, q, seed, num_bits=num_bits)

        ciphertext = BBS_Stream_Cipher.encrypt(file_content, keystream, istext=False)

        with open(output_file, 'wb') as file:
            file.write(bytes(ciphertext))

    @staticmethod
    def decrypt_file(input_file, output_file, p, q, seed):
        with open(input_file, 'rb') as file:
            ciphertext = file.read()

        num_bits = len(ciphertext) * 8
        keystream = BBS_Stream_Cipher.blum_blum_shub_generator(p, q, seed, num_bits=num_bits)

        decrypted_text = BBS_Stream_Cipher.decrypt(ciphertext, keystream, istext=False)

        with open(output_file, 'wb') as file:
            file.write(bytes(decrypted_text))

    @staticmethod
    def save_image(image, filename):
        cv2.imwrite(filename, image)

    @staticmethod
    def load_image(filename):
        return cv2.imread(filename)

    @staticmethod
    def display_image(image, title):
        cv2.imshow(title, image)
        cv2.waitKey()

    @staticmethod
    def encrypt_image(image, keystream, istext=True):
        imageBytes = image.tobytes()

        if istext:
            ciphertext, _ = BBS_Stream_Cipher.encrypt(imageBytes, keystream, istext=True)
        else:
            ciphertext = BBS_Stream_Cipher.encrypt(imageBytes, keystream, istext=False)

        encryptedImage = np.frombuffer(bytes(ciphertext), dtype=image.dtype).reshape(image.shape)

        return encryptedImage

    @staticmethod
    def decrypt_image(encrypted_image, keystream, istext=True):
        encryptedBytes = encrypted_image.tobytes()

        if istext:
            decrypted_image = BBS_Stream_Cipher.decrypt(encryptedBytes, keystream, istext=True)
        else:
            decrypted_image = BBS_Stream_Cipher.decrypt(encryptedBytes, keystream, istext=False)

        decryptedImage = np.frombuffer(decrypted_image, dtype=encrypted_image.dtype).reshape(encrypted_image.shape)

        return decryptedImage

    @staticmethod
    def save_image(image, filename):
        cv2.imwrite(filename, image)

    @staticmethod
    def load_image(filename):
        return cv2.imread(filename)

    @staticmethod
    def display_image(image, title):
        cv2.imshow(title, image)
        cv2.waitKey()


if __name__ == '__main__':
    p, q, seed = 13, 11, 100
    bbs = BBS_Stream_Cipher(p, q, seed)

    plaintext = "Hello, world"
    keystream = bbs.blum_blum_shub_generator(num_bits=len(plaintext) * 8)
    ciphertext, decoded_string_encrypted = bbs.encrypt(plaintext, keystream, istext=True)
    decrypted_text = bbs.decrypt(ciphertext, keystream, istext=True)

    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {decoded_string_encrypted}")
    print(f"Decrypted Text: {decrypted_text}")



    # Load the original image

    p, q, seed = BBS_Stream_Cipher.find_prime_congruent_number_x0()
    bbs = BBS_Stream_Cipher(p, q, seed)
    input_file = 'tux_clear.bmp'
    original_image = bbs.load_image(input_file)
    #print(original_image)
    # Calculate the number of bits in the image
    bits = original_image.nbytes * 8
    # Generate a keystream for encryption
    keystream = bbs.blum_blum_shub_generator(num_bits=bits)

    # Encrypt the original image
    encrypted_image = bbs.encrypt_image(original_image, keystream, istext=False)

    # Decrypt the encrypted image
    decrypted_image = bbs.decrypt_image(encrypted_image, keystream, istext=False)

    # Save the encrypted and decrypted images
    output_file_encrypted = 'encrypted_tux.bmp'
    output_file_decrypted = 'decrypted_tux.bmp'

    bbs.save_image(encrypted_image, output_file_encrypted)
    bbs.display_image(encrypted_image, 'Encrypted Image')
    bbs.save_image(decrypted_image, output_file_decrypted)

