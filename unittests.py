import unittest
from bbs_class import BBS_Stream_Cipher
from math import gcd

class TestBBSStreamCipher(unittest.TestCase):
    def setUp(self):
        self.p, self.q, self.seed = 11, 19, 3
        self.bbs = BBS_Stream_Cipher(self.p, self.q, self.seed)

    def test_blum_blum_shub_generator(self):
        # Test the BBS generator for a specific sequence of numbers
        expected_keystream=['11000001']
        keystream = self.bbs.blum_blum_shub_generator(num_bits=8)
        print(expected_keystream,keystream)
        self.assertEqual(keystream, expected_keystream)

    def test_encrypt_decrypt_text(self):
        plaintext = "Hello, world"
        keystream = self.bbs.blum_blum_shub_generator(num_bits=len(plaintext) * 8)
        ciphertext, decoded_string_encrypted = self.bbs.encrypt(plaintext, keystream, istext=True)
        decrypted_text = self.bbs.decrypt(ciphertext, keystream, istext=True)

        self.assertEqual(plaintext, decrypted_text)

    def test_find_prime_congruent_number_x0(self):
        p, q, seed = BBS_Stream_Cipher.find_prime_congruent_number_x0()
        self.assertTrue(BBS_Stream_Cipher.is_prime(p))
        self.assertTrue(BBS_Stream_Cipher.is_prime(q))
        self.assertTrue(BBS_Stream_Cipher.congruence_check(p))
        self.assertTrue(BBS_Stream_Cipher.congruence_check(q))
        self.assertEqual(gcd(seed, p * q), 1)

    def test_image_encryption_decryption(self):
        # Load the original image
        input_file = 'tux_clear.bmp'
        original_image = self.bbs.load_image(input_file)

        bits = original_image.nbytes * 8

        keystream = self.bbs.blum_blum_shub_generator(num_bits=bits)

        encrypted_image = self.bbs.encrypt_image(original_image, keystream, istext=False)

        decrypted_image = self.bbs.decrypt_image(encrypted_image, keystream, istext=False)

        # Compare the original image and the decrypted image
        self.assertTrue((original_image == decrypted_image).all())

    # You can add more test methods for other functionality

if __name__ == '__main__':
    unittest.main()
