import unittest
from blum_goldwasser import BGWCryptosystem

class TestBGWCryptosystem(unittest.TestCase):

    def test_encrypt_decrypt(self):
        p_value = 19
        q_value = 7
        x_value = 1234
        n = p_value * q_value
        bgw = BGWCryptosystem()

        # Test 1
        plaintext = "101101"
        encrypted_text, xt_result = bgw.encrypt(n, x_value, plaintext)
        decrypted_text = bgw.decrypt(p_value, q_value, xt_result, encrypted_text)
        self.assertEqual(plaintext, decrypted_text)

        # Test 2
        plaintext = "110010"
        encrypted_text, xt_result = bgw.encrypt(n, x_value, plaintext)
        decrypted_text = bgw.decrypt(p_value, q_value, xt_result, encrypted_text)
        self.assertEqual(plaintext, decrypted_text)

        # Add more tests as needed

    def test_invalid_input(self):
        p_value = 19
        q_value = 7
        x_value = 1234
        n = p_value * q_value
        bgw = BGWCryptosystem()

        # Test invalid input for encrypt
        plaintext = "11001"
        with self.assertRaises(ValueError):
            bgw.encrypt(n, x_value, plaintext)

        # Test invalid input for decrypt
        encrypted_text, xt_result = bgw.encrypt(n, x_value, "101010")
        with self.assertRaises(ValueError):
            bgw.decrypt(p_value, q_value, xt_result, "10101")

        # Add more tests as needed

if __name__ == '__main__':
    unittest.main()