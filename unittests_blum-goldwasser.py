import unittest
import random
import math
from math import gcd
from blum_goldwasser import BGWCryptosystem

class TestBGWCryptosystem(unittest.TestCase):
    @staticmethod
    def generate_random_odd():
        number = random.randint(1, 2 ** 19 - 1)
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
            p = BGWCryptosystem.generate_random_odd()
            q = BGWCryptosystem.generate_random_odd()

            n = p * q
            log2_log2_n = round(math.log2(math.log2(n)))

            if log2_log2_n in {2, 4, 8} and BGWCryptosystem.is_prime(p) and BGWCryptosystem.congruence_check(
                    p) and BGWCryptosystem.is_prime(q) and BGWCryptosystem.congruence_check(q):
                seed = random.randint(2, n)
                while gcd(seed, n) != 1:
                    print("seed and p*q are not coprime")
                    seed = random.randint(2, n)
                return p, q, seed

    def test_generate_random_odd(self):
        random_odd = BGWCryptosystem.generate_random_odd()
        self.assertTrue(random_odd % 2 != 0)

    def test_congruence_check(self):
        self.assertTrue(BGWCryptosystem.congruence_check(3, 4))
        self.assertFalse(BGWCryptosystem.congruence_check(4, 4))

    def test_is_prime(self):
        self.assertTrue(BGWCryptosystem.is_prime(17))
        self.assertFalse(BGWCryptosystem.is_prime(15))

    def test_find_prime_congruent_number_x0(self):
        p, q, seed = BGWCryptosystem.find_prime_congruent_number_x0()
        n = p * q
        log2_log2_n = round(math.log2(math.log2(n)))
        self.assertIn(log2_log2_n, {2, 4, 8})
        self.assertTrue(BGWCryptosystem.is_prime(p))
        self.assertTrue(BGWCryptosystem.congruence_check(p))
        self.assertTrue(BGWCryptosystem.is_prime(q))
        self.assertTrue(BGWCryptosystem.congruence_check(q))
        self.assertEqual(gcd(seed, n), 1)

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
