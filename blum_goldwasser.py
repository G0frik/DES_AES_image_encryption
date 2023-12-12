import math
import random
from math import gcd

class BGWCryptosystem:
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
            print(log2_log2_n)

            if log2_log2_n in {2, 4, 8} and BGWCryptosystem.is_prime(p) and BGWCryptosystem.congruence_check(p) and BGWCryptosystem.is_prime(q) and BGWCryptosystem.congruence_check(q):
                seed = random.randint(2, n)
                while gcd(seed, n) != 1:
                    print("seed and p*q are not coprime")
                    seed = random.randint(2, n)
                return p, q, seed
    def encrypt(self, n, x, m):
        h = round(math.log2(math.log2(n)))
        if h in {2, 4, 8}:
            m= BGWCryptosystem.str_to_binary(m)
        if len(m) % h != 0:
            raise ValueError("m is not a multiple of h")
        t = len(m) // h
        xi = (x ** 2) % n
        c = ''
        for i in range(t):
            mi = m[i * h:(i + 1) * h]
            xi = (xi ** 2) % n
            xi_bin = bin(xi)
            pi = xi_bin[-h:]
            mi_int = int(mi, 2)
            pi_int = int(pi, 2)
            ci = pi_int ^ mi_int
            ci_bin = format(ci, '0' + str(h) + 'b')
            c += ci_bin
        xt = (xi ** 2) % n

        return c, xt

    def decrypt(self, p, q, xt, c):

        n=p*q
        gcd, a, b = self.gcdExtended(p, q)
        assert a * p + b * q == 1
        assert p % 4 == 3 and q % 4 == 3
        h = round(math.log2(math.log2(n)))
        print(h, "h")
        if len(c) % h != 0:
            raise ValueError("m is not a multiple of h")
        t = len(c) // h
        d1 = (((p + 1) // 4) ** (t + 1)) % (p - 1)
        d2 = (((q + 1) // 4) ** (t + 1)) % (q - 1)
        print(d1,d2, "d1,d2")
        u = (xt ** d1) % p
        v = (xt ** d2) % q

        x0 = (v * a * p + u * b * q) % n
        xi = x0
        m = ''
        print("im here")
        for i in range(t):

            ci = c[i * h:(i + 1) * h]
            xi = (xi ** 2) % n
            xi_bin = bin(xi)
            pi = xi_bin[-h:]
            ci_int = int(ci, 2)
            pi_int = int(pi, 2)
            mi = pi_int ^ ci_int
            mi_bin = format(mi, '0' + str(h) + 'b')
            m += mi_bin

            return m

    def gcdExtended(self, a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self.gcdExtended(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    @staticmethod
    def str_to_binary(string):
        # Initialize empty list to store binary values
        binary_list = []

        # Iterate through each character in the string
        for char in string:
            # Convert character to binary, pad with leading zeroes and append to list
            binary_list.append(bin(ord(char))[2:].zfill(8))

        # Join the binary values in the list and return as a single string
        return ''.join(binary_list)

    @staticmethod
    def binary_to_str(binary_str):
        # Split the binary string into 8-bit chunks
        binary_chunks = [binary_str[i:i + 8] for i in range(0, len(binary_str), 8)]

        # Convert each 8-bit chunk back to decimal and then to a character
        char_list = [chr(int(chunk, 2)) for chunk in binary_chunks]

        # Join the characters into a single string
        return ''.join(char_list)


# Example usage:
p_value = 19
q_value = 7


message = "101101"

bgw = BGWCryptosystem()

bgw.find_prime_congruent_number_x0()
# Encrypt
plaintext = message
x_value = 1234
encrypted_text, xt_result = bgw.encrypt(p_value*q_value, x_value, plaintext)
print(encrypted_text, xt_result)
# Decrypt
decrypted_text = bgw.decrypt(p_value, q_value, xt_result, encrypted_text)
print(plaintext,decrypted_text)

