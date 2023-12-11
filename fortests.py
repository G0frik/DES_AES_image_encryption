import numpy as np
import random
from math import gcd


def str_to_binary(string):
    # Initialize empty list to store binary values
    binary_list = []

    # Iterate through each character in the string
    for char in string:
        # Convert character to binary, pad with leading zeroes and append to list
        binary_list.append(bin(ord(char))[2:].zfill(8))

    # Join the binary values in the list and return as a single string
    return ''.join(binary_list)
def binary_to_str(binary_str):
    # Split the binary string into 8-bit chunks
    binary_chunks = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]

    # Convert each 8-bit chunk back to decimal and then to a character
    char_list = [chr(int(chunk, 2)) for chunk in binary_chunks]

    # Join the characters into a single string
    return ''.join(char_list)

# Test with example input
test_str = "GeeksforGeeks"
print(binary_to_str(str_to_binary(test_str)),test_str)
print()

def generate_random_odd():
    number = random.randint(1, 2**31 - 1)
    if number % 2 == 0:
        number += 1
    return number


def congruence_check(num, modulo=4):
    if num % modulo == 3:
        return True
    else:
        return False


def is_prime(num, k=5):
    for i in range(2, k):
        n = pow(i, num - 1, num)
        if n != 1:
            return False
    return True



def find_prime_congruent_number_x0():
    while True:
        p = generate_random_odd()
        q = generate_random_odd()

        if is_prime(p) and congruence_check(p) and is_prime(q) and congruence_check(q):
            n = p * q
            seed = random.randint(2, n)
            while gcd(seed, n) != 1:
                print("seed and p*q are not coprime")
                seed = random.randint(2, n)
            return p, q, seed
def BGW_enc(p, q, x, m):
    m= str_to_binary(m)
    n = p * q
    gcd,a,b=gcdExtended(p,q)
    assert a * p + b * q == 1
    assert p%4 == 3 and q%4 == 3

    k = int(np.log2(n))
    h = int(np.log2(k))
    print("k:", k, "h:", h)
    t = len(m) // h
    print("t:",t)
    xi = x
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


def BGW_dec(p, q, xt, c):
    n = p * q
    gcd, a, b = gcdExtended(p, q)
    k = int(np.log2(n))
    h = int(np.log2(k))

    t = len(c) // h

    d1 = (((p + 1) // 4) ** (t + 1)) % (p - 1)
    d2 = (((q + 1) // 4) ** (t + 1)) % (q - 1)


    u = (xt ** d1) % p

    v = (xt ** d2) % q

    x0 = (v * a * p + u * b * q) % n

    xi = x0
    m = ''
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

    return binary_to_str(m)


def gcdExtended(a, b):
    # Base Case
    if a == 0:
        return b, 0, 1

    gcd, x1, y1 = gcdExtended(b % a, a)

    # Update x and y using results of recursive
    # call
    x = y1 - (b // a) * x1
    y = x1

    return gcd, x, y




if __name__ == "__main__":
    m = 'hello'

    p = 499
    q = 547
    x0 = 159201

    c, xt = BGW_enc(p, q,x0, m)
    print("ciphertext:", c)
    d = BGW_dec(p, q, xt, c)
    print("decrypted plaintext:", d, "plaintext:", m)
    print("asserting that decrypted plaintext == m...")
    assert m == d
    print("assertion correct! done.")
