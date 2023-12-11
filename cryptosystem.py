import random
from math import gcd



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
# Defining given constants
P = 499
Q = 547
A = -57
B = 52

m = '10011100000100001100'


# Takes a list of binary integers and concatenates them all into a string
def printableList(l):
    return ''.join([str(x) for x in l])


# Computes the B list, gathering the least significant bits of x_i
def computeB(X):

    # Generating bits for BBS
    b = []
    for i in range(L):
        # Getting b_i = least sig. bit of x_i
        b.insert(0, int(bin(X[i])[-1]))
        print(b)
        # Calculating x_(i+1) = (x^2)%N
        X.append((X[i] * X[i]) % N)

    return b


if __name__ == "__main__":
    # Printing long lines because im anal about separating output from commands ¯\_(ツ)_/¯
    print("\n=====================================================")


    X = [159201]

    # Quickly converting string to list of ints for easier bitwise operating
    m = [int(x) for x in m]
    print("The plaintext is:\t", printableList(m))

    ############################### KEY GENERATION ###########################
def generation_public_key(P,Q):
    N = P * Q
    return N

    L = len(m)

def encryption_blum_goldwasser(X,m):
    ################################# ENCRYPTION #############################
    L= len(m)
    b = computeB(X,L)

    c = []
    for i in range(L):
        bit = int(m[i])

        # XOR operation on plaintext[i] ^ X[i]
        c.append(bit ^ b[i])

    print("The ciphertext is:\t", printableList(c))
    print(X)
    print(L, "is the length of m", "\nX[L] is", X[L])
    print("\nSent to Alice: \t\t({}, {})\n".format(printableList(c), X[L]))

    ################################# DECRYPTION #############################

    r_p = pow(X[L], (((P + 1) // 4) ** L), P)
    r_q = pow(X[L], (((Q + 1) // 4) ** L), Q)

    # Getting the multiplicative inverses of the primes
    P_inverse = int(pow(499 ,-1, 547))
    Q_inverse = int(pow(547 ,-1, 499))

    # Redefining our global X for our new B array
    X = [((Q * (Q_inverse % P) * r_p) + (P * (P_inverse % Q) * r_q)) % N]
    print(X, "\nNEW X")
    new_B = computeB(X)

    # XORing the ciphertext to recompute the plaintext
    new_m = []
    for i in range(L):
        bit = int(c[i])

        # XOR operation on ciphertext[i] ^ X[i]
        new_m.append(bit ^ new_B[i])

    print("Alice deciphered to:\t", printableList(new_m))
    print("Original message was:\t", printableList(m))
    print("=====================================================\n")