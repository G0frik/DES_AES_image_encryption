import random,time,re,cv2,numpy as np
from math import gcd



def time_check(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"{func.__name__} took {execution_time:.4f} seconds to execute.")
        return result
    return wrapper


def generate_random_odd():
    number = random.randint(1, 2**31 - 1)
    if number % 2 == 0:
        number += 1
    return number


def congruence_check(num,modulo=4):
    if num % modulo == 3:
        return True
    else:
        return False


def is_prime(num,k=5):
    for i in range(2, k):
        n = pow(i, num - 1, num)
        #print(n)
        if n != 1:
            return False
    return True

@time_check

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

@time_check
def blum_blum_shub_generator(p, q, seed, num_bits=6):
    n = p * q
    xi = seed
    random_bits=[]

    for _ in range(num_bits):
        xi=xi*xi%n
        random_bits.append(str(xi%2))
    random_bits = ''.join(random_bits)
    return re.findall("........",random_bits)

@time_check
def encrypt(plaintext, keystream,istext=True):
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
@time_check
def decrypt(ciphertext, keystream,istext=True):
    if istext:
        plaintext = [ciphertext[i] ^ int(keystream[i], 2) for i in range(len(ciphertext))]
        decoded_string = ''.join(chr(code_point) for code_point in plaintext)
        return decoded_string
    else:
        plaintext = [ciphertext[i] ^ int(keystream[i], 2) for i in range(len(ciphertext))]
        return bytes(plaintext)


def encrypt_file(input_file, output_file, p, q, seed):
    with open(input_file, 'rb') as file:
        file_content = file.read()

    num_bits = len(file_content) * 8
    keystream = blum_blum_shub_generator(p, q, seed, num_bits=num_bits)

    ciphertext = encrypt(file_content, keystream, istext=False)

    with open(output_file, 'wb') as file:
        file.write(bytes(ciphertext))


def decrypt_file(input_file, output_file, p, q, seed):
    with open(input_file, 'rb') as file:
        ciphertext = file.read()

    num_bits = len(ciphertext) * 8
    keystream = blum_blum_shub_generator(p, q, seed, num_bits=num_bits)

    decrypted_text = decrypt(ciphertext, keystream, istext=False)

    with open(output_file, 'wb') as file:
        file.write(bytes(decrypted_text))


def encrypt_image(image, keystream, istext=True):
    # Convert original image data to bytes
    imageBytes = image.tobytes()

    # Encrypt using your custom function
    if istext:
        ciphertext, _ = encrypt(imageBytes, keystream, istext=True)
    else:
        ciphertext = encrypt(imageBytes, keystream, istext=False)

    # Convert ciphertext bytes to encrypted image data
    encryptedImage = np.frombuffer(bytes(ciphertext), dtype=image.dtype).reshape(image.shape)

    return encryptedImage

def decrypt_image(encrypted_image, keystream, istext=True):
    # Convert encrypted image data to bytes
    encryptedBytes = encrypted_image.tobytes()

    # Decrypt using your custom function
    if istext:
        decrypted_image = decrypt(encryptedBytes, keystream, istext=True)
    else:
        decrypted_image = decrypt(encryptedBytes, keystream, istext=False)

    # Convert bytes to decrypted image data
    decryptedImage = np.frombuffer(decrypted_image, dtype=encrypted_image.dtype).reshape(encrypted_image.shape)

    return decryptedImage
def save_image(image, filename):
    cv2.imwrite(filename, image)
def load_image(filename):
    return cv2.imread(filename)
def display_image(image, title):
    cv2.imshow(title, image)
    cv2.waitKey()
# Example usage:
"""p, q, seed = 11,19,3
plaintext="hello brother"
keystream = blum_blum_shub_generator(p, q, seed, num_bits=len(plaintext) * 8)
print(keystream)
ciphertext,decoded_string_encrypted = encrypt(plaintext, keystream)
print(ciphertext)
decrypted_text = decrypt(ciphertext, keystream)
print(p,q,seed)

print(f"Plaintext: {plaintext}")
print(f"Ciphertext: {decoded_string_encrypted}")
print(f"Decrypted Text: {decrypted_text}")
"""
if __name__ == '__main__':
    """ #print(PowModParallel(PowModGmp, [1, 2, 3, 4, 5], 2, 7))
    print("here")
    #powmodlist = PowModGmp([1, 2, 3, 4, 5], 2, 7)
    #print(powmodlist[1])
    # print(pow(2,2,7))
    p, q, seed = 13,11,100
    stringto="Hello, how are you brother"
    print(f"p: {p}, q: {q}, seed: {seed}")
    keystreamnew = blum_blum_shub_generator(p, q, seed, num_bits=len(stringto)*8)
    ciphertext,decoded=encrypt(stringto.encode(),keystreamnew)
    print(keystreamnew,ciphertext,decoded)"""
    p,q,seed=find_prime_congruent_number_x0()
    seed=100
    p,q=13,11
    print(p,q,seed)

    with open('pg100.txt', 'r',encoding='utf-8') as file:
        # Read the contents of the file into a string
        file_content=file.read()
        print(len(file_content), "len")
        file_content=file_content.encode()

    print(len(file_content), "len")
    file_content=b"Hello, world"
    keystreamnew = blum_blum_shub_generator(p, q, seed, num_bits=len(file_content) * 8,)
    #print(keystreamnew)
    #print(keystream)
    ciphertext,decoded_string_encrypted = encrypt(file_content, keystreamnew,istext=True)
    decrypted_text = decrypt(ciphertext, keystreamnew,istext=True)
    print(decoded_string_encrypted,decrypted_text,ciphertext)
    #print(decrypted_text)
    #print(decrypted_text)
    """
    output_file = 'encrypted_tux.bmp'
    p, q, seed = 13, 11, 100

    # Encrypt the input file
    encrypt_file(input_file, output_file, p, q, seed)

    # Decrypt the encrypted file
    decrypted_output_file = 'decrypted_tux.bmp'
    decrypt_file(output_file, decrypted_output_file, p, q, seed)
    input_file = 'tux_clear.bmp'
    with open('tux_clear.bmp', 'rb') as file:
        # Read the contents of the file into a string
        file_content = file.read()
        print(len(file_content), "len")
        #file_content = file_content.encode()
    original_image = load_image(input_file)
    bits=original_image.nbytes*8

    p, q, seed = 11, 19, 47
    keystream = blum_blum_shub_generator(p, q, seed, num_bits=8)
    print(p*q,keystream,157%2,137%2)
    p,q,seed=find_prime_congruent_number_x0()
    keystream = blum_blum_shub_generator(p, q, seed, num_bits=bits)
    #print(keystream)
    encrypted_image = encrypt_image(original_image, keystream, istext=False)
    decrypted_image = decrypt_image(encrypted_image, keystream, istext=False)

    save_image(encrypted_image, 'encrypted_tux.bmp')
    save_image(decrypted_image, 'decrypted_tux.bmp')
    print(p,q,seed)
    display_image(encrypted_image, "Encrypted image")"""







