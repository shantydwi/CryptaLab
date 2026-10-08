from math import gcd

GROUP_NAME = "The cipherlings"
GROUP_MEMBERS = [
    "> Ririn Rahma Arifa - 237006171",
    "> Tia Amelia - 237006162",
    "> Shanty Dwi Septiani - 237006161",
]

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def affine_encrypt(plaintext, a, b):
    if gcd(a, 26) != 1:
        raise ValueError("Nilai a harus relatif prima dengan 26.")

    ciphertext = ""

    for char in plaintext.upper():
        if char.isalpha():
            p = ALPHABET.index(char)
            c = (a * p + b) % 26
            ciphertext += ALPHABET[c]
        else:
            ciphertext += char

    return ciphertext


def affine_decrypt(ciphertext, a, b):
    if gcd(a, 26) != 1:
        raise ValueError("Nilai a harus relatif prima dengan 26.")

    a_invers = mod_inverse(a, 26)

    plaintext = ""

    for char in ciphertext.upper():
        if char.isalpha():
            c = ALPHABET.index(char)
            p = (a_invers * (c - b)) % 26
            plaintext += ALPHABET[p]
        else:
            plaintext += char

    return plaintext


print(f"\nOur group name, {GROUP_NAME}")
print(f"this is the members: ")
print(*GROUP_MEMBERS, sep="\n")
print("-------------------------------------\n")

# ===================
# DEMO UJI
# ===================

options = [
    "------ This is the option: ------",
    "1. Penjelasan Cipher",
    "2. Demo hardcode",
    "3. Enkripsi",
    "4. Dekripsi",
]
print(*options, sep="\n")

choice = int(input("\nYou can only choose one at a time ><.\nSo, what's your choice? "))

# --- explanation
explanation = """
Affine Cipher adalah algoritma kriptografi klasik yang mengenkripsi
setiap huruf menggunakan fungsi matematika linear pada modulo 26.

Rumus enkripsi:
C = (aP + b) mod 26

Rumus dekripsi:
P = a^-1(C - b) mod 26

Keterangan:
P  = nilai plaintext
C  = nilai ciphertext
a dan b = parameter/kunci
a^-1 = invers modulo dari a

Nilai a harus relatif prima dengan 26 agar proses dekripsi dapat dilakukan.
"""

if choice == 1:
    print(explanation)
elif choice == 2:
    print("==== AFFINE CIPHER ====")

    plaintext = "HELLO WORLD"
    a = 5
    b = 8

    ciphertext = affine_encrypt(plaintext, a, b)
    hasil_dekripsi = affine_decrypt(ciphertext, a, b)

    print("Plaintext        :", plaintext)
    print("Key/Parameter    : a =", a, "b =", b)
    print("Ciphertext       :", ciphertext)
    print("Decryption Result:", hasil_dekripsi)
elif choice == 3:
    print("==== Encryption ====")

    plaintext = input("Enter plaintext: ")
    a = int(input("Enter a value: "))
    b = int(input("Enter b value: "))

    if gcd(a, 26) != 1:
        print("\nInvalid value for a. a must be relatively prime to 26.")
    else:
        ciphertext = affine_encrypt(plaintext, a, b)

        print("\nPlaintext  : ", plaintext)
        print("a            :", a)
        print("b            :", b)
        print("Ciphertext   :", ciphertext)
elif choice == 4:
    print("==== Decryption ====")

    ciphertext = input("Enter ciphertext: ")
    a = int(input("Enter a value: "))
    b = int(input("Enter b value: "))

    if gcd(a, 26) != 1:
        print("\nInvalid value for a. a must be relatively prime to 26.")
    else:
        plaintext = affine_decrypt(ciphertext, a, b)

    print("\nCiphertext  : ", ciphertext)
    print("a             :", a)
    print("b             :", b)
    print("Plaintext     :", plaintext)
else:
    print("\nUpss.. It looks like your choice is invalid..")
