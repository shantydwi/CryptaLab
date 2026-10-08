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


def determinant(matrix):
    return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]


def matrix_inverse(matrix):
    det = determinant(matrix)
    det_mod = det % 26

    if gcd(det_mod, 26) != 1:
        raise ValueError("Matrix tidak memiliki invers module 26.")

    det_inverse = mod_inverse(det_mod, 26)

    adjugate = [
        [matrix[1][1], -matrix[0][1]],
        [-matrix[1][0], matrix[0][0]],
    ]

    inverse_matrix = [
        [(det_inverse * adjugate[i][j] % 26) for j in range(2)] for i in range(2)
    ]
    return inverse_matrix


def hill_encrypt(plaintext, key_matrix):
    plaintext = plaintext.upper()
    plaintext = "".join(char for char in plaintext if char.isalpha())
    if len(plaintext) % 2 != 0:
        plaintext += "x"

    ciphertext = ""

    for i in range(0, len(plaintext), 2):
        p1 = ALPHABET.index(plaintext[i])
        p2 = ALPHABET.index(plaintext[i + 1])

        c1 = (key_matrix[0][0] * p1 + key_matrix[0][1] * p2) % 26

        c2 = (key_matrix[1][0] * p1 + key_matrix[1][1] * p2) % 26

        ciphertext += ALPHABET[c1]
        ciphertext += ALPHABET[c2]

    return ciphertext


def hill_decrypt(ciphertext, key_matrix):
    ciphertext = ciphertext.upper()

    inverse_matrix = matrix_inverse(key_matrix)

    plaintext = ""

    for i in range(0, len(ciphertext), 2):
        c1 = ALPHABET.index(ciphertext[i])
        c2 = ALPHABET.index(ciphertext[i + 1])

        p1 = (inverse_matrix[0][0] * c1 + inverse_matrix[0][1] * c2) % 26
        p2 = (inverse_matrix[1][0] * c1 + inverse_matrix[1][1] * c2) % 26

        plaintext += ALPHABET[p1]
        plaintext += ALPHABET[p2]

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
==== PENJELASAN HILL CIPHER ====

Hill Cipher adalah algoritma kriptografi klasik yang menggunakan
operasi matriks untuk mengenkripsi dan mendekripsi plaintext.

Plaintext dibagi menjadi blok-blok karakter dengan ukuran sesuai
dimensi matriks kunci.

Rumus enkripsi:
C = K × P mod 26

Rumus dekripsi:
P = K^-1 × C mod 26

Keterangan:
P    = plaintext
C    = ciphertext
K    = matriks kunci
K^-1 = invers matriks kunci

Matriks kunci harus memiliki invers modulo 26 agar proses dekripsi
dapat dilakukan.
"""

if choice == 1:
    print(explanation)
elif choice == 2:
    print("==== hill CIPHER ====")

    plaintext = "HELP"

    key_matrix = [
        [3, 3],
        [2, 5],
    ]

    ciphertext = hill_encrypt(plaintext, key_matrix)
    hasil_dekripsi = hill_decrypt(ciphertext, key_matrix)

    print("Plaintext        : ", plaintext)
    print("Key Matrix       : ", key_matrix)
    print("Ciphertext       :", ciphertext)
    print("Decryption Result:", hasil_dekripsi)

elif choice == 3:
    print("==== Encryption ====")

    plaintext = input("Enter key plaintext: ")
    a11 = int(input("a11: "))
    a12 = int(input("a12: "))
    a21 = int(input("a21: "))
    a22 = int(input("a22: "))

    key_matrix = [[a11, a12], [a21, a22]]

    det = determinant(key_matrix)

    if gcd(det % 26, 26) != 1:
        print("\nInvalid key matrix. The determinant must be relatively prime to 26.")
    else:
        ciphertext = hill_encrypt(plaintext, key_matrix)

        print("\nPlaintext  : ", plaintext)
        print("Key Matrix   :", key_matrix)
        print("Dterminant   :", det)
        print("Ciphertext   : ", ciphertext)
elif choice == 4:
    print("==== Decryption ====")

    ciphertext = input("Enter ciphertext: ")

    a11 = int(input("a11: "))
    a12 = int(input("a12: "))
    a21 = int(input("a21: "))
    a22 = int(input("a22: "))

    key_matrix = [[a11, a12], [a21, a22]]

    det = determinant(key_matrix)

    if gcd(det % 26, 26) != 1:
        print("\nInvalid value for a. The determinant must be relatively prime to 26.")
    else:
        plaintext = hill_decrypt(ciphertext, key_matrix)

        print("\nCiphertext  : ", ciphertext)
        print("Key Matrix    :", key_matrix)
        print("Dterminant   :", det)
        print("Plaintext     : ", plaintext)

else:
    print("\nUpss.. It looks like your choice is invalid..")
