# ============================================================
# IMPLEMENTASI HILL CIPHER (MODUL)
# ============================================================
from math import gcd

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
        raise ValueError("Matrix tidak memiliki invers modulo 26.")

    det_inverse = mod_inverse(det_mod, 26)

    adjugate = [
        [matrix[1][1], -matrix[0][1]],
        [-matrix[1][0], matrix[0][0]],
    ]

    inverse_matrix = [
        [(det_inverse * adjugate[i][j]) % 26 for j in range(2)]
        for i in range(2)
    ]
    return inverse_matrix


def hill_encrypt(plaintext, key_matrix):
    plaintext = plaintext.upper()
    plaintext = "".join(char for char in plaintext if char.isalpha())

    if not plaintext:
        return ""

    if len(plaintext) % 2 != 0:
        plaintext += "X"

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
    ciphertext = "".join(char for char in ciphertext if char.isalpha())

    if len(ciphertext) % 2 != 0:
        raise ValueError("Panjang ciphertext harus genap.")

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