# ============================================================
# IMPLEMENTASI AFFINE CIPHER (MODUL)
# ============================================================
from math import gcd

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