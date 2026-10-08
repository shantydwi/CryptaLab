# ============================================================
# VARIAN VIGENERE CIPHER (AUTO-KEY) - MODUL
# ============================================================

def varian_vigenere_encrypt(plaintext, key):
    plaintext = "".join(c for c in plaintext.upper() if c.isalpha())
    key = "".join(c for c in key.upper() if c.isalpha())

    if not key:
        raise ValueError("key tidak boleh kosong")

    extended_key = key + plaintext

    ciphertext = ""

    for i, char in enumerate(plaintext):
        p = ord(char) - ord('A')
        k = ord(extended_key[i]) - ord('A')

        c = (p + k) % 26
        ciphertext += chr(c + ord('A'))

    return ciphertext


def varian_vigenere_decrypt(ciphertext, key):
    ciphertext = "".join(c for c in ciphertext.upper() if c.isalpha())
    key = "".join(c for c in key.upper() if c.isalpha())

    if not key:
        raise ValueError("key tidak boleh kosong")

    plaintext = ""

    for i, char in enumerate(ciphertext):
        c = ord(char) - ord('A')

        if i < len(key):
            k = ord(key[i]) - ord('A')
        else:
            k = ord(plaintext[i - len(key)]) - ord('A')

        p = (c - k) % 26
        plaintext += chr(p + ord('A'))

    return plaintext