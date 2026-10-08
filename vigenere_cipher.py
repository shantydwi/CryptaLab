# ============================================================
# IMPLEMENTASI VIGENERE CIPHER (MODUL)
# ============================================================


# ------------------------------------------------------------
# Fungsi untuk membersihkan teks
# Hanya huruf A-Z yang digunakan
# ------------------------------------------------------------
def clean_text(text):
    return "".join(char for char in text.upper() if char.isalpha())


# ------------------------------------------------------------
# Fungsi enkripsi Vigenere Cipher
#
# Rumus:
# C = (P + K) mod 26
#
# P = posisi plaintext
# K = posisi key
# C = posisi ciphertext
# ------------------------------------------------------------
def vigenere_encrypt(plaintext, key):

    plaintext = clean_text(plaintext)
    key = clean_text(key)

    if not key:
        raise ValueError("Key tidak boleh kosong.")

    ciphertext = ""

    for i, char in enumerate(plaintext):

        # Posisi huruf plaintext
        p = ord(char) - ord("A")

        # Posisi huruf key
        k = ord(key[i % len(key)]) - ord("A")

        # Rumus Vigenere
        c = (p + k) % 26

        # Ubah kembali menjadi huruf
        ciphertext += chr(c + ord("A"))

    return ciphertext


# ------------------------------------------------------------
# Fungsi dekripsi Vigenere Cipher
#
# Rumus:
# P = (C - K) mod 26
# ------------------------------------------------------------
def vigenere_decrypt(ciphertext, key):

    ciphertext = clean_text(ciphertext)
    key = clean_text(key)

    if not key:
        raise ValueError("Key tidak boleh kosong.")

    plaintext = ""

    for i, char in enumerate(ciphertext):

        # Posisi huruf ciphertext
        c = ord(char) - ord("A")

        # Posisi huruf key
        k = ord(key[i % len(key)]) - ord("A")

        # Rumus dekripsi
        p = (c - k) % 26

        # Ubah kembali menjadi huruf
        plaintext += chr(p + ord("A"))

    return plaintext