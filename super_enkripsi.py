# SUPER ENKRIPSI: EXTENDED VIGENERE + TRANSPOSISI KOLOM (MODUL)

from extended_vigenere_cipher import (
    encrypt_extended_vigenere,
    decrypt_extended_vigenere,
    encrypt_extended_vigenere_bytes,
    decrypt_extended_vigenere_bytes,
)


# TRANSPOSISI KOLOM
def transposisi_kolom_encrypt(plaintext_bytes, key):
    """
    Cipher transposisi kolom.
    plaintext_bytes : bytes
    key             : string (kata kunci)
    return          : bytes
    """
    if not key:
        raise ValueError("Key transposisi tidak boleh kosong.")

    n_cols = len(key)
    n_rows = (len(plaintext_bytes) + n_cols - 1) // n_cols

    # Padding dengan spasi (0x20) agar penuh
    padded = plaintext_bytes + b'\x20' * (n_rows * n_cols - len(plaintext_bytes))

    # Buat matriks baris x kolom
    matrix = [list(padded[i * n_cols:(i + 1) * n_cols]) for i in range(n_rows)]

    # Urutan kolom berdasarkan karakter key (di-sort alfabetis)
    order = sorted(range(n_cols), key=lambda i: key[i])

    # Baca kolom sesuai urutan
    result = bytearray()
    for col in order:
        for row in range(n_rows):
            result.append(matrix[row][col])

    return bytes(result)


def transposisi_kolom_decrypt(ciphertext_bytes, key):
    if not key:
        raise ValueError("Key transposisi tidak boleh kosong.")

    n_cols = len(key)
    n_rows = (len(ciphertext_bytes) + n_cols - 1) // n_cols

    order = sorted(range(n_cols), key=lambda i: key[i])

    # Pecah ciphertext ke kolom sesuai urutan
    cols_data = {}
    idx = 0
    for col in order:
        cols_data[col] = list(ciphertext_bytes[idx:idx + n_rows])
        idx += n_rows

    # Rekonstruksi matriks per baris
    result = bytearray()
    for row in range(n_rows):
        for col in range(n_cols):
            result.append(cols_data[col][row])

    return bytes(result)


# ==============================
# SUPER ENKRIPSI (versi string — untuk input teks manual)
# ==============================

def super_enkripsi(plaintext, key_extended, key_transposisi):
    # Simpan panjang plaintext asli di 4 byte pertama
    plaintext_bytes = plaintext.encode("utf-8")
    panjang = len(plaintext_bytes)
    header = panjang.to_bytes(4, "big")
    payload = header + plaintext_bytes

    key_ext_bytes = key_extended.encode("utf-8")

    # Tahap 1: Extended Vigenere (byte)
    hasil_vigenere = encrypt_extended_vigenere_bytes(payload, key_ext_bytes)

    # Tahap 2: Transposisi Kolom
    hasil_transposisi = transposisi_kolom_encrypt(
        hasil_vigenere, key_transposisi
    )

    return hasil_vigenere, hasil_transposisi


def super_dekripsi(ciphertext, key_extended, key_transposisi):
    # ciphertext bisa bytes atau str
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode("latin-1")

    # Tahap 1: Transposisi Kolom (kebalikan)
    hasil_transposisi = transposisi_kolom_decrypt(
        ciphertext, key_transposisi
    )

    key_ext_bytes = key_extended.encode("utf-8")

    # Tahap 2: Extended Vigenere (kebalikan)
    hasil_vigenere = decrypt_extended_vigenere_bytes(
        hasil_transposisi, key_ext_bytes
    )

    # Baca panjang asli dari 4 byte pertama
    panjang_asli = int.from_bytes(hasil_vigenere[:4], "big")
    plaintext_bytes = hasil_vigenere[4:4 + panjang_asli]

    return hasil_transposisi, plaintext_bytes.decode("utf-8")


# ==============================
# SUPER ENKRIPSI (versi byte — untuk file biner)
# ==============================

def super_enkripsi_bytes(plaintext_bytes, key_extended, key_transposisi):
    key_ext = key_extended.encode("utf-8")

    # Simpan panjang plaintext di 4 byte pertama
    panjang = len(plaintext_bytes)
    header = panjang.to_bytes(4, "big")
    payload = header + plaintext_bytes

    # Tahap 1: Extended Vigenere (byte)
    hasil_vigenere = encrypt_extended_vigenere_bytes(payload, key_ext)

    # Tahap 2: Transposisi Kolom
    hasil_transposisi = transposisi_kolom_encrypt(
        hasil_vigenere, key_transposisi
    )

    return hasil_vigenere, hasil_transposisi


def super_dekripsi_bytes(ciphertext_bytes, key_extended, key_transposisi):
    key_ext = key_extended.encode("utf-8")

    # Tahap 1: Transposisi Kolom (kebalikan)
    hasil_transposisi = transposisi_kolom_decrypt(
        ciphertext_bytes, key_transposisi
    )

    # Tahap 2: Extended Vigenere (kebalikan)
    hasil_vigenere = decrypt_extended_vigenere_bytes(
        hasil_transposisi, key_ext
    )

    # Baca panjang asli dari 4 byte pertama
    panjang_asli = int.from_bytes(hasil_vigenere[:4], "big")
    plaintext_bytes = hasil_vigenere[4:4 + panjang_asli]

    return hasil_transposisi, plaintext_bytes