# EXTENDED VIGENERE CIPHER (MODUL) - MODULO 256

def encrypt_extended_vigenere(plaintext, key):
    plaintext_bytes = plaintext.encode("utf-8")
    key_bytes = key.encode("utf-8")

    if not key_bytes:
        raise ValueError("Key tidak boleh kosong.")

    ciphertext = bytearray()

    for i in range(len(plaintext_bytes)):
        p = plaintext_bytes[i]
        k = key_bytes[i % len(key_bytes)]

        # C = (P + K) mod 256
        c = (p + k) % 256
        ciphertext.append(c)

    return bytes(ciphertext)


def decrypt_extended_vigenere(ciphertext, key):
    key_bytes = key.encode("utf-8")

    if not key_bytes:
        raise ValueError("Key tidak boleh kosong.")

    plaintext = bytearray()

    for i in range(len(ciphertext)):
        c = ciphertext[i]
        k = key_bytes[i % len(key_bytes)]

        # P = (C - K) mod 256
        p = (c - k) % 256
        plaintext.append(p)

    return bytes(plaintext)


# ============================================================
# FUNGSI BYTE (untuk file biner)
# ============================================================

def encrypt_extended_vigenere_bytes(plaintext_bytes, key_bytes):
    """Enkripsi byte asli dengan Extended Vigenere (byte-to-byte)."""
    if not key_bytes:
        raise ValueError("Key tidak boleh kosong.")

    ciphertext = bytearray()
    for i in range(len(plaintext_bytes)):
        p = plaintext_bytes[i]
        k = key_bytes[i % len(key_bytes)]
        c = (p + k) % 256
        ciphertext.append(c)

    return bytes(ciphertext)


def decrypt_extended_vigenere_bytes(ciphertext_bytes, key_bytes):
    """Dekripsi byte dengan Extended Vigenere (byte-to-byte)."""
    if not key_bytes:
        raise ValueError("Key tidak boleh kosong.")

    plaintext = bytearray()
    for i in range(len(ciphertext_bytes)):
        c = ciphertext_bytes[i]
        k = key_bytes[i % len(key_bytes)]
        p = (c - k) % 256
        plaintext.append(p)

    return bytes(plaintext)