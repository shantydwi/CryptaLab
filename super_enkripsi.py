import base64


# ==============================
# VARIAN VIGENERE
# ==============================

def varian_vigenere_encrypt(plaintext, key):
    plaintext = "".join(c for c in plaintext.upper() if c.isalpha())
    key = "".join(c for c in key.upper() if c.isalpha())

    if not key:
        raise ValueError("Key tidak boleh kosong")

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
        raise ValueError("Key tidak boleh kosong")

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


# ==============================
# EXTENDED VIGENERE
# ==============================

def extended_vigenere_encrypt(plaintext, key):
    plaintext_bytes = plaintext.encode("utf-8")
    key_bytes = key.encode("utf-8")

    ciphertext = bytearray()

    for i in range(len(plaintext_bytes)):
        p = plaintext_bytes[i]
        k = key_bytes[i % len(key_bytes)]

        c = (p + k) % 256
        ciphertext.append(c)

    return bytes(ciphertext)


def extended_vigenere_decrypt(ciphertext, key):
    key_bytes = key.encode("utf-8")

    plaintext = bytearray()

    for i in range(len(ciphertext)):
        c = ciphertext[i]
        k = key_bytes[i % len(key_bytes)]

        p = (c - k) % 256
        plaintext.append(p)

    return bytes(plaintext)


# ==============================
# SUPER ENKRIPSI
# ==============================

def super_enkripsi(plaintext, key_varian, key_extended):

    # Tahap 1
    hasil_varian = varian_vigenere_encrypt(
        plaintext,
        key_varian
    )

    # Tahap 2
    hasil_extended = extended_vigenere_encrypt(
        hasil_varian,
        key_extended
    )

    return hasil_varian, hasil_extended


# ==============================
# SUPER DEKRIPSI
# ==============================

def super_dekripsi(ciphertext, key_varian, key_extended):

    # Tahap 1
    hasil_extended = extended_vigenere_decrypt(
        ciphertext,
        key_extended
    )

    hasil_extended = hasil_extended.decode("utf-8")

    # Tahap 2
    hasil_varian = varian_vigenere_decrypt(
        hasil_extended,
        key_varian
    )

    return hasil_extended, hasil_varian


# ==============================
# PROGRAM UTAMA
# ==============================

print("=" * 60)
print("              SUPER ENKRIPSI")
print("       VARIAN VIGENERE + EXTENDED VIGENERE")
print("=" * 60)

plaintext = input("\nMasukkan plaintext      : ")
key_varian = input("Masukkan key Varian     : ")
key_extended = input("Masukkan key Extended   : ")

if not key_varian or not key_extended:

    print("\nError: Key tidak boleh kosong.")

else:

    # ENKRIPSI
    hasil_varian, ciphertext = super_enkripsi(
        plaintext,
        key_varian,
        key_extended
    )

    ciphertext_base64 = base64.b64encode(
        ciphertext
    ).decode("ascii")

    # DEKRIPSI
    hasil_extended, hasil_dekripsi = super_dekripsi(
        ciphertext,
        key_varian,
        key_extended
    )

    print("\n" + "=" * 60)
    print("HASIL SUPER ENKRIPSI")
    print("=" * 60)

    print("Plaintext             :", plaintext)
    print("Key Varian            :", key_varian)
    print("Key Extended          :", key_extended)

    print("\nTahap 1 - Varian Vigenere")
    print("Ciphertext 1          :", hasil_varian)

    print("\nTahap 2 - Extended Vigenere")
    print("Ciphertext Base64     :", ciphertext_base64)

    print("\n" + "=" * 60)
    print("HASIL SUPER DEKRIPSI")
    print("=" * 60)

    print("Tahap 1 - Extended    :", hasil_extended)
    print("Hasil Dekripsi        :", hasil_dekripsi)

    print("\n" + "=" * 60)

    if hasil_dekripsi == "".join(
        c for c in plaintext.upper() if c.isalpha()
    ):
        print("STATUS                : BERHASIL")
    else:
        print("STATUS                : GAGAL")

    print("=" * 60)