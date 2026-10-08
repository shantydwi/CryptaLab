import base64


def encrypt_extended_vigenere(plaintext, key):
    plaintext_bytes = plaintext.encode("utf-8")
    key_bytes = key.encode("utf-8")

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

    plaintext = bytearray()

    for i in range(len(ciphertext)):
        c = ciphertext[i]
        k = key_bytes[i % len(key_bytes)]

        # P = (C - K) mod 256
        p = (c - k) % 256
        plaintext.append(p)

    return bytes(plaintext)


# PROGRAM UTAMA
print("=" * 50)
print("       EXTENDED VIGENERE CIPHER")
print("              MODULO 256")
print("=" * 50)

plaintext = input("\nMasukkan plaintext : ")
key = input("Masukkan key       : ")

if not key:
    print("\nError: Key tidak boleh kosong.")

else:
    # ENKRIPSI
    ciphertext = encrypt_extended_vigenere(plaintext, key)

    # Ciphertext ditampilkan dalam Base64
    ciphertext_base64 = base64.b64encode(ciphertext).decode("ascii")

    # DEKRIPSI
    decrypted_bytes = decrypt_extended_vigenere(ciphertext, key)
    decrypted_text = decrypted_bytes.decode("utf-8")

    # Plaintext hasil dekripsi dalam Base64
    decrypted_base64 = base64.b64encode(
        decrypted_bytes
    ).decode("ascii")

    print("\n" + "=" * 50)
    print("HASIL ENKRIPSI")
    print("=" * 50)

    print("Plaintext          :", plaintext)
    print("Key                :", key)
    print("Ciphertext Base64  :", ciphertext_base64)

    print("\n" + "=" * 50)
    print("HASIL DEKRIPSI")
    print("=" * 50)

    print("Ciphertext Base64  :", ciphertext_base64)
    print("Key                :", key)
    print("Plaintext Base64   :", decrypted_base64)
    print("Hasil Dekripsi     :", decrypted_text)

    if decrypted_text == plaintext:
        print("Status             : BERHASIL")
    else:
        print("Status             : GAGAL")