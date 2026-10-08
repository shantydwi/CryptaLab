# ============================================================
# IMPLEMENTASI VIGENERE CIPHER
# ============================================================

GROUP_NAME = "The cipherlings"

GROUP_MEMBERS = [
    "Ririn Rahma Arifa - 237006171",
    "Tia Amelia - 237006162",
    "Shanty Dwi Septiani - 237006161",
]


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


# ------------------------------------------------------------
# Fungsi untuk menampilkan proses perhitungan
# ------------------------------------------------------------
def show_process(plaintext, key, ciphertext):

    plaintext = clean_text(plaintext)
    key = clean_text(key)

    print("\nProses Enkripsi:")
    print("-" * 60)
    print(f"Plaintext : {plaintext}")
    print(f"Key       : {key}")
    print(f"Key ulang : {''.join(key[i % len(key)] for i in range(len(plaintext)))}")
    print(f"Ciphertext: {ciphertext}")

    print("\nDetail per karakter:")

    for i, char in enumerate(plaintext):

        p = ord(char) - ord("A")
        k_char = key[i % len(key)]
        k = ord(k_char) - ord("A")
        c = (p + k) % 26

        print(
            f"{char} + {k_char} "
            f"-> ({p} + {k}) mod 26 = {c} "
            f"-> {chr(c + ord('A'))}"
        )


# ------------------------------------------------------------
# DEMO PROGRAM
# ------------------------------------------------------------
def main():

    print("=" * 60)
    print("IMPLEMENTASI VIGENERE CIPHER")
    print("=" * 60)

    print(f"\nNama Kelompok : {GROUP_NAME}")

    print("\nAnggota:")
    for member in GROUP_MEMBERS:
        print(f"- {member}")

    # --------------------------------------------------------
    # Data pengujian
    # --------------------------------------------------------
    plaintext = "ATTACKATDAWN"
    key = "LEMON"

    print("\n" + "-" * 60)
    print("DEMO UJI VIGENERE CIPHER")
    print("-" * 60)

    print(f"Plaintext       : {plaintext}")
    print(f"Key             : {key}")

    # Enkripsi
    ciphertext = vigenere_encrypt(plaintext, key)

    # Tampilkan proses
    show_process(plaintext, key, ciphertext)

    # Dekripsi
    decrypted = vigenere_decrypt(ciphertext, key)

    print("\n" + "-" * 60)
    print("HASIL")
    print("-" * 60)

    print(f"Plaintext       : {plaintext}")
    print(f"Key             : {key}")
    print(f"Ciphertext      : {ciphertext}")
    print(f"Hasil Dekripsi  : {decrypted}")

    # --------------------------------------------------------
    # Verifikasi hasil
    # --------------------------------------------------------
    print("\n" + "-" * 60)

    if decrypted == clean_text(plaintext):
        print("STATUS          : BERHASIL")
        print("Enkripsi dan dekripsi berjalan dengan benar.")
    else:
        print("STATUS          : GAGAL")
        print("Hasil dekripsi tidak sama dengan plaintext.")

    print("-" * 60)


# ------------------------------------------------------------
# Menjalankan program
# ------------------------------------------------------------
if __name__ == "__main__":
    main()
