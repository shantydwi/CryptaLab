# ============================================================
# IMPLEMENTASI PLAYFAIR CIPHER
# ============================================================

GROUP_NAME = "The cipherlings"

GROUP_MEMBERS = [
    "Ririn Rahma Arifa - 237006171",
    "Tia Amelia - 237006162",
    "Shanty Dwi Septiani - 237006161",
]


# ------------------------------------------------------------
# Membuat matriks Playfair 5x5
# Huruf J digabung dengan I
# ------------------------------------------------------------
def create_matrix(key):
    key = key.upper().replace("J", "I")
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    letters = []

    for char in key + alphabet:
        if char.isalpha() and char not in letters:
            letters.append(char)

    return [letters[i : i + 5] for i in range(0, 25, 5)]


# ------------------------------------------------------------
# Menampilkan matriks
# ------------------------------------------------------------
def print_matrix(matrix):
    print("\nMatriks Playfair:")
    print("+---+---+---+---+---+")

    for row in matrix:
        print("| " + " | ".join(row) + " |")
        print("+---+---+---+---+---+")


# ------------------------------------------------------------
# Menyiapkan plaintext menjadi pasangan huruf
# ------------------------------------------------------------
def prepare_text(text):
    text = text.upper()
    text = "".join(char for char in text if char.isalpha())
    text = text.replace("J", "I")

    pairs = []
    i = 0

    while i < len(text):
        first = text[i]

        # Jika huruf terakhir, tambahkan X
        if i + 1 >= len(text):
            second = "X"
            i += 1

        # Jika dua huruf sama, sisipkan X
        elif text[i] == text[i + 1]:
            second = "X"
            i += 1

        else:
            second = text[i + 1]
            i += 2

        pairs.append(first + second)

    return pairs


# ------------------------------------------------------------
# Mencari posisi huruf dalam matriks
# ------------------------------------------------------------
def find_position(matrix, char):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col

    raise ValueError(f"Karakter '{char}' tidak ditemukan.")


# ------------------------------------------------------------
# Enkripsi pasangan huruf
# ------------------------------------------------------------
def encrypt_pair(pair, matrix):
    row1, col1 = find_position(matrix, pair[0])
    row2, col2 = find_position(matrix, pair[1])

    # Baris sama -> geser ke kanan
    if row1 == row2:
        return matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]

    # Kolom sama -> geser ke bawah
    elif col1 == col2:
        return matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]

    # Membentuk persegi panjang
    else:
        return matrix[row1][col2] + matrix[row2][col1]


# ------------------------------------------------------------
# Dekripsi pasangan huruf
# ------------------------------------------------------------
def decrypt_pair(pair, matrix):
    row1, col1 = find_position(matrix, pair[0])
    row2, col2 = find_position(matrix, pair[1])

    # Baris sama -> geser ke kiri
    if row1 == row2:
        return matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]

    # Kolom sama -> geser ke atas
    elif col1 == col2:
        return matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]

    # Membentuk persegi panjang
    else:
        return matrix[row1][col2] + matrix[row2][col1]


# ------------------------------------------------------------
# Enkripsi utama
# ------------------------------------------------------------
def playfair_encrypt(plaintext, key):
    matrix = create_matrix(key)
    pairs = prepare_text(plaintext)

    ciphertext = ""

    for pair in pairs:
        ciphertext += encrypt_pair(pair, matrix)

    return ciphertext


# ------------------------------------------------------------
# Dekripsi utama
# ------------------------------------------------------------
def playfair_decrypt(ciphertext, key):
    matrix = create_matrix(key)

    ciphertext = ciphertext.upper()
    ciphertext = "".join(char for char in ciphertext if char.isalpha())

    plaintext = ""

    for i in range(0, len(ciphertext), 2):
        pair = ciphertext[i : i + 2]
        plaintext += decrypt_pair(pair, matrix)

    return plaintext


# ------------------------------------------------------------
# DEMO PROGRAM
# ------------------------------------------------------------
def main():

    print("=" * 60)
    print("IMPLEMENTASI PLAYFAIR CIPHER")
    print("=" * 60)

    print(f"\nNama Kelompok : {GROUP_NAME}")

    print("Anggota:")
    for member in GROUP_MEMBERS:
        print(f"- {member}")

    # Data pengujian
    plaintext = "HARI INI"
    key = "KUNCI"

    print("\n" + "-" * 60)
    print("DEMO UJI PLAYFAIR CIPHER")
    print("-" * 60)

    print(f"Plaintext       : {plaintext}")
    print(f"Key             : {key}")

    # Membuat matriks
    matrix = create_matrix(key)

    print_matrix(matrix)

    # Menampilkan pasangan huruf
    pairs = prepare_text(plaintext)

    print(f"\nPasangan Huruf  : {' '.join(pairs)}")

    # Enkripsi
    ciphertext = playfair_encrypt(plaintext, key)

    print(f"Ciphertext      : {ciphertext}")

    # Dekripsi
    decrypted = playfair_decrypt(ciphertext, key)

    print(f"Hasil Dekripsi  : {decrypted}")

    # --------------------------------------------------------
    # Verifikasi
    # --------------------------------------------------------

    normalized_plaintext = plaintext.upper().replace("J", "I").replace(" ", "")

    # Hapus X padding di bagian akhir
    decrypted_clean = decrypted.rstrip("X")

    print("\n" + "-" * 60)

    print(f"Plaintext Normal : {normalized_plaintext}")
    print(f"Dekripsi Bersih  : {decrypted_clean}")

    if decrypted_clean == normalized_plaintext:
        print("STATUS           : BERHASIL")
        print("Enkripsi dan dekripsi berjalan dengan benar.")
    else:
        print("STATUS           : GAGAL")
        print("Hasil dekripsi tidak sama dengan plaintext.")

    print("-" * 60)


# ------------------------------------------------------------
# Menjalankan program
# ------------------------------------------------------------
if __name__ == "__main__":
    main()
