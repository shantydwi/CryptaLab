# ============================================================
# IMPLEMENTASI PLAYFAIR CIPHER (MODUL)
# ============================================================


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

    return [letters[i:i + 5] for i in range(0, 25, 5)]


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
    if not key:
        raise ValueError("Key tidak boleh kosong.")

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
    if not key:
        raise ValueError("Key tidak boleh kosong.")

    matrix = create_matrix(key)

    ciphertext = ciphertext.upper()
    ciphertext = "".join(char for char in ciphertext if char.isalpha())

    if len(ciphertext) % 2 != 0:
        raise ValueError("Panjang ciphertext harus genap.")

    plaintext = ""

    for i in range(0, len(ciphertext), 2):
        pair = ciphertext[i:i + 2]
        plaintext += decrypt_pair(pair, matrix)

    return plaintext