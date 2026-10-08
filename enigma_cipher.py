# 4. ENIGMA CIPHER
# ------------------------------------------------------------
# IDENTITAS KELOMPOK
GROUP_NAME = "The Cipherlings"
GROUP_MEMBERS = [
    "Ririn Rahma Arifa - 237006171",
    "Tia Amelia - 237006162",
    "Shanty Dwi Septiani - 237006161",
]


# KONFIGURASI ENIGMA
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Wiring Rotor Enigma I, II, dan III
ROTORS = {
    "I": {"wiring": "EKMFLGDQVZNTOWYHXUSPAIBRCJ", "notch": "Q"},
    "II": {"wiring": "AJDKSIRUXBLHWTMCQGZNPYFVOE", "notch": "E"},
    "III": {"wiring": "BDFHJLCPRTXVZNYEIWGAKMUSQO", "notch": "V"},
}

# Reflector B
REFLECTOR_B = "YRUHQSLDPXNGOKMIEBFZCWVJAT"


# FUNGSI PLUGBOARD
def create_plugboard(pairs):
    """
    Membuat pasangan huruf pada plugboard.

    Contoh:
    "AB CD EF"

    berarti:
    A <-> B
    C <-> D
    E <-> F
    """

    # Awalnya setiap huruf dipetakan ke dirinya sendiri
    mapping = {letter: letter for letter in ALPHABET}

    if not pairs:
        return mapping

    for pair in pairs.upper().split():

        # Setiap pasangan harus berisi dua huruf
        if len(pair) != 2:
            raise ValueError("Setiap pasangan plugboard harus terdiri dari 2 huruf.")

        a, b = pair

        # Validasi huruf
        if a not in ALPHABET or b not in ALPHABET:
            raise ValueError("Plugboard hanya boleh menggunakan huruf A-Z.")

        # Tidak boleh memasangkan huruf dengan dirinya sendiri
        if a == b:
            raise ValueError(
                "Huruf plugboard tidak boleh dipasangkan dengan dirinya sendiri."
            )

        # Satu huruf tidak boleh digunakan dua kali
        if mapping[a] != a or mapping[b] != b:
            raise ValueError(
                "Satu huruf tidak boleh digunakan pada dua pasangan plugboard."
            )

        # Membuat pasangan dua arah
        mapping[a] = b
        mapping[b] = a

    return mapping


# FUNGSI ROTOR - JALUR MAJU
def rotor_forward(char, wiring, position):
    """
    Melewatkan huruf melalui rotor pada jalur maju
    menuju reflector.
    """

    # Mengubah huruf menjadi indeks 0-25
    index = ALPHABET.index(char)

    # Menyesuaikan indeks dengan posisi rotor
    shifted_index = (index + position) % 26

    # Melakukan substitusi berdasarkan wiring rotor
    mapped_char = wiring[shifted_index]

    # Mengembalikan pergeseran posisi rotor
    output_index = (ALPHABET.index(mapped_char) - position) % 26

    return ALPHABET[output_index]


# FUNGSI ROTOR - JALUR KEMBALI
def rotor_backward(char, wiring, position):
    """
    Melewatkan huruf melalui rotor pada jalur kembali
    setelah dipantulkan oleh reflector.
    """

    # Mengubah huruf menjadi indeks
    index = ALPHABET.index(char)

    # Menyesuaikan dengan posisi rotor
    shifted_index = (index + position) % 26

    shifted_char = ALPHABET[shifted_index]

    # Mencari posisi huruf pada wiring rotor
    mapped_index = wiring.index(shifted_char)

    # Mengembalikan pergeseran rotor
    output_index = (mapped_index - position) % 26

    return ALPHABET[output_index]


# FUNGSI REFLECTOR
def reflector(char):
    """
    Memantulkan sinyal menggunakan Reflector B.
    """

    index = ALPHABET.index(char)

    return REFLECTOR_B[index]


# FUNGSI PERGERAKAN ROTOR
def step_rotors(positions):
    """
    Menggerakkan rotor menggunakan mekanisme turnover
    dan double-stepping.

    Urutan posisi:
    [Rotor kiri, Rotor tengah, Rotor kanan]

    Rotor III = kanan
    Rotor II  = tengah
    Rotor I   = kiri
    """

    left, middle, right = positions

    # Mengecek apakah rotor berada pada posisi notch
    middle_at_notch = ALPHABET[middle] == ROTORS["II"]["notch"]

    right_at_notch = ALPHABET[right] == ROTORS["III"]["notch"]

    # Jika rotor tengah berada di notch, rotor kiri ikut bergerak
    if middle_at_notch:
        left = (left + 1) % 26

    # Rotor tengah bergerak jika:
    # - rotor tengah berada di notch, atau
    # - rotor kanan berada di notch
    if middle_at_notch or right_at_notch:
        middle = (middle + 1) % 26

    # Rotor kanan selalu bergerak setiap huruf
    right = (right + 1) % 26

    return [left, middle, right]


# FUNGSI UTAMA ENIGMA
def enigma(
    text, rotor_names=("I", "II", "III"), initial_positions="AAA", plugboard_pairs=""
):
    """
    Fungsi utama Enigma Cipher.

    Fungsi yang sama digunakan untuk proses enkripsi
    maupun dekripsi.

    Parameter:
    text              = teks yang diproses
    rotor_names       = urutan rotor dari kiri ke kanan
    initial_positions = posisi awal rotor, contoh "AAA"
    plugboard_pairs   = pasangan plugboard
    """

    text = text.upper()

    # Validasi posisi awal
    if len(initial_positions) != 3:
        raise ValueError("Posisi awal rotor harus terdiri dari 3 huruf.")

    # Mengubah posisi rotor dari huruf menjadi angka
    # A = 0, B = 1, ..., Z = 25
    positions = [
        ALPHABET.index(initial_positions[0].upper()),
        ALPHABET.index(initial_positions[1].upper()),
        ALPHABET.index(initial_positions[2].upper()),
    ]

    # Membuat konfigurasi plugboard
    plugboard = create_plugboard(plugboard_pairs)

    # Mengambil wiring masing-masing rotor
    left_rotor = ROTORS[rotor_names[0]]["wiring"]
    middle_rotor = ROTORS[rotor_names[1]]["wiring"]
    right_rotor = ROTORS[rotor_names[2]]["wiring"]

    result = ""

    # Memproses setiap karakter
    for char in text:

        # Karakter selain A-Z tidak dienkripsi
        if char not in ALPHABET:
            result += char
            continue

        # 1. ROTOR BERGERAK
        positions = step_rotors(positions)

        left_pos, middle_pos, right_pos = positions

        # 2. MASUK MELALUI PLUGBOARD
        char = plugboard[char]

        # 3. JALUR MAJU MELALUI ROTOR
        # Rotor kanan (III)
        char = rotor_forward(char, right_rotor, right_pos)

        # Rotor tengah (II)
        char = rotor_forward(char, middle_rotor, middle_pos)

        # Rotor kiri (I)
        char = rotor_forward(char, left_rotor, left_pos)

        # 4. REFLECTOR
        char = reflector(char)

        # 5. JALUR KEMBALI MELALUI ROTOR
        # Rotor kiri (I)
        char = rotor_backward(char, left_rotor, left_pos)

        # Rotor tengah (II)
        char = rotor_backward(char, middle_rotor, middle_pos)

        # Rotor kanan (III)
        char = rotor_backward(char, right_rotor, right_pos)

        # 6. KELUAR MELALUI PLUGBOARD
        char = plugboard[char]

        # Menambahkan hasil ke output
        result += char

    return result


# DEMO UJI ENIGMA CIPHER
# Plaintext yang akan dienkripsi
plaintext = "KRIPTOGRAFI"

# Urutan rotor
rotor_order = ("I", "II", "III")

# Posisi awal rotor
initial_position = "AAA"

# Konfigurasi plugboard
plugboard_setting = "AV BS CG DL FU HZ IN KM OW RX"


# PROSES ENKRIPSI
ciphertext = enigma(plaintext, rotor_order, initial_position, plugboard_setting)


# PROSES DEKRIPSI
# Enigma menggunakan proses yang sama untuk dekripsi.
# Posisi rotor harus dikembalikan ke posisi awal yang sama.

decrypted_text = enigma(ciphertext, rotor_order, initial_position, plugboard_setting)


# MENAMPILKAN IDENTITAS KELOMPOK
print("=" * 60)
print("       IMPLEMENTASI KRIPTOGRAFI KLASIK")
print("=" * 60)

print("Nama Kelompok :", GROUP_NAME)
print("Anggota       :")

for member in GROUP_MEMBERS:
    print("  -", member)


# MENAMPILKAN HASIL DEMO ENIGMA
print()
print("=" * 60)
print("                 DEMO ENIGMA CIPHER")
print("=" * 60)

print("Plaintext       :", plaintext)
print("Rotor           :", " - ".join(rotor_order))
print("Posisi Awal     :", initial_position)
print("Reflector       : B")
print("Plugboard       :", plugboard_setting)

print("-" * 60)

print("Ciphertext      :", ciphertext)
print("Hasil Dekripsi  :", decrypted_text)

print("-" * 60)


# VERIFIKASI HASIL DEKRIPSI
if decrypted_text == plaintext:
    print("Status          : DEKRIPSI BERHASIL")
    print("                  Hasil dekripsi sama dengan plaintext.")
else:
    print("Status          : DEKRIPSI GAGAL")
    print("                  Hasil dekripsi tidak sama dengan plaintext.")

print("=" * 60)
