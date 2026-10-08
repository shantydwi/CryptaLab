# ============================================================
# ENIGMA CIPHER (MODUL)
# ============================================================

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Wiring Rotor Enigma I, II, dan III
ROTORS = {
    "I":   {"wiring": "EKMFLGDQVZNTOWYHXUSPAIBRCJ", "notch": "Q"},
    "II":  {"wiring": "AJDKSIRUXBLHWTMCQGZNPYFVOE", "notch": "E"},
    "III": {"wiring": "BDFHJLCPRTXVZNYEIWGAKMUSQO", "notch": "V"},
}

# Reflector B
REFLECTOR_B = "YRUHQSLDPXNGOKMIEBFZCWVJAT"


# ------------------------------------------------------------
# FUNGSI PLUGBOARD
# ------------------------------------------------------------
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
    mapping = {letter: letter for letter in ALPHABET}

    if not pairs:
        return mapping

    for pair in pairs.upper().split():

        if len(pair) != 2:
            raise ValueError(
                "Setiap pasangan plugboard harus terdiri dari 2 huruf."
            )

        a, b = pair

        if a not in ALPHABET or b not in ALPHABET:
            raise ValueError("Plugboard hanya boleh menggunakan huruf A-Z.")

        if a == b:
            raise ValueError(
                "Huruf plugboard tidak boleh dipasangkan dengan dirinya sendiri."
            )

        if mapping[a] != a or mapping[b] != b:
            raise ValueError(
                "Satu huruf tidak boleh digunakan pada dua pasangan plugboard."
            )

        mapping[a] = b
        mapping[b] = a

    return mapping


# ------------------------------------------------------------
# FUNGSI ROTOR - JALUR MAJU
# ------------------------------------------------------------
def rotor_forward(char, wiring, position):
    index = ALPHABET.index(char)
    shifted_index = (index + position) % 26
    mapped_char = wiring[shifted_index]
    output_index = (ALPHABET.index(mapped_char) - position) % 26
    return ALPHABET[output_index]


# ------------------------------------------------------------
# FUNGSI ROTOR - JALUR KEMBALI
# ------------------------------------------------------------
def rotor_backward(char, wiring, position):
    index = ALPHABET.index(char)
    shifted_index = (index + position) % 26
    shifted_char = ALPHABET[shifted_index]
    mapped_index = wiring.index(shifted_char)
    output_index = (mapped_index - position) % 26
    return ALPHABET[output_index]


# ------------------------------------------------------------
# FUNGSI REFLECTOR
# ------------------------------------------------------------
def reflector(char):
    index = ALPHABET.index(char)
    return REFLECTOR_B[index]


# ------------------------------------------------------------
# FUNGSI PERGERAKAN ROTOR
# ------------------------------------------------------------
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

    middle_at_notch = ALPHABET[middle] == ROTORS["II"]["notch"]
    right_at_notch  = ALPHABET[right]  == ROTORS["III"]["notch"]

    if middle_at_notch:
        left = (left + 1) % 26

    if middle_at_notch or right_at_notch:
        middle = (middle + 1) % 26

    right = (right + 1) % 26

    return [left, middle, right]


# ------------------------------------------------------------
# FUNGSI UTAMA ENIGMA
# ------------------------------------------------------------
def enigma(
    text,
    rotor_names=("I", "II", "III"),
    initial_positions="AAA",
    plugboard_pairs="",
):
    """
    Fungsi utama Enigma Cipher.
    Fungsi yang sama digunakan untuk proses enkripsi
    maupun dekripsi.
    """
    text = text.upper()

    if len(initial_positions) != 3:
        raise ValueError("Posisi awal rotor harus terdiri dari 3 huruf.")

    positions = [
        ALPHABET.index(initial_positions[0].upper()),
        ALPHABET.index(initial_positions[1].upper()),
        ALPHABET.index(initial_positions[2].upper()),
    ]

    plugboard = create_plugboard(plugboard_pairs)

    left_rotor   = ROTORS[rotor_names[0]]["wiring"]
    middle_rotor = ROTORS[rotor_names[1]]["wiring"]
    right_rotor  = ROTORS[rotor_names[2]]["wiring"]

    result = ""

    for char in text:

        if char not in ALPHABET:
            result += char
            continue

        # 1. Rotor bergerak
        positions = step_rotors(positions)
        left_pos, middle_pos, right_pos = positions

        # 2. Masuk melalui plugboard
        char = plugboard[char]

        # 3. Jalur maju melalui rotor
        char = rotor_forward(char, right_rotor, right_pos)
        char = rotor_forward(char, middle_rotor, middle_pos)
        char = rotor_forward(char, left_rotor, left_pos)

        # 4. Reflector
        char = reflector(char)

        # 5. Jalur kembali melalui rotor
        char = rotor_backward(char, left_rotor, left_pos)
        char = rotor_backward(char, middle_rotor, middle_pos)
        char = rotor_backward(char, right_rotor, right_pos)

        # 6. Keluar melalui plugboard
        char = plugboard[char]

        result += char

    return result