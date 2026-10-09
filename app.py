from flask import Flask, render_template, request, jsonify
import base64
import json

from vigenere_cipher import vigenere_encrypt, vigenere_decrypt
from varian_vigenere_cipher import (
    varian_vigenere_encrypt,
    varian_vigenere_decrypt,
)
from extended_vigenere_cipher import (
    encrypt_extended_vigenere,
    decrypt_extended_vigenere,
    encrypt_extended_vigenere_bytes,
    decrypt_extended_vigenere_bytes,
)
from affine_cipher import affine_encrypt, affine_decrypt
from hill_cipher import hill_encrypt, hill_decrypt
from playfair_cipher import playfair_encrypt, playfair_decrypt
from super_enkripsi import (
    super_enkripsi,
    super_dekripsi,
    super_enkripsi_bytes,
    super_dekripsi_bytes,
)
from enigma_cipher import enigma

app = Flask(__name__)


# =====================================================
# HEADER UNTUK CIPHER 26 HURUF
# =====================================================

HEADER_START = "FILENAMESTART"
HEADER_END = "FILENAMEEND"


def encode_filename(filename):
    """
    Encode nama file agar tahan proses .upper() di cipher 26 huruf.
    Huruf besar didahului BIG, huruf kecil SMALL, titik jadi DOT.

    Contoh: "Kripto.txt" -> "BIGKSMALLrSMALLiSMALLpSMALLtSMALLoDOTSMALLtSMALLxSMALLt"
    """
    result = []
    for ch in filename:
        if ch == ".":
            result.append("DOT")
        elif ch.isupper():
            result.append("BIG" + ch)              # huruf besar
        elif ch.islower():
            result.append("SMALL" + ch.upper())    # huruf kecil (di-upper biar aman)
        else:
            result.append("ASIS" + ch)             # angka/simbol
    return "".join(result)


def decode_filename(encoded):
    """
    Kembalikan nama file dari format encode_filename().
    """
    result = []
    i = 0
    while i < len(encoded):
        if encoded[i:i + 3] == "BIG":
            if i + 3 < len(encoded):
                result.append(encoded[i + 3].upper())
            i += 4
        elif encoded[i:i + 5] == "SMALL":
            if i + 5 < len(encoded):
                result.append(encoded[i + 5].lower())
            i += 6
        elif encoded[i:i + 3] == "DOT":
            result.append(".")
            i += 3
        elif encoded[i:i + 4] == "ASIS":
            if i + 4 < len(encoded):
                result.append(encoded[i + 4])
            i += 5
        else:
            i += 1
    return "".join(result)


def wrap_text_header(text, filename):
    encoded_name = encode_filename(filename)
    return HEADER_START + encoded_name + HEADER_END + text


def unwrap_text_header(decrypted_text):
    if HEADER_START in decrypted_text and HEADER_END in decrypted_text:
        start_idx = decrypted_text.index(HEADER_START) + len(HEADER_START)
        end_idx = decrypted_text.index(HEADER_END)

        encoded_name = decrypted_text[start_idx:end_idx]
        original_filename = decode_filename(encoded_name)

        raw_text = decrypted_text[end_idx + len(HEADER_END):]
        return original_filename, raw_text

    return None, decrypted_text


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/process", methods=["POST"])
def process():
    data = request.get_json() or {}

    algorithm = data.get("algorithm", "").lower()
    mode = data.get("mode", "encrypt").lower()
    text = data.get("text", "")
    key = data.get("key", "")
    is_file = data.get("isFile", False)
    filename = data.get("filename", "")

    BINARY_CIPHERS = ["extended", "super"]

    try:
        result = ""

        # =====================================================
        # FILE BINER — Extended Vigenere & Super Enkripsi
        # =====================================================
        if is_file and algorithm in BINARY_CIPHERS:

            if algorithm == "extended":
                key_bytes = key.encode("utf-8")

                if mode == "encrypt":
                    raw_bytes = base64.b64decode(text)
                    name_bytes = filename.encode("utf-8")
                    header_len = len(name_bytes).to_bytes(2, "big")
                    payload = header_len + name_bytes + raw_bytes

                    cb = encrypt_extended_vigenere_bytes(payload, key_bytes)
                    result = base64.b64encode(cb).decode("ascii")
                else:
                    cb = base64.b64decode(text)
                    pb = decrypt_extended_vigenere_bytes(cb, key_bytes)

                    header_len = int.from_bytes(pb[:2], "big")
                    original_filename = pb[2:2 + header_len].decode("utf-8")
                    raw_bytes = pb[2 + header_len:]

                    result = json.dumps({
                        "filename": original_filename,
                        "data": base64.b64encode(raw_bytes).decode("ascii")
                    })

            elif algorithm == "super":
                if "," not in key:
                    raise ValueError(
                        "Format key Super: keyExtended,keyTransposisi"
                    )
                ke, kt = key.split(",", 1)
                ke, kt = ke.strip(), kt.strip()

                if mode == "encrypt":
                    raw_bytes = base64.b64decode(text)
                    name_bytes = filename.encode("utf-8")
                    header_len = len(name_bytes).to_bytes(2, "big")
                    payload = header_len + name_bytes + raw_bytes

                    _, cb = super_enkripsi_bytes(payload, ke, kt)
                    result = base64.b64encode(cb).decode("ascii")
                else:
                    cb = base64.b64decode(text)
                    _, pb = super_dekripsi_bytes(cb, ke, kt)

                    header_len = int.from_bytes(pb[:2], "big")
                    original_filename = pb[2:2 + header_len].decode("utf-8")
                    raw_bytes = pb[2 + header_len:]

                    result = json.dumps({
                        "filename": original_filename,
                        "data": base64.b64encode(raw_bytes).decode("ascii")
                    })

        # =====================================================
        # FILE TEKS (cipher 26 huruf)
        # =====================================================
        elif is_file and algorithm not in BINARY_CIPHERS:

            # Decode base64 dulu (frontend kirim base64 dari byte file .dat)
            if mode == "decrypt":
                raw_bytes = base64.b64decode(text)
                text = raw_bytes.decode("utf-8", errors="replace")

            if algorithm == "vigenere":
                if mode == "encrypt":
                    wrapped = wrap_text_header(text, filename)
                    result = vigenere_encrypt(wrapped, key)
                else:
                    pb = vigenere_decrypt(text, key)
                    original_filename, raw_text = unwrap_text_header(pb)
                    result = json.dumps({
                        "filename": original_filename or filename or "decrypted.txt",
                        "data": raw_text
                    })

            elif algorithm == "autokey":
                if mode == "encrypt":
                    wrapped = wrap_text_header(text, filename)
                    result = varian_vigenere_encrypt(wrapped, key)
                else:
                    pb = varian_vigenere_decrypt(text, key)
                    original_filename, raw_text = unwrap_text_header(pb)
                    result = json.dumps({
                        "filename": original_filename or filename or "decrypted.txt",
                        "data": raw_text
                    })

            elif algorithm == "playfair":
                if mode == "encrypt":
                    wrapped = wrap_text_header(text, filename)
                    result = playfair_encrypt(wrapped, key)
                else:
                    pb = playfair_decrypt(text, key)
                    original_filename, raw_text = unwrap_text_header(pb)
                    result = json.dumps({
                        "filename": original_filename or filename or "decrypted.txt",
                        "data": raw_text
                    })

            elif algorithm == "affine":
                parts = key.split(",")
                if len(parts) != 2:
                    raise ValueError("Format key Affine: a,b (contoh: 5,8)")
                a, b = int(parts[0].strip()), int(parts[1].strip())

                if mode == "encrypt":
                    wrapped = wrap_text_header(text, filename)
                    result = affine_encrypt(wrapped, a, b)
                else:
                    pb = affine_decrypt(text, a, b)
                    original_filename, raw_text = unwrap_text_header(pb)
                    result = json.dumps({
                        "filename": original_filename or filename or "decrypted.txt",
                        "data": raw_text
                    })

            elif algorithm == "hill":
                parts = key.split(",")
                if len(parts) != 4:
                    raise ValueError(
                        "Format key Hill: a11,a12,a21,a22 (contoh: 3,3,2,5)"
                    )
                vals = [int(p.strip()) for p in parts]
                matrix = [[vals[0], vals[1]], [vals[2], vals[3]]]

                if mode == "encrypt":
                    wrapped = wrap_text_header(text, filename)
                    result = hill_encrypt(wrapped, matrix)
                else:
                    pb = hill_decrypt(text, matrix)
                    original_filename, raw_text = unwrap_text_header(pb)
                    result = json.dumps({
                        "filename": original_filename or filename or "decrypted.txt",
                        "data": raw_text
                    })

            elif algorithm == "enigma":
                parts = key.split(",", 4)
                if len(parts) < 4:
                    raise ValueError(
                        "Format key Enigma: rotor1,rotor2,rotor3,posisi[,plugboard]"
                    )
                rotors = (parts[0].strip(), parts[1].strip(), parts[2].strip())
                posisi = parts[3].strip() if len(parts) > 3 else "AAA"
                plug = parts[4].strip() if len(parts) > 4 else ""

                if mode == "encrypt":
                    wrapped = wrap_text_header(text, filename)
                    result = enigma(wrapped, rotors, posisi, plug)
                else:
                    pb = enigma(text, rotors, posisi, plug)
                    original_filename, raw_text = unwrap_text_header(pb)
                    result = json.dumps({
                        "filename": original_filename or filename or "decrypted.txt",
                        "data": raw_text
                    })

            else:
                return jsonify({"error": "Algoritma tidak dikenal"}), 400

        # =====================================================
        # INPUT TEKS MANUAL (tanpa file)
        # =====================================================
        else:
            if algorithm == "vigenere":
                result = vigenere_encrypt(text, key) if mode == "encrypt" \
                         else vigenere_decrypt(text, key)

            elif algorithm == "autokey":
                result = varian_vigenere_encrypt(text, key) if mode == "encrypt" \
                         else varian_vigenere_decrypt(text, key)

            elif algorithm == "extended":
                if mode == "encrypt":
                    cb = encrypt_extended_vigenere(text, key)
                    result = base64.b64encode(cb).decode("ascii")
                else:
                    cb = base64.b64decode(text)
                    result = decrypt_extended_vigenere(cb, key).decode(
                        "utf-8", errors="replace"
                    )

            elif algorithm == "affine":
                parts = key.split(",")
                if len(parts) != 2:
                    raise ValueError("Format key Affine: a,b (contoh: 5,8)")
                a, b = int(parts[0].strip()), int(parts[1].strip())
                result = affine_encrypt(text, a, b) if mode == "encrypt" \
                         else affine_decrypt(text, a, b)

            elif algorithm == "hill":
                parts = key.split(",")
                if len(parts) != 4:
                    raise ValueError(
                        "Format key Hill: a11,a12,a21,a22 (contoh: 3,3,2,5)"
                    )
                vals = [int(p.strip()) for p in parts]
                matrix = [[vals[0], vals[1]], [vals[2], vals[3]]]
                result = hill_encrypt(text, matrix) if mode == "encrypt" \
                         else hill_decrypt(text, matrix)

            elif algorithm == "playfair":
                result = playfair_encrypt(text, key) if mode == "encrypt" \
                         else playfair_decrypt(text, key)

            elif algorithm == "super":
                if "," not in key:
                    raise ValueError(
                        "Format key Super: keyExtended,keyTransposisi"
                    )
                ke, kt = key.split(",", 1)
                ke, kt = ke.strip(), kt.strip()

                if mode == "encrypt":
                    _, cb = super_enkripsi(text, ke, kt)
                    result = base64.b64encode(cb).decode("ascii")
                else:
                    cb = base64.b64decode(text)
                    _, result = super_dekripsi(cb, ke, kt)

            elif algorithm == "enigma":
                parts = key.split(",", 4)
                if len(parts) < 4:
                    raise ValueError(
                        "Format key Enigma: rotor1,rotor2,rotor3,posisi[,plugboard]"
                    )
                rotors = (parts[0].strip(), parts[1].strip(), parts[2].strip())
                posisi = parts[3].strip() if len(parts) > 3 else "AAA"
                plug = parts[4].strip() if len(parts) > 4 else ""
                result = enigma(text, rotors, posisi, plug)

            else:
                return jsonify({"error": "Algoritma tidak dikenal"}), 400

        return jsonify({"result": result})

    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    app.run(debug=True)