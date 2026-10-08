from flask import Flask, render_template, request, jsonify
import base64

from vigenere_cipher import vigenere_encrypt, vigenere_decrypt
from varian_vigenere_cipher import (
    varian_vigenere_encrypt,
    varian_vigenere_decrypt,
)
from extended_vigenere_cipher import (
    encrypt_extended_vigenere,
    decrypt_extended_vigenere,
)
from affine_cipher import affine_encrypt, affine_decrypt
from hill_cipher import hill_encrypt, hill_decrypt
from playfair_cipher import playfair_encrypt, playfair_decrypt
from super_enkripsi import super_enkripsi, super_dekripsi
from enigma_cipher import enigma

app = Flask(__name__)


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

    try:
        result = ""

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
                result = decrypt_extended_vigenere(cb, key).decode("utf-8", errors="replace")

        elif algorithm == "affine":
            a, b = map(int, key.split(","))
            result = affine_encrypt(text, a, b) if mode == "encrypt" \
                     else affine_decrypt(text, a, b)

        elif algorithm == "hill":
            vals = list(map(int, key.split(",")))
            matrix = [[vals[0], vals[1]], [vals[2], vals[3]]]
            result = hill_encrypt(text, matrix) if mode == "encrypt" \
                     else hill_decrypt(text, matrix)

        elif algorithm == "playfair":
            result = playfair_encrypt(text, key) if mode == "encrypt" \
                     else playfair_decrypt(text, key)

        elif algorithm == "super":
            kv, ke = key.split(",", 1)
            if mode == "encrypt":
                _, cb = super_enkripsi(text, kv.strip(), ke.strip())
                result = base64.b64encode(cb).decode("ascii")
            else:
                cb = base64.b64decode(text)
                _, result = super_dekripsi(cb, kv.strip(), ke.strip())

        elif algorithm == "enigma":
            parts = key.split(",", 4)
            rotors = (parts[0], parts[1], parts[2])
            posisi = parts[3] if len(parts) > 3 else "AAA"
            plug = parts[4] if len(parts) > 4 else ""
            result = enigma(text, rotors, posisi, plug)

        else:
            return jsonify({"error": "Algoritma tidak dikenal"}), 400

        return jsonify({"result": result})

    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    app.run(debug=True)