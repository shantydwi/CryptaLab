# Cara Menjalankan Web CryptaLab
1. clone repository 
Clone repository CryptaLab dengan perintah:
git clone https://github.com/shantydwi/CryptaLab.git

masuk ke direktori proyek:
cd CryptaLab

2. install dependencies yang diperlukan:
install flask dengan menjalankan command:
pip install flask

3. menjalankan program
pada terminal jalankan command:
python app.py 

setelah server flask berjalan, buka alamat lokal yang ditampilkan di terminal melalui browser

# Fitur yang tersedia

1. Variasi algoritma kriptografi
Terdapat 8 variasi algoritma:
- Vigenere Cipher
- Auto-key Vigenere
- Extended Vigenere
- Playfair Cipher
- Affine Cipher
- Hill Cipher
- Super Enkripsi (Extended Vigenere + Columnar transposition)
- Enigma Cipher

2. Input Pesan
Terdapat 2 cara untuk menginputkan pesan:
- Pesan diketik atau di copy paste pada field yang tersedia
- Unggah pesan dari penyimpanan komputer

Untuk menginputkan kunci, field disesuaikan dengan ketentuan setiap cipher:
- Inputan satu parameter kunci untuk cipher Vigenere cipher, auto-key Vigenere, Extended Vigenere, dan Playfair Cipher
- Inputan dua parameter kunci untuk Affine Cipher
- Inputan dua kunci Extended Vigenere dan Columnar Transposition untuk Super Enkripsi
- Inputan Matriks untuk Hill Cipher
- Inputan Plugboard (opsional) dan Penyesuaian Rotor untuk Enigma Cipher

Ketentuan untuk input dengan mengunggah file:
- Algoritma Vigenere Cipher, Affine Cipher dan sejenisnya hanya bisa memproses file teks. misal .txt, .csv, .json, .html, .xml, .log dan sejenisnya.
- Algoritma Extended vigenere cipher dan Super Enkripsi bisa memproses file dengan ekstensi pdf, docx, jpg, jpeg dan sejenisnya.

Terdapat 2 opsi proses yang bisa dijalankan:
- Enkripsi (plaintext -> ciphertext)
- Dekripsi (ciphertext -> plaintext)

3. Hasil
Hasil enkripsi dan dekripsi ditampilkan dalam 2 format: 
- Text (plaintext atau ciphertext) 
- Base64
Keduanya dipisahkan dalam Tab berbeda pada web, sehingga hasilnya lebih mudah dilihat 

Terdapat informasi tambahan yang ditampilkan:
- Status hasil enkripsi/dekripsi (sisi kiri bawah)
    Sukses  : Enkripsi/Dekripsi berhasil
    Error   : Key tidak boleh kosong
    Pesan kosong    : Silakan masukkan pesan terlebih dahulu
- Jumlah karakter hasil enkripsi/dekripsi (sisi kanan bawah)

Terdapat fitur unduh hasil:
- hasil enkripsi dapat diunduh, dan akan tersimpan dalam file dengan ekstensi .txt
- hasil dekripsi dapat diunduh, dan akan tersimpan dalam file dengan ekstensi yang sama seperti sebelum di enkripsi. misalnya mengenkripsi sebuah file soal_uts.pdf, hasilnya soal_uts_result.txt. file hasil enkripsi di dekripsi hasilnya soal_uts.pdf

# Cara Menggunakan Cipher
1. Pilih Cipher yang ingin digunakan
2. Masukkan plaintext pada kolom input atau unggah file dari komputer
3. Masukkan kunci atau konfigurasi yang diperlukan sesuai dengan cipher yang dipilih
4. Klik tombol Enkripsi untuk mengenkripsi pesan
5. Untuk mengembalikan pesan, masukkan ciphertext dan kunci/konfigurasi yang sesuai, kemudian klik tombol Dekripsi
6. Lihat hasilnya pada tab Text atau Base64
7. Unduh hasilnya jika diperlukan
