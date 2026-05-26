# -*- coding: utf-8 -*-
"""
SimpleCipher -- Aplikasi Enkripsi File Simetris
===============================================
Algoritma: SimpleCipher v3 (terinspirasi AES / SPN)
Platform : Desktop Windows, Python 3.x
Library  : numpy (opsional, otomatis dideteksi), tkinter (bawaan Python)

Struktur 6 Ronde (v3):
  [MOD] PBKDF2 -- password diproses via PBKDF2-HMAC-SHA256 (10.000 iterasi)
                  menghasilkan master_key 32 byte yang menurunkan round key,
                  round salt, dan mac_key. Memperlambat brute-force attack.

  [MOD] HMAC   -- setelah enkripsi, HMAC-SHA256 dihitung atas seluruh
                  VERSION+IV+SALT+ciphertext (Encrypt-then-MAC). Saat dekripsi,
                  HMAC diverifikasi TERLEBIH DAHULU sebelum memproses ciphertext.
                  Mencegah padding oracle dan chosen-ciphertext attack.

  Format header file v3:
    [VERSION 1B] + [IV 16B] + [SALT 16B] + [CIPHERTEXT] + [MAC 32B]

  Urutan per ronde: XOR -> S-Box -> AddSalt -> Swap
  Dekripsi terbalik: Swap -> SubSalt -> Inv S-Box -> XOR
  Diulang 6 kali.
"""

import os
import sys
import hmac          # [MOD] HMAC   -- untuk autentikasi Encrypt-then-MAC
import hashlib
import random
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# ══════════════════════════════════════════════════════════════════════════════
# ALGORITMA ENKRIPSI
# ══════════════════════════════════════════════════════════════════════════════

ROUNDS     = 6
CHUNK_SIZE = 4 * 1024 * 1024   # proses per 4 MB agar hemat RAM

# ── S-Box tetap (seed 42, Fisher-Yates) ──────────────────────────────────────
_rng  = random.Random(42)
SBOX  = list(range(256))
_rng.shuffle(SBOX)
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

# ── Ukuran field header & konstanta ──────────────────────────────────────────
IV_SIZE     = 16           # [MOD] IV     -- panjang IV dalam byte
SALT_SIZE   = 16           # [MOD] PBKDF2 -- panjang SALT untuk PBKDF2
MAC_SIZE    = 32           # [MOD] HMAC   -- panjang HMAC-SHA256 tag
VERSION     = b'\x03'      # [MOD] HMAC   -- byte penanda format v3 (tolak v1/v2)
PBKDF2_ITER = 10_000       # [MOD] PBKDF2 -- jumlah iterasi PBKDF2

# ── Deteksi numpy ─────────────────────────────────────────────────────────────
try:
    import numpy as np
    _HAS_NUMPY = True
    # [MOD] S-Box -- versi numpy untuk lookup cepat di level C
    _NP_SBOX     = np.array(SBOX,     dtype=np.uint8)
    _NP_INV_SBOX = np.array(INV_SBOX, dtype=np.uint8)
except ImportError:
    _HAS_NUMPY = False


# ── Key Derivation ────────────────────────────────────────────────────────────

def _gen_bytes(master_key: bytes, iv: bytes, tag: bytes, index: int, n: int) -> bytes:
    """
    Generate n byte material dari master_key + iv + tag + index via SHA-256 chaining.
    Digunakan untuk membuat round key dan round salt secara deterministik.

    [MOD] PBKDF2 -- parameter pertama sekarang master_key (hasil PBKDF2), bukan
    password mentah. Brute-force password kini harus menjalankan PBKDF2 setiap
    tebakan, bukan hanya SHA-256 tunggal.

    [MOD] IV -- iv tetap digabungkan agar round key unik per sesi enkripsi.
    """
    # [MOD] PBKDF2 -- gunakan master_key (bukan password) sebagai basis hash
    h   = hashlib.sha256(master_key + iv + tag + index.to_bytes(4, 'big')).digest()
    out = bytearray()
    while len(out) < n:
        out += h
        h = hashlib.sha256(h + master_key).digest()  # [MOD] PBKDF2 -- chain dari master_key
    return bytes(out[:n])


def _precompute(master_key: bytes, iv: bytes, chunk_idx: int, n: int):  # [MOD] PBKDF2
    """
    Precompute semua round key dan round salt untuk satu chunk.
    chunk_idx membuat material berbeda per chunk sehingga pola tidak berulang.

    [MOD] PBKDF2 -- parameter pertama sekarang master_key (bukan password).
    [MOD] IV     -- iv diteruskan ke _gen_bytes untuk keunikan per sesi.

    Returns:
        rks   : list of bytes, satu per ronde, panjang n
        salts : list of bytes, satu per ronde, panjang n
    """
    rks   = [_gen_bytes(master_key, iv, b'RK' + chunk_idx.to_bytes(4, 'big'), r, n)  # [MOD] PBKDF2
             for r in range(ROUNDS)]
    salts = [_gen_bytes(master_key, iv, b'ST' + chunk_idx.to_bytes(4, 'big'), r, n)  # [MOD] PBKDF2
             for r in range(ROUNDS)]
    return rks, salts


# ── Operasi Per Ronde ─────────────────────────────────────────────────────────

if _HAS_NUMPY:
    # ── Versi numpy: operasi array sekaligus (cepat) ──────────────────────────

    def _xor(data: 'np.ndarray', key: bytes) -> 'np.ndarray':
        """XOR setiap byte data dengan byte round key."""
        return data ^ np.frombuffer(key, dtype=np.uint8)

    # [MOD] S-Box -- substitusi forward: setiap byte data diganti via SBOX lookup
    def _apply_sbox(data: 'np.ndarray') -> 'np.ndarray':
        """Lookup S-Box: data[i] -> SBOX[data[i]] untuk setiap byte."""
        return _NP_SBOX[data]

    # [MOD] S-Box -- substitusi inverse: kebalikan _apply_sbox untuk dekripsi
    def _apply_inv_sbox(data: 'np.ndarray') -> 'np.ndarray':
        """Lookup Inverse S-Box: data[i] -> INV_SBOX[data[i]] untuk dekripsi."""
        return _NP_INV_SBOX[data]

    def _add_salt(data: 'np.ndarray', salt: bytes) -> 'np.ndarray':
        """Tambah salt: setiap byte data ditambah byte salt (mod 256)."""
        return ((data.astype(np.uint16) +
                 np.frombuffer(salt, dtype=np.uint8)) % 256).astype(np.uint8)

    def _sub_salt(data: 'np.ndarray', salt: bytes) -> 'np.ndarray':
        """Inverse add_salt: kurangi salt (mod 256)."""
        return ((data.astype(np.uint16) -
                 np.frombuffer(salt, dtype=np.uint8)) % 256).astype(np.uint8)

    def _swap_halves(data: 'np.ndarray') -> 'np.ndarray':
        """Tukar dua setengah data. [A|B] -> [B|A]. Self-inverse."""
        mid = len(data) // 2
        return np.concatenate([data[mid:], data[:mid]])

    def _enc_chunk(raw: bytes, rks, salts) -> bytes:
        data = np.frombuffer(raw, dtype=np.uint8).copy()
        for r in range(ROUNDS):
            data = _xor(data, rks[r])        # 2. XOR dengan round key
            data = _apply_sbox(data)          # 3. [MOD] S-Box -- substitusi non-linear
            data = _add_salt(data, salts[r])  # 4. tambah salt
            data = _swap_halves(data)         # 5. tukar dua setengah
        return data.tobytes()

    def _dec_chunk(raw: bytes, rks, salts) -> bytes:
        data = np.frombuffer(raw, dtype=np.uint8).copy()
        for r in range(ROUNDS - 1, -1, -1):
            data = _swap_halves(data)         # inv 5: tukar balik (self-inverse)
            data = _sub_salt(data, salts[r])  # inv 4: kurangi salt
            data = _apply_inv_sbox(data)      # inv 3: [MOD] S-Box -- inverse substitusi
            data = _xor(data, rks[r])         # inv 2: XOR (self-inverse)
        return data.tobytes()

else:
    # ── Versi pure Python: bytearray, tanpa numpy ─────────────────────────────

    def _xor(data: bytearray, key: bytes) -> bytearray:
        return bytearray(a ^ b for a, b in zip(data, key))

    # [MOD] S-Box -- substitusi forward: setiap byte diganti via SBOX lookup
    def _apply_sbox(data: bytearray) -> bytearray:
        """Lookup S-Box: data[i] -> SBOX[data[i]] untuk setiap byte."""
        return bytearray(SBOX[b] for b in data)

    # [MOD] S-Box -- substitusi inverse: kebalikan _apply_sbox untuk dekripsi
    def _apply_inv_sbox(data: bytearray) -> bytearray:
        """Lookup Inverse S-Box: data[i] -> INV_SBOX[data[i]] untuk dekripsi."""
        return bytearray(INV_SBOX[b] for b in data)

    def _add_salt(data: bytearray, salt: bytes) -> bytearray:
        return bytearray((a + b) % 256 for a, b in zip(data, salt))

    def _sub_salt(data: bytearray, salt: bytes) -> bytearray:
        return bytearray((a - b) % 256 for a, b in zip(data, salt))

    def _swap_halves(data: bytearray) -> bytearray:
        mid = len(data) // 2
        return data[mid:] + data[:mid]

    def _enc_chunk(raw: bytes, rks, salts) -> bytes:
        data = bytearray(raw)
        for r in range(ROUNDS):
            data = _xor(data, rks[r])         # 2. XOR dengan round key
            data = _apply_sbox(data)           # 3. [MOD] S-Box -- substitusi non-linear
            data = _add_salt(data, salts[r])   # 4. tambah salt
            data = _swap_halves(data)          # 5. tukar dua setengah
        return bytes(data)

    def _dec_chunk(raw: bytes, rks, salts) -> bytes:
        data = bytearray(raw)
        for r in range(ROUNDS - 1, -1, -1):
            data = _swap_halves(data)          # inv 5: tukar balik (self-inverse)
            data = _sub_salt(data, salts[r])   # inv 4: kurangi salt
            data = _apply_inv_sbox(data)       # inv 3: [MOD] S-Box -- inverse substitusi
            data = _xor(data, rks[r])          # inv 2: XOR (self-inverse)
        return bytes(data)


# ── Padding ───────────────────────────────────────────────────────────────────

def _add_padding(data: bytes) -> bytes:
    """
    PKCS#7-style padding ke kelipatan 16 byte.
    Nilai padding = jumlah byte yang ditambahkan.

    Contoh: data 13 byte -> pad = 3 -> tambah [3, 3, 3]
    Contoh: data 16 byte -> pad = 16 -> tambah [16]*16 (padding penuh)
    """
    pad = 16 - (len(data) % 16)
    return data + bytes([pad] * pad)

def _remove_padding(data: bytes) -> bytes:
    """Hapus padding berdasarkan nilai byte terakhir."""
    return data[: -data[-1]]


# ── Fungsi Utama ──────────────────────────────────────────────────────────────

def encrypt(plaintext: bytes, password: str,
            progress_cb=None) -> bytes:
    """
    Enkripsi data menggunakan SimpleCipher v3 (6 ronde, chunked).

    Format output: [VERSION 1B] + [IV 16B] + [SALT 16B] + [CIPHERTEXT] + [MAC 32B]

    [MOD] PBKDF2 -- password -> PBKDF2-HMAC-SHA256(password, salt, 10_000) -> master_key.
                    master_key menurunkan round key, round salt, dan mac_key.
    [MOD] HMAC   -- MAC = HMAC-SHA256(mac_key, VERSION+IV+SALT+ciphertext) ditambahkan
                    di akhir output (Encrypt-then-MAC).

    Parameters:
        plaintext  : data asli dalam bytes
        password   : kata sandi bebas panjang (string atau bytes)
        progress_cb: opsional, fn(bytes_done, total_bytes)

    Returns:
        bytes: VERSION + IV + SALT + ciphertext_body + MAC
    """
    pw   = password.encode('utf-8') if isinstance(password, str) else password
    iv   = os.urandom(IV_SIZE)    # [MOD] IV     -- IV acak 16 byte per sesi
    salt = os.urandom(SALT_SIZE)  # [MOD] PBKDF2 -- SALT acak 16 byte untuk PBKDF2

    # [MOD] PBKDF2 -- turunkan master_key dari password + salt via PBKDF2-HMAC-SHA256
    master_key = hashlib.pbkdf2_hmac(
        'sha256', pw, salt, PBKDF2_ITER, dklen=32
    )  # [MOD] PBKDF2

    # [MOD] PBKDF2 -- turunkan mac_key dari master_key via domain separation label 'MAC'
    mac_key = hashlib.sha256(master_key + b'MAC').digest()  # [MOD] PBKDF2

    padded = _add_padding(plaintext)
    total  = len(padded)
    out    = bytearray()
    done   = 0

    for ci, start in enumerate(range(0, total, CHUNK_SIZE)):
        chunk      = padded[start : start + CHUNK_SIZE]
        n          = len(chunk)
        rks, salts = _precompute(master_key, iv, ci, n)  # [MOD] PBKDF2 -- gunakan master_key
        out       += _enc_chunk(chunk, rks, salts)
        done      += n
        if progress_cb:
            progress_cb(done, total)

    ciphertext_body = bytes(out)

    # [MOD] HMAC -- hitung MAC atas VERSION+IV+SALT+ciphertext (Encrypt-then-MAC)
    mac_tag = hmac.new(
        mac_key, VERSION + iv + salt + ciphertext_body, hashlib.sha256
    ).digest()  # [MOD] HMAC

    # [MOD] PBKDF2 / HMAC -- susun output final: header + ciphertext + MAC
    return VERSION + iv + salt + ciphertext_body + mac_tag  # [MOD] HMAC


def decrypt(ciphertext: bytes, password: str,
            progress_cb=None) -> bytes:
    """
    Dekripsi data menggunakan SimpleCipher v3 (6 ronde terbalik, chunked).

    Format input: [VERSION 1B] + [IV 16B] + [SALT 16B] + [CIPHERTEXT] + [MAC 32B]

    [MOD] HMAC   -- MAC diverifikasi PERTAMA sebelum memproses ciphertext.
                    Menggunakan hmac.compare_digest() (constant-time) untuk mencegah
                    timing attack. Jika gagal, raise ValueError dan hentikan proses.
    [MOD] PBKDF2 -- SALT diekstrak dari header dan digunakan untuk me-derive ulang
                    master_key dan mac_key dengan parameter yang identik saat enkripsi.

    Parameters:
        ciphertext : bytes output dari encrypt() (VERSION+IV+SALT+data+MAC)
        password   : kata sandi yang sama dengan saat enkripsi
        progress_cb: opsional, fn(bytes_done, total_bytes)

    Returns:
        plaintext dalam bytes
    """
    pw = password.encode('utf-8') if isinstance(password, str) else password

    # [MOD] HMAC -- validasi panjang minimum: 1(VER)+16(IV)+16(SALT)+32(MAC) = 65 byte
    MIN_LEN = 1 + IV_SIZE + SALT_SIZE + MAC_SIZE  # [MOD] HMAC
    if len(ciphertext) < MIN_LEN:
        raise ValueError("File tidak valid atau bukan format SimpleCipher v3.")

    # [MOD] HMAC -- periksa VERSION byte pertama: tolak file v1/v2 secara eksplisit
    if ciphertext[:1] != VERSION:  # [MOD] HMAC
        raise ValueError(
            "Format file tidak kompatibel. "
            "File ini mungkin dibuat oleh versi lama SimpleCipher."
        )  # [MOD] HMAC

    # Ekstrak semua field dari header
    offset          = 1
    iv              = ciphertext[offset : offset + IV_SIZE];   offset += IV_SIZE    # [MOD] IV
    salt            = ciphertext[offset : offset + SALT_SIZE]; offset += SALT_SIZE  # [MOD] PBKDF2
    ciphertext_body = ciphertext[offset : -MAC_SIZE]           # data terenkripsi
    mac_tag         = ciphertext[-MAC_SIZE:]                   # MAC 32 byte terakhir # [MOD] HMAC

    # [MOD] PBKDF2 -- re-derive master_key dari password + salt yang sama saat enkripsi
    master_key = hashlib.pbkdf2_hmac(
        'sha256', pw, salt, PBKDF2_ITER, dklen=32
    )  # [MOD] PBKDF2

    # [MOD] PBKDF2 -- re-derive mac_key identik dengan saat enkripsi
    mac_key = hashlib.sha256(master_key + b'MAC').digest()  # [MOD] PBKDF2

    # [MOD] HMAC -- verifikasi MAC dengan constant-time comparison (cegah timing attack)
    expected_mac = hmac.new(
        mac_key, VERSION + iv + salt + ciphertext_body, hashlib.sha256
    ).digest()  # [MOD] HMAC
    if not hmac.compare_digest(expected_mac, mac_tag):   # [MOD] HMAC -- constant-time
        raise ValueError(
            "Autentikasi gagal: file rusak atau kunci salah."
        )  # [MOD] HMAC -- HENTIKAN di sini, jangan proses ciphertext

    # Lanjutkan dekripsi hanya jika MAC valid
    total = len(ciphertext_body)
    out   = bytearray()
    done  = 0

    for ci, start in enumerate(range(0, total, CHUNK_SIZE)):
        chunk      = ciphertext_body[start : start + CHUNK_SIZE]
        n          = len(chunk)
        rks, salts = _precompute(master_key, iv, ci, n)  # [MOD] PBKDF2 -- master_key
        out       += _dec_chunk(chunk, rks, salts)
        done      += n
        if progress_cb:
            progress_cb(done, total)

    return _remove_padding(bytes(out))


def suggest_output(input_path: str, mode: str) -> str:
    """Sarankan nama file output berdasarkan mode."""
    if mode == 'enc':
        return input_path + '.sc'
    if input_path.endswith('.sc'):
        return input_path[:-3]
    return input_path + '_decrypted'


def fmt_size(n: int) -> str:
    for u in ['B', 'KB', 'MB', 'GB']:
        if n < 1024:
            return f'{n:.1f} {u}'
        n /= 1024
    return f'{n:.1f} GB'


# ══════════════════════════════════════════════════════════════════════════════
# USER INTERFACE
# ══════════════════════════════════════════════════════════════════════════════

# ── Warna & Font ──────────────────────────────────────────────────────────────
BG       = "#1e2130"
PANEL    = "#252840"
BORDER   = "#363b5e"
INPUT_BG = "#1a1d2e"
BLUE     = "#4f8ef7"
GREEN    = "#3ecf8e"
AMBER    = "#f7c94f"
RED      = "#f76f6f"
FG       = "#e8eaf6"
FG2      = "#9da3c8"
FG3      = "#5c6285"
FONT     = ("Segoe UI", 11)
FONT_B   = ("Segoe UI", 11, "bold")
FONT_T   = ("Segoe UI", 20, "bold")
FONT_S   = ("Segoe UI", 9)
FONT_M   = ("Consolas", 9)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SimpleCipher — Enkripsi File Simetris")
        self.geometry("700x580")
        self.minsize(640, 520)
        self.configure(bg=BG)
        self.resizable(True, True)
        self._busy    = False
        self._in_path = tk.StringVar()
        self._out_path= tk.StringVar()
        self._passwd  = tk.StringVar()
        self._show_pw = tk.BooleanVar(value=False)
        self._build()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self):
        # Header
        hdr = tk.Frame(self, bg=PANEL, height=60)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="SimpleCipher", font=FONT_T,
                 fg=BLUE, bg=PANEL).pack(side=tk.LEFT, padx=20, pady=12)
        lib_txt = "numpy: aktif" if _HAS_NUMPY else "numpy: tidak tersedia (mode lambat)"
        lib_col = GREEN if _HAS_NUMPY else AMBER
        tk.Label(hdr, text=lib_txt, font=FONT_S,
                 fg=lib_col, bg=PANEL).pack(side=tk.RIGHT, padx=16)

        body = tk.Frame(self, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=20, pady=12)

        # ── Panel: File Input ──
        self._panel("File Input", body, [
            self._file_row,
            self._out_row,
        ])

        # ── Panel: Kunci ──
        self._panel("Kunci Enkripsi", body, [
            self._key_row,
        ])

        # ── Panel: Progress ──
        pg_frame = tk.Frame(body, bg=PANEL,
                            highlightthickness=1, highlightbackground=BORDER)
        pg_frame.pack(fill=tk.X, pady=(0, 8))

        tk.Label(pg_frame, text="Progress", font=FONT_B,
                 fg=FG, bg=PANEL).pack(anchor="w", padx=14, pady=(10, 4))
        self._prog_bar = ttk.Progressbar(pg_frame, orient="horizontal",
                                          mode="determinate", length=100)
        self._prog_bar.pack(fill=tk.X, padx=14, pady=(0, 4))
        self._prog_lbl = tk.Label(pg_frame, text="Siap.", font=FONT_S,
                                   fg=FG2, bg=PANEL)
        self._prog_lbl.pack(anchor="w", padx=14, pady=(0, 10))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TProgressbar", troughcolor=INPUT_BG,
                        background=BLUE, thickness=10)

        # ── Tombol Enkripsi & Dekripsi ──
        btn_row = tk.Frame(body, bg=BG)
        btn_row.pack(fill=tk.X, pady=(4, 0))

        self._btn_enc = self._btn(btn_row, "Enkripsi", GREEN,
                                   self._run_encrypt)
        self._btn_enc.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        self._btn_dec = self._btn(btn_row, "Dekripsi", AMBER,
                                   self._run_decrypt)
        self._btn_dec.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 0))

        # ── Status bar ──
        self._status = tk.Label(self, text="Pilih file dan masukkan kunci untuk memulai.",
                                 font=FONT_S, fg=FG2, bg=PANEL,
                                 anchor="w", padx=16, pady=8)
        self._status.pack(fill=tk.X, side=tk.BOTTOM)

    def _panel(self, title, parent, row_builders):
        frame = tk.Frame(parent, bg=PANEL,
                         highlightthickness=1, highlightbackground=BORDER)
        frame.pack(fill=tk.X, pady=(0, 8))
        tk.Label(frame, text=title, font=FONT_B,
                 fg=FG, bg=PANEL).pack(anchor="w", padx=14, pady=(10, 4))
        tk.Frame(frame, bg=BORDER, height=1).pack(fill=tk.X, padx=14)
        for builder in row_builders:
            builder(frame)
        tk.Frame(frame, bg=BG, height=1).pack(pady=(0, 4))

    def _btn(self, parent, text, color, cmd):
        b = tk.Button(parent, text=text, font=FONT_B,
                      bg=color, fg=BG, activebackground=BG,
                      activeforeground=color, relief="flat", bd=0,
                      padx=16, pady=10, cursor="hand2", command=cmd)
        return b

    # ── Row builders ──────────────────────────────────────────────────────────

    def _file_row(self, parent):
        row = tk.Frame(parent, bg=PANEL)
        row.pack(fill=tk.X, padx=14, pady=6)

        tk.Label(row, text="File Input:", font=FONT, fg=FG2,
                 bg=PANEL, width=10, anchor="w").pack(side=tk.LEFT)

        entry = tk.Entry(row, textvariable=self._in_path, font=FONT,
                         bg=INPUT_BG, fg=FG, insertbackground=FG,
                         relief="flat", bd=0,
                         highlightthickness=1, highlightbackground=BORDER,
                         highlightcolor=BLUE)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5, padx=(0, 8))

        self._in_path.trace_add("write", self._on_input_change)

        tk.Button(row, text="Browse", font=FONT_S, bg=BLUE, fg=BG,
                  relief="flat", bd=0, padx=10, pady=5, cursor="hand2",
                  command=self._browse_in).pack(side=tk.LEFT)

        # Info ukuran file
        self._file_info = tk.Label(parent, text="", font=FONT_S,
                                    fg=FG3, bg=PANEL)
        self._file_info.pack(anchor="w", padx=14)

    def _out_row(self, parent):
        row = tk.Frame(parent, bg=PANEL)
        row.pack(fill=tk.X, padx=14, pady=(0, 6))

        tk.Label(row, text="File Output:", font=FONT, fg=FG2,
                 bg=PANEL, width=10, anchor="w").pack(side=tk.LEFT)

        entry = tk.Entry(row, textvariable=self._out_path, font=FONT,
                         bg=INPUT_BG, fg=FG, insertbackground=FG,
                         relief="flat", bd=0,
                         highlightthickness=1, highlightbackground=BORDER,
                         highlightcolor=BLUE)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5, padx=(0, 8))

        tk.Button(row, text="Browse", font=FONT_S, bg=BLUE, fg=BG,
                  relief="flat", bd=0, padx=10, pady=5, cursor="hand2",
                  command=self._browse_out).pack(side=tk.LEFT)

    def _key_row(self, parent):
        row = tk.Frame(parent, bg=PANEL)
        row.pack(fill=tk.X, padx=14, pady=6)

        tk.Label(row, text="Kunci:", font=FONT, fg=FG2,
                 bg=PANEL, width=10, anchor="w").pack(side=tk.LEFT)

        self._pw_entry = tk.Entry(row, textvariable=self._passwd, font=FONT,
                                   bg=INPUT_BG, fg=FG, insertbackground=FG,
                                   show="*", relief="flat", bd=0,
                                   highlightthickness=1, highlightbackground=BORDER,
                                   highlightcolor=BLUE)
        self._pw_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5, padx=(0, 8))

        tk.Checkbutton(row, text="Tampilkan", font=FONT_S,
                       variable=self._show_pw, command=self._toggle_pw,
                       bg=PANEL, fg=FG2, activebackground=PANEL,
                       activeforeground=FG, selectcolor=INPUT_BG,
                       cursor="hand2").pack(side=tk.LEFT)

        tk.Label(parent, text="Kunci bisa berupa kata, kalimat, atau string apapun.",
                 font=FONT_S, fg=FG3, bg=PANEL).pack(anchor="w", padx=14, pady=(0, 4))

    # ── Event Handlers ────────────────────────────────────────────────────────

    def _browse_in(self):
        path = filedialog.askopenfilename(title="Pilih file")
        if path:
            self._in_path.set(path)

    def _browse_out(self):
        path = filedialog.asksaveasfilename(title="Simpan output sebagai")
        if path:
            self._out_path.set(path)

    def _on_input_change(self, *_):
        p = self._in_path.get()
        if os.path.isfile(p):
            sz = os.path.getsize(p)
            self._file_info.configure(
                text=f"Ukuran: {fmt_size(sz)}")
            if not self._out_path.get():
                # Auto-suggest: jika file .sc -> suggest decrypt, else encrypt
                mode = 'dec' if p.endswith('.sc') else 'enc'
                self._out_path.set(suggest_output(p, mode))
        else:
            self._file_info.configure(text="")

    def _toggle_pw(self):
        self._pw_entry.configure(show="" if self._show_pw.get() else "*")

    # ── Validasi ──────────────────────────────────────────────────────────────

    def _validate(self) -> bool:
        if not self._in_path.get() or not os.path.isfile(self._in_path.get()):
            self._set_status("Pilih file input yang valid.", RED)
            return False
        if not self._out_path.get():
            self._set_status("Tentukan lokasi file output.", RED)
            return False
        if not self._passwd.get():
            self._set_status("Masukkan kunci enkripsi.", RED)
            return False
        return True

    # ── Enkripsi / Dekripsi ───────────────────────────────────────────────────

    def _run_encrypt(self):
        if self._busy or not self._validate():
            return
        self._start_job("Mengenkripsi", self._do_encrypt)

    def _run_decrypt(self):
        if self._busy or not self._validate():
            return
        self._start_job("Mendekripsi", self._do_decrypt)

    def _start_job(self, label, fn):
        self._busy = True
        self._btn_enc.configure(state=tk.DISABLED)
        self._btn_dec.configure(state=tk.DISABLED)
        self._prog_bar["value"] = 0
        self._prog_lbl.configure(text=f"{label}...")
        self._set_status(f"{label}...", FG2)
        threading.Thread(target=fn, daemon=True).start()

    def _do_encrypt(self):
        in_p  = self._in_path.get()
        out_p = self._out_path.get()
        pw    = self._passwd.get()
        try:
            with open(in_p, 'rb') as f:
                data = f.read()
            sz = len(data)

            def cb(done, total):
                pct = int(done / total * 100)
                self.after(0, lambda p=pct, d=done, t=total: self._update_prog(
                    p, f"Enkripsi... {p}%  ({fmt_size(d)} / {fmt_size(t)})"))

            result = encrypt(data, pw, progress_cb=cb)

            with open(out_p, 'wb') as f:
                f.write(result)

            msg = (f"Enkripsi selesai!\n\n"
                   f"File asli : {os.path.basename(in_p)}  ({fmt_size(sz)})\n"
                   f"File enc  : {os.path.basename(out_p)}  ({fmt_size(len(result))})\n"
                   f"Algoritma : SimpleCipher v3, {ROUNDS} ronde\n"
                   f"KDF       : PBKDF2-HMAC-SHA256, {PBKDF2_ITER:,} iterasi\n"  # [MOD] PBKDF2
                   f"Integritas: HMAC-SHA256 (Encrypt-then-MAC)\n"               # [MOD] HMAC
                   f"Output    : {out_p}")
            self.after(0, lambda: self._finish(True, msg))

        except Exception as ex:
            # [MOD] HMAC -- pesan generik agar tidak bocorkan info internal
            self.after(0, lambda: self._finish(False, str(ex)))

    def _do_decrypt(self):
        in_p  = self._in_path.get()
        out_p = self._out_path.get()
        pw    = self._passwd.get()
        try:
            with open(in_p, 'rb') as f:
                data = f.read()

            def cb(done, total):
                pct = int(done / total * 100)
                self.after(0, lambda p=pct, d=done, t=total: self._update_prog(
                    p, f"Dekripsi... {p}%  ({fmt_size(d)} / {fmt_size(t)})"))

            result = decrypt(data, pw, progress_cb=cb)

            with open(out_p, 'wb') as f:
                f.write(result)

            msg = (f"Dekripsi selesai!\n\n"
                   f"File enc    : {os.path.basename(in_p)}\n"
                   f"File hasil  : {os.path.basename(out_p)}  ({fmt_size(len(result))})\n"
                   f"Output      : {out_p}")
            self.after(0, lambda: self._finish(True, msg))

        except ValueError as ex:
            # [MOD] HMAC   -- pesan error HMAC dan format ditampilkan langsung (sudah aman)
            # [MOD] PBKDF2 -- jangan bocorkan info internal; tampilkan pesan generik untuk
            #                  error lain (padding, dll.) agar tidak jadi oracle
            err = str(ex)
            if "autentikasi" not in err.lower() and "kompatibel" not in err.lower() and "valid" not in err.lower():
                err = "Kunci salah atau file tidak dapat didekripsi."  # [MOD] HMAC -- pesan generik
            self.after(0, lambda: self._finish(False, err))
        except Exception as ex:
            # [MOD] HMAC -- tangkap semua error lain, tampilkan pesan generik
            self.after(0, lambda: self._finish(False, "Kunci salah atau file tidak dapat didekripsi."))

    def _finish(self, ok: bool, msg: str):
        self._busy = False
        self._btn_enc.configure(state=tk.NORMAL)
        self._btn_dec.configure(state=tk.NORMAL)
        if ok:
            self._prog_bar["value"] = 100
            self._prog_lbl.configure(text="Selesai.")
            self._set_status("Selesai.", GREEN)
            messagebox.showinfo("Berhasil", msg)
        else:
            self._prog_bar["value"] = 0
            self._prog_lbl.configure(text="Gagal.")
            self._set_status(f"Gagal: {msg}", RED)
            messagebox.showerror("Gagal", msg)

    def _update_prog(self, pct: int, text: str):
        self._prog_bar["value"] = pct
        self._prog_lbl.configure(text=text)
        self._prog_bar.update_idletasks()

    def _set_status(self, text: str, color: str = FG2):
        self._status.configure(text=text, fg=color)


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Pindahkan working directory ke folder file ini
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    app = App()
    app.mainloop()
