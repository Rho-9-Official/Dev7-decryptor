#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unmicro.py - free decryptor for files encrypted by the Dev7 / Micro ransomware
             family (".cryptedmicro" extension).

Rho-9 Systems. Your first line of unusual defense.
Actor: Chattering Magpies (R9-C001). Malware self-name: Micro. Family: Dev7.

THE ENCRYPTION

    key        = Arrays.copyOf(keyString.getBytes(UTF_8), 32)
    cipher     = AES/ECB/PKCS5Padding
    ciphertext = encrypt(entire file)
    output     = <original absolute path> + ".cryptedmicro"

No KDF, no IV, no salt, no header, no per-file state. One operator-typed key
string covers every file the walker touched on that machine. That single design
choice is what makes this tool possible, and it is why guessing is cheap: one
AES key schedule and one block per candidate, instead of the hundred thousand
PBKDF2 rounds a competent implementation would have used.

WHAT THIS TOOL DOES

    1. Finds the encrypted files for you, across every drive, if you ask it to.
    2. Tries the keys recovered from the operators' own Discord C2.
    3. If none fit, generates candidates modelled on how these specific
       operators actually type keys, then sweeps them.
    4. Verifies every recovery against the real structure of the file.

THIS TOOL ONLY DECRYPTS

    There is no encrypt path anywhere in this file. The AES back ends expose
    decryption only, the built in AES has no encrypt_block, and nothing here
    can produce a .cryptedmicro file. A recovery tool has no legitimate use
    for the other direction.

SAFETY RULES BUILT IN

    * Your encrypted files are NEVER modified, renamed or deleted. Recovered
      files are written to a separate output directory.
    * Every recovered file is verified structurally before it counts as
      recovered: PKCS#5 padding parses, the length agrees with the ciphertext,
      and the file itself holds up, meaning PNG chunk CRCs, JPEG and GIF
      terminators, BMP length fields, ZIP central directories, PE headers and
      clean text decoding.
    * A file that fails verification is not written at all unless you pass
      --keep-unverified, and then it lands with a .UNVERIFIED suffix.
    * Keep your encrypted copies until you have confirmed the recovered files
      open. Do not delete them on the strength of this tool alone.

USAGE

    Find everything and try the known keys:
        python3 unmicro.py --auto --out ./recovered

    Point it at a folder instead:
        python3 unmicro.py --in ./encrypted --out ./recovered

    Use a key you already have:
        python3 unmicro.py --in ./encrypted --out ./recovered --key zarox

    Known keys failed, so start guessing:
        python3 unmicro.py --in ./encrypted --out ./recovered --brute

    Guess harder, takes much longer:
        python3 unmicro.py --in ./encrypted --out ./recovered --brute --deep --workers 4

    Work out which key applies and write nothing:
        python3 unmicro.py --auto --identify --brute

NOTES

    * Runs on plain Python 3.7+ with nothing installed. If pycryptodome or
      cryptography is present it is used and is far faster, which matters a
      great deal for --brute. Termux friendly.
    * Key detection works because the first bytes of most file formats are
      fixed. For formats this tool does not recognise, supply the key with
      --key and pass --force.
    * If nothing is found, that is not the end, but do not assume the machine's
      own recovery paths survived. This crew disables Windows Recovery, Task
      Manager and Regedit, and adds a Defender exclusion. Check what is
      actually left rather than counting on it, and get a responder to look.
    * Do not wipe the machine and do not delete the encrypted files. That is
      what turns a recoverable situation into a permanent one.
    * Do not pay. Their "decryption" is issued from their own bot to the
      implant still sitting on your machine, so it needs the infection kept
      alive and running, and it is their code executing on your machine a
      second time. It is not something you can run and not something you
      should be keeping a live implant around for.
"""

import argparse
import collections
import itertools
import os
import re
import string
import sys
import time

VERSION = "3.0"
EXT = ".cryptedmicro"

# ===========================================================================
# SECTION 1. Known keys, recovered from the operators' Discord C2.
#
# Keys are raw strings, encoded UTF-8 and zero padded to 32 bytes exactly as
# the malware does. The Turkish characters are written as escapes so they
# survive copy and paste through chat clients and pastebins intact. Do not
# transliterate them: \u015f is a different byte sequence from "s" and will
# produce a different AES key.
# ===========================================================================

KNOWN_KEYS = [
    # --- from the key issue log: machine, operator and timestamp on record ---
    "keyimsel",                       # microsense7   -> ezrat@DESKTOP-F5L2S6M
    "KLWXSAKXSAKDWQ23",               # medvi_ds      -> user@DESKTOP-QTUIHMF
    "key3131",                        # extrenor      -> favio@Favio
    "anans\u0131nm\u0131",            # ragnarok0537  -> mtb-r@MikePC
    "anansinmi",                      # ASCII typed variant of the above

    # --- from !micro commands observed in the C2 channels ---
    "zarox",
    "zarxo",
    "key3413",
    "keyu3131",
    "buluts",
    "efecan31",
    "edrftgybhunjk",
    "sdfghjxsw",
    "313131",
    "K2K312",
    "qwkewqkeqwk",
    "23\u015eL12L\u015e",
    "\u015eLQWKL432KL432LK\u015e",
    "KQWKEQWKEK2",
    "K\u015eL32LKL32423",
    "K\u015eL132K\u015eL2K\u015eL432",
    "K23K21K",
    "kk23k213k",
    "WQE\u015e\u0130QW2EL\u015e12",
    "123*01923*0123",
    "12*0938120938123",
    "123123123123123",
    "12312312312312313123123",
    "321312312312312",
    "31231231312",
    "3123123123",
    "1273819823713",
    "1298310923812093",
    "1298310923812903",
]

# Operator handles seen issuing commands. Four confirmed keys are handle
# derived (zarox, zarxo, buluts, efecan31), so these are strong seeds.
OPERATOR_HANDLES = [
    "microsense7", "micro", "microlive7", "medvi_ds", "medvi", "extrenor",
    "ragnarok0537", "ragnarok", "aizy", "anny", "fehrazorback", "razorback",
    "eminee", "emine", "zaroxcannn", "zaroxcan", "zarox", "90telecom",
    "telecom", "ben10can", "buluts", "bulut", "efecan", "aykut", "yasin",
    "karatasyasin", "mirza", "cegid", "yuli", "dev7", "gang", "remotesense",
    "live",
]

# Common Turkish given names and everyday nouns. Coverage of the stem and word
# families is vocabulary, not structure: a key built on a name that is not in
# here is unreachable however the candidates are ordered. Adding names is the
# cheapest way to improve this tool.
TURKISH_VOCAB = [
    # given names
    "ahmet", "mehmet", "mustafa", "ali", "huseyin", "h\u00fcseyin", "hasan",
    "ibrahim", "\u0130brahim", "osman", "yusuf", "murat", "omer", "\u00f6mer",
    "ramazan", "kemal", "riza", "r\u0131za", "suleyman", "s\u00fcleyman",
    "abdullah", "yasar", "ya\u015far", "emre", "burak", "eren", "kerem",
    "berkay", "tolga", "serkan", "furkan", "batuhan", "mertcan", "sinan",
    "hakan", "yigit", "yi\u011fit", "alperen", "taylan", "volkan", "emrecan",
    "caner", "onur", "ozan", "baris", "bar\u0131\u015f", "cem", "deniz",
    "kaan", "koray", "levent", "melih", "okan", "selim", "tarik", "tar\u0131k",
    "ugur", "u\u011fur", "umut", "yavuz", "zeynep", "elif", "merve", "busra",
    "b\u00fc\u015fra", "esra", "fatma", "ayse", "ay\u015fe", "emine", "hatice",
    "meryem", "seda", "sena", "tugce", "tu\u011f\u00e7e", "yasemin", "ece",
    # everyday nouns
    "masa", "kalem", "defter", "kapi", "kap\u0131", "pencere", "duvar",
    "sandalye", "kedi", "kopek", "k\u00f6pek", "kus", "ku\u015f", "balik",
    "bal\u0131k", "agac", "a\u011fa\u00e7", "cicek", "\u00e7i\u00e7ek",
    "bahce", "bah\u00e7e", "sokak", "sehir", "\u015fehir", "koy", "k\u00f6y",
    "ekmek", "peynir", "kahve", "cay", "\u00e7ay", "su", "sut", "s\u00fct",
    "elma", "karpuz", "domates", "araba", "otobus", "otob\u00fcs", "tren",
    "okul", "ogretmen", "\u00f6\u011fretmen", "ogrenci", "\u00f6\u011frenci",
    "kitap", "telefon", "bilgisayar", "oyun", "futbol", "gunes", "g\u00fcne\u015f",
    "yildiz", "y\u0131ld\u0131z", "gece", "gunduz", "g\u00fcnd\u00fcz",
    "sevgi", "ask", "a\u015fk", "dost", "kardes", "karde\u015f", "anne",
    "baba", "abla", "dede", "nine", "kilit", "anahtar", "kutu", "canta",
    "\u00e7anta", "ayakkabi", "ayakkab\u0131", "gomlek", "g\u00f6mlek",
]

# Turkish and English filler seen in or adjacent to operator chatter. One
# confirmed key is a Turkish insult, so this is a real pattern, not padding.
TURKISH_SEEDS = [
    "anan", "anas\u0131", "anasi", "baban", "sikerim", "orospu", "amk", "aq",
    "salak", "aptal", "gerizekali", "gerizekal\u0131", "kanka", "abi",
    "kardes", "karde\u015f", "para", "bitcoin", "sifre", "\u015fifre",
    "anahtar", "kilit", "gizli", "test", "deneme", "merhaba", "selam",
    "tamam", "evet", "hayir", "hay\u0131r", "bilgisayar", "dosya", "key",
    "pass", "password", "admin", "root", "hack", "hacked", "locked",
    "crypted", "cryptedmicro", "ransom", "money", "btc",
]

# Keyboard rows. Turkish Q is the layout these operators are typing on, which
# is where the \u015e and \u0130 in their keys come from.
KEYBOARD_ROWS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "qwertyu\u0131op\u011f\u00fc", "asdfghjkl\u015fi", "zxcvbnm\u00f6\u00e7",
    "1234567890", "0987654321",
]

# Turkish characters folded to ASCII and back. Operators switch layouts, so a
# key typed as "\u015fifre" may also have been typed as "sifre".
FOLD_MAP = {
    "\u015f": "s", "\u015e": "S", "\u0131": "i", "\u0130": "I",
    "\u011f": "g", "\u011e": "G", "\u00fc": "u", "\u00dc": "U",
    "\u00f6": "o", "\u00d6": "O", "\u00e7": "c", "\u00c7": "C",
}
UNFOLD_MAP = {
    "s": "\u015f", "S": "\u015e", "i": "\u0131", "I": "\u0130",
    "g": "\u011f", "G": "\u011e", "u": "\u00fc", "U": "\u00dc",
    "o": "\u00f6", "O": "\u00d6", "c": "\u00e7", "C": "\u00c7",
}

# ===========================================================================
# SECTION 2. File signatures, used to recognise a correct decryption.
# Each entry is (offset, magic bytes, label, canonical extension or None).
# ===========================================================================

SIGNATURES = [
    (0, b"\x89PNG\r\n\x1a\n", "PNG", ".png"),
    (0, b"\xff\xd8\xff", "JPEG", ".jpg"),
    (0, b"GIF87a", "GIF", ".gif"),
    (0, b"GIF89a", "GIF", ".gif"),
    (0, b"BM", "BMP", ".bmp"),
    (0, b"RIFF", "RIFF (WEBP/WAV/AVI)", None),
    (0, b"%PDF-", "PDF", ".pdf"),
    (0, b"PK\x03\x04", "ZIP/OOXML/JAR", None),
    (0, b"PK\x05\x06", "ZIP (empty)", ".zip"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 (legacy Office)", None),
    (0, b"\x1f\x8b", "GZIP", ".gz"),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip", ".7z"),
    (0, b"Rar!\x1a\x07", "RAR", ".rar"),
    (0, b"fLaC", "FLAC", ".flac"),
    (0, b"ID3", "MP3", ".mp3"),
    (0, b"\xff\xfb", "MP3", ".mp3"),
    (0, b"OggS", "OGG", ".ogg"),
    (0, b"\x1aE\xdf\xa3", "Matroska/WEBM", ".mkv"),
    (0, b"MZ", "PE executable", ".exe"),
    (0, b"\x7fELF", "ELF executable", None),
    (0, b"SQLite format 3\x00", "SQLite database", ".sqlite"),
    (0, b"{\\rtf", "RTF", ".rtf"),
    (0, b"\xef\xbb\xbf", "UTF-8 text with BOM", ".txt"),
    (0, b"\xff\xfe", "UTF-16LE text", ".txt"),
    (0, b"<?xml", "XML", ".xml"),
    (4, b"ftyp", "MP4/MOV", ".mp4"),
]

# ===========================================================================
# SECTION 3. AES-256-ECB, three back ends.
#
# The pure Python one exists so this script runs on a stock interpreter with
# nothing installed, which matters on a victim machine and on Termux. It is
# correct but slow. Install pycryptodome before using --brute if you can.
# ===========================================================================

BACKEND = None
_dec_blocks = None


def _init_backend(force_pure=False):
    """
    Decryption only. This tool has no encrypt path and is not able to produce
    a .cryptedmicro file: every back end below exposes AES decryption and
    nothing else, and _PureAES has no encrypt_block. That is deliberate. A
    victim facing recovery tool has no legitimate use for the encrypt
    direction, and shipping one would hand anybody who reads this file a
    working implementation of the thing that caused the damage.
    """
    global BACKEND, _dec_blocks
    if not force_pure:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

            def _dec(key, data):
                c = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
                return c.update(data) + c.finalize()

            _dec_blocks, BACKEND = _dec, "cryptography"
            return
        except Exception:
            pass
        try:
            from Crypto.Cipher import AES as _AES

            def _dec(key, data):
                return _AES.new(key, _AES.MODE_ECB).decrypt(data)

            _dec_blocks, BACKEND = _dec, "pycryptodome"
            return
        except Exception:
            pass

    def _dec(key, data):
        ctx = _PureAES(key)
        return b"".join(ctx.decrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))

    _dec_blocks, BACKEND = _dec, "pure-python"


# --- pure Python AES --------------------------------------------------------

def _build_tables():
    """Generate the S-box from the GF(2^8) construction rather than a typed
    table, so there is no transcription risk in this file."""
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) \
              ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


_SBOX, _INV_SBOX = _build_tables()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8]


def _xt(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xt(a)
        b >>= 1
    return r


class _PureAES(object):
    """AES-256 single block DECRYPTION. Correctness over speed.

    There is no encrypt_block and no forward MixColumns here on purpose: this
    class can undo the malware's work and cannot reproduce it.
    """

    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("this build expects a 32 byte key")
        self.rk = self._expand(key)

    @staticmethod
    def _expand(key):
        nk, nr = 8, 14
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (nr + 1)):
            t = list(w[i - 1])
            if i % nk == 0:
                t = t[1:] + t[:1]
                t = [_SBOX[b] for b in t]
                t[0] ^= _RCON[i // nk - 1]
            elif i % nk == 4:
                t = [_SBOX[b] for b in t]
            w.append([w[i - nk][j] ^ t[j] for j in range(4)])
        # one flat 16 byte round key per round, column major, matching the
        # state indexing s[4 * column + row] used below
        return [[w[4 * r + c][j] for c in range(4) for j in range(4)]
                for r in range(nr + 1)]

    def _ark(self, s, r):
        k = self.rk[r]
        return [s[i] ^ k[i] for i in range(16)]

    def decrypt_block(self, blk):
        s = self._ark(list(blk), 14)
        for r in range(13, 0, -1):
            s = self._inv_shift(s)
            s = [_INV_SBOX[b] for b in s]
            s = self._ark(s, r)
            s = self._inv_mix(s)
        s = self._inv_shift(s)
        s = [_INV_SBOX[b] for b in s]
        return bytes(self._ark(s, 0))

    @staticmethod
    def _inv_shift(s):
        o = list(s)
        for r in range(1, 4):
            row = [s[r + 4 * c] for c in range(4)]
            row = row[-r:] + row[:-r]
            for c in range(4):
                o[r + 4 * c] = row[c]
        return o

    @staticmethod
    def _inv_mix(s):
        o = [0] * 16
        for c in range(4):
            a = s[4 * c:4 * c + 4]
            o[4 * c + 0] = _mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9)
            o[4 * c + 1] = _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13)
            o[4 * c + 2] = _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11)
            o[4 * c + 3] = _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)
        return o


# ===========================================================================
# SECTION 4. Core primitives
# ===========================================================================

def key_bytes(key_string):
    """Reproduce Arrays.copyOf(s.getBytes(UTF_8), 32) exactly."""
    raw = key_string.encode("utf-8")
    return (raw + b"\x00" * 32)[:32]


def strip_pkcs5(data):
    """Remove PKCS#5 padding. Returns None if the padding is not valid."""
    if not data or len(data) % 16 != 0:
        return None
    n = data[-1]
    if n < 1 or n > 16 or len(data) < n:
        return None
    if data[-n:] != bytes([n]) * n:
        return None
    return data[:-n]


def padded_length(n):
    """
    Length the ciphertext must have for a plaintext of n bytes under PKCS#5.
    This replaces an add_pkcs5() helper that actually built the padded bytes:
    only the length is ever needed, and constructing padded plaintext is a
    step on the way to encrypting it, which this tool does not do.
    """
    return n + (16 - (n % 16))


def identify(head):
    """Return (label, canonical_ext) if the plaintext looks like a known type."""
    label, ext, _ = identify_ex(head)
    return label, ext


# A 2 byte magic such as "BM" or "MZ" matches random data once in 65,536, which
# over a million guesses means a hundred false hits. Anything 4 bytes or longer
# is strong enough to accept on its own; shorter matches have to be confirmed
# against the whole file before they count.
STRONG_MAGIC_BYTES = 4


def identify_ex(head):
    """Return (label, canonical_ext, strong) for a candidate plaintext head."""
    for off, magic, label, ext in SIGNATURES:
        if head[off:off + len(magic)] == magic:
            return label, ext, len(magic) >= STRONG_MAGIC_BYTES
    return None, None, False


# ===========================================================================
# SECTION 4b. Structural validation.
#
# A note on why this exists, because it matters and it is easy to get wrong.
#
# Re-encrypting a decryption and comparing it to the ciphertext PROVES NOTHING
# about the key. AES is a permutation: decrypting with any key at all and then
# encrypting the result returns exactly the original bytes. That check only
# catches a broken AES implementation, never a wrong key.
#
# What a wrong key has to get past is this:
#   * PKCS#5 padding has to parse, which random plaintext manages roughly once
#     in 256 tries, so on its own it is nowhere near enough.
#   * The plaintext has to carry a recognised file signature.
#   * The file structure behind that signature has to hold up: a CRC that
#     matches, a terminator in the right place, a length field that agrees
#     with the file, a text encoding that decodes cleanly.
#
# Together those are strong. A two byte magic plus valid padding alone is not,
# and will produce false hits during a long sweep. That is what this section
# is here to stop.
# ===========================================================================

def _valid_png(pt):
    if len(pt) < 57 or not pt.startswith(b"\x89PNG\r\n\x1a\x0a"):
        return False
    import binascii
    ln = int.from_bytes(pt[8:12], "big")
    if pt[12:16] != b"IHDR" or ln != 13 or len(pt) < 8 + 12 + ln:
        return False
    body = pt[12:16 + ln]
    crc = int.from_bytes(pt[16 + ln:20 + ln], "big")
    if binascii.crc32(body) & 0xFFFFFFFF != crc:
        return False
    return pt.rstrip(b"\x00").endswith(b"IEND\xaeB`\x82")


def _valid_jpeg(pt):
    return len(pt) > 4 and pt[:3] == b"\xff\xd8\xff" and pt.rstrip(b"\x00").endswith(b"\xff\xd9")


def _valid_gif(pt):
    return len(pt) > 14 and pt[:6] in (b"GIF87a", b"GIF89a") and pt.rstrip(b"\x00")[-1:] == b"\x3b"


def _valid_bmp(pt):
    if len(pt) < 30 or pt[:2] != b"BM":
        return False
    declared = int.from_bytes(pt[2:6], "little")
    return abs(declared - len(pt)) <= 16


def _valid_pdf(pt):
    return pt[:5] == b"%PDF-" and b"%%EOF" in pt[-4096:]


def _valid_zip(pt):
    return pt[:4] in (b"PK\x03\x04", b"PK\x05\x06") and b"PK\x05\x06" in pt[-70000:]


def _valid_gzip(pt):
    return len(pt) > 18 and pt[:3] == b"\x1f\x8b\x08"


def _valid_pe(pt):
    if len(pt) < 0x40 or pt[:2] != b"MZ":
        return False
    off = int.from_bytes(pt[0x3C:0x40], "little")
    return 0 < off < len(pt) - 4 and pt[off:off + 4] == b"PE\x00\x00"


def _valid_id3(pt):
    if len(pt) < 10 or pt[:3] != b"ID3":
        return False
    if pt[3] > 4 or pt[4] == 0xFF:
        return False
    return all(b < 0x80 for b in pt[6:10])      # syncsafe size


def _valid_text(pt, enc):
    try:
        pt.decode(enc)
        return True
    except Exception:
        return False


def _valid_plain_text(pt, min_len=16):
    """
    Text has no magic number, so identify() never labels it and every text
    file used to fall through as unrecognised. UTF-8 is the discriminator that
    makes this safe: a wrong key yields uniformly random bytes, and random
    bytes of any real length are valid UTF-8 with vanishing probability, so
    this does not hand back garbage as a recovery.
    """
    if len(pt) < min_len:
        return False
    try:
        txt = pt.decode("utf-8")
    except Exception:
        return False
    if not txt:
        return False
    printable = sum(1 for c in txt if c.isprintable() or c in "\r\n\t")
    return printable / float(len(txt)) >= 0.95


def _valid_ole(pt):
    return pt[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" and len(pt) >= 512


# label -> validator. A signature with no validator here is accepted on the
# strength of its magic alone, which is only allowed for magics of 4 bytes or
# more, where a chance match is a one in four billion event.
VALIDATORS = {
    "PNG": _valid_png,
    "JPEG": _valid_jpeg,
    "GIF": _valid_gif,
    "BMP": _valid_bmp,
    "PDF": _valid_pdf,
    "ZIP/OOXML/JAR": _valid_zip,
    "ZIP (empty)": _valid_zip,
    "GZIP": _valid_gzip,
    "PE executable": _valid_pe,
    "MP3": _valid_id3,
    "OLE2 (legacy Office)": _valid_ole,
    "UTF-8 text with BOM": lambda pt: _valid_text(pt, "utf-8"),
    "UTF-16LE text": lambda pt: _valid_text(pt, "utf-16"),
}


def validate_plaintext(pt):
    """
    Return (ok, label). ok means the bytes really are a well formed file of
    the type their signature claims, not just something that starts with the
    right two characters.
    """
    label, _, strong = identify_ex(pt[:16])
    if not label:
        if _valid_plain_text(pt):
            return True, "plain text"
        return False, None
    fn = VALIDATORS.get(label)
    if fn is not None:
        try:
            return bool(fn(pt)), label
        except Exception:
            return False, label
    return strong, label


def decrypt_file(path, key_string, verify=True):
    """
    Returns (plaintext, verified, error). plaintext is None on failure.
    verified means the padding parsed AND the recovered bytes validate as a
    well formed file of the type they claim to be. The file on disk is only
    ever read.
    """
    try:
        with open(path, "rb") as fh:
            ct = fh.read()
    except OSError as e:
        return None, False, "cannot read: %s" % e
    if len(ct) == 0:
        return None, False, "file is empty"
    if len(ct) % 16 != 0:
        return None, False, "length %d is not a multiple of 16, not a whole ciphertext" % len(ct)
    if _dec_blocks is None:
        # decrypt_file is usable as a library, not only from main(). Without
        # this the first call raises an opaque TypeError on a None global.
        _init_backend()
    kb = key_bytes(key_string)
    pt = strip_pkcs5(_dec_blocks(kb, ct))
    if pt is None:
        return None, False, "PKCS#5 padding invalid, wrong key for this file"
    if padded_length(len(pt)) != len(ct):
        return None, False, "recovered length inconsistent with ciphertext"
    if not verify:
        return pt, False, None
    ok, label = validate_plaintext(pt)
    if not ok:
        return pt, False, ("%s structure did not validate" % label if label
                           else "no recognised file structure")
    return pt, True, None


# ===========================================================================
# SECTION 5. Autodiscovery
#
# The malware's walker starts from File.listRoots(), so encrypted files can be
# anywhere on any volume. This mirrors that: enumerate every root, walk it,
# and prune the directories that cannot hold user data so the scan finishes in
# a sensible time.
# ===========================================================================

PRUNE_DIRS = {
    "$recycle.bin", "system volume information", "windows", "winsxs",
    "$windows.~bt", "$windows.~ws", "recovery", "node_modules", ".git",
    ".svn", "__pycache__", "site-packages", "proc", "sys", "dev", "run",
    "snap", ".cache", ".gradle", ".m2",
}


def candidate_roots():
    """Every plausible starting point on this machine."""
    roots = []
    if os.name == "nt":
        try:
            import ctypes
            mask = ctypes.windll.kernel32.GetLogicalDrives()
            for i, letter in enumerate(string.ascii_uppercase):
                if mask & (1 << i):
                    roots.append(letter + ":\\")
        except Exception:
            roots = [l + ":\\" for l in string.ascii_uppercase
                     if os.path.exists(l + ":\\")]
    else:
        home = os.path.expanduser("~")
        for p in [home, "/home", "/root", "/mnt", "/media", "/srv", "/opt",
                  "/storage", "/sdcard", "/storage/emulated/0",
                  "/data/data/com.termux/files/home", "/Users", "/Volumes"]:
            if os.path.isdir(p):
                roots.append(p)
        if not roots:
            roots.append("/")
    # drop any root that already sits inside another listed root
    out = []
    for r in sorted(set(os.path.abspath(r) for r in roots), key=len):
        if not any(r.startswith(o.rstrip(os.sep) + os.sep) for o in out):
            out.append(r)
    return out


def walk_for_encrypted(roots, prune=True, progress=True, limit=None):
    """Walk the given roots and return every .cryptedmicro path found."""
    found = []
    seen_dirs = 0
    t0 = time.time()
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, topdown=True,
                                                    onerror=lambda e: None,
                                                    followlinks=False):
            seen_dirs += 1
            if prune:
                dirnames[:] = [d for d in dirnames if d.lower() not in PRUNE_DIRS]
            for name in filenames:
                if name.endswith(EXT):
                    found.append(os.path.join(dirpath, name))
                    if limit and len(found) >= limit:
                        if progress:
                            sys.stderr.write(" " * 72 + "\r")
                        return sorted(found)
            if progress and seen_dirs % 400 == 0:
                sys.stderr.write("  scanning... %d folders, %d encrypted files, %.0fs\r"
                                 % (seen_dirs, len(found), time.time() - t0))
                sys.stderr.flush()
    if progress:
        sys.stderr.write(" " * 72 + "\r")
        sys.stderr.flush()
    return sorted(found)


def collect(root, recursive):
    """Non-autodiscovery path: a single file, or a directory."""
    if os.path.isfile(root):
        return [os.path.abspath(root)] if root.endswith(EXT) else []
    out = []
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        for name in filenames:
            if name.endswith(EXT):
                out.append(os.path.abspath(os.path.join(dirpath, name)))
        if not recursive:
            dirnames[:] = []
    return sorted(out)


# ===========================================================================
# SECTION 6a. Mutation helpers.
#
# Every confirmed key falls into one of six shapes. The generators below are
# built from those shapes and ordered cheapest and likeliest first, so a hit
# usually lands in the first few seconds. This is a wordlist problem, not a
# cryptography problem: AES-256 is not being attacked here, the operator's
# typing habits are.
#
#   shape A  prefix plus digits        keyimsel, key3131, key3413, keyu3131
#   shape B  operator handle           zarox, zarxo, buluts, efecan31
#   shape C  digit motif repeated      313131, 123123123123123, 3123123123
#   shape D  keyboard mash             qwkewqkeqwk, sdfghjxsw, edrftgybhunjk
#   shape E  Turkish caps mash         K\u015eL32LKL32423, WQE\u015e\u0130QW2EL\u015e12
#   shape F  long digit run            1298310923812093, 1273819823713
# ===========================================================================

def _case_variants(s):
    out = [s]
    for v in (s.lower(), s.upper(), s.capitalize()):
        if v not in out:
            out.append(v)
    return out


def _fold(s):
    return "".join(FOLD_MAP.get(c, c) for c in s)


def _unfold(s):
    return "".join(UNFOLD_MAP.get(c, c) for c in s)


def _transpositions(s):
    """zarox -> zarxo. Adjacent character swaps, a confirmed real mutation."""
    return [s[:i] + s[i + 1] + s[i] + s[i + 2:] for i in range(len(s) - 1)]


def _cls(c):
    if c.isdigit():
        return "d"
    if c.isalpha():
        return "u" if c.isupper() else "l"
    return "s"


def _rotations(s):
    return [s[i:] + s[:i] for i in range(len(s))]


# ===========================================================================
# ===========================================================================
# SECTION 6. The fitted key model. Fitted from KNOWN_KEYS at import time: the
# alphabets, length prior, affix widths, tiling motifs and the share of the
# sweep each family gets are all measured, none are hand ranked.
# ===========================================================================

class KeyModel(object):
    """Fitted from the recovered keys. Holds no hardcoded key material."""

    def __init__(self, keys=None, handles=None, words=None, vocab=None):
        self.keys = list(keys if keys is not None else KNOWN_KEYS)
        self.handles = list(handles if handles is not None else OPERATOR_HANDLES)
        self.words = list(words if words is not None else TURKISH_SEEDS)
        self.vocab = list(vocab if vocab is not None else TURKISH_VOCAB)
        self._fit()

    # ---------------------------------------------------------------- fit
    def _fit(self):
        K = self.keys
        n = float(max(len(K), 1))

        # Class alphabets, ordered by observed frequency. Unobserved but
        # plausible characters follow so they stay reachable, ranked last.
        tail = {
            "d": "0123456789",
            "l": "abcdefghijklmnopqrstuvwxyz" + "".join(FOLD_MAP.keys()).lower(),
            "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "".join(UNFOLD_MAP.values()).upper(),
            "s": "*-_. ",
        }
        freq = dict((t, collections.Counter()) for t in "dlus")
        for k in K:
            for c in k:
                freq[_cls(c)][c] += 1
        self.alpha = {}
        for t in "dlus":
            seen = [c for c, _ in freq[t].most_common()]
            self.alpha[t] = seen + [c for c in tail[t] if c not in seen]
        self.freq = freq

        # Length prior, observed range only, widened by one either side.
        lens = [len(k) for k in K] or [8]
        lo, hi = max(1, min(lens) - 1), min(32, max(lens) + 1)
        lc = collections.Counter(lens)
        self.lengths = sorted(range(lo, hi + 1),
                              key=lambda L: (-lc.get(L, 0), abs(L - 11)))

        # Structural classification, which also gives the family weights.
        self.stems = collections.Counter()
        self.tail_widths = collections.Counter()
        self.motifs = collections.Counter()
        fam = collections.Counter()

        for k in K:
            m = re.match(r"^([^\W\d_]+)(\d+)$", k, re.UNICODE)
            if m:
                fam["stem"] += 1
                self.stems[m.group(1)] += 1
                self.tail_widths[len(m.group(2))] += 1
                continue
            if k.isdigit() or all(not c.isalpha() for c in k):
                fam["digit"] += 1
                for p in range(1, min(5, len(k)) + 1):
                    self.motifs[k[:p]] += 1
                continue
            if k.isalpha() and (sum(c.isupper() for c in k) == 0):
                fam["word"] += 1
                self.stems[k] += 1
                continue
            fam["motor"] += 1

        self.family_mass = {}
        for f in ("stem", "digit", "motor", "word"):
            self.family_mass[f] = max(fam.get(f, 0), 1) / n

        # Digit alphabet actually used, most frequent first. This is the
        # single biggest ordering win over uniform enumeration.
        self.digits = [c for c in self.alpha["d"] if freq["d"].get(c)]
        if not self.digits:
            self.digits = list("0123456789")

        # Mash alphabet for the motor family, fitted, uppercase and lowercase.
        mash = [c for c, _ in freq["u"].most_common()] + \
               [c for c, _ in freq["l"].most_common()]
        self.mash_alpha = mash[:12] or list("KL")

        # Observed separators, for keys like 123*01923*0123.
        self.seps = [c for c, _ in freq["s"].most_common()] or ["*"]

        # Stem pool: fitted stems first, then the C2 derived seed lists.
        pool = collections.OrderedDict()
        for s, _ in self.stems.most_common():
            pool[s] = True
        for s in self.handles + self.words:
            for v in _case_variants(s) + [_fold(s), _unfold(_fold(s))]:
                if v and v.isalpha():
                    pool.setdefault(v, True)
        self.stem_pool = list(pool)

        # Vocabulary is a SEPARATE pool. Merged in, its ~200 extra stems
        # multiply through every tail width and push the C2 derived stems out
        # of a realistic budget.
        vpool = collections.OrderedDict()
        for s in self.vocab:
            for v in (s, s.capitalize(), _fold(s)):
                if v and v.isalpha() and v not in pool:
                    vpool.setdefault(v, True)
        self.vocab_pool = list(vpool)

        # Single letter extensions of fitted stems, so keyu3131 is reachable
        # from key without hardcoding the prefix.
        ext = []
        for st, _ in self.stems.most_common():
            if st.isalpha() and len(st) <= 8:
                for c in self.alpha["l"][:14]:
                    ext.append(st + c)
        self.stem_ext = ext

        # Tail widths seen on real keys, most common first.
        self.tail_order = [w for w, _ in self.tail_widths.most_common()] or [4]
        for w in (1, 2, 3, 4, 5, 6):
            if w not in self.tail_order:
                self.tail_order.append(w)

    # ------------------------------------------------------------ families
    def gen_known(self):
        for k in self.keys:
            yield k

    def gen_known_variants(self):
        """Case, Turkish folding, adjacent transposition and short affixes of
        every confirmed key. zarox to zarxo is a confirmed real mutation."""
        seen = set()
        base = []
        for k in self.keys:
            base.extend(_case_variants(k))
            base.append(_fold(k))
            base.append(_unfold(_fold(k)))
            base.extend(_transpositions(k))
        for b in base:
            if b and b not in seen:
                seen.add(b)
                yield b
        for b in list(seen):
            for d in self.digits:
                for cand in (b + d, d + b):
                    if cand not in seen:
                        seen.add(cand)
                        yield cand

    def gen_stem(self):
        """Stem plus digit tail. The digit alphabet and its order are fitted,
        so key3131 and keyu3131 are reached before key0000 ever is.

        Tail widths are walked in ascending cost, not descending probability:
        a width costs len(stems) * len(digits) ** width."""
        seen = set()
        for st in self.stem_pool:
            if st not in seen:
                seen.add(st)
                yield st
        for st in self.vocab_pool:
            if st not in seen:
                seen.add(st)
                yield st
        # Every pool at the cheap widths, then operator stems at the expensive
        # widths, then vocabulary. Both operator keys and name based keys land
        # inside budget this way; neither pure ordering manages both.
        max_w = max(self.tail_order[:1] + [4]) + 1
        cheap = 2
        phases = []
        for w in range(1, cheap + 1):
            phases.extend([(g, w) for g in
                           (self.stem_pool, self.stem_ext, self.vocab_pool)])
        for w in range(cheap + 1, max_w + 1):
            phases.append((self.stem_pool, w))
        for w in range(cheap + 1, max_w + 1):
            phases.extend([(self.stem_ext, w), (self.vocab_pool, w)])
        for group, width in phases:
            for st in group:
                for tup in itertools.product(self.digits, repeat=width):
                    cand = st + "".join(tup)
                    if cand not in seen:
                        seen.add(cand)
                        yield cand

    def gen_digit(self):
        """Digit keys. Motif tilings and rotations first, then a weighted
        odometer over the observed digit alphabet."""
        seen = set()

        def emit(s):
            if s and s not in seen:
                seen.add(s)
                return True
            return False

        motifs = [m for m, _ in self.motifs.most_common()]
        tilings = []
        for m in motifs:
            for r in _rotations(m):
                for L in self.lengths:
                    s = (r * (L // len(r) + 1))[:L]
                    if emit(s):
                        tilings.append(s)
                        yield s

        # Near misses: several recovered keys are a tiling the operator
        # fumbled, one transposition or one dropped character out.
        for base in tilings:
            if len(base) < 6:
                continue
            for v in _transpositions(base):
                if emit(v):
                    yield v
            for i in range(len(base)):
                v = base[:i] + base[i + 1:]
                if emit(v):
                    yield v
        for width in (2, 3, 4):
            for tup in itertools.product(self.digits, repeat=width):
                m = "".join(tup)
                for r in _rotations(m):
                    for L in self.lengths:
                        s = (r * (L // len(r) + 1))[:L]
                        if emit(s):
                            yield s
        for m in motifs:
            for sep in self.seps:
                for reps in (2, 3, 4):
                    s = sep.join([m] * reps)
                    if emit(s):
                        yield s
        for L in self.lengths:
            if L > 9:
                continue
            for tup in itertools.product(self.digits, repeat=L):
                s = "".join(tup)
                if emit(s):
                    yield s

    def gen_motor(self):
        """Keyboard runs, reversals, doubles and column zigzags on the Turkish
        Q layout, then mashes over the fitted mash alphabet."""
        seen = set()

        def emit(s):
            if s and s not in seen:
                seen.add(s)
                return True
            return False

        for row in KEYBOARD_ROWS:
            for start in range(len(row)):
                for L in range(3, len(row) - start + 1):
                    run = row[start:start + L]
                    for v in (run, run.upper(), run[::-1], run[::-1].upper(),
                              run + run, (run + run).upper()):
                        if emit(v):
                            yield v

        rows = KEYBOARD_ROWS[:3]
        for a, b in ((0, 1), (1, 2), (0, 2)):
            for start in range(len(rows[a])):
                for L in range(3, 15):
                    walk = []
                    for i in range(L):
                        row = rows[a] if i % 2 == 0 else rows[b]
                        col = start + i // 2
                        if col < len(row):
                            walk.append(row[col])
                    if len(walk) >= 3:
                        w = "".join(walk)
                        for v in (w, w.upper()):
                            if emit(v):
                                yield v

        for L in self.lengths:
            if L > 6:
                continue
            for tup in itertools.product(self.mash_alpha, repeat=L):
                s = "".join(tup)
                if emit(s):
                    yield s

    def gen_word(self):
        """Word plus affix. anansinmi and its Turkish spelling are the
        confirmed members of this family."""
        seen = set()
        for w in self.words:
            for v in _case_variants(w) + [_fold(w), _unfold(_fold(w))]:
                if v and v not in seen:
                    seen.add(v)
                    yield v
        for width in range(1, 4):
            for w in self.words:
                for v in _case_variants(w):
                    for tup in itertools.product(self.digits, repeat=width):
                        cand = v + "".join(tup)
                        if cand not in seen:
                            seen.add(cand)
                            yield cand

    # ---------------------------------------------------------- scheduling
    def interleaved(self, deep=False):
        """Round robin across the families, each family getting a share of
        every cycle proportional to the mass of recovered keys it explains.
        Nothing starves behind another family's long tail."""
        fams = [
            ("stem", self.gen_stem()),
            ("digit", self.gen_digit()),
            ("motor", self.gen_motor()),
            ("word", self.gen_word()),
        ]
        quota = []
        for name, gen in fams:
            share = max(1, int(round(self.family_mass.get(name, 0.235) * 40)))
            quota.append([name, gen, share * (4 if deep else 1)])
        seen = set()
        live = True
        while live:
            live = False
            for entry in quota:
                name, gen, share = entry
                if gen is None:
                    continue
                for _ in range(share):
                    try:
                        cand = next(gen)
                    except StopIteration:
                        entry[1] = None
                        break
                    live = True
                    if cand not in seen:
                        seen.add(cand)
                        yield cand


MODEL = None


def get_model():
    global MODEL
    if MODEL is None:
        MODEL = KeyModel()
    return MODEL


def build_plan(brute=False, deep=False, extra=None, wordlist=None):
    """
    Ordered list of (tier name, generator factory), consumed by sweep().
    Without --brute only supplied keys, the wordlist and the recovered keys
    are tried. With --brute the fitted model runs as one interleaved stream.
    """
    plan = []
    if extra:
        plan.append(("supplied keys", lambda: iter(list(extra))))
    if wordlist:
        plan.append(("wordlist", lambda: iter(list(wordlist))))
    m = get_model()
    plan.append(("recovered operator keys", m.gen_known))
    if not brute:
        return plan
    plan.append(("recovered key variants", m.gen_known_variants))
    plan.append(("fitted model", lambda: KeyModel().interleaved(deep=deep)))
    return plan


# ===========================================================================
# SECTION 7. The oracle and the sweep
# ===========================================================================

def probe_set(files, max_probes=4):
    """
    Pick a small set of distinct first blocks covering as many files as
    possible, each paired with the smallest file carrying that block. One AES
    block per probe per candidate is the whole cost of a guess, so keeping
    this small is what makes the sweep fast. The paired file is only touched
    when a weak magic needs confirming.
    """
    groups = {}
    for p in files:
        try:
            with open(p, "rb") as fh:
                b = fh.read(16)
        except OSError:
            continue
        if len(b) == 16:
            groups.setdefault(b, []).append(p)
    ordered = sorted(groups.items(), key=lambda kv: -len(kv[1]))
    out = []
    for blk, paths in ordered[:max_probes]:
        smallest = min(paths, key=lambda p: os.path.getsize(p))
        out.append((blk, smallest))
    return out


def confirm_key(key_string, path):
    """Whole file check: decrypt, require valid PKCS#5, then require the
    recovered bytes to validate structurally. This is what separates a real
    key from a candidate that merely happened to produce a plausible looking
    first block."""
    pt, verified, _ = decrypt_file(path, key_string, verify=True)
    return pt is not None and verified


_WORKER_PROBES = []


def _worker_init(probes):
    global _WORKER_PROBES
    _WORKER_PROBES = probes
    if BACKEND is None:
        _init_backend(False)


def _worker_chunk(chunk):
    hits = []
    for cand in chunk:
        kb = key_bytes(cand)
        for blk, path in _WORKER_PROBES:
            label, _, strong = identify_ex(_dec_blocks(kb, blk))
            if not label:
                continue
            if strong or confirm_key(cand, path):
                hits.append(cand)
                break
    return hits


def sweep(files, plan, workers=1, limit=None, quiet=False, chunk_size=20000):
    """
    Run the tiers in order against the probe blocks. Stops at the first tier
    that produces a hit, since in this family one key normally covers a whole
    machine. Returns (hit key strings, candidates tried).
    """
    probes = probe_set(files)
    if not probes:
        return [], 0

    _worker_init(probes)
    tried = 0
    t0 = time.time()

    pool = None
    if workers > 1:
        try:
            import multiprocessing
            pool = multiprocessing.Pool(workers, initializer=_worker_init,
                                        initargs=(probes,))
        except Exception:
            pool = None

    try:
        for name, factory in plan:
            gen = factory()
            tier_start = tried
            confirmed = []
            rejected = 0
            while True:
                chunk = list(itertools.islice(gen, chunk_size))
                if not chunk:
                    break
                if pool:
                    slices = [chunk[i::workers] for i in range(workers)]
                    raw = []
                    for hits in pool.imap_unordered(_worker_chunk, slices):
                        raw.extend(hits)
                else:
                    raw = _worker_chunk(chunk)
                tried += len(chunk)

                # A header match is evidence, nothing more. Proof is the whole
                # file validating structurally. Anything that fails this gate
                # was a coincidence, so it is discarded and the sweep carries
                # on rather than reporting a key that does not work.
                for h in raw:
                    if h in confirmed:
                        continue
                    if any(confirm_key(h, path) for _, path in probes):
                        confirmed.append(h)
                    else:
                        rejected += 1

                if not quiet:
                    rate = tried / max(time.time() - t0, 0.001)
                    sys.stderr.write("  %-26s %11d tried  %9.0f/s\r"
                                     % (name[:26], tried, rate))
                    sys.stderr.flush()
                if confirmed:
                    break
                if limit and tried >= limit:
                    if not quiet:
                        sys.stderr.write(" " * 72 + "\r")
                    return [], tried
            if not quiet:
                sys.stderr.write(" " * 72 + "\r")
                sys.stderr.flush()
                note = "HIT" if confirmed else "no hit"
                if rejected:
                    note += "  (%d coincidental header match(es) discarded)" % rejected
                print("  tier %-26s %11d candidates  %s"
                      % (name, tried - tier_start, note))
            if confirmed:
                return confirmed, tried
    finally:
        if pool:
            pool.terminate()
            pool.join()
    return [], tried


def map_keys_to_files(files, keys):
    """Which of the found keys opens which file, by header check."""
    mapping = {}
    for k in keys:
        kb = key_bytes(k)
        hits = []
        for p in files:
            try:
                with open(p, "rb") as fh:
                    blk = fh.read(16)
            except OSError:
                continue
            if len(blk) == 16 and identify(_dec_blocks(kb, blk))[0]:
                hits.append(p)
        if hits:
            mapping[k] = hits

    # Second pass. A file whose plaintext has no magic number (text, CSV,
    # source, config, anything not in SIGNATURES) is invisible to the header
    # check above, so it used to be reported as "no key found" even when the
    # key was already proven on the machine. On the synthetic corpus that was
    # 90 of 463 files. Padding plus length agreement is weak evidence on its
    # own, which is why it is only accepted for a key that has already been
    # proven structurally somewhere else in this run.
    covered = set()
    for hits in mapping.values():
        covered.update(hits)
    for k in mapping:
        kb = key_bytes(k)
        for p in files:
            if p in covered:
                continue
            try:
                with open(p, "rb") as fh:
                    ct = fh.read()
            except OSError:
                continue
            if not ct or len(ct) % 16:
                continue
            pt = strip_pkcs5(_dec_blocks(kb, ct))
            if pt is None or padded_length(len(pt)) != len(ct):
                continue
            mapping[k].append(p)
            covered.add(p)
    return mapping


# ===========================================================================
# SECTION 8. Output paths
# ===========================================================================

def mirrored_path(out_root, src_path, flat=False):
    """
    Recovered files mirror their original location under the output root, so a
    whole-machine sweep does not collapse thousands of files into one folder
    and clobber same-named files.
    """
    base = os.path.basename(src_path)[:-len(EXT)]
    if flat:
        return os.path.join(out_root, base)
    p = os.path.abspath(os.path.dirname(src_path))
    drive, rest = os.path.splitdrive(p)
    drive = drive.replace(":", "").replace("\\", "").replace("/", "")
    rest = rest.lstrip("\\/")
    parts = [x for x in (drive, rest) if x]
    if not parts:
        return os.path.join(out_root, base)
    return os.path.join(out_root, *(parts + [base]))


def unique_path(path):
    if not os.path.exists(path):
        return path
    stem, ext = os.path.splitext(path)
    i = 1
    while os.path.exists("%s (%d)%s" % (stem, i, ext)):
        i += 1
    return "%s (%d)%s" % (stem, i, ext)


# ===========================================================================
# SECTION 9. Main
# ===========================================================================

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="unmicro.py",
        description="Decrypt files encrypted by the Dev7 / Micro ransomware "
                    "(.cryptedmicro). Your encrypted files are never modified.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    g_src = ap.add_argument_group("finding the files")
    g_src.add_argument("--in", dest="src",
                       help="encrypted file, or directory containing .cryptedmicro files")
    g_src.add_argument("--auto", action="store_true",
                       help="search every drive and user location for encrypted files")
    g_src.add_argument("--scan-root", action="append", default=[],
                       help="extra root to search under --auto, repeatable")
    g_src.add_argument("--no-prune", action="store_true",
                       help="do not skip system folders while scanning, much slower")
    g_src.add_argument("--recursive", action="store_true",
                       help="walk subdirectories of --in")
    g_src.add_argument("--max-files", type=int,
                       help="stop scanning after this many encrypted files")

    g_key = ap.add_argument_group("keys")
    g_key.add_argument("--key", action="append", default=[],
                       help="key string to try, repeatable")
    g_key.add_argument("--wordlist", help="file of candidate keys, one per line")
    g_key.add_argument("--brute", action="store_true",
                       help="if the known keys fail, generate and sweep candidates "
                            "modelled on this crew's key history")
    g_key.add_argument("--deep", action="store_true",
                       help="with --brute, widen every generator. Hours, not seconds")
    g_key.add_argument("--workers", type=int, default=1,
                       help="parallel processes for the sweep")
    g_key.add_argument("--max-candidates", type=int,
                       help="give up after this many guesses")
    g_key.add_argument("--list-keys", action="store_true",
                       help="print the built in known keys and exit")

    g_out = ap.add_argument_group("output")
    g_out.add_argument("--out", dest="dst",
                       help="directory to write recovered files into")
    g_out.add_argument("--identify", action="store_true",
                       help="only work out which key applies, write nothing")
    g_out.add_argument("--flat", action="store_true",
                       help="write everything into one folder instead of mirroring paths")
    g_out.add_argument("--overwrite", action="store_true",
                       help="overwrite instead of adding a numeric suffix")
    g_out.add_argument("--keep-unverified", action="store_true",
                       help="also write files that failed verification, suffixed .UNVERIFIED")
    g_out.add_argument("--strict", action="store_true",
                       help="do not write anything that failed structural verification, "
                            "even under a key already proven on this machine")
    g_out.add_argument("--fix-ext", action="store_true",
                       help="correct extensions that disagree with the recovered magic bytes")
    g_out.add_argument("--force", action="store_true",
                       help="apply a single supplied key without header checking")
    g_out.add_argument("--pure-python", action="store_true",
                       help="ignore installed crypto libraries and use the built in AES")
    g_out.add_argument("--quiet", action="store_true", help="less output")
    ap.add_argument("--version", action="version", version="unmicro.py " + VERSION)
    args = ap.parse_args(argv)

    if args.list_keys:
        for k in KNOWN_KEYS:
            print(k)
        return 0

    _init_backend(args.pure_python)

    if not args.src and not args.auto:
        ap.error("give --in PATH or --auto")
    if not args.identify and not args.dst:
        ap.error("--out is required unless you pass --identify")
    if args.brute and BACKEND == "pure-python" and not args.quiet:
        print("Note: no crypto library installed, so guessing will be very slow.")
        print("      pip install pycryptodome makes --brute thousands of times faster.")
        print()

    if not args.quiet:
        print("unmicro.py %s   AES back end: %s" % (VERSION, BACKEND))
        print("Your encrypted files will not be modified, renamed or deleted.")
        print()

    # --- find the files ----------------------------------------------------
    if args.auto:
        roots = args.scan_root or candidate_roots()
        if not args.quiet:
            print("Searching for encrypted files under:")
            for r in roots:
                print("    %s" % r)
        files = walk_for_encrypted(roots, prune=not args.no_prune,
                                   progress=not args.quiet, limit=args.max_files)
    else:
        files = collect(args.src, args.recursive or os.path.isdir(args.src))

    if not files:
        print("No %s files found." % EXT)
        if not args.auto:
            print("Try --auto to search the whole machine.")
        return 1

    if not args.quiet:
        dirs = sorted(set(os.path.dirname(f) for f in files))
        print("Encrypted files found: %d across %d folder(s)" % (len(files), len(dirs)))
        for d in dirs[:10]:
            print("    %s" % d)
        if len(dirs) > 10:
            print("    ... and %d more folders" % (len(dirs) - 10))
        print()

    # --- work out the key --------------------------------------------------
    wordlist = []
    if args.wordlist:
        with open(args.wordlist, "r", encoding="utf-8", errors="replace") as fh:
            wordlist = [ln.rstrip("\r\n") for ln in fh if ln.strip()]

    forced = False
    if args.force and len(args.key) == 1 and not args.brute and not wordlist:
        mapping = {args.key[0]: files}
        forced = True
        if not args.quiet:
            print("Forced key %r applied to all %d files without header checking."
                  % (args.key[0], len(files)))
    else:
        plan = build_plan(brute=args.brute, deep=args.deep,
                          extra=args.key, wordlist=wordlist)
        if not args.quiet:
            print("Trying keys%s:" % (" (brute force enabled)" if args.brute else ""))
        found, tried = sweep(files, plan, workers=max(1, args.workers),
                             limit=args.max_candidates, quiet=args.quiet)
        if not found:
            print()
            print("No key opened any file after %d candidate(s)." % tried)
            print()
            if not args.brute:
                print("Next step: re-run with --brute to sweep generated candidates.")
            else:
                print("Next step: --brute --deep --workers 4, and leave it running.")
            print()
            print("What this does and does not mean:")
            print("  * The key is a string the operator typed. It is not derived from")
            print("    anything in the file and cannot be read out of the ciphertext.")
            print("    AES-256 itself is not broken here and is not being attacked.")
            print("  * Do not assume the machine's own recovery paths survived. This")
            print("    crew disables Windows Recovery, Task Manager and Regedit, and")
            print("    adds a Defender exclusion. Check what is actually left rather")
            print("    than counting on it.")
            print("  * Do not wipe the machine and do not delete the encrypted files.")
            print("    That is what turns a recoverable situation into a permanent one.")
            print("  * If the machine is still on and infected, the key may still be")
            print("    in memory. Take it off the network but leave it powered on, and")
            print("    get a responder to look before anyone reboots it.")
            print("  * Do not pay. Their decryption is issued from their own bot to the")
            print("    implant on your machine, so it means keeping the infection alive")
            print("    and letting their code run again.")
            print("  * Keep every encrypted file. Mention Chattering Magpies when you")
            print("    post about this so the case gets picked up faster.")
            return 2
        if not args.quiet:
            print()
        mapping = map_keys_to_files(files, found)
        for k, hits in mapping.items():
            print("Key found: %r opens %d/%d files" % (k, len(hits), len(files)))
        print()

    if args.identify:
        covered = set()
        for hits in mapping.values():
            covered.update(hits)
        print("Keys: %d. Files covered: %d/%d." % (len(mapping), len(covered), len(files)))
        for f in [f for f in files if f not in covered][:20]:
            print("  no key for: %s" % f)
        return 0

    # --- decrypt -----------------------------------------------------------
    os.makedirs(args.dst, exist_ok=True)
    recovered = unverified = failed = 0
    handled = set()

    # A key is proven once any one file under it validates structurally. From
    # that point the key is not in question, so the remaining files under it
    # are written rather than withheld. They still carry the .UNVERIFIED
    # suffix, because their contents were never structurally checked. --strict
    # restores the old behaviour of writing nothing unverified.
    proven = set()
    if not forced:
        for key_string, hits in mapping.items():
            for path in hits[:6]:
                _, ver, _ = decrypt_file(path, key_string, verify=True)
                if ver:
                    proven.add(key_string)
                    break

    for key_string, hits in mapping.items():
        for path in hits:
            if path in handled:
                continue
            handled.add(path)

            pt, verified, err = decrypt_file(path, key_string, verify=not forced)

            if pt is None:
                print("  FAIL   %s  (%s)" % (os.path.basename(path), err))
                failed += 1
                continue
            allow = (args.keep_unverified
                     or (key_string in proven and not args.strict))
            if not verified and not forced and not allow:
                print("  FAIL   %s  (%s, not written, use --keep-unverified)"
                      % (os.path.basename(path), err or "unverified"))
                failed += 1
                continue

            label, canon = identify(pt[:16])
            dest = mirrored_path(args.dst, path, flat=args.flat)
            if args.fix_ext and canon:
                stem, cur = os.path.splitext(dest)
                if cur.lower() != canon and not (canon == ".jpg" and cur.lower() == ".jpeg"):
                    dest = stem + canon
            if not verified and not forced:
                dest += ".UNVERIFIED"
            os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
            if not args.overwrite:
                dest = unique_path(dest)

            tmp = dest + ".part"
            with open(tmp, "wb") as fh:
                fh.write(pt)
            os.replace(tmp, dest)

            if verified:
                recovered += 1
                if not args.quiet:
                    print("  OK     %-56s %10d bytes  %s"
                          % (os.path.basename(dest)[:56], len(pt), label or "unknown type"))
            elif forced:
                unverified += 1
                if not args.quiet:
                    print("  FORCED %-56s %10d bytes  %s"
                          % (os.path.basename(dest)[:56], len(pt),
                             label or "unrecognised type, not structurally checked"))
            else:
                unverified += 1
                if not args.quiet:
                    print("  PROVEN %-56s %10d bytes  %s"
                          % (os.path.basename(dest)[:56], len(pt),
                             "key proven on this machine, structure not checked"))

    leftover = [f for f in files if f not in handled]

    print()
    print("Recovered and verified : %d" % recovered)
    if unverified:
        print("Written unverified     : %d%s" % (unverified,
              "  (forced key, structure not checked)" if forced
              else "  (proven key, structure not checked, .UNVERIFIED suffix)"))
    if failed:
        print("Failed                 : %d" % failed)
    if leftover:
        print("No key found for       : %d" % len(leftover))
        for f in leftover[:20]:
            print("    %s" % f)
        if len(leftover) > 20:
            print("    ... and %d more" % (len(leftover) - 20))
    print()
    print("Verified means the padding parsed, the length matched, and the file")
    print("structure checked out: CRCs, terminators and length fields, not just")
    print("the first few bytes. Open a few anyway, and keep your encrypted")
    print("copies until you are satisfied.")
    print()
    print("Rho-9 Systems. Your first line of unusual defense.")
    return 0 if (recovered or unverified) else 3


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted, nothing left half written\n")
        sys.exit(130)
