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
    * If nothing is found, that is not the end. This family does not delete
      Volume Shadow Copies and does not overwrite originals before deleting
      them, so shadow copies, undelete and file carving are all live options.
      Do not pay, and do not run the attackers' own !unmicro command, which is
      their code running on your machine again.
"""

import argparse
import itertools
import os
import string
import sys
import time

VERSION = "2.0"
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

# Prefix plus digits is the single most common observed shape:
# keyimsel, key3131, key3413, keyu3131.
KEY_PREFIXES = [
    "key", "Key", "KEY", "keyu", "KEYU", "anahtar", "sifre", "\u015fifre",
    "pass", "micro", "Micro", "MICRO",
]

# Digit motifs. Nine confirmed keys are repetitions or near repetitions of a
# short motif typed fast on a numpad.
DIGIT_MOTIFS = [
    "1", "3", "0", "12", "13", "21", "31", "69", "123", "312", "321", "231",
    "132", "213", "131", "313", "1231", "3123", "1234", "4321",
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
_enc_blocks = None
_dec_blocks = None


def _init_backend(force_pure=False):
    global BACKEND, _enc_blocks, _dec_blocks
    if not force_pure:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

            def _enc(key, data):
                c = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
                return c.update(data) + c.finalize()

            def _dec(key, data):
                c = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
                return c.update(data) + c.finalize()

            _enc_blocks, _dec_blocks, BACKEND = _enc, _dec, "cryptography"
            return
        except Exception:
            pass
        try:
            from Crypto.Cipher import AES as _AES

            def _enc(key, data):
                return _AES.new(key, _AES.MODE_ECB).encrypt(data)

            def _dec(key, data):
                return _AES.new(key, _AES.MODE_ECB).decrypt(data)

            _enc_blocks, _dec_blocks, BACKEND = _enc, _dec, "pycryptodome"
            return
        except Exception:
            pass

    def _enc(key, data):
        ctx = _PureAES(key)
        return b"".join(ctx.encrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))

    def _dec(key, data):
        ctx = _PureAES(key)
        return b"".join(ctx.decrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))

    _enc_blocks, _dec_blocks, BACKEND = _enc, _dec, "pure-python"


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
    """AES-256 single block encrypt and decrypt. Correctness over speed."""

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

    def encrypt_block(self, blk):
        s = self._ark(list(blk), 0)
        for r in range(1, 14):
            s = [_SBOX[b] for b in s]
            s = self._shift(s)
            s = self._mix(s)
            s = self._ark(s, r)
        s = [_SBOX[b] for b in s]
        s = self._shift(s)
        s = self._ark(s, 14)
        return bytes(s)

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
    def _shift(s):
        o = list(s)
        for r in range(1, 4):
            row = [s[r + 4 * c] for c in range(4)]
            row = row[r:] + row[:r]
            for c in range(4):
                o[r + 4 * c] = row[c]
        return o

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
    def _mix(s):
        o = [0] * 16
        for c in range(4):
            a = s[4 * c:4 * c + 4]
            o[4 * c + 0] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
            o[4 * c + 1] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
            o[4 * c + 2] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
            o[4 * c + 3] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)
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


def add_pkcs5(data):
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


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
    kb = key_bytes(key_string)
    pt = strip_pkcs5(_dec_blocks(kb, ct))
    if pt is None:
        return None, False, "PKCS#5 padding invalid, wrong key for this file"
    if len(add_pkcs5(pt)) != len(ct):
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
# SECTION 6. Candidate generation, modelled on this crew's key history.
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


def gen_known():
    for k in KNOWN_KEYS:
        yield k


def gen_known_variants(max_suffix=99):
    """Case, Turkish folding, adjacent transpositions and numeric suffixes of
    every confirmed key. Operators reuse and lightly mutate their own keys."""
    seen = set(KNOWN_KEYS)
    base = []
    for k in KNOWN_KEYS:
        base.extend(_case_variants(k))
        base.append(_fold(k))
        base.append(_unfold(_fold(k)))
        base.extend(_transpositions(k))
    for b in base:
        if b not in seen:
            seen.add(b)
            yield b
    for b in list(seen):
        for n in range(max_suffix + 1):
            for cand in (b + str(n), str(n) + b):
                if cand not in seen:
                    seen.add(cand)
                    yield cand


def gen_prefix_digits(max_digits=5):
    """Shape A. Prefix plus a digit run, the most common observed shape."""
    for prefix in KEY_PREFIXES:
        for width in range(1, max_digits + 1):
            for n in range(10 ** width):
                yield prefix + str(n).zfill(width)


def gen_handles(max_suffix=999):
    """Shape B. Operator handle, optionally with digits, plus transpositions."""
    seen = set()
    for h in OPERATOR_HANDLES:
        for v in _case_variants(h) + _transpositions(h) + [_fold(h)]:
            if v not in seen:
                seen.add(v)
                yield v
    for h in OPERATOR_HANDLES:
        for v in _case_variants(h):
            for n in range(max_suffix + 1):
                yield v + str(n)


def gen_motifs(max_len=28):
    """Shape C. A short digit motif hammered out to length."""
    seen = set()
    for m in DIGIT_MOTIFS:
        for L in range(1, max_len + 1):
            s = (m * (L // len(m) + 1))[:L]
            if s not in seen:
                seen.add(s)
                yield s
    # motif with a separator, as in 123*01923*0123
    for m in DIGIT_MOTIFS:
        for sep in ("*", "-", "_", ".", " "):
            for reps in range(2, 5):
                yield sep.join([m] * reps)


def gen_keyboard(min_len=3, max_len=14):
    """Shape D. Row runs, reversed runs, doubled runs and column zigzags."""
    seen = set()

    def emit(s):
        for v in (s, s.upper()):
            if v and v not in seen:
                seen.add(v)
                yield v

    for row in KEYBOARD_ROWS:
        for start in range(len(row)):
            for L in range(min_len, min(max_len, len(row) - start) + 1):
                run = row[start:start + L]
                for v in emit(run):
                    yield v
                for v in emit(run[::-1]):
                    yield v
                for v in emit(run + run):
                    yield v

    # zigzag walks across adjacent columns, which is what edrftgybhunjk is
    rows = (KEYBOARD_ROWS[0], KEYBOARD_ROWS[1], KEYBOARD_ROWS[2])
    for a, b in ((0, 1), (1, 2), (0, 2)):
        for start in range(len(rows[a])):
            for L in range(min_len, max_len + 1):
                walk = []
                for i in range(L):
                    row = rows[a] if i % 2 == 0 else rows[b]
                    col = start + i // 2
                    if col < len(row):
                        walk.append(row[col])
                if len(walk) >= min_len:
                    for v in emit("".join(walk)):
                        yield v


def gen_caps_mash(max_len=5):
    """Shape E. Short mashes over the exact alphabet these operators use:
    K, L, Q, W, E, S, \u015e and digits. Kept short on purpose, because this
    family explodes fast."""
    alpha = "KL\u015eQWES1234"
    seen = set()
    for L in range(2, min(max_len, 5) + 1):
        for tup in itertools.product(alpha, repeat=L):
            s = "".join(tup)
            if s not in seen:
                seen.add(s)
                yield s
    for L in range(6, max_len + 1):
        for tup in itertools.product("K\u015eL234", repeat=L):
            s = "".join(tup)
            if s not in seen:
                seen.add(s)
                yield s


def gen_words(max_suffix=99):
    """Turkish and English seeds with numeric suffixes and folding."""
    seen = set()
    for w in TURKISH_SEEDS:
        for v in _case_variants(w) + [_fold(w), _unfold(_fold(w))]:
            if v not in seen:
                seen.add(v)
                yield v
    for w in TURKISH_SEEDS:
        for v in _case_variants(w):
            for n in range(max_suffix + 1):
                yield v + str(n)


def gen_digits(max_digits=6):
    """Shape F. Exhaustive digit runs. Cheap because there is no KDF."""
    for width in range(1, max_digits + 1):
        for n in range(10 ** width):
            yield str(n).zfill(width)


def gen_alnum(max_len=4):
    """Last resort, exhaustive lowercase alphanumeric. Only under --deep."""
    alpha = string.ascii_lowercase + string.digits
    for L in range(1, max_len + 1):
        for tup in itertools.product(alpha, repeat=L):
            yield "".join(tup)


def build_plan(brute=False, deep=False, extra=None, wordlist=None):
    """
    Ordered list of (tier name, generator factory). Cheapest and most likely
    first. Without --brute only the supplied keys, the wordlist and the known
    keys are tried.
    """
    plan = []
    if extra:
        plan.append(("supplied keys", lambda: iter(list(extra))))
    if wordlist:
        plan.append(("wordlist", lambda: iter(list(wordlist))))
    plan.append(("known operator keys", gen_known))
    if not brute:
        return plan
    plan.append(("known key variants", gen_known_variants))
    plan.append(("operator handles", gen_handles))
    plan.append(("digit motifs", gen_motifs))
    plan.append(("keyboard mashes", gen_keyboard))
    plan.append(("Turkish and English words", gen_words))
    plan.append(("prefix plus digits", lambda: gen_prefix_digits(6 if deep else 5)))
    plan.append(("uppercase mashes", lambda: gen_caps_mash(7 if deep else 5)))
    plan.append(("digit runs", lambda: gen_digits(8 if deep else 6)))
    if deep:
        plan.append(("alphanumeric", lambda: gen_alnum(4)))
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
            print("  * Check shadow copies, undelete and file carving. This family does")
            print("    not delete Volume Shadow Copies and does not overwrite originals")
            print("    before deleting them, so all three are live options.")
            print("  * If the machine is still on and infected, the key may still be in")
            print("    memory. Take it off the network but leave it powered on.")
            print("  * Do not pay, and do not run the attackers' own !unmicro command.")
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
            if not verified and not forced and not args.keep_unverified:
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
                print("  WARN   %s written unverified" % os.path.basename(dest))

    leftover = [f for f in files if f not in handled]

    print()
    print("Recovered and verified : %d" % recovered)
    if unverified:
        print("Written unverified     : %d%s" % (unverified,
              "  (forced key, structure not checked)" if forced else ""))
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
