#!/usr/bin/env python3
"""
File Protection Utility (task4)
===============================
Converts a file into a protected (encrypted) format and restores it when the
correct password is supplied.

Security design (standard library only)
---------------------------------------
  * Key derivation : PBKDF2-HMAC-SHA256, 200,000 iterations, random 16-byte salt
  * Encryption     : keystream from HMAC-SHA256 in counter mode (stream cipher),
                     unique random 16-byte nonce per file
  * Integrity      : HMAC-SHA256 over header + ciphertext (encrypt-then-MAC), so a
                     wrong password OR a tampered file is detected before restore
  * Separate encryption and MAC keys are derived from the password

Protected file layout
---------------------
    MAGIC(6) | VERSION(1) | SALT(16) | NONCE(16) | CIPHERTEXT(n) | TAG(32)

NOTE: This is an educational implementation of the concepts. For production
data, prefer a vetted library (e.g. `cryptography` with AES-GCM or Fernet).

Usage
-----
    python task4_file_protection_utility.py protect  secret.txt
    python task4_file_protection_utility.py restore  secret.txt.locked
    python task4_file_protection_utility.py protect  a.txt -o a.bin --delete-original
    python task4_file_protection_utility.py restore  a.bin -o a_restored.txt
    python task4_file_protection_utility.py demo        # self-test with a temp file
    python task4_file_protection_utility.py             # interactive menu
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import os
import struct
import sys
import tempfile
from typing import Optional

MAGIC = b"FPROT1"
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 16
TAG_LEN = 32
ITERATIONS = 200_000
EXT = ".locked"
HEADER_LEN = len(MAGIC) + 1 + SALT_LEN + NONCE_LEN


class ProtectionError(Exception):
    """Raised for any failure to protect or restore a file."""


# --------------------------------------------------------------------------- #
# Crypto primitives
# --------------------------------------------------------------------------- #

def derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    """Derive independent encryption and MAC keys from a password."""
    material = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=64)
    return material[:32], material[32:]


def _keystream_xor(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """XOR data with an HMAC-SHA256(counter) keystream."""
    out = bytearray(len(data))
    block_size = 32
    for i in range(0, len(data), block_size):
        counter = i // block_size
        block = hmac.new(key, nonce + struct.pack(">Q", counter), hashlib.sha256).digest()
        chunk = data[i:i + block_size]
        out[i:i + len(chunk)] = bytes(a ^ b for a, b in zip(chunk, block))
    return bytes(out)


# --------------------------------------------------------------------------- #
# Core operations
# --------------------------------------------------------------------------- #

def protect_bytes(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    enc_key, mac_key = derive_keys(password, salt)
    ciphertext = _keystream_xor(plaintext, enc_key, nonce)
    header = MAGIC + bytes([VERSION]) + salt + nonce
    tag = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
    return header + ciphertext + tag


def restore_bytes(blob: bytes, password: str) -> bytes:
    if len(blob) < HEADER_LEN + TAG_LEN or not blob.startswith(MAGIC):
        raise ProtectionError("Not a protected file (bad format).")
    if blob[len(MAGIC)] != VERSION:
        raise ProtectionError("Unsupported file version.")
    salt = blob[len(MAGIC) + 1: len(MAGIC) + 1 + SALT_LEN]
    nonce = blob[len(MAGIC) + 1 + SALT_LEN: HEADER_LEN]
    ciphertext = blob[HEADER_LEN:-TAG_LEN]
    tag = blob[-TAG_LEN:]

    enc_key, mac_key = derive_keys(password, salt)
    expected = hmac.new(mac_key, blob[:HEADER_LEN] + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ProtectionError("Wrong password, or the file has been modified/corrupted.")
    return _keystream_xor(ciphertext, enc_key, nonce)


def protect_file(path: str, password: str, out: Optional[str] = None, delete_original: bool = False) -> str:
    if not os.path.isfile(path):
        raise ProtectionError(f"File not found: {path}")
    out = out or path + EXT
    if os.path.abspath(out) == os.path.abspath(path):
        raise ProtectionError("Output path must differ from the input path.")
    with open(path, "rb") as fh:
        data = fh.read()
    with open(out, "wb") as fh:
        fh.write(protect_bytes(data, password))
    if delete_original:
        os.remove(path)
    return out


def restore_file(path: str, password: str, out: Optional[str] = None) -> str:
    if not os.path.isfile(path):
        raise ProtectionError(f"File not found: {path}")
    if out is None:
        out = path[:-len(EXT)] if path.endswith(EXT) else path + ".restored"
        if os.path.exists(out):
            out += ".restored"
    if os.path.abspath(out) == os.path.abspath(path):
        raise ProtectionError("Output path must differ from the input path.")
    with open(path, "rb") as fh:
        blob = fh.read()
    plaintext = restore_bytes(blob, password)   # raises before anything is written
    with open(out, "wb") as fh:
        fh.write(plaintext)
    return out


# --------------------------------------------------------------------------- #
# CLI helpers
# --------------------------------------------------------------------------- #

def ask_password(confirm: bool) -> str:
    pw = getpass.getpass("Password: ")
    if not pw:
        raise ProtectionError("Password cannot be empty.")
    if confirm:
        if len(pw) < 8:
            print("Warning: short password; use 8+ characters for better protection.", file=sys.stderr)
        if getpass.getpass("Confirm password: ") != pw:
            raise ProtectionError("Passwords do not match.")
    return pw


def run_demo() -> int:
    print("Running self-test...")
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "note.txt")
        original = b"Top secret: meeting at 9am.\n" * 50
        with open(src, "wb") as fh:
            fh.write(original)

        locked = protect_file(src, "correct horse battery")
        blob = open(locked, "rb").read()
        print(f"  Protected -> {os.path.basename(locked)} ({len(blob)} bytes)")
        print(f"  Plaintext visible in protected file? {b'Top secret' in blob}")

        try:
            restore_file(locked, "wrong password", os.path.join(tmp, "bad.txt"))
            print("  Wrong password: FAILED (was accepted!)")
            return 1
        except ProtectionError as exc:
            print(f"  Wrong password rejected: {exc}")

        tampered = bytearray(blob)
        tampered[HEADER_LEN + 3] ^= 1
        tpath = os.path.join(tmp, "tampered.locked")
        open(tpath, "wb").write(bytes(tampered))
        try:
            restore_file(tpath, "correct horse battery", os.path.join(tmp, "t.txt"))
            print("  Tamper check: FAILED")
            return 1
        except ProtectionError:
            print("  Tampered file detected and rejected.")

        restored = restore_file(locked, "correct horse battery", os.path.join(tmp, "restored.txt"))
        ok = open(restored, "rb").read() == original
        print(f"  Correct password restores identical content? {ok}")
        return 0 if ok else 1


def interactive() -> int:
    print("File Protection Utility\n  1) Protect a file\n  2) Restore a file\n  3) Self-test\n  4) Quit")
    choice = input("Choose: ").strip()
    try:
        if choice == "1":
            path = input("File to protect: ").strip().strip('"')
            out = protect_file(path, ask_password(confirm=True))
            print(f"Protected file saved as: {out}")
        elif choice == "2":
            path = input("File to restore: ").strip().strip('"')
            out = restore_file(path, ask_password(confirm=False))
            print(f"Restored file saved as: {out}")
        elif choice == "3":
            return run_demo()
        else:
            return 0
    except ProtectionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="Protect (encrypt) and restore (decrypt) files with a password.")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("protect", help="Encrypt a file")
    p.add_argument("file")
    p.add_argument("-o", "--output")
    p.add_argument("--delete-original", action="store_true", help="Remove the plaintext file afterwards")
    r = sub.add_parser("restore", help="Decrypt a protected file")
    r.add_argument("file")
    r.add_argument("-o", "--output")
    sub.add_parser("demo", help="Run a built-in self-test")
    args = ap.parse_args(argv)

    if args.cmd is None:
        return interactive()
    try:
        if args.cmd == "demo":
            return run_demo()
        if args.cmd == "protect":
            out = protect_file(args.file, ask_password(confirm=True), args.output, args.delete_original)
            print(f"Protected file saved as: {out}")
        elif args.cmd == "restore":
            out = restore_file(args.file, ask_password(confirm=False), args.output)
            print(f"Restored file saved as: {out}")
    except ProtectionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print()
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
