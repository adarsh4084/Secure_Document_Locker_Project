"""Cryptographic primitives for Secure Document Locker.

This module is independent of the web framework so its file encryption routines
can be tested separately. It implements streaming AES-256-GCM encryption and
password/PIN key derivation; it does not implement account authorization.
"""
from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"SDL1"
CHUNK_SIZE = 1024 * 1024
PASSWORD_KDF_ITERATIONS = 600_000


def derive_password_key(password: str, salt: bytes, iterations: int = PASSWORD_KDF_ITERATIONS) -> bytes:
    """Derive a 256-bit key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))


def derive_pin_hash(pin: str, salt: bytes) -> bytes:
    """Return a salted, memory-hard PIN hash. Online rate limiting is also required."""
    return hashlib.scrypt(pin.encode("ascii"), salt=salt, n=2**14, r=8, p=1, dklen=32)


def safe_unlink(path: str | Path | None) -> None:
    if not path:
        return
    try:
        Path(path).unlink(missing_ok=True)
    except OSError:
        pass


def encrypt_stream(source: BinaryIO, destination: Path, key: bytes, aad: bytes) -> int:
    """Encrypt a stream as SDL1 | 12-byte nonce | ciphertext | 16-byte tag.

    Reads the source in bounded chunks, so the cipher itself does not require the
    entire document in memory. The caller should store the random key encrypted.
    """
    nonce = secrets.token_bytes(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(aad)
    total = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("wb") as out:
            out.write(MAGIC)
            out.write(nonce)
            while True:
                chunk = source.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                out.write(encryptor.update(chunk))
            out.write(encryptor.finalize())
            out.write(encryptor.tag)
            out.flush()
            os.fsync(out.fileno())
    except Exception:
        safe_unlink(destination)
        raise
    return total


def decrypt_stream(source_path: Path, destination: Path, key: bytes, aad: bytes) -> None:
    """Decrypt to a temporary file and verify the GCM tag before returning.

    The destination may briefly contain unauthenticated partial plaintext while
    processing, but it is removed on any exception and must never be served unless
    this function returns successfully.
    """
    try:
        with source_path.open("rb") as source:
            source.seek(0, os.SEEK_END)
            total_size = source.tell()
            if total_size < len(MAGIC) + 12 + 16:
                raise ValueError("Encrypted file is incomplete.")
            source.seek(0)
            if source.read(len(MAGIC)) != MAGIC:
                raise ValueError("Encrypted file format is not recognized.")
            nonce = source.read(12)
            source.seek(-16, os.SEEK_END)
            tag = source.read(16)
            ciphertext_size = total_size - len(MAGIC) - 12 - 16
            source.seek(len(MAGIC) + 12)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
            decryptor.authenticate_additional_data(aad)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("wb") as out:
                remaining = ciphertext_size
                while remaining > 0:
                    chunk = source.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise ValueError("Encrypted file ended unexpectedly.")
                    remaining -= len(chunk)
                    out.write(decryptor.update(chunk))
                out.write(decryptor.finalize())
                out.flush()
                os.fsync(out.fileno())
    except Exception:
        safe_unlink(destination)
        raise


def wrap_file_key(vault_key: bytes, data_key: bytes, file_id: str) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(vault_key).encrypt(nonce, data_key, file_id.encode("ascii"))


def unwrap_file_key(vault_key: bytes, wrapped_key: bytes, file_id: str) -> bytes:
    if len(wrapped_key) < 12 + 16:
        raise ValueError("File key metadata is incomplete.")
    return AESGCM(vault_key).decrypt(wrapped_key[:12], wrapped_key[12:], file_id.encode("ascii"))
