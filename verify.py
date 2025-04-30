#!/usr/bin/env python3
"""
verify.py

Extracts and verifies the hidden RSA signature from a PNG image.
"""

import os
import sys
import struct
import random
import hashlib
import argparse
from typing import Tuple

from PIL import Image
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric \
    import padding as asym_padding, rsa
from cryptography.hazmat.primitives import serialization

# Configuration
PUBLIC_KEY_PATH = "keys/public.pem"
SIGNED_IMAGE_PATH = "images/signed.png"
INPUT_IMAGE_PATH = "images/thinking.png"
AES_KEY_SIZE = 32  # bytes (256-bit)


def load_public_key(path: str) -> rsa.RSAPublicKey:
    """
    Load an RSA public key from a PEM file.

    Args:
        path: Path to the PEM file containing the public key.

    Returns:
        An RSAPublicKey object.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If loading fails or wrong key type.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Public key not found: {path}")
    with open(path, 'rb') as key_file:
        data = key_file.read()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Loaded key is not an RSA public key")
    return key


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt ciphertext (IV || ciphertext) using AES-256-CBC with PKCS7 padding.

    Args:
        ciphertext: Bytes of IV concatenated with encrypted data.
        key: AES key (32 bytes).

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If key length is incorrect.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes")
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def extract_lsb(image: Image.Image, length: int, seed: int) -> bytes:
    """
    Extract a byte sequence of given length from the LSB of RGB channels.

    Args:
        image: PIL Image in RGB mode.
        length: Number of bytes to extract.
        seed: Random seed used for pixel ordering.

    Returns:
        Extracted bytes.
    """
    pixels = list(image.getdata())
    total_pixels = len(pixels)
    total_bits = length * 8

    random.seed(seed)
    indices = list(range(total_pixels))
    random.shuffle(indices)

    bits = []
    for i in range(total_bits):
        pixel = pixels[indices[i // 3]]
        bits.append(pixel[i % 3] & 1)

    data = bytearray()
    for i in range(0, total_bits, 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        data.append(byte)
    return bytes(data)


def verify_signature(aes_key: bytes, seed: int) -> Tuple[bool, str]:
    """
    Extract, decrypt, and verify the RSA signature embedded in the image.

    Args:
        aes_key: AES key bytes (32 bytes).
        seed: Seed for LSB extraction.

    Returns:
        Tuple[bool, str]: (True, success_message) or (False, error_message).
    """
    try:
        pub = load_public_key(PUBLIC_KEY_PATH)
    except Exception as e:
        return False, f"Error loading public key: {e}"

    # Determine encrypted payload length
    sig_len = pub.key_size // 8
    checksum_len = hashlib.sha256().digest_size
    payload_len = 4 + sig_len + checksum_len
    padded_len = ((payload_len + 15) // 16) * 16
    encrypted_len = 16 + padded_len

    if not os.path.exists(SIGNED_IMAGE_PATH):
        return False, f"Signed image not found: {SIGNED_IMAGE_PATH}"

    stego_img = Image.open(SIGNED_IMAGE_PATH).convert('RGB')
    try:
        encrypted = extract_lsb(stego_img, encrypted_len, seed)
    except Exception as e:
        return False, f"Failed to extract data: {e}"

    try:
        payload = aes_decrypt(encrypted, aes_key)
    except Exception as e:
        return False, f"AES decryption failed: {e}"

    total_len = struct.unpack('>I', payload[:4])[0]
    signature = payload[4:4 + total_len]
    checksum = payload[4 + total_len:4 + total_len + checksum_len]

    if hashlib.sha256(signature).digest() != checksum:
        return False, "Checksum mismatch: data corrupted."

    if not os.path.exists(INPUT_IMAGE_PATH):
        return False, f"Original image not found: {INPUT_IMAGE_PATH}"

    orig_img = Image.open(INPUT_IMAGE_PATH).convert('RGB')
    data = orig_img.tobytes()
    try:
        pub.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True, "Signature is valid."
    except Exception:
        return False, "Signature is invalid."


def main() -> None:
    """
    Command-line interface for verifying the hidden signature.
    """
    parser = argparse.ArgumentParser(
        description="Verify hidden RSA signature in a PNG image"
    )
    parser.add_argument(
        '--aes_key',
        required=True,
        help='AES-256 key as 64 hex characters'
    )
    parser.add_argument(
        '--seed',
        required=True,
        type=int,
        help='Seed for LSB extraction'
    )
    args = parser.parse_args()

    try:
        aes_key = bytes.fromhex(args.aes_key)
    except ValueError:
        print("Invalid AES key hex string")
        sys.exit(1)
    if len(aes_key) != AES_KEY_SIZE:
        print(f"AES key must be {AES_KEY_SIZE*2} hex characters")
        sys.exit(1)

    success, message = verify_signature(aes_key, args.seed)
    print(message)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
