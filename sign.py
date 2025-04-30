"""
sign.py

"""

import os
import sys
import struct
import random
import hashlib
import argparse
from typing import Optional

from PIL import Image
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric \
    import padding as asym_padding, rsa
from cryptography.hazmat.primitives import serialization

# Configuration
AES_KEY_SIZE = 32  # bytes (256-bit)
AES_KEY_HEX = os.urandom(AES_KEY_SIZE).hex()  # Default; override via --aes_key
SEED = 42  # Default LSB embedding seed; override via --seed

PRIVATE_KEY_PATH = "keys/private.pem"
INPUT_IMAGE_PATH = "images/thinking.png"
OUTPUT_SIGNED_IMAGE_PATH = "images/signed.png"


def load_private_key(
        path: str,
        password: Optional[bytes] = None
        ) -> rsa.RSAPrivateKey:
    """
    Load an RSA private key from a PEM file.

    Args:
        path: Path to the PEM file.
        password: Password.

    Returns:
        An RSAPrivateKey object.

    Raises:
        FileNotFoundError: If the key file does not exist.
        ValueError: If the key cannot be loaded.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Private key not found: {path}")
    with open(path, "rb") as key_file:
        key_data = key_file.read()
    try:
        key = serialization.load_pem_private_key(key_data, password=password)
    except Exception as err:
        raise ValueError("Failed to load private key") from err
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("Loaded key is not an RSA private key")
    return key


def rsa_sign(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Sign data.

    Args:
        data: Byte string to sign.
        private_key: RSAPrivateKey.

    Returns:
        The signature bytes.
    """
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext.

    Args:
        plaintext: Data to encrypt.
        key: AES key.

    Returns:
        IV concatenated with ciphertext.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes.")
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext


def embed_lsb(
        image: Image.Image,
        payload: bytes,
        seed: int = SEED
        ) -> Image.Image:
    """
    Embed payload bytes.

    Args:
        image: A PIL Image in RGB mode.
        payload: Bytes to embed.
        seed: Random seed for pixel ordering.

    Returns:
        A new PIL Image with embedded data.
    """
    pixels = list(image.getdata())
    bits = [(byte >> bit) & 1 for byte in payload for bit in range(7, -1, -1)]
    capacity = len(pixels) * 3
    if len(bits) > capacity:
        raise ValueError("Payload too large for image capacity")

    random.seed(seed)
    indices = list(range(len(pixels)))
    random.shuffle(indices)

    new_pixels = pixels.copy()
    for i, bit in enumerate(bits):
        pix_idx = indices[i // 3]
        channel = i % 3  # 0=R, 1=G, 2=B
        rgb = list(new_pixels[pix_idx])
        rgb[channel] = (rgb[channel] & ~1) | bit
        new_pixels[pix_idx] = tuple(rgb)

    stego = Image.new(image.mode, image.size)
    stego.putdata(new_pixels)
    return stego


def sign_and_hide_complex(
    image_path: str,
    private_key_path: str,
    output_path: str,
    aes_key: bytes,
    seed: int = SEED,
    key_password: Optional[bytes] = None,
) -> None:
    """
    Sign the image, encrypt the signature, and hide it in the image.

    Args:
        image_path: Path to the input PNG.
        private_key_path: Path to the private key PEM file.
        output_path: Path to save the signed image.
        aes_key: AES key.
        seed: Seed for LSB embedding.
        key_password: Password for the private key.
    """
    private_key = load_private_key(private_key_path, password=key_password)
    img = Image.open(image_path).convert("RGB")
    data = img.tobytes()

    signature = rsa_sign(data, private_key)
    checksum = hashlib.sha256(signature).digest()
    payload = struct.pack(">I", len(signature)) + signature + checksum

    encrypted_payload = aes_encrypt(payload, aes_key)
    stego_img = embed_lsb(img, encrypted_payload, seed)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    stego_img.save(output_path)


def main() -> None:
    """
    Command-line interface: parse arguments and run.
    """
    parser = argparse.ArgumentParser(
        description="Sign a PNG with RSA/AES-LSB steganography"
    )
    parser.add_argument(
        "--aes_key", default=AES_KEY_HEX, help="AES key as 64-hex characters"
    )
    parser.add_argument("--seed", type=int, default=SEED, help="Seed")
    parser.add_argument(
        "--pk_password",
        default=None,
        help="Passphrase for an encrypted private key PEM",
    )
    args = parser.parse_args()

    try:
        aes_key_bytes = bytes.fromhex(args.aes_key)
    except ValueError:
        print("Invalid AES key hex string")
        sys.exit(1)
    if len(aes_key_bytes) != AES_KEY_SIZE:
        print(f"AES key must be {AES_KEY_SIZE*2} hex characters")
        sys.exit(1)

    key_password = args.pk_password.encode() if args.pk_password else None

    sign_and_hide_complex(
        image_path=INPUT_IMAGE_PATH,
        private_key_path=PRIVATE_KEY_PATH,
        output_path=OUTPUT_SIGNED_IMAGE_PATH,
        aes_key=aes_key_bytes,
        seed=args.seed,
        key_password=key_password,
    )
    print(f"Signed image saved to {OUTPUT_SIGNED_IMAGE_PATH}")
    print(
            f"Use AES key (hex): {args.aes_key} " +
            "and seed: {args.seed} for verification"
        )


if __name__ == "__main__":
    main()
