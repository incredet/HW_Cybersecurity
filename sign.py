"""
sign.py

"""

import os
import argparse
import base64
from typing import Optional

from PIL import Image, PngImagePlugin
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric \
    import padding as asym_padding, rsa
from cryptography.hazmat.primitives import serialization

# Configuration
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


def rsa_sign(
    inp: str,
    out: str,
    key_path: str,
    password: Optional[bytes] = None
) -> None:
    """
    Sign the PNG image and embed its signature into PNG metadata.

    Args:
        inp: Path to the input PNG.
        out: Path for the output signed PNG.
        key_path: Path to the RSA private key PEM.
        password: Optional passphrase for the private key.
    """
    img = Image.open(inp)
    pixel_data = img.tobytes()
    private_key = load_private_key(key_path, password)

    signature = private_key.sign(
        pixel_data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    sig_b64 = base64.b64encode(signature).decode('ascii')
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("signature", sig_b64)

    img.save(out, "PNG", pnginfo=metadata)
    print(f"Signed image saved to {out}")


def main() -> None:
    """
    Command-line interface: parse arguments and run.
    """
    parser = argparse.ArgumentParser(
        description="Sign a PNG with RSA/AES-LSB steganography"
    )
    parser.add_argument(
        "--pk_password",
        default=None,
        help="Passphrase for an encrypted private key PEM",
    )
    args = parser.parse_args()
    args = parser.parse_args()

    key_password = args.pk_password.encode() if args.pk_password else None

    rsa_sign(
        inp=INPUT_IMAGE_PATH,
        key_path=PRIVATE_KEY_PATH,
        out=OUTPUT_SIGNED_IMAGE_PATH,
        password=key_password
    )


if __name__ == "__main__":
    main()
