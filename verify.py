"""
verify.py

Verifies an RSA-PSS signature embedded into PNG metadata.
"""

import os
import sys
import base64
import argparse

from PIL import Image
from cryptography.hazmat.primitives import (hashes,
                                            serialization)
from cryptography.hazmat.primitives.asymmetric import \
    padding as asym_padding, rsa

# Configuration
PUBLIC_KEY_PATH = "keys/public.pem"
SIGNED_IMAGE_PATH = "images/signed.png"


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
    with open(path, "rb") as key_file:
        key_data = key_file.read()
    key = serialization.load_pem_public_key(key_data)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Loaded key is not an RSA public key")
    return key


def verify_image(signed_path: str, public_key_path: str) -> bool:
    """
    Verify the RSA signature stored in the PNGs metadata.

    Args:
        signed_path: Path to the signed PNG image.
        public_key_path: Path to the RSA public key PEM.

    Returns:
        True if signature is valid, False otherwise.
    """
    if not os.path.exists(signed_path):
        print(f"Signed image not found: {signed_path}")
        return False

    # Load image and extract signature
    img = Image.open(signed_path)
    info = img.info
    if "signature" not in info:
        print("No signature metadata found.")
        return False

    sig_b64 = info["signature"]
    try:
        signature = base64.b64decode(sig_b64)
    except Exception:
        print("Signature metadata is not valid base64.")
        return False

    public_key = load_public_key(public_key_path)
    pixel_data = img.tobytes()
    try:
        public_key.verify(
            signature,
            pixel_data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid.")
        return True
    except Exception:
        print("Signature is invalid.")
        return False


def main() -> None:
    """
    Command-line interface: parse arguments and run verification.
    """
    parser = argparse.ArgumentParser(
        description="Verify RSA signature embedded in PNG metadata"
    )
    parser.add_argument(
        "--signed",
        default=SIGNED_IMAGE_PATH,
        help="Path to the signed PNG image"
    )
    parser.add_argument(
        "--pub_key",
        default=PUBLIC_KEY_PATH,
        help="Path to the RSA public key PEM"
    )
    args = parser.parse_args()

    valid = verify_image(args.signed, args.pub_key)
    sys.exit(0 if valid else 1)


if __name__ == "__main__":
    main()
