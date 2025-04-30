# RSA Stego Project

This project provides two Python scripts to embed and verify digital signatures in PNG images:

- **sign.py**: Signs a PNG image with RSA, encrypts the signature using AES-256-CBC, and hides it via LSB steganography.  

- **verify.py**: Extracts the hidden payload, decrypts with AES-256-CBC, and verifies the RSA signature.

---

## Requirements

Install dependencies via pip:

```bash
pip install -r requirements.txt

1. Generate RSA Keys

openssl genrsa -des3 -out keys/private.pem 4096

openssl rsa -in keys/private.pem -outform PEM -pubout -out keys/public.pem

2. Usage

* Signing
Edit sign.py constants or supply arguments:
--aes_key (64 hex characters)
--seed (integer)
--pk_password (if your private key PEM is encrypted)

(hint --pk_password "pass")

* Run
python sign.py --aes_key <hex> --seed 42 --pk_password mypass

Result
The signed image will be saved to images/signed.png.


* Verifying

Edit verify.py paths if needed:
PUBLIC_KEY_PATH
SIGNED_IMAGE_PATH
ORIGINAL_IMAGE_PATH

Run
python verify.py --aes_key <hex> --seed 42
Result
Prints the verification message and exits with code 0 (valid) or 1 (invalid).

