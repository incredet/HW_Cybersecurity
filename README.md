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

# RSA Stego Project

A simple tool to hide a digital signature inside a PNG image and check it later.

---

## Applications

- **Protect image integrity**  
  Make sure your image wasn’t changed by anyone else.  
- **Prove ownership**  
  Show that you’re the author of a photo or artwork.  
- **Invisible watermark**  
  Hide info inside the pixels without changing how the image looks.

---

## How it works

1. **Sign**  
   - Compute a SHA-256 hash of the image bytes.  
   - Sign that hash with your RSA private key (PSS + SHA-256).

2. **Encrypt**  
   - Put the signature (and its length + checksum) into a little data block.  
   - Encrypt that block with AES-256-CBC (with random IV).

3. **Hide**  
   - Turn the encrypted data into bits.  
   - Shuffle pixel order using a seed.  
   - Write each bit into the least significant bit of R, G, or B channels.

4. **Verify**  
   - Extract the bits (using the same seed).  
   - Decrypt with your AES key.  
   - Check the checksum and verify the RSA signature against the original image.


