# RSA Stego Project

This project provides two Python scripts to sign and verify digital signatures in PNG images.

---

## Requirements

Install dependencies via pip:

```bash
pip install -r requirements.txt
```

1. Generate RSA Keys
```bash
openssl genrsa -des3 -out keys/private.pem 4096

openssl rsa -in keys/private.pem -outform PEM -pubout -out keys/public.pem
```

2. Usage

* Signing
Edit sign.py constants or supply arguments:

--pk_password (if your private key PEM is encrypted)

(hint --pk_password "pass")

* Run
```bash
python sign.py --pk_password mypass
```

Result
The signed image will be saved to images/signed.png.


* Verifying

Edit verify.py paths if needed:
PUBLIC_KEY_PATH
SIGNED_IMAGE_PATH
ORIGINAL_IMAGE_PATH

Run
```bash
python verify.py
```
Result
Prints the verification message and exits with code 0 (valid) or 1 (invalid).

1. **Parse Arguments**  
```bash
   python verify.py --signed <signed.png> --pub_key <public.pem>
```

--signed: Path to the signed PNG (default: "images/signed.png")

--pub_key: Path to the RSA public key PEM (default: "keys/public.pem")


* Checks the info dictionary for a text chunk named "signature". 
If missing prints **“No signature metadata found.”** and exits with failure.

* Uses PSS + SHA-256 to check authenticity.
   **On success** prints **“Signature is valid.”** and exits with code `0`
   
   **On failure** prints **“Signature is invalid.”** and exits with code `1`

---

## Example

1. **Sign an image** (with `sign.py`):

```bash
   python sign.py --pk_password mypass
```
2. **Verify the signed image**:

```bash
   python verify.py --signed images/signed.png --pub_key keys/public.pem
```

   * You’ll see **“Signature is valid.”** if nothing was changed after signing.


## Applications

- **Protect image integrity**  
  Make sure your image wasn’t changed by anyone else.  
- **Prove ownership**  
  Show that you’re the author of a photo or artwork.  
- **Invisible watermark**  
  Hide info inside the pixels without changing how the image looks.

---

## How It Works

1. **RSA Signature (PSS + SHA-256)**  
   - We read the raw pixel bytes of the PNG.  
   - We compute an RSA-PSS signature over those bytes using SHA-256.  
   - The signature guarantees authenticity and integrity.

2. **Base64 Encoding & Metadata Embedding**  
   - The binary signature is Base64-encoded to fit into PNG text chunks.  
   - We insert it under the key signature in the PNG’s tEXt metadata.

3. **Verification**  
   - Read the signature metadata, Base64-decode it.  
   - Recompute the pixel-byte digest and use the RSA public key to verify the PSS signature.  
   - No original file needed—verification works directly on the signed PNG.



