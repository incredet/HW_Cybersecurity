import os
import struct
import random
import hashlib
from PIL import Image
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Конфігурація
AES_KEY_SIZE = 32  # 256-bit
# Глобальні змінні: задайте тут свій AES-ключ (hex, 64 символи) та seed
AES_KEY_HEX = os.urandom(AES_KEY_SIZE).hex()  # Згенерувати випадковий ключ
SEED = 42

PRIVATE_KEY_PATH = "keys/private.pem"
INPUT_IMAGE_PATH = "images/thinking.png"
OUTPUT_SIGNED_IMAGE_PATH = "images/signed.png"



def load_private_key(path: str, key_password) -> rsa.RSAPrivateKey:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Файл {path} не знайдено.")
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=key_password)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("Завантажений ключ не є RSA приватним ключем.")
    return key


def rsa_sign(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES-ключ має бути {AES_KEY_SIZE} байт.")
    # PKCS7 padding
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext  # IV||ciphertext


def embed_bits_in_image(img: Image.Image, bitstream: bytes, seed: int) -> Image.Image:
    w, h = img.size
    total_pixels = w * h
    bits = [(b >> i) & 1 for b in bitstream for i in range(7, -1, -1)]
    if len(bits) > total_pixels * 3:
        raise ValueError("Замало пікселів для вбудовування всіх бітів.")

    pixels = list(img.getdata())
    random.seed(seed)
    idxs = list(range(total_pixels))
    random.shuffle(idxs)

    new_pixels = pixels.copy()
    for bit_idx, bit in enumerate(bits):
        pixel_idx = idxs[bit_idx // 3]
        channel = bit_idx % 3  # 0=R,1=G,2=B
        px = list(new_pixels[pixel_idx])
        px[channel] = (px[channel] & ~1) | bit
        new_pixels[pixel_idx] = tuple(px)

    stego = Image.new(img.mode, img.size)
    stego.putdata(new_pixels)
    return stego


def sign_and_hide_complex(image_path: str,
                          private_key_path: str,
                          output_path: str,
                          aes_key: bytes,
                          seed: int, 
                          key_password: str) -> None:
    # 1. RSA-підпис
    priv = load_private_key(private_key_path, key_password)
    img = Image.open(image_path).convert("RGB")
    data = img.tobytes()
    sig = rsa_sign(data, priv)

    # 2. Контрольна сума
    checksum = hashlib.sha256(sig).digest()

    # 3. payload = [len(sig) BE4] || sig || checksum
    payload = struct.pack(">I", len(sig)) + sig + checksum

    # 4. AES-шифрування
    encrypted = aes_encrypt(payload, aes_key)

    # 5. Вбудовуємо біти
    stego = embed_bits_in_image(img, encrypted, seed)

    # 6. Зберігаємо
    stego.save(output_path, "PNG")
    print(f"Успіх: {output_path}")
    print(f"Для перевірки: seed={seed}, aes_key(hex)={aes_key.hex()}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Complex RSA+AES LSB stego")
    parser.add_argument("--pk_password", help="Пароль для зашифрованого приватного ключа")
    args = parser.parse_args()

    key_password = args.pk_password.encode() if args.pk_password else None


    # Конвертуємо глобальний hex у bytes
    try:
        aes_key = bytes.fromhex(AES_KEY_HEX)
    except ValueError:
        raise ValueError("Некоректний hex-рядок в AES_KEY_HEX.")
    if len(aes_key) != AES_KEY_SIZE:
        raise ValueError(f"AES_KEY_HEX має бути {AES_KEY_SIZE*2} hex-символів.")

    sign_and_hide_complex(
        image_path=INPUT_IMAGE_PATH,
        private_key_path=PRIVATE_KEY_PATH,
        output_path=OUTPUT_SIGNED_IMAGE_PATH,
        aes_key=aes_key,
        seed=SEED,
        key_password = key_password
    )

if __name__ == "__main__":
    main()
