#!/usr/bin/env python3
# verify_signature_complex.py

import os
import sys
import struct
import random
import hashlib
import argparse
from PIL import Image
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.primitives import serialization

# ========== КОНФІГУРАЦІЯ ШЛЯХІВ ==========
PUBLIC_KEY_PATH   = "keys/public.pem"
SIGNED_IMAGE_PATH = "images/signed.png"
INPUT_IMAGE_PATH  = "images/thinking.png"  # оригінальне зображення для перевірки
# ======================================
AES_KEY_SIZE = 32  # 256-bit key (32 bytes)


def load_public_key(path: str) -> rsa.RSAPublicKey:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Файл {path} не знайдено.")
    with open(path, "rb") as f:
        data = f.read()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Завантажений ключ не є RSA публічним ключем.")
    return key


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES-ключ має бути {AES_KEY_SIZE} байт.")
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def extract_bits_from_image(img: Image.Image, length_bytes: int, seed: int) -> bytes:
    w, h = img.size
    total_pixels = w * h
    total_bits = length_bytes * 8
    pixels = list(img.getdata())
    random.seed(seed)
    idxs = list(range(total_pixels))
    random.shuffle(idxs)
    bits = []
    for bit_idx in range(total_bits):
        pixel_idx = idxs[bit_idx // 3]
        ch = bit_idx % 3
        bits.append(pixels[pixel_idx][ch] & 1)

    data = bytearray()
    for i in range(0, total_bits, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        data.append(byte)
    return bytes(data)


def verify_signature(aes_key: bytes, seed: int) -> None:
    # 1) Завантажити RSA публічний ключ
    try:
        pub = load_public_key(PUBLIC_KEY_PATH)
    except Exception as e:
        print(f"❌ Помилка завантаження публічного ключа: {e}")
        sys.exit(1)

    # 2) Обчислити довжину шифрованого блоку
    sig_len = pub.key_size // 8
    payload_len = 4 + sig_len + 32  # 4 байти довжини, підпис, SHA256 checksum
    padded_len = ((payload_len + 15) // 16) * 16  # PKCS7
    encrypted_len = 16 + padded_len  # IV + ciphertext

    # 3) Відкрити зображення та витягти зашифрований payload
    if not os.path.exists(SIGNED_IMAGE_PATH):
        print(f"❌ Файл {SIGNED_IMAGE_PATH} не знайдено.")
        sys.exit(1)
    img = Image.open(SIGNED_IMAGE_PATH).convert("RGB")
    try:
        encrypted = extract_bits_from_image(img, encrypted_len, seed)
    except Exception as e:
        print(f"❌ Не вдалося витягти дані зі зображення: {e}")
        sys.exit(1)

    # 4) Дешифрувати AES
    try:
        payload = aes_decrypt(encrypted, aes_key)
    except Exception as e:
        print(f"❌ AES-розшифрування не вдалося: {e}")
        sys.exit(1)

    # 5) Розпакувати payload
    total_len = struct.unpack(">I", payload[:4])[0]
    sig = payload[4:4 + total_len]
    checksum = payload[4 + total_len:4 + total_len + 32]

    # 6) Перевірка контрольної суми
    if hashlib.sha256(sig).digest() != checksum:
        print("❌ Невірна контрольна сума. Дані пошкоджено.")
        sys.exit(1)

    # 7) Перевірка RSA підпису на оригінальних байтах
    if not os.path.exists(INPUT_IMAGE_PATH):
        print(f"❌ Оригінальний файл {INPUT_IMAGE_PATH} не знайдено.")
        sys.exit(1)
    orig = Image.open(INPUT_IMAGE_PATH).convert("RGB")
    data = orig.tobytes()
    try:
        pub.verify(
            sig,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("✅ Підпис дійсний.")
    except Exception:
        print("❌ Невірний підпис.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Verify hidden RSA signature in PNG via AES+LSB stego")
    parser.add_argument("--aes_key", required=True,
                        help="AES-256 ключ у hex (64 символи)")
    parser.add_argument("--seed", type=int, required=True,
                        help="seed для витягування бітів")
    args = parser.parse_args()

    # Конвертація ключа
    try:
        aes_key = bytes.fromhex(args.aes_key)
    except ValueError:
        print("❌ Некоректний hex AES-ключ.")
        sys.exit(1)
    if len(aes_key) != AES_KEY_SIZE:
        print(f"❌ AES-ключ має бути {AES_KEY_SIZE*2} hex-символів.")
        sys.exit(1)

    # Виконати верифікацію
    verify_signature(aes_key, args.seed)

if __name__ == "__main__":
    main()
