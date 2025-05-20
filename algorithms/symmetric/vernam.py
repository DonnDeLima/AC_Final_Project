import streamlit as st
import random

def text_to_decimal(text: str) -> str:
    return ''.join([f"{ord(c):03}" for c in text])

def decimal_to_text(decimal_str: str) -> str:
    chars = [chr(int(decimal_str[i:i+3])) for i in range(0, len(decimal_str), 3)]
    return ''.join(chars)

def generate_key(length: int) -> str:
    return ''.join([f"{random.randint(0, 9):03}" for _ in range(length)])

def vernam_encrypt(plaintext_dec: str, key_dec: str) -> str:
    if len(plaintext_dec) != len(key_dec):
        raise ValueError("Key length must match")
    return ''.join([f"{int(plaintext_dec[i:i+3]) ^ int(key_dec[i:i+3]):03}"
                    for i in range(0, len(plaintext_dec), 3)])

def vernam_decrypt(ciphertext_dec: str, key_dec: str) -> str:
    if len(ciphertext_dec) != len(key_dec):
        raise ValueError("Key length must match")
    return ''.join([f"{int(ciphertext_dec[i:i+3]) ^ int(key_dec[i:i+3]):03}"
                    for i in range(0, len(ciphertext_dec), 3)])
