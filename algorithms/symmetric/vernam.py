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
    return ''.join([f"{int(plaintext_dec[i:i+3]) ^ int(key_dec[i:i+3]):03}"
                    for i in range(0, len(plaintext_dec), 3)])

def vernam_decrypt(ciphertext_dec: str, key_dec: str) -> str:
    return ''.join([f"{int(ciphertext_dec[i:i+3]) ^ int(key_dec[i:i+3]):03}"
                    for i in range(0, len(ciphertext_dec), 3)])

def run():
    st.subheader("🔑 Vernam Cipher")
    mode = st.radio("Mode", ["Encrypt", "Decrypt"])
    input_type = st.radio("Input Type", ["Manual Text", "File (.txt)"])

    input_text = ""
    if input_type == "Manual Text":
        input_text = st.text_area("Enter your message:")
    else:
        uploaded_file = st.file_uploader("Upload a .txt file", type=["txt"])
        if uploaded_file:
            input_text = uploaded_file.read().decode("utf-8")

    if input_text:
        plaintext_dec = text_to_decimal(input_text)
        key_input = st.text_input("Enter key (leave blank to auto-generate):")

        if key_input:
            key_dec = text_to_decimal(key_input)
        else:
            key_dec = generate_key(len(plaintext_dec) // 3)

        if len(key_dec) != len(plaintext_dec):
            st.error("Key length must match text length. Check your input.")
            return

        if st.button("Run Vernam Cipher"):
            if mode == "Encrypt":
                cipher_dec = vernam_encrypt(plaintext_dec, key_dec)
                st.text_area("Encrypted (Decimal Form)", cipher_dec, height=200)
                st.code(f"Key Used: {decimal_to_text(key_dec)}")
            else:
                decrypted_dec = vernam_decrypt(plaintext_dec, key_dec)
                decrypted_text = decimal_to_text(decrypted_dec)
                st.text_area("Decrypted Text", decrypted_text, height=200)
                st.code(f"Key Used: {decimal_to_text(key_dec)}")
