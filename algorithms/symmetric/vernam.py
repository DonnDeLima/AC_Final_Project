import streamlit as st
import random

# ---------- Vernam Cipher Functions ----------
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

# ---------- Streamlit UI ----------
def run():
    st.subheader("🔐 Vernam Cipher")

    col1, col2 = st.columns(2)

    with col1:
        input_method = st.radio("Input Method", ["Manual Input", "Upload File"])
        if input_method == "Manual Input":
            plaintext = st.text_area("Enter Plaintext", key="pt_input")
        else:
            uploaded_file = st.file_uploader("Upload .txt file", type=["txt"])
            plaintext = uploaded_file.read().decode("utf-8") if uploaded_file else ""

    with col2:
        key = st.text_input("Enter Key (same length as plaintext)")

    # Encrypt button
    if st.button("Encrypt"):
        if not plaintext:
            st.error("Plaintext is empty.")
        elif not key:
            st.error("Key is empty.")
        else:
            try:
                pt_dec = text_to_decimal(plaintext)
                key_dec = text_to_decimal(key)
                ciphertext_dec = vernam_encrypt(pt_dec, key_dec)
                st.success("Encryption successful!")
                st.text_area("Ciphertext (decimal)", ciphertext_dec, height=200)
            except ValueError as e:
                st.tooltip(str(e))

    # Decrypt button
    if st.button("Decrypt"):
        if not plaintext:
            st.error("Ciphertext is empty.")
        elif not key:
            st.error("Key is empty.")
        else:
            try:
                ct_dec = plaintext
                key_dec = text_to_decimal(key)
                decrypted_dec = vernam_decrypt(ct_dec, key_dec)
                decrypted_text = decimal_to_text(decrypted_dec)
                st.success("Decryption successful!")
                st.text_area("Decrypted Text", decrypted_text, height=200)
            except ValueError as e:
                st.tooltip(str(e))
