import streamlit as st
import random

# ---- Logic ---- #
def text_to_decimal(text: str) -> str:
    return ''.join([f"{ord(c):03}" for c in text])

def decimal_to_text(decimal_str: str) -> str:
    chars = [chr(int(decimal_str[i:i+3])) for i in range(0, len(decimal_str), 3)]
    return ''.join(chars)

def generate_key(length: int) -> str:
    return ''.join([f"{random.randint(0, 9):03}" for _ in range(length)])

def vernam_encrypt(plaintext_dec: str, key_dec: str) -> str:
    return ''.join([
        f"{int(plaintext_dec[i:i+3]) ^ int(key_dec[i:i+3]):03}"
        for i in range(0, len(plaintext_dec), 3)
    ])

def vernam_decrypt(ciphertext_dec: str, key_dec: str) -> str:
    return vernam_encrypt(ciphertext_dec, key_dec)  # XOR is symmetric

# ---- Streamlit UI ---- #
def run():
    st.subheader("🔑 Vernam Cipher")

    mode = st.radio("Mode", ["Encrypt", "Decrypt"])
    input_method = st.radio("Input Method", ["Manual text", "Upload .txt file"])

    text = ""
    if input_method == "Manual text":
        text = st.text_area("Enter your message:")
    else:
        uploaded_file = st.file_uploader("Upload a .txt file", type="txt")
        if uploaded_file:
            text = uploaded_file.read().decode("utf-8")

    key_input = st.text_input("Optional: Provide key (leave blank to auto-generate):")

    if st.button("Run Vernam Cipher"):
        if not text:
            st.warning("Please provide input text.")
            return

        dec_text = text_to_decimal(text)

        if mode == "Encrypt":
            # Pad or generate key
            if key_input:
                key_dec = text_to_decimal(key_input)
                if len(key_dec) < len(dec_text):
                    key_dec += generate_key((len(dec_text) - len(key_dec)) // 3)
                key_dec = key_dec[:len(dec_text)]
            else:
                key_dec = generate_key(len(dec_text) // 3)

            cipher_dec = vernam_encrypt(dec_text, key_dec)
            cipher_text = decimal_to_text(cipher_dec)

            st.code(f"Cipher Text: {cipher_text}")
            st.text_area("Generated Key (save this to decrypt):", decimal_to_text(key_dec), height=100)
            st.caption("You may copy and save this key text for decryption.")

        else:  # Decrypt
            if not key_input:
                st.error("Decryption requires the original key.")
                return

            key_dec = text_to_decimal(key_input)
            cipher_dec = text_to_decimal(text)

            if len(cipher_dec) != len(key_dec):
                st.error("Key length must match encrypted message.")
                return

            plain_dec = vernam_decrypt(cipher_dec, key_dec)
            plain_text = decimal_to_text(plain_dec)

            st.code(f"Decrypted Text: {plain_text}")
