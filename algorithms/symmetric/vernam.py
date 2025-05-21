import streamlit as st
import random

# ---- Vernam Cipher Core Functions ----
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

# ---- Streamlit Interface ----
def run():
    st.subheader("🔐 Vernam Cipher")

    col1, col2 = st.columns(2)
    with col1:
        text_input = st.text_area("Enter Plaintext or Ciphertext", help="Enter the message for encryption or decryption")
    with col2:
        key_input = st.text_area("Enter Key (optional)", help="Leave blank to auto-generate during encryption")

    file = st.file_uploader("Or upload a .txt file", type=["txt"])
    if file:
        text_input = file.read().decode("utf-8")

    operation = st.radio("Operation", ["Encrypt", "Decrypt"])
    run_button = st.button("Run Vernam Cipher")

    if run_button:
        if not text_input.strip():
            st.warning("Input text is required.")
            return

        try:
            text_dec = text_to_decimal(text_input)

            if operation == "Encrypt":
                if not key_input.strip():
                    key_dec = generate_key(len(text_input))
                    key_str = decimal_to_text(key_dec)
                else:
                    key_dec = text_to_decimal(key_input)
                    key_str = key_input

                if len(key_dec) != len(text_dec):
                    st.text_input("⚠️ Invalid key length", value="", help="Key must match the length of the input text.")
                    return

                cipher_dec = vernam_encrypt(text_dec, key_dec)
                cipher_text = decimal_to_text(cipher_dec)  # ASCII output
                st.success("🔐 Encrypted ASCII Text")
                st.code(cipher_text)
                st.text_area("🔑 Key Used", key_str, height=100)

            else:  # Decrypt
                if not key_input.strip():
                    st.text_input("⚠️ Key required for decryption", value="", help="You must provide the key used for encryption.")
                    return
                key_dec = text_to_decimal(key_input)
                if len(key_dec) != len(text_dec):
                    st.text_input("⚠️ Invalid key length", value="", help="Key must match the length of the ciphertext.")
                    return
                plain_dec = vernam_decrypt(text_dec, key_dec)
                plain_text = decimal_to_text(plain_dec)
                st.success("🔓 Decrypted Text")
                st.code(plain_text)

        except Exception as e:
            st.error(f"Error: {e}")
