import streamlit as st
import random
import base64

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

def decimal_str_to_bytes(decimal_str: str) -> bytes:
    return bytes(int(decimal_str[i:i+3]) for i in range(0, len(decimal_str), 3))

def bytes_to_decimal_str(b: bytes) -> str:
    return ''.join([f"{byte:03}" for byte in b])

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
            if operation == "Encrypt":
                # Prepare plaintext bytes
                plaintext_bytes = text_input.encode('utf-8')

                if not key_input.strip():
                    # Auto-generate random key bytes
                    key_bytes = bytes(random.randint(0, 255) for _ in range(len(plaintext_bytes)))
                    key_display = base64.b64encode(key_bytes).decode()
                else:
                    # Treat user input as raw string key, encode to base64
                    key_bytes_raw = key_input.encode('utf-8')
                    if len(key_bytes_raw) != len(plaintext_bytes):
                        st.error("Key length must match plaintext length (in bytes).")
                        return
                    key_bytes = key_bytes_raw
                    key_display = base64.b64encode(key_bytes).decode()

                if len(key_bytes) != len(plaintext_bytes):
                    st.error("Key length must match the plaintext length in bytes.")
                    return

                # XOR encryption
                cipher_bytes = bytes([b ^ k for b, k in zip(plaintext_bytes, key_bytes)])

                # Output base64 encoded ciphertext
                cipher_text_b64 = base64.b64encode(cipher_bytes).decode()

                st.success("🔐 Encrypted Text (Base64)")
                st.code(cipher_text_b64)
                st.text_area("🔑 Key Used (Base64)", key_display, height=100)

            else:  # Decrypt
                if not key_input.strip():
                    st.error("Key is required for decryption.")
                    return
                if not text_input.strip():
                    st.error("Ciphertext is required for decryption.")
                    return

                try:
                    cipher_bytes = base64.b64decode(text_input)
                    key_bytes = base64.b64decode(key_input)
                except Exception:
                    st.error("Ciphertext and Key must be base64 encoded strings.")
                    return

                if len(cipher_bytes) != len(key_bytes):
                    st.error("Key length must match the ciphertext length.")
                    return

                plain_bytes = bytes([c ^ k for c, k in zip(cipher_bytes, key_bytes)])
                try:
                    plain_text = plain_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    plain_text = plain_bytes.hex()
                    st.warning("Plaintext contains non-UTF8 bytes; showing hex instead.")

                st.success("🔓 Decrypted Text")
                st.text_area("", plain_text, height=200)

        except Exception as e:
            st.error(f"Error: {e}")
