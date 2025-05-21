import streamlit as st
import random
import base64

def is_base64(s):
    try:
        return base64.b64encode(base64.b64decode(s)).decode() == s
    except Exception:
        return False

def run():
    st.subheader("🔐 Vernam Cipher")

    col1, col2 = st.columns(2)
    with col1:
        text_input = st.text_area("Enter Plaintext or Ciphertext", help="Enter the message for encryption or decryption")
    with col2:
        key_input = st.text_area("Enter Key (Base64 for decryption or plain for encryption)", help="Leave blank to auto-generate during encryption")

    file = st.file_uploader("Or upload a .txt file", type=["txt"])
    if file:
        text_input = file.read().decode("utf-8")

    operation = st.radio("Operation", ["Encrypt", "Decrypt"])

    if not text_input.strip():
        st.info("Input text is required.")
        return

    try:
        if operation == "Encrypt":
            plaintext_bytes = text_input.encode('utf-8')

            if not key_input.strip():
                key_bytes = bytes(random.randint(0, 255) for _ in range(len(plaintext_bytes)))
            else:
                key_bytes_raw = key_input.encode('utf-8')
                if len(key_bytes_raw) != len(plaintext_bytes):
                    st.error("Key length must match plaintext length (in bytes).")
                    return
                key_bytes = key_bytes_raw

            if len(key_bytes) != len(plaintext_bytes):
                st.error("Key length must match the plaintext length in bytes.")
                return

            cipher_bytes = bytes([b ^ k for b, k in zip(plaintext_bytes, key_bytes)])
            cipher_text_b64 = base64.b64encode(cipher_bytes).decode()
            key_display = base64.b64encode(key_bytes).decode()

            st.success("🔐 Encrypted Text (Base64)")
            st.code(cipher_text_b64)
            st.text_area("🔑 Key Used (Base64)", key_display, height=100)

        else:  # Decrypt
            if not key_input.strip():
                st.error("Key is required for decryption.")
                return

            try:
                cipher_bytes = base64.b64decode(text_input)
            except Exception:
                st.error("Ciphertext must be base64 encoded.")
                return

            # Encode key if it's not base64 yet
            if is_base64(key_input):
                key_bytes = base64.b64decode(key_input)
            else:
                key_bytes = base64.b64encode(key_input.encode('utf-8'))
                key_bytes = base64.b64decode(key_bytes)

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
            st.text_area("Decrypted Output", plain_text, height=200)

    except Exception as e:
        st.error(f"Error: {e}")
