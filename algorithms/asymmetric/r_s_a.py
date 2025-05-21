import streamlit as st
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

from Crypto.PublicKey import RSA

def rsa_encrypt(plaintext: str, public_key_pem: str) -> str:
    try:
        public_key = RSA.import_key(public_key_pem)  # Convert string to key object
        cipher = PKCS1_OAEP.new(public_key)
        plaintext_bytes = plaintext.encode()

        max_chunk_size = public_key.size_in_bytes() - 42  # for OAEP padding

        chunks = [plaintext_bytes[i:i + max_chunk_size] for i in range(0, len(plaintext_bytes), max_chunk_size)]
        encrypted_chunks = [cipher.encrypt(chunk) for chunk in chunks]

        encrypted_data = b''.join(encrypted_chunks)
        return base64.b64encode(encrypted_data).decode()
    except Exception as e:
        return f"Encryption error: {e}"


def rsa_decrypt(ciphertext_b64: str, private_key_str: str) -> str:
    try:
        private_key = RSA.import_key(private_key_str)
        cipher = PKCS1_OAEP.new(private_key)
        ciphertext = base64.b64decode(ciphertext_b64)
        decrypted = cipher.decrypt(ciphertext)
        return decrypted.decode('utf-8')
    except Exception as e:
        return f"Decryption error: {e}"

def run():
    st.subheader("🔐 RSA Encryption/Decryption")

    text_input = st.text_area("Enter Plaintext or Ciphertext (Base64)", help="This accepts alphanumeric and symbols.")
    file = st.file_uploader("Or upload a .txt file", type=["txt"])
    if file:
        text_input = file.read().decode("utf-8")

    st.markdown("---")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("##### 🔑 Key (Paste or Generate)")
        key_input = st.text_area("Paste your RSA key here")
        if key_input:
            try:
                public_key = RSA.import_key(key_input)
                encrypted_text = rsa_encrypt(text_input, public_key)
            except Exception as e:
                st.error(f"Key import error: {e}")
                
        if st.button("Generate New Key Pair"):
            private_key, public_key = generate_rsa_keys()
            st.session_state['rsa_private'] = private_key.decode()
            st.session_state['rsa_public'] = public_key.decode()
            st.success("🔑 New key pair generated")

    with col2:
        if 'rsa_private' in st.session_state and 'rsa_public' in st.session_state:
            st.text_area("🔐 Public Key (for Encryption)", st.session_state['rsa_public'], height=150)
            st.text_area("🔓 Private Key (for Decryption)", st.session_state['rsa_private'], height=150)

    operation = st.radio("Operation", ["Encrypt", "Decrypt"])
    if text_input and key_input:
        if operation == "Encrypt":
            result = rsa_encrypt(text_input, key_input)
            st.success("🔐 Encrypted Output (Base64)")
            st.code(result, language="text")
        elif operation == "Decrypt":
            result = rsa_decrypt(text_input, key_input)
            st.success("🔓 Decrypted Output")
            st.text_area("Decrypted Text", result, height=200)

