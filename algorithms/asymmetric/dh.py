import streamlit as st
import base64

def simple_encrypt(plaintext: str, alice_private: int, bob_public: int) -> str:
    shared_key = alice_private + bob_public
    encrypted = [ord(char) + shared_key for char in plaintext]
    return base64.b64encode(bytes(encrypted)).decode()

def simple_decrypt(cipher_b64: str, bob_private: int, alice_public: int) -> str:
    shared_key = bob_private + alice_public
    try:
        cipher_bytes = base64.b64decode(cipher_b64)
        decrypted = ''.join([chr(byte - shared_key) for byte in cipher_bytes])
        return decrypted
    except Exception as e:
        return f"[Decryption Error] {e}"

def run():
    st.subheader("🔐 Simple Alice & Bob Key-Pair Cryptography Demo")

    col1, col2 = st.columns(2)
    with col1:
        alice_private = st.number_input("🔑 Alice's Private Key", min_value=1, value=5)
        bob_public = st.number_input("🧾 Bob's Public Key", min_value=1, value=7)
    with col2:
        bob_private = st.number_input("🔑 Bob's Private Key", min_value=1, value=3)
        alice_public = st.number_input("🧾 Alice's Public Key", min_value=1, value=9)

    mode = st.radio("Select Mode", ["Encrypt (Alice → Bob)", "Decrypt (Bob → Alice)"])

    message = st.text_area("Enter Message (Plaintext or Base64 Ciphertext)")

    if not message.strip():
        st.info("Enter a message to proceed.")
        return

    if mode == "Encrypt (Alice → Bob)":
        encrypted = simple_encrypt(message, alice_private, bob_public)
        st.success("🔐 Encrypted Message (Base64)")
        st.code(encrypted)
    else:
        decrypted = simple_decrypt(message.strip(), bob_private, alice_public)
        st.success("🔓 Decrypted Message")
        st.text_area("", decrypted, height=200)

if __name__ == "__main__":
    run()
