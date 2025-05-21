import streamlit as st
import random
import base64
import string

# Large prime and generator for DH (using small example primes for demo, replace with secure ones)
P = 0xE95E4A5F737059DC60DF5991D45029409E60FC09  # example 160-bit prime (not cryptographically secure here)
G = 2

def generate_private_key():
    return random.randint(2, P - 2)

def generate_public_key(private_key):
    return pow(G, private_key, P)

def generate_shared_secret(their_pub, own_priv):
    return pow(their_pub, own_priv, P)

def xor_cipher(data: bytes, key_bytes: bytes) -> bytes:
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])

def run():
    st.subheader("🔐 Diffie-Hellman Key Exchange + Symmetric Encryption (XOR)")

    col1, col2 = st.columns(2)

    with col1:
        # Simulate two users' private and public keys
        priv_a = generate_private_key()
        pub_a = generate_public_key(priv_a)
        priv_b = generate_private_key()
        pub_b = generate_public_key(priv_b)

        st.markdown("**User A's Keys:**")
        st.text_area("Private Key A", str(priv_a), height=40, disabled=True)
        st.text_area("Public Key A", str(pub_a), height=40, disabled=True)

        st.markdown("**User B's Keys:**")
        st.text_area("Private Key B", str(priv_b), height=40, disabled=True)
        st.text_area("Public Key B", str(pub_b), height=40, disabled=True)

        st.markdown("---")

        # User chooses which key to use as own private/public for encryption/decryption simulation
        use_user = st.selectbox("Use keys of:", ["User A", "User B"])

    with col2:
        file = st.file_uploader("Upload a .txt file (optional)", type=["txt"])
        text_input = st.text_area("Enter Plaintext or Ciphertext", help="Supports alphanumeric and symbols")
        if file:
            text_input = file.read().decode("utf-8")

        operation = st.radio("Operation", ["Encrypt", "Decrypt"])

    # Determine private/public keys based on user choice
    if use_user == "User A":
        own_priv = priv_a
        their_pub = pub_b
    else:
        own_priv = priv_b
        their_pub = pub_a

    shared_secret = generate_shared_secret(their_pub, own_priv)
    # Convert shared secret to bytes (fixed length)
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")
    if len(shared_secret_bytes) == 0:
        shared_secret_bytes = b'\x00'

    if text_input.strip():
        try:
            if operation == "Encrypt":
                plaintext_bytes = text_input.encode("utf-8")
                cipher_bytes = xor_cipher(plaintext_bytes, shared_secret_bytes)
                cipher_b64 = base64.b64encode(cipher_bytes).decode()
                st.success("🔐 Encrypted Text (Base64)")
                st.text_area("", cipher_b64, height=200)
            else:
                try:
                    cipher_bytes = base64.b64decode(text_input)
                except Exception:
                    st.error("Input ciphertext must be Base64 encoded.")
                    return

                plain_bytes = xor_cipher(cipher_bytes, shared_secret_bytes)
                try:
                    plain_text = plain_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    plain_text = plain_bytes.hex()
                    st.warning("Decrypted text contains non-UTF8 bytes; showing hex.")

                st.success("🔓 Decrypted Text")
                st.text_area("", plain_text, height=200)

            # Show shared secret for info/debug (base64)
            st.info(f"Shared Secret (Base64): {base64.b64encode(shared_secret_bytes).decode()}")

        except Exception as e:
            st.error(f"Error: {e}")
