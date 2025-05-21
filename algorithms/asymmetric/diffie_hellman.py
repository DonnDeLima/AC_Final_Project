import streamlit as st
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Diffie-Hellman parameters (safe prime and generator)
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
    "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E"
    "7EC6F44C42E9A63A36210000000000090563", 16
)
G = 2

def diffie_hellman_generate_private_key():
    return int.from_bytes(get_random_bytes(32), 'big')

def diffie_hellman_generate_public_key(private_key):
    return pow(G, private_key, P)

def diffie_hellman_generate_shared_key(their_public, my_private):
    return pow(their_public, my_private, P)

def derive_aes_key(shared_secret: int) -> bytes:
    key_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    return key_bytes[:16].ljust(16, b'\0')

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    return cipher.iv + ct_bytes

def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    iv = ciphertext[:AES.block_size]
    ct = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

def run():
    st.subheader("🔐 Diffie-Hellman Key Exchange with AES Encryption")

    text_input = st.text_area("Plaintext or Ciphertext (Base64 for ciphertext)")
    file = st.file_uploader("Or upload a .txt file", type=["txt"])

    col1, col2 = st.columns(2)
    with col1:
        your_private_key_input = st.text_area(
            "Input Your Private Key for Decryption (hex)",
            help="Private key should be a large random hex number."
        )
    with col2:
        their_public_key_input = st.text_area(
            "Input Their Public Key for Encryption (hex)",
            help="Public key from the other party."
        )

    st.markdown("---")
    st.markdown("### Key Generation (Simulation)")

    col1, col2 = st.columns(2)
    with col1:
        your_private_key_display = st.empty()
        your_public_key_display = st.empty()
    with col2:
        other_private_key_display = st.empty()
        other_public_key_display = st.empty()

    # Generate keys on button click
    if st.button("Generate New Key Pair"):
        private_key = diffie_hellman_generate_private_key()
        public_key = diffie_hellman_generate_public_key(private_key)
        other_private_key = diffie_hellman_generate_private_key()
        other_public_key = diffie_hellman_generate_public_key(other_private_key)

        st.session_state['your_private_key'] = hex(private_key)[2:]
        st.session_state['your_public_key'] = hex(public_key)[2:]
        st.session_state['other_private_key'] = hex(other_private_key)[2:]
        st.session_state['other_public_key'] = hex(other_public_key)[2:]

    # Load keys from session state or from inputs
    your_private_key_input = your_private_key_input.strip() or st.session_state.get('your_private_key', '')
    their_public_key_input = their_public_key_input.strip() or st.session_state.get('other_public_key', '')
    other_private_key = int(st.session_state.get('other_private_key', '0'), 16) if 'other_private_key' in st.session_state else None

    try:
        private_key = int(your_private_key_input, 16) if your_private_key_input else None
    except ValueError:
        st.error("Invalid your private key format. Must be hex.")
        return

    your_public_key = diffie_hellman_generate_public_key(private_key) if private_key else None

    if your_public_key:
        your_public_key_display.text_area("Your Public Key", hex(your_public_key)[2:], height=100)
    if your_private_key_input:
        your_private_key_display.text_area("Your Private Key", your_private_key_input, height=100)

    if 'other_public_key' in st.session_state:
        other_public_key_display.text_area("Other Party's Public Key", st.session_state['other_public_key'], height=100)
    if 'other_private_key' in st.session_state:
        other_private_key_display.text_area("Other Party's Private Key (hidden)", st.session_state['other_private_key'], height=100)

    if not your_private_key_input or not their_public_key_input:
        st.warning("Please enter/generate your private key and their public key to proceed.")
        return

    try:
        their_public_key = int(their_public_key_input, 16)
    except ValueError:
        st.error("Invalid their public key format. Must be hex.")
        return

    # Load text from file if uploaded
    if file is not None:
        text_input = file.read().decode("utf-8")

    if not text_input.strip():
        st.info("Enter text or upload a file to encrypt/decrypt.")
        return

    operation = st.radio("Operation", ["Encrypt", "Decrypt"])

    if st.button("Run Cipher"):
        try:
            # Generate shared secret and derive AES key
            shared_secret = diffie_hellman_generate_shared_key(their_public_key, private_key)
            aes_key = derive_aes_key(shared_secret)

            if operation == "Encrypt":
                plaintext_bytes = text_input.encode('utf-8')
                ciphertext = aes_encrypt(plaintext_bytes, aes_key)
                cipher_b64 = base64.b64encode(ciphertext).decode()
                st.success("🔐 Encrypted Text (Base64)")
                st.text_area("", cipher_b64, height=200)
            else:  # Decrypt
                try:
                    ciphertext_b64_clean = "".join(text_input.strip().split())
                    ciphertext_bytes = base64.b64decode(ciphertext_b64_clean)
                    plaintext_bytes = aes_decrypt(ciphertext_bytes, aes_key)
                    plaintext = plaintext_bytes.decode('utf-8')
                    st.success("🔓 Decrypted Text")
                    st.text_area("", plaintext, height=200)
                except (ValueError, base64.binascii.Error) as e:
                    st.error(f"Invalid ciphertext or padding error: {e}")
        except Exception as e:
            st.error(f"Error during {operation.lower()}: {e}")

if __name__ == "__main__":
    run()
