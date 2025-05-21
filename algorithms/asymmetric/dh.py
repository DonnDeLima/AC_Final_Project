import streamlit as st
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Diffie-Hellman Parameters (Safe Prime and Generator)
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B225"
    "14A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44"
    "C42E9A63A36210000000000090563", 16
)
G = 2

def generate_private_key():
    return int.from_bytes(get_random_bytes(32), 'big')

def generate_public_key(private_key):
    return pow(G, private_key, P)

def generate_shared_secret(public_key, private_key):
    return pow(public_key, private_key, P)

def derive_aes_key(shared_secret: int) -> bytes:
    key_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    return key_bytes[:16].ljust(16, b'\0')

def aes_encrypt(plaintext: str, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def aes_decrypt(ciphertext_b64: str, key: bytes) -> str:
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = ciphertext[:AES.block_size]
    ct = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

def run():
    st.subheader("🔐 Alice and Bob: Key Exchange & AES Encryption")

    # Generate key pairs
    alice_private = generate_private_key()
    bob_private = generate_private_key()
    alice_public = generate_public_key(alice_private)
    bob_public = generate_public_key(bob_private)

    # Exchange public keys and compute shared secret
    alice_shared = generate_shared_secret(bob_public, alice_private)
    bob_shared = generate_shared_secret(alice_public, bob_private)

    # Derive AES key from shared secret
    aes_key_alice = derive_aes_key(alice_shared)
    aes_key_bob = derive_aes_key(bob_shared)

    st.markdown("### 🔑 Key Exchange")
    st.code(f"Alice Private Key: {alice_private}")
    st.code(f"Bob Private Key: {bob_private}")
    st.code(f"Alice Public Key: {alice_public}")
    st.code(f"Bob Public Key: {bob_public}")

    st.markdown("### 🤝 Shared Secret (Should Match)")
    st.code(f"Alice Computes: {alice_shared}")
    st.code(f"Bob Computes:   {bob_shared}")

    st.markdown("### ✍️ Enter Message to Encrypt (Alice → Bob)")
    message = st.text_area("Plaintext")

    if message.strip():
        try:
            encrypted = aes_encrypt(message, aes_key_alice)
            decrypted = aes_decrypt(encrypted, aes_key_bob)

            st.success("🔐 Encrypted by Alice (Base64)")
            st.code(encrypted)

            st.success("🔓 Decrypted by Bob")
            st.code(decrypted)
        except Exception as e:
            st.error(f"Error: {e}")
    else:
        st.info("Enter a message to encrypt.")

if __name__ == "__main__":
    run()
