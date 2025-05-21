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
    return int.from_bytes(get_random_bytes(32), 'big') % (P-2) + 1  # private key in [1, P-2]

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

    with st.expander("ℹ️ About Diffie-Hellman Key Exchange with AES"):
        st.markdown("""
        **🕰️ Brief History**  
        The **Diffie-Hellman Key Exchange** was introduced in 1976 by **Whitfield Diffie** and **Martin Hellman**. It was the first public key exchange method enabling two parties to establish a shared secret over an insecure channel.

        **🔐 Purpose**  
        - Securely establish a **shared secret** without directly transmitting it.
        - Often used to derive symmetric keys (e.g., for **AES encryption**) in secure communication.

        **🔄 How It Works**  
        1. Both parties agree on a large prime `P` and a generator `G`.
        2. Each party generates a **private key** and a corresponding **public key**:
           - `A_private`, `A_public = G^A_private mod P`
           - `B_private`, `B_public = G^B_private mod P`
        3. They exchange **public keys**.
        4. Each party computes the shared secret:
           - `shared = B_public^A_private mod P` (same as `A_public^B_private mod P`)

        **🔐 AES Integration**  
        - The shared secret is converted into a symmetric key.
        - This key is then used in **AES (Advanced Encryption Standard)** for encrypting/decrypting the actual message.

        **🧾 Pseudocode**  
        ```
        P, G = known safe prime and generator
        A_private = random()
        A_public = pow(G, A_private, P)

        B_private = random()
        B_public = pow(G, B_private, P)

        # After exchange:
        shared_key = pow(B_public, A_private, P)
        aes_key = derive_from(shared_key)
        encrypted = AES.encrypt(message, aes_key)
        ```

        **📋 Use Cases**  
        - Secure messaging apps
        - TLS (used in HTTPS)
        - VPNs and other key agreement protocols

        **⚠️ Note**  
        Diffie-Hellman alone does not provide authentication. It's often combined with authentication mechanisms to prevent **Man-in-the-Middle** (MITM) attacks.
        """)



    # Input plaintext/ciphertext
    text_input = st.text_area("Plaintext or Ciphertext (Base64 for ciphertext)")
    file = st.file_uploader("Or upload a .txt file", type=["txt"])
    if file:
        text_input = file.read().decode("utf-8")

    # Columns for Alice and Bob keys
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Alice's Keys")
        if st.button("Generate Alice's Key Pair"):
            alice_private_key = diffie_hellman_generate_private_key()
            alice_public_key = diffie_hellman_generate_public_key(alice_private_key)
            st.session_state['alice_private'] = alice_private_key
            st.session_state['alice_public'] = alice_public_key
            st.toast("Alice's keys generated")

        alice_private_key = st.text_area("Alice's Private Key (hex)", 
                                         hex(st.session_state.get('alice_private', 0))[2:])
        alice_public_key = st.text_area("Alice's Public Key (hex)", 
                                        hex(st.session_state.get('alice_public', 0))[2:])

    with col2:
        st.markdown("### Bob's Keys")
        if st.button("Generate Bob's Key Pair"):
            bob_private_key = diffie_hellman_generate_private_key()
            bob_public_key = diffie_hellman_generate_public_key(bob_private_key)
            st.session_state['bob_private'] = bob_private_key
            st.session_state['bob_public'] = bob_public_key
            st.toast("Bob's keys generated")

        bob_private_key = st.text_area("Bob's Private Key (hex)", 
                                       hex(st.session_state.get('bob_private', 0))[2:])
        bob_public_key = st.text_area("Bob's Public Key (hex)", 
                                     hex(st.session_state.get('bob_public', 0))[2:])

    st.markdown("---")
    operation = st.radio("Operation", ["Encrypt", "Decrypt"])

    # Validate keys input
    try:
        if alice_private_key.strip():
            alice_private = int(alice_private_key.strip(), 16)
        else:
            alice_private = None
        if bob_public_key.strip():
            bob_public = int(bob_public_key.strip(), 16)
        else:
            bob_public = None

        if bob_private_key.strip():
            bob_private = int(bob_private_key.strip(), 16)
        else:
            bob_private = None
        if alice_public_key.strip():
            alice_public = int(alice_public_key.strip(), 16)
        else:
            alice_public = None
    except ValueError:
        st.error("Invalid hex key format.")
        return

    if not text_input.strip():
        st.info("Enter text or upload a file to encrypt/decrypt.")
        return

    if operation == "Encrypt":
        if alice_private is None or bob_public is None:
            st.warning("Alice's private key and Bob's public key are required for encryption.")
            return

        shared_secret = diffie_hellman_generate_shared_key(bob_public, alice_private)
        aes_key = derive_aes_key(shared_secret)

        ciphertext = aes_encrypt(text_input.encode('utf-8'), aes_key)
        cipher_b64 = base64.b64encode(ciphertext).decode()
        st.success("🔐 Encrypted Text (Base64)")
        st.text_area("", cipher_b64, height=200)

    else:  # Decrypt
        if bob_private is None or alice_public is None:
            st.warning("Bob's private key and Alice's public key are required for decryption.")
            return

        try:
            ciphertext_b64_clean = "".join(text_input.strip().split())
            ciphertext_bytes = base64.b64decode(ciphertext_b64_clean)
        except Exception as e:
            st.error(f"Invalid Base64 ciphertext: {e}")
            return

        shared_secret = diffie_hellman_generate_shared_key(alice_public, bob_private)
        aes_key = derive_aes_key(shared_secret)

        try:
            plaintext_bytes = aes_decrypt(ciphertext_bytes, aes_key)
            plaintext = plaintext_bytes.decode('utf-8')
            st.success("🔓 Decrypted Text")
            st.text_area("", plaintext, height=200)
        except Exception as e:
            st.error(f"Decryption failed: {e}")

if __name__ == "__main__":
    run()
