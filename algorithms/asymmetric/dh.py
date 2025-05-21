import streamlit as st

# Diffie-Hellman parameters (small prime for demonstration, NOT secure)
P = 23  # small prime for simplicity
G = 5   # primitive root modulo P

def mod_exp(base, exp, mod):
    return pow(base, exp, mod)

def xor_encrypt_decrypt(message: str, key: int) -> str:
    # Simple XOR of message bytes with key repeated
    key_bytes = key.to_bytes((key.bit_length() + 7) // 8 or 1, 'big')
    msg_bytes = message.encode()
    result = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(msg_bytes)])
    return result.decode(errors='ignore')

st.title("Diffie-Hellman Key Exchange Demo")

# Alice generates private key
alice_private = st.number_input("Alice's Private Key (secret)", min_value=1, max_value=P-2, value=6)
alice_public = mod_exp(G, alice_private, P)
st.write(f"Alice's Public Key: {alice_public}")

# Bob generates private key
bob_private = st.number_input("Bob's Private Key (secret)", min_value=1, max_value=P-2, value=15)
bob_public = mod_exp(G, bob_private, P)
st.write(f"Bob's Public Key: {bob_public}")

# Alice computes shared secret using Bob's public key
alice_shared = mod_exp(bob_public, alice_private, P)
st.write(f"Alice's Computed Shared Secret: {alice_shared}")

# Bob computes shared secret using Alice's public key
bob_shared = mod_exp(alice_public, bob_private, P)
st.write(f"Bob's Computed Shared Secret: {bob_shared}")

st.markdown("---")

operation = st.radio("Choose operation:", ["Encrypt", "Decrypt"])

text_input = st.text_area("Input text")

if operation == "Encrypt":
    if text_input:
        ciphertext = xor_encrypt_decrypt(text_input, alice_shared)
        st.success("Encrypted text (XOR cipher):")
        st.code(ciphertext.encode('utf-8').hex())
elif operation == "Decrypt":
    if text_input:
        try:
            # input is hex string for ciphertext
            ciphertext_bytes = bytes.fromhex(text_input)
            # convert to string for XOR decrypt
            ciphertext_str = ciphertext_bytes.decode('latin1')
            plaintext = xor_encrypt_decrypt(ciphertext_str, bob_shared)
            st.success("Decrypted text:")
            st.code(plaintext)
        except Exception as e:
            st.error(f"Failed to decrypt: {e}")
