import streamlit as st

from algorithms.symmetric import caesar, vernam, vigenere
from algorithms.asymmetric import rsa, diffie_hellman
from algorithms.hashing import sha1, sha3, sha256, md5

# ------------------ Page Setup ------------------ #
st.set_page_config(page_title="Cryptography App", layout="wide")
st.title("🔐 Applied Cryptography Application")

# ------------------ Side Bar ------------------ #
st.sidebar.title("🧪 Choose a Cryptographic Algorithm")

category = st.sidebar.radio("Category", ["Symmetric", "Asymmetric", "Hashing"])

if category == "Symmetric":
    algo = st.sidebar.selectbox("Select Algorithm", ["Caesar Cipher", "Vernam Cipher", "Vigenere Cipher"])
    if algo == "Caesar Cipher":
        caesar.run()
    elif algo == "Vernam Cipher":
        vernam.run()
    elif algo == "Vigenere Cipher":
        vigenere.run()

elif category == "Asymmetric":
    algo = st.sidebar.selectbox("Select Algorithm", ["RSA", "Diffie-Hellman"])
    if algo == "RSA":
        rsa.run()
    elif algo == 'Diffie-Hellman':
        diffie_hellman.run()

elif category == "Hashing":
    algo = st.sidebar.selectbox("Select Algorithm", ["SHA-1", "MD5", "SHA-256", "SHA-3"])
    if algo == "SHA-1":
        sha1.run()
    elif algo == 'MD5':
        md5.run()
    elif algo == 'SHA-256':
        sha256.run()
    elif algo == 'SHA-3':
        sha3.run()
        
# -------------------------------------------------------- #
