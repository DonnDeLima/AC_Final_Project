import streamlit as st

from algorithms.symmetric import caesar, vernam, vigenere
from algorithms.asymmetric import rsa, diffie_hellman
from algorithms.hashing import sha1, sha3, sha256, md5

# ------------------ Page Setup ------------------ #
st.set_page_config(page_title="Cryptography App", layout="wide")
st.title("🔐 Applied Cryptography Application")

# ------------------ Sidebar (Accordion Style) ------------------ #
st.sidebar.title("🧪 Choose a Cryptographic Algorithm")
selected_algorithm = None

with st.sidebar.expander("🔁 Symmetric Algorithms", expanded=True):
    if st.button("Caesar Cipher"):
        selected_algorithm = "caesar"
    if st.button("Vernam Cipher"):
        selected_algorithm = "vernam"
    if st.button("Vigenere Cipher"):
        selected_algorithm = "vigenere"

with st.sidebar.expander("🔀 Asymmetric Algorithms", expanded=False):
    if st.button("RSA"):
        selected_algorithm = "rsa"
    if st.button("Diffie-Hellman"):
        selected_algorithm = "diffie_hellman"

with st.sidebar.expander("📎 Hashing Algorithms", expanded=False):
    if st.button("SHA-1"):
        selected_algorithm = "sha1"
    if st.button("MD5"):
        selected_algorithm = "md5"
    if st.button("SHA-256"):
        selected_algorithm = "sha256"
    if st.button("SHA-3"):
        selected_algorithm = "sha3"

# ------------------ Main Panel ------------------ #
if selected_algorithm == "caesar":
    caesar.run()
elif selected_algorithm == "vernam":
    vernam.run()
elif selected_algorithm == "vigenere":
    vigenere.run()
elif selected_algorithm == "rsa":
    rsa.run()
elif selected_algorithm == "diffie_hellman":
    diffie_hellman.run()
elif selected_algorithm == "sha1":
    sha1.run()
elif selected_algorithm == "md5":
    md5.run()
elif selected_algorithm == "sha256":
    sha256.run()
elif selected_algorithm == "sha3":
    sha3.run()
else:
    st.info("Select an algorithm from the sidebar to begin.")
