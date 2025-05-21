import streamlit as st

from algorithms.symmetric import caesar, vernam, vigenere
from algorithms.asymmetric import r_s_a, diffie_hellman, dh
from algorithms.hashing import sha1, sha3, sha256, md5

# ------------------ Page Setup ------------------ #
st.set_page_config(page_title="Cryptography App", layout="wide")
st.title("🔐 Applied Cryptography Application")

# ------------------ Sidebar State Setup ------------------ #
if "selected_algorithm" not in st.session_state:
    st.session_state.selected_algorithm = None

# ------------------ Sidebar (Accordion Style) ------------------ #
st.sidebar.title("🧪 Choose a Cryptographic Algorithm")

with st.sidebar.expander("🔁 Symmetric Algorithms", expanded=False):
    if st.button("Caesar Cipher"):
        st.session_state.selected_algorithm = "caesar"
    if st.button("Vernam Cipher"):
        st.session_state.selected_algorithm = "vernam"
    if st.button("Vigenere Cipher"):
        st.session_state.selected_algorithm = "vigenere"

with st.sidebar.expander("🔀 Asymmetric Algorithms", expanded=False):
    if st.button("RSA"):
        st.session_state.selected_algorithm = "rsa"
    if st.button("Diffie-Hellman"):
        st.session_state.selected_algorithm = "diffie_hellman"

with st.sidebar.expander("📎 Hashing Algorithms", expanded=False):
    if st.button("SHA-1"):
        st.session_state.selected_algorithm = "sha1"
    if st.button("SHA-256"):
        st.session_state.selected_algorithm = "sha256"
    if st.button("SHA-3"):
        st.session_state.selected_algorithm = "sha3"
    if st.button("MD5"):
        st.session_state.selected_algorithm = "md5"

# ------------------ Main Panel ------------------ #
selected_algorithm = st.session_state.selected_algorithm

if selected_algorithm == "caesar":
    caesar.run()
elif selected_algorithm == "vernam":
    vernam.run()
elif selected_algorithm == "vigenere":
    vigenere.run()
elif selected_algorithm == "rsa":
    r_s_a.run()
elif selected_algorithm == "diffie_hellman":
    dh.run()
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
