import streamlit as st
import hashlib

def sha256_hash(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def run():
    st.subheader("🔐 SHA-256 Hasher")
    text_input = st.text_area("Enter Text", help="Type your message to hash")

    file = st.file_uploader("Or upload a .txt file", type=["txt"])

    if file:
        try:
            text_input = file.read().decode("utf-8")
        except Exception:
            st.error("Uploaded file must be a valid UTF-8 text file.")
            return

    if not text_input.strip():
        st.info("Awaiting text input or file upload...")
        return

    try:
        result = sha256_hash(text_input)
        st.success("🧾 SHA-256 Hash")
        st.code(result)
    except Exception as e:
        st.error(f"Hashing failed: {e}")
