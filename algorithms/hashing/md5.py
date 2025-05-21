import streamlit as st
import hashlib

def md5_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def run():
    st.subheader("🔐 MD5 Hasher")
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
        result = md5_hash(text_input)
        st.success("🧾 MD5 Hash")
        st.code(result)
    except Exception as e:
        st.error(f"Hashing failed: {e}")
