import streamlit as st
import hashlib

def sha256_hash(text: str) -> str:
    """Generate SHA-256 hash of the input text."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def run():
    st.title("🔐 SHA-256 Hasher")

    st.markdown("Enter text below to generate its SHA-256 hash.")

    text = st.text_area("🔤 Enter Text to Hash", height=150)

    if st.button("Generate SHA-256 Hash"):
        if not text.strip():
            st.warning("Please enter some text.")
        else:
            hashed = sha256_hash(text)
            st.success("SHA-256 Hash:")
            st.code(hashed)

if __name__ == "__main__":
    run()
