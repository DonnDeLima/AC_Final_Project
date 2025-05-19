import streamlit as st
import hashlib

def hash_text(text):
    return hashlib.sha3_256(text.encode()).hexdigest()

def hash_file(file):
    sha3 = hashlib.sha3_256()
    while chunk := file.read(8192):
        sha3.update(chunk)
    return sha3.hexdigest()

def run():
    st.subheader("🔐 SHA-3 Hashing")

    mode = st.radio("Choose input type:", ["Text", "File"])

    if mode == "Text":
        text = st.text_area("Enter text to hash:")
        if st.button("Hash Text"):
            if text:
                result = hash_text(text)
                st.success(f"SHA-3 Hash:\n{result}")
            else:
                st.warning("Please enter some text.")
    else:
        file = st.file_uploader("Upload a file to hash:", type=None)
        if file and st.button("Hash File"):
            result = hash_file(file)
            st.success(f"SHA-3 File Hash:\n{result}")
        elif not file:
            st.warning("Please upload a file.")
