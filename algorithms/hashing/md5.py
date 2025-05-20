import streamlit as st
import hashlib

def md5_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def run():
    st.subheader("🔐 MD5 Hasher")

    text = st.text_area("Enter Text")

    if st.button("Generate MD5 Hash"):
        result = md5_hash(text)
        st.success("MD5 Hash:")
        st.code(result)

if __name__ == "__main__":
    run()
