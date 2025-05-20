import hashlib
import streamlit as st

class SHACrypto:
    def hash_text(self, text: str) -> str:
        hash_func = hashlib.sha1()
        hash_func.update(text.encode('utf-8'))
        return hash_func.hexdigest()

# Streamlit UI
def run():
    crypto = SHACrypto()

    st.subheader("🔐 SHA-1 Hashing")

    mode = st.radio("Choose input type:", ["Text", "File"])

    if mode == "Text":
        text = st.text_area("Enter text to hash:")
        if st.button("Hash Text"):
            if text:
                result = crypto.hash_text(text)
                st.success(f"SHA-1 Hash:\n{result}")
            else:
                st.warning("Please enter some text.")
    else:
        uploaded_file = st.file_uploader("Upload a file to hash:")
        if uploaded_file and st.button("Hash File"):
            data = uploaded_file.read()
            result = hashlib.sha1(data).hexdigest()
            st.success(f"SHA-1 File Hash:\n{result}")
        elif not uploaded_file:
            st.warning("Please upload a file.")
