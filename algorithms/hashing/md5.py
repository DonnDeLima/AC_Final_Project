import streamlit as st
import hashlib

def md5_hash(text: str) -> str:
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def run():
    st.subheader("🔐 MD5 Cipher")

    col1, col2 = st.columns(2)
    with col1:
        text_input = st.text_area("Enter Plaintext or Hash", help="Message to hash or verify")
    with col2:
        key_input = st.text_area("Enter Key (Optional)", help="Used as salt during hashing or verification")

    file = st.file_uploader("Or upload a .txt file", type=["txt"])
    if file:
        text_input = file.read().decode("utf-8")

    operation = st.radio("Operation", ["Encrypt", "Decrypt"])

    if text_input.strip():
        try:
            salted_input = text_input + key_input if key_input else text_input

            if operation == "Encrypt":
                hashed = md5_hash(salted_input)
                st.success("🔐 MD5 Hash (Encrypted Output)")
                st.code(hashed)

            else:  # Decrypt (verification)
                st.info("MD5 is one-way; this checks if a hash matches a given input.")
                col_verify1, col_verify2 = st.columns(2)
                with col_verify1:
                    compare_input = st.text_input("Text to Compare")
                with col_verify2:
                    target_hash = st.text_input("Target MD5 Hash")

                if compare_input and target_hash:
                    salted_compare = compare_input + key_input if key_input else compare_input
                    if md5_hash(salted_compare) == target_hash:
                        st.success("✅ Match Found")
                    else:
                        st.error("❌ No Match")

        except Exception as e:
            st.error(f"Error: {e}")
