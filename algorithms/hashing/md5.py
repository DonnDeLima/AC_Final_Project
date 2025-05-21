import streamlit as st
import hashlib

def md5_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def run():
    st.subheader("🔐 MD5 Hasher")

    with st.expander("ℹ️ About MD5 Hashing"):
        st.markdown("""
        **🕰️ Brief History**  
        - **MD5 (Message-Digest Algorithm 5)** was developed by **Ron Rivest** in 1991.
        - It was widely used for checksums and cryptographic hashing.

        **🔧 How It Works**  
        - Converts input data of any length into a **128-bit hash** (32-character hexadecimal string).
        - Small changes in input result in a significantly different hash (avalanche effect).
        - It is **non-reversible**: you cannot retrieve the original text from the hash.

        **🧾 Pseudocode**  
        ```
        def md5_hash(text):
            return MD5(text.encode('utf-8')).hexdigest()
        ```

        **📋 Use Cases**  
        - File integrity verification (checksums)
        - Password hashing (not recommended today)
        - Digital fingerprinting

        **⚠️ Limitations**  
        - **Not secure for cryptographic use** due to vulnerabilities (e.g., collisions).
        - Use stronger hashes like **SHA-256** for secure applications.
        """)

    
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
