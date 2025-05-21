import streamlit as st
import hashlib

def sha256_hash(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def run():
    st.subheader("🔐 SHA-256 Hasher")

    with st.expander("ℹ️ About SHA-256 Hashing"):
        st.markdown("""
        **🕰️ Brief History**  
        SHA-256 (Secure Hash Algorithm 256-bit) is part of the **SHA-2 family**, developed by the **NSA** and published by **NIST** in 2001. It is widely used in cryptographic applications.

        **🔧 How It Works**  
        - Takes an input of any length and produces a fixed 256-bit (64-character hex) output.
        - The process involves multiple rounds of bitwise operations, modular additions, and logical functions.
        - Designed to be **one-way** (non-reversible) and **collision-resistant**.

        **🧾 Pseudocode**  
        ```
        def sha256_hash(input):
            preprocess input
            initialize hash values
            for each 512-bit chunk:
                create message schedule
                run 64 rounds of compression
                update hash values
            return final hash
        ```

        **📋 Use Cases**  
        - Password storage (hashed, not encrypted)
        - File integrity verification (e.g., checksum)
        - Digital signatures and certificates
        - Blockchain (e.g., Bitcoin uses SHA-256)

        **⚠️ Limitations**  
        - Not meant for encryption or secure message hiding
        - Slower than lightweight hashes (but more secure)
        - Susceptible to brute-force if not combined with salt/pepper
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
        result = sha256_hash(text_input)
        st.success("🧾 SHA-256 Hash")
        st.code(result)
    except Exception as e:
        st.error(f"Hashing failed: {e}")
