import streamlit as st
import hashlib

def sha1_hash(text):
    return hashlib.sha1(text.encode('utf-8')).hexdigest()

def run():
    st.subheader("🔐 SHA-1 Hasher")

    with st.expander("ℹ️ About SHA-1 Hashing"):
        st.markdown("""
        **🕰️ Brief History**  
        **SHA-1 (Secure Hash Algorithm 1)** was developed by the **NSA** and published in **1995** as a U.S. Federal Information Processing Standard.
        
        **🔧 How It Works**  
        - Converts any input (text or file) into a **160-bit (40-character)** hexadecimal hash.
        - It is a **one-way function**: you can't reverse the hash to retrieve the original input.
        - Even a small change in input results in a drastically different hash (avalanche effect).
        
        **🧾 Pseudocode**  
        ```
        function SHA1(text):
            Convert text to UTF-8 bytes
            Apply SHA-1 compression algorithm
            Return 160-bit hexadecimal digest
        ```
        
        **📋 Use Cases**  
        - File integrity verification
        - Digital signatures
        - Version control (e.g., Git uses SHA-1)
        
        **⚠️ Limitations**  
        - **Cryptographically broken**: vulnerable to collision attacks
        - Not recommended for secure applications; use **SHA-256** or stronger instead
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
        result = sha1_hash(text_input)
        st.success("🧾 SHA-1 Hash")
        st.code(result)
    except Exception as e:
        st.error(f"Hashing failed: {e}")
