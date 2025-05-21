import streamlit as st
import hashlib

def sha3_hash(text):
    return hashlib.sha3_256(text.encode('utf-8')).hexdigest()

def run():
    st.subheader("🔐 SHA-3 Hasher (256-bit)")

with st.expander("ℹ️ About SHA-3 Hashing"):
    st.markdown("""
    **🔎 What is SHA-3?**

    **🕰️ Brief History** 
      SHA-3 (Secure Hash Algorithm 3) is the latest member of the SHA family, standardized by NIST in 2015.  
      It was designed as a backup in case SHA-2 was compromised, based on the Keccak algorithm.

    **🔧 How It Works**  
      SHA-3 processes input data in blocks through a sponge construction, absorbing input and squeezing out a fixed-length hash.  
      This implementation uses SHA3-256, producing a 256-bit (32-byte) hash.

    **🧾 Pseudocode**   
      ```
      Initialize state
      Absorb input blocks into the state with permutation
      Squeeze output hash from the state
      Return fixed-length hash digest
      ```

    **🧾 Pseudocode**  
      - Verifying data integrity  
      - Password hashing (with proper salting)  
      - Digital signatures  
      - Cryptographic applications requiring collision resistance

     **⚠️ Limitations**   
      - Not reversible (hashing is one-way)  
      - Not suitable for encryption/decryption  
      - Vulnerable if used without salting in password storage  
      - Slower than some SHA-2 variants in certain hardware setups  
      - Fixed output length (not ideal for variable-length digest needs)
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
        result = sha3_hash(text_input)
        st.success("🧾 SHA-3 Hash")
        st.code(result)
    except Exception as e:
        st.error(f"Hashing failed: {e}")
