import streamlit as st
import string

printable = string.printable  # contains digits, letters, punctuation, etc.

def encrypt(text, shift):
    return ''.join(
        c if c == ' ' else printable[(printable.index(c) + shift) % len(printable)] if c in printable else c
        for c in text
    )

def decrypt(text, shift):
    return encrypt(text, -shift)

def run():
    st.subheader("🔐 Caesar Cipher")

    with st.expander("ℹ️ About Caesar Cipher"):
        st.markdown("""
        **🕰️ Brief History**  
        The Caesar cipher is one of the oldest known encryption techniques, attributed to **Julius Caesar**, who used it to send secret military messages.

        **🔧 How It Works**  
        - Each character in the plaintext is shifted by a fixed number of positions (the "key") in a defined character set.
        - Decryption simply shifts characters back by the same amount.
        - Characters outside the set remain unchanged.

        **🧾 Pseudocode**  
        ```
        for char in text:
            if char in character_set:
                index = character_set.index(char)
                shifted_index = (index + key) % len(character_set)  # use -key for decryption
                output += character_set[shifted_index]
            else:
                output += char
        ```

        **📋 Use Cases**  
        - Basic obfuscation
        - Cryptography education
        - Not secure for modern applications

        **⚠️ Limitations**  
        - Vulnerable to **brute-force attacks** due to small key space
        - Easily broken with **frequency analysis**
        """)


    col1, col2 = st.columns(2)
    with col1:
        text_input = st.text_area("Enter Plaintext or Ciphertext", help="Accepts letters, numbers, and symbols.")
    with col2:
        shift = st.slider("Shift (1–25)", 1, 25, 3)

    file = st.file_uploader("Or upload a .txt file", type=["txt"])
    if file:
        text_input = file.read().decode("utf-8")

    operation = st.radio("Operation", ["Encrypt", "Decrypt"])

    if text_input.strip():
        try:
            result = encrypt(text_input, shift) if operation == "Encrypt" else decrypt(text_input, shift)
            st.success("🔐 Result")
            st.text_area("", result, height=200)
        except Exception as e:
            st.error(f"Error: {e}")
