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

    with st.expander("ℹ️ What is the Caesar Cipher?"):
        st.markdown("""
        **Caesar Cipher Overview**
    
        - **History**: One of the oldest known ciphers, used by Julius Caesar to send military messages.
        - **Mechanism**: Shifts each character in the text by a fixed number (the "shift key") within a set of characters.
        - **Pseudocode**:
          ```
          For each character in the input:
              If character is in the character set:
                  Find its index.
                  Add the shift (or subtract for decryption).
                  Wrap around if needed (modulo length of set).
                  Replace character.
              Else:
                  Leave as is.
          ```
        - **Use Cases**:
          - Simple obfuscation
          - Educational demonstrations of classical encryption
          - Not suitable for modern secure communication
    
        - **Character Set**: This version supports all printable characters (letters, digits, punctuation, etc.).
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
