import streamlit as st
import string

printable = string.printable  # contains digits, letters, punctuation, etc.

def encrypt(text, shift):
    return ''.join(
        printable[(printable.index(c) + shift) % len(printable)] if c in printable else c
        for c in text
    )

def decrypt(text, shift):
    return encrypt(text, -shift)

def run():
    st.subheader("🔐 Caesar Cipher")

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
