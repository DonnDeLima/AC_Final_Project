import streamlit as st

def encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    return result

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
    run_button = st.button("Run Caesar Cipher")

    if run_button:
        if not text_input.strip():
            st.warning("Input text is required.")
            return
        try:
            result = encrypt(text_input, shift) if operation == "Encrypt" else decrypt(text_input, shift)
            st.success("🔐 Result")
            st.text_area("", result, height=200)
        except Exception as e:
            st.error(f"Error: {e}")
