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
    st.subheader("🔤 Caesar Cipher")

    mode = st.radio("Mode", ["Encrypt", "Decrypt"])
    text = st.text_area("Enter Text")
    shift = st.slider("Shift", 1, 25, 3)

    if st.button("Run Caesar Cipher"):
        if mode == "Encrypt":
            result = encrypt(text, shift)
        else:
            result = decrypt(text, shift)
        st.success(f"Result: {result}")
