import streamlit as st
import string

class VigenereCipher:
    def __init__(self, key: str):
        self.key = self._format_key(key)
        if not self.key:
            self.key = "A"
        self.alphabet = string.ascii_uppercase
        self.alphabet_size = len(self.alphabet)
    
    def _format_key(self, key: str):
        return ''.join(filter(str.isalpha, key.upper()))
    
    def _shift_char(self, char, key_char, encrypt=True):
        if char.upper() not in self.alphabet:
            return char
        shift = self.alphabet.index(key_char)
        char_index = self.alphabet.index(char.upper())
        if not encrypt:
            shift = -shift
        shifted = self.alphabet[(char_index + shift) % self.alphabet_size]
        return shifted if char.isupper() else shifted.lower()
    
    def encrypt(self, text: str) -> str:
        result = []
        key_index = 0
        for char in text:
            if char.isalpha():
                key_char = self.key[key_index % len(self.key)]
                result.append(self._shift_char(char, key_char, encrypt=True))
                key_index += 1
            else:
                result.append(char)
        return ''.join(result)
    
    def decrypt(self, text: str) -> str:
        result = []
        key_index = 0
        for char in text:
            if char.isalpha():
                key_char = self.key[key_index % len(self.key)]
                result.append(self._shift_char(char, key_char, encrypt=False))
                key_index += 1
            else:
                result.append(char)
        return ''.join(result)

def run():
    st.subheader("🔤 Vigenère Cipher")

    key = st.text_input("Enter Cipher Key:")
    if not key or not any(c.isalpha() for c in key):
        st.warning("Please enter a valid key containing letters.")
        return

    cipher = VigenereCipher(key)
    mode = st.radio("Mode", ["Encrypt", "Decrypt"])
    text = st.text_area("Enter Text:")

    if st.button("Run Vigenère Cipher"):
        if mode == "Encrypt":
            result = cipher.encrypt(text)
        else:
            result = cipher.decrypt(text)
        st.success(f"Result:\n{result}")
