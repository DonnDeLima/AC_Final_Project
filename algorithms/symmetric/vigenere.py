import streamlit as st
import string

class VigenereCipher:
    def __init__(self, key: str):
        self.key = self._format_key(key)
        if not self.key:
            self.key = "A"
        self.alphabet = string.printable
        self.alphabet_size = len(self.alphabet)

    def _format_key(self, key: str):
        return ''.join(c for c in key if c in string.printable)

    def _shift_char(self, char, key_char, encrypt=True):
        if char not in self.alphabet or key_char not in self.alphabet:
            return char
        shift = self.alphabet.index(key_char)
        char_index = self.alphabet.index(char)
        if not encrypt:
            shift = -shift
        return self.alphabet[(char_index + shift) % self.alphabet_size]

    def encrypt(self, text: str) -> str:
        result = []
        key_index = 0
        for char in text:
            key_char = self.key[key_index % len(self.key)]
            result.append(self._shift_char(char, key_char, encrypt=True))
            key_index += 1
        return ''.join(result)

    def decrypt(self, text: str) -> str:
        result = []
        key_index = 0
        for char in text:
            key_char = self.key[key_index % len(self.key)]
            result.append(self._shift_char(char, key_char, encrypt=False))
            key_index += 1
        return ''.join(result)

def run():
    st.subheader("🔤 Vigenère Cipher")

    with st.expander("ℹ️ About Vigenère Cipher"):
        st.markdown("""
        **🕰️ Brief History**  
        The Vigenère cipher, developed in the 16th century by Blaise de Vigenère, is a classical **polyalphabetic substitution cipher**. It was considered unbreakable for centuries and nicknamed “le chiffre indéchiffrable” (the indecipherable cipher).
    
        **🔧 How It Works**  
        - Uses a keyword to determine the shift for each character in the plaintext.
        - Each character in the key determines how much to shift the corresponding plaintext character.
        - The key is repeated to match the length of the text.
    
        **🧾 Pseudocode**  
        ```
        for i in range(len(text)):
            shift = alphabet.index(key[i % len(key)])
            if encrypt:
                output_char = alphabet[(alphabet.index(text[i]) + shift) % len(alphabet)]
            else:
                output_char = alphabet[(alphabet.index(text[i]) - shift) % len(alphabet)]
        ```
    
        **📋 Use Cases**  
        - Historical encryption in diplomatic and military communication.
        - Introductory cryptography education.
        - Lightweight encryption scenarios (non-critical use).
    
        **⚠️ Limitations**  
        - Vulnerable to **frequency analysis** if the key is short or reused.
        - Not secure for modern standards.
        """)

    col1, col2 = st.columns(2)
    with col1:
        text_input = st.text_area("Enter Plaintext or Ciphertext", help="Supports alphanumeric and symbols")
    with col2:
        key_input = st.text_area("Enter Cipher Key", help="Must contain at least one printable character")

    file = st.file_uploader("Or upload a .txt file", type=["txt"])
    if file:
        text_input = file.read().decode("utf-8")

    operation = st.radio("Operation", ["Encrypt", "Decrypt"])

    if not key_input.strip():
        st.warning("Key is required.")
        return

    cipher = VigenereCipher(key_input)

    if text_input.strip():
        try:
            if operation == "Encrypt":
                result = cipher.encrypt(text_input)
                st.success("🔐 Encrypted Text")
                st.text_area("", result, height=200)
            else:
                result = cipher.decrypt(text_input)
                st.success("🔓 Decrypted Text")
                st.text_area("", result, height=200)
        except Exception as e:
            st.error(f"Error: {e}")
