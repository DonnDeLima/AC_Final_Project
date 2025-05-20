def encrypt_decrypt(text, shift_keys, ifdecrypt):
    """
    Encrypts a text using Caesar Cipher with a list of shift keys.
    Args:
        text: The text to encrypt.
        shift_keys: A list of integers representing the shift values for each character.
        ifdecrypt: flag if decrypt or encrypt
    Returns:
        A string containing the encrypted text if encrypt and plain text if decrypt
    """
    result = []
    shift_length = len(shift_keys)
    
    for i, char in enumerate(text):
        shift = shift_keys[i % shift_length]
        if ifdecrypt:
            shift = -shift
            
        if 32 <= ord(char) <= 126:
                new_char = chr((ord(char) -32 + shift) % 94 + 32)
        
        else:
            new_char = char
        result.append(new_char)
        
        if ifdecrypt:
            print(f"{i} {char} {-shift} {new_char}")
        else:
            print(f"{i} {char} {shift} {new_char}")
        
            
    return ''.join(result)
            

# Example usage
if __name__ =="__main__":
    # User input text
    text = input("")
    
    # Input shift keys and perform encryption
    shift_keys_input = input("")
    shift_keys = list(map(int, shift_keys_input.split()))
    cipher_text = encrypt_decrypt(text, shift_keys, False)
    
    #Perform decryption 
    print("----------")
    decrypted_text = encrypt_decrypt(cipher_text, shift_keys, True)
    
    print("----------")
    print(f"Text: {text}")
    print(f"Shift keys: { ' '.join(map(str, shift_keys))}")
    print(f"Cipher: {cipher_text}")
    print(f"Decrypted text: {decrypted_text}")
    
    





