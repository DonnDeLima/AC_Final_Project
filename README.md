### ***CSAC 329 - Applied Cryptography***
# **Applied Cryptography Application**


This Streamlit-based web application provides an interactive interface for exploring and using a variety of cryptographic algorithms, including **symmetric**, **asymmetric**, and **hashing** techniques. It is designed for educational and practical use cases, allowing users to input plaintext or files and observe real-time encryption/decryption or hashing results.

**Live Web App**: [Click here to access the app]([https://your-app-url.com](https://acfinalproject-38xarvga3vrxtwtvhxendq.streamlit.app))

**Group Members:** 
- De Lima, Donn Robert
- Belgado, Ruby Joy
- Regaspi, Marevel

---
---
                   
## **Introduction:** 
Protecting personal information from unauthorized access has become increasingly important as the world grows more digitally connected. Cryptography plays a critical role in achieving this goal by ensuring the confidentiality, integrity, and authenticity of digital data. From securing stored information to protecting online communications, cryptographic techniques are essential for maintaining trust and security in today's digital environment.

Cryptography enables secure communication by using algorithms to transform readable data into an unreadable format, which can only be reverted by authorized parties. It underpins a wide range of everyday applications, including secure messaging, email encryption, digital signatures, and online banking. As such, professionals working in cybersecurity, software development, and IT infrastructure must possess both theoretical knowledge and practical skills in cryptographic methods.

This project aims to provide a hands-on, interactive platform for learning and experimenting with commonly used cryptographic algorithms. The purpose is to build a user-friendly application developed using Streamlit that allows users to perform encryption, decryption, and hashing on real-world data. By integrating multiple cryptographic tools into a single, accessible interface, the project seeks to enhance users’ understanding of core concepts such as symmetric and asymmetric encryption, hashing, and secure key exchange. This practical approach not only supports academic learning but also prepares users for real-life applications in the field of information security.

---
---

## **Objectives:**  
The objective of this project is to design and build an interactive, user-friendly application that demonstrates the use of core cryptographic techniques. The specific goals include:

- Implement core cryptographic algorithms including symmetric, asymmetric, and hashing techniques for securing text and files.
- Develop an intuitive user interface using Streamlit to allow easy access to encryption, decryption, and hashing functions.
- Ensure secure data processing for confidentiality, integrity verification, and password protection.

---
---

### **Framework and Structure**
The application is built using [Streamlit](https://streamlit.io/), a Python framework for rapidly building and deploying interactive web apps.

The app structure is modular, with cryptographic algorithms implemented in separate Python modules categorized as follows:

cryptography-app/ <br>
├── app.py # Main entry point (UI + routing logic) <br>
├── algorithms/ <br>
│ ├── symmetric/ <br>
│ │ ├── caesar.py <br>
│ │ ├── vernam.py <br>
│ │ └── vigenere.py <br>
│ ├── asymmetric/ <br>
│ │ ├── r_s_a.py <br>
│ │ └── diffie_hellman.py <br>
│ └── hashing/ <br>
│ ├── sha1.py <br>
│ ├── sha256.py <br>
│ ├── sha3.py <br>
│ └── md5.py <br>

---
---

##  **Implemented Algorithms**

Below is a summary of each cryptographic algorithm implemented in the application, categorized by type and detailed with background, process, libraries used, and integration details.


### ***Symmetric Algorithms***

#### 1. **Caesar Cipher**
- **Type**: Symmetric
- **Background**: One of the oldest known ciphers, used by Julius Caesar to securely communicate with his generals. It is a simple substitution cipher.
- **How it Works**:
  - Each letter in the plaintext is shifted by a fixed number of positions in the alphabet.
  - Decryption reverses the shift.
  - **Pseudocode**:
    ```python
    shift = 3
    encrypted = ''.join([shift_letter(c, shift) for c in plaintext])
    ```
- **Libraries Used**: None (pure Python logic).
- **Integration**:
  - `algorithms/symmetric/caesar.py` contains a `run()` function called from `app.py` when Caesar is selected.

---

#### 2. **Vernam Cipher**
- **Type**: Symmetric
- **Background**: Invented by Gilbert Vernam in 1917. Considered theoretically unbreakable when used as a one-time pad.
- **How it Works**:
  - Plaintext is XORed with a random key of the same length.
  - Same process for encryption and decryption.
  - **Pseudocode**:
    ```python
    ciphertext = ''.join([chr(ord(p) ^ ord(k)) for p, k in zip(plaintext, key)])
    ```
- **Libraries Used**: None (uses `ord()` and `chr()` in Python).
- **Integration**:
  - Implemented in `vernam.py` and loaded via `run()` when selected.

---

#### 3. **Vigenère Cipher**
- **Type**: Symmetric
- **Background**: Developed in the 16th century by Giovan Battista Bellaso and later misattributed to Blaise de Vigenère.
- **How it Works**:
  - Uses a repeating keyword to apply multiple Caesar shifts to the plaintext.
  - **Pseudocode**:
    ```python
    for i in range(len(plaintext)):
        shift = ord(key[i % len(key)]) - ord('A')
        encrypted += shift_letter(plaintext[i], shift)
    ```
- **Libraries Used**: None.
- **Integration**:
  - Defined in `vigenere.py`, activated via the main `run()` call.

---

## ***Asymmetric Algorithms***

#### 4. **RSA**
- **Type**: Asymmetric
- **Background**: Developed in 1977 by Rivest, Shamir, and Adleman. Widely used for secure data transmission.
- **How it Works**:
  1. **Key Generation**: Generates a **public key** (shared) and a **private key** (kept secret).
  2. **Encryption**: Uses the **public key** to encrypt plaintext.
  3. **Decryption**: Uses the **private key** to decrypt ciphertext.
  
  Based on the mathematical difficulty of factoring large prime numbers.

  **Pseudocode**:
    
    Key Generation:
    ``` python
              Generate two large primes p and q
              n = p * q
              φ(n) = (p-1)*(q-1)
              Choose e (public exponent), such that 1 < e < φ(n)
              Compute d ≡ e⁻¹ mod φ(n) (private exponent)
    ```
    Encryption:
    ``` python
            ciphertext = plaintext^e mod n
    ```
    
    Decryption:
    ``` python
            plaintext = ciphertext^d mod n
    ```
- **Libraries Used**: `random`, `math` (no external cryptography libraries).
- **Integration**:
  - Located in `r_s_a.py`, plugged into main via `st.session_state.selected_algorithm`.

---

#### 5. **Diffie-Hellman Key Exchange**
- **Type**: Asymmetric (Key Exchange Protocol)
- **Background**: Introduced in 1976 by Whitfield Diffie and Martin Hellman; first practical method for public key exchange.
- **How it Works**:
    1. Both parties agree on a large prime `P` and a generator `G`.
    2. Each party generates a **private key** and a corresponding **public key**:
       - `A_private`, `A_public = G^A_private mod P`
       - `B_private`, `B_public = G^B_private mod P`
    3. They exchange **public keys**.
    4. Each party computes the shared secret:
       
       - `shared = B_public^A_private mod P` (same as `A_public^B_private mod P`)

    **AES Integration**  
    - The shared secret is converted into a symmetric key.
    - This key is then used in **AES (Advanced Encryption Standard)** for encrypting/decrypting the actual message.

    **Pseudocode**  
    ``` python
    P, G = known safe prime and generator
    A_private = random()
    A_public = pow(G, A_private, P)

    B_private = random()
    B_public = pow(G, B_private, P)

    # After exchange:
    shared_key = pow(B_public, A_private, P)
    aes_key = derive_from(shared_key)
    encrypted = AES.encrypt(message, aes_key)
    ```

- **Libraries Used**: `random`, `math`.
- **Integration**:
  - Implemented in `diffie_hellman.py`, accessible through sidebar routing.

---

## ***Hashing Algorithms***

#### 6. **SHA-1**
- **Type**: Hash
- **Background**: Designed by NSA in 1995. Now considered weak due to collision vulnerabilities.
- **How it Works**:
  - Produces a 160-bit hash from any input using bitwise operations and modular arithmetic.
- **Libraries Used**: `hashlib`
- **Integration**:
  - Defined in `sha1.py`, called via `sha1.run()`.

---

#### 7. **SHA-256**
- **Type**: Hash
- **Background**: Part of SHA-2 family, published by NIST in 2001. Common in blockchain and secure applications.
- **How it Works**:
  - Outputs a 256-bit hash using complex round functions.
- **Libraries Used**: `hashlib`
- **Integration**:
  - In `sha256.py`, rendered when selected.

---

#### 8. **SHA-3**
- **Type**: Hash
- **Background**: Released by NIST in 2015. Uses Keccak algorithm, distinct from SHA-2's design.
- **How it Works**:
  - Sponge construction to absorb and squeeze message into 256-bit digest.
- **Libraries Used**: `hashlib` (Python 3.6+)
- **Integration**:
  - Available via `sha3.py` module.

---

#### 9. **MD5**
- **Type**: Hash
- **Background**: Developed by Ron Rivest in 1992. Now obsolete due to collisions.
- **How it Works**:
  - 128-bit digest generated via compression function.
- **Libraries Used**: `hashlib`
- **Integration**:
  - Rendered through `md5.py` when selected in sidebar.

---

### Summary Table

| Algorithm         | Type       | Library Used | File             |
|------------------|------------|---------------|------------------|
| Caesar Cipher     | Symmetric  | None          | `caesar.py`      |
| Vernam Cipher     | Symmetric  | None          | `vernam.py`      |
| Vigenère Cipher   | Symmetric  | None          | `vigenere.py`    |
| RSA               | Asymmetric | `math`, `random` | `r_s_a.py`       |
| Diffie-Hellman    | Asymmetric | `math`, `random` | `diffie_hellman.py` |
| SHA-1             | Hash       | `hashlib`     | `sha1.py`        |
| SHA-256           | Hash       | `hashlib`     | `sha256.py`      |
| SHA-3             | Hash       | `hashlib`     | `sha3.py`        |
| MD5               | Hash       | `hashlib`     | `md5.py`         |

---
---

## **Step by Step Guide**
1. Homepage: Provides an introduction and navigation options.
   
![1](https://github.com/user-attachments/assets/930c0726-f952-4320-9228-0900802252a1)
   
2. Choose from different Cryptograhic Algorithms

![FINAL NA 2](https://github.com/user-attachments/assets/f4c1e149-2779-41e2-90b9-d2d5b35b727a)

3. Type or paste your plain text into the input box, or upload a .txt file containing the content you wish to encrypt, decrypt, or hash.

- Manual Input
![3](https://github.com/user-attachments/assets/cd8d413f-9a3a-422a-b819-4f9c0e804e7d)
- .txt File Upload
![3](https://github.com/user-attachments/assets/343bbffd-25d6-47c3-bb58-7801b5bfc9c7)

4.  Select whether to **ENCRYPT** a plaintext or **DECRYPT** a ciphertext.

![image](https://github.com/user-attachments/assets/1541a95e-6b29-4cef-8bf6-ef1549ca09c9)

5.  Depending on the hashing algorithm, the result of the encryption will be displayed dynamically.
   
![image](https://github.com/user-attachments/assets/edd3065b-4081-4ba0-9447-8fc3a479410b)

6.  You can then copy the result for future reference.

![image](https://github.com/user-attachments/assets/653f42c4-dcb5-48fb-8e63-63eada4ef9b4)

7. For hashing algorithms, select your desired hash function, then click to generate the hash.
![HASH](https://github.com/user-attachments/assets/f9495db2-36a7-4c86-bb19-fc75ce4adbd4)

---
---

## **Future Enhancements**
To further improve the application, the following features are planned:

**UI/UX Enhancements**
- Optimized drag-and-drop file upload.
- Dark/light mode toggle.
- Progress indicators for large file operations.

**Advanced Cryptographic Features**
- Addition of other cryptographic algorithms and systems. 
- Implementation of hybrid encryption.
- Addition of digital signatures.
- Implementation of key management tools




