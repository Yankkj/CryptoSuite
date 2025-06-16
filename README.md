# CryptoSuite 

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A cryptographic tool suite developed in Python with a graphical user interface (GUI) using Tkinter. CryptoSuite allows you to encrypt, decrypt, analyze, and manage keys for various ciphers, from classical to modern ones.

---

### Table of Contents

- [About The Project](#about-the-project)
- [Features](#features)
- [Gallery](#gallery)
- [Explanation of the Cryptographies](#explanation-of-the-cryptographies)
  - [Classical Ciphers](#classical-ciphers)
  - [Modern Symmetric Cryptography (AES)](#modern-symmetric-cryptography-aes)
  - [Modern Asymmetric Cryptography (RSA)](#modern-asymmetric-cryptography-rsa)
  - [Encoding (Base64)](#encoding-base64)
- [How To Use](#how-to-use)
- [License](#license)

---

### About The Project

**CryptoSuite** was created as a tool to demonstrate and interact with different cryptography algorithms in a visual and friendly environment. It was built using the following technologies:

- **Python 3**
- **Tkinter** for the graphical interface.
- The **cryptography** library for secure implementations of AES and RSA.

### Features

- **Encryption & Decryption**: Supports multiple ciphers, including Caesar, Vigenère, ROT13, Base64, AES, and RSA.
- **Key Management**: Generate, save, and load AES keys and RSA key pairs (public/private).
- **Cipher Analysis**: A tool to break the Caesar Cipher through brute force and letter frequency analysis.
- **Operations History**: Logs all encryption, decryption, and breaking actions, allowing for review and export.
- **Modern Interface**: A clean, dark-themed design for a pleasant user experience.

---

### Explanation of the Cryptographies

The project implements different types of algorithms, each with its own characteristics and use cases.

#### Classical Ciphers

These are historically important algorithms but are now considered insecure for protecting sensitive information. They are excellent for educational purposes.

- **Caesar Cipher**: One of the simplest ciphers. It involves replacing each letter of the text with another that is a fixed number of positions down the alphabet. The "fixed number" is the key. **ROT13** is a special case of the Caesar Cipher where the key is always 13.
- **Vigenère Cipher**: An evolution of the Caesar Cipher. Instead of using a fixed shift, it uses a **keyword**. Each letter of the keyword defines a different shift, making frequency analysis much more difficult.

#### Modern Symmetric Cryptography (AES)

- **AES (Advanced Encryption Standard)**: The global standard for symmetric encryption. "Symmetric" means that **the same key** is used to both encrypt and decrypt the data.
  - In this project, we use the `Fernet` implementation from the `cryptography` library. It is very secure because it combines AES (in CBC mode) with an authentication code (HMAC) to ensure that the data not only remains secret but also has not been tampered with.

#### Modern Asymmetric Cryptography (RSA)

- **RSA (Rivest-Shamir-Adleman)**: The most popular standard for asymmetric cryptography. "Asymmetric" means that **two different keys** are used:
  - **Public Key**: Used to encrypt. It can be shared with anyone.
  - **Private Key**: Used to decrypt. It must be kept in absolute secrecy by the owner.
  - This method is fundamental for secure communication on the internet (like in HTTPS and digital signatures). The project uses **OAEP padding**, which adds randomness and prevents attacks, making it the recommended practice for RSA today.

#### Encoding (Base64)

- **Base64**: It is important to understand that **Base64 is not encryption**, but rather an **encoding** scheme. It does not hide the information, it only transforms it into a text format that can be easily transmitted by systems that only support plain text (ASCII). Anyone can "decode" Base64 without needing a key.

---

### How To Use

Follow the steps below to run the project on your local machine.

**Prerequisites:**

- Python 3.9 or higher.

**Installation:**

1.  Clone the repo:
    ```sh
    git clone [https://github.com/Yankkj/CryptoSuite.git](https://github.com/Yankkj/CryptoSuite.git)
    ```
2.  Navigate to the project directory:
    ```sh
    cd CryptoSuite
    ```
3.  (Recommended) Create and activate a virtual environment:

    ```sh
    # For Windows
    python -m venv venv
    .\venv\Scripts\activate

    # For macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

4.  Install dependencies:
    ```sh
    pip install -r requirements.txt
    ```
5.  Run the application:
    ```sh
    python src/main.py
    ```

---

### License

Distributed under the MIT License. See `LICENSE` for more information.
