# Encoder/Decoder

Encoder/Decoder is a Python GUI application that allows you to encode and decode text using various algorithms and encryption methods.

## Features

- Base64 Encoding and Decoding
- Base32 Encoding and Decoding
- Caesar Cipher Encoding and Decoding
- MD5, SHA-1, and SHA-256 Hashing
- Fernet Encryption and Decryption
- RSA Encryption and Decryption
- ROT13 Encoding and Decoding
- Vigenere Cipher Encoding and Decoding

## Usage

1. Enter the text you want to encode or decode in the "Enter text" field.
2. Select the desired algorithm from the "Select algorithm" dropdown menu.
3. Provide any additional parameters (e.g., shift for Caesar Cipher, keyword for Vigenere Cipher).
4. Click the "Encode/Decode" button.
5. View the result in the "Result" field.
6. Use the "Copy to Clipboard" button to copy the result.

## Installation

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/your-username/EncoderDecoder.git
   cd EncoderDecoder


Install the dependencies:
pip install cryptography

Run the application:

python encoder_decoder.py
