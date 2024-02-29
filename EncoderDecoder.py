import tkinter as tk
from tkinter import ttk, messagebox
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def select_all(event):
    event.widget.select_range(0, tk.END)
    return 'break'

def encode_decode():
    input_text = input_entry.get().strip()
    selected_option = algorithm_var.get()
    
    if not input_text:
        messagebox.showwarning("Warning", "Please enter text.")
        return

    try:
        if selected_option == "Base64 Encode":
            result = base64.b64encode(input_text.encode()).decode()
            show_result("Base64 Encoding", result)
        elif selected_option == "Base64 Decode":
            result = base64.b64decode(input_text).decode()
            show_result("Base64 Decoding", result)
        elif selected_option == "Base32 Encode":
            result = base64.b32encode(input_text.encode()).decode()
            show_result("Base32 Encoding", result)
        elif selected_option == "Base32 Decode":
            result = base64.b32decode(input_text).decode()
            show_result("Base32 Decoding", result)
        elif selected_option == "Caesar Cipher Encode":
            shift = int(shift_var.get())
            result = caesar_cipher(input_text, shift)
            show_result("Caesar Cipher Encoding", result)
        elif selected_option == "Caesar Cipher Decode":
            shift = int(shift_var.get())
            result = caesar_cipher(input_text, -shift)
            show_result("Caesar Cipher Decoding", result)
        elif selected_option == "MD5 Hash":
            result = hashlib.md5(input_text.encode()).hexdigest()
            show_result("MD5 Hashing", result)
        elif selected_option == "SHA-1 Hash":
            result = hashlib.sha1(input_text.encode()).hexdigest()
            show_result("SHA-1 Hashing", result)
        elif selected_option == "SHA-256 Hash":
            result = hashlib.sha256(input_text.encode()).hexdigest()
            show_result("SHA-256 Hashing", result)
        elif selected_option == "Fernet Encryption":
            key = Fernet.generate_key()
            cipher = Fernet(key)
            encrypted_text = cipher.encrypt(input_text.encode())
            result = base64.b64encode(encrypted_text).decode()
            show_result("Fernet Encryption", result)
        elif selected_option == "Fernet Decryption":
            key = Fernet.generate_key()
            cipher = Fernet(key)
            decrypted_text = cipher.decrypt(base64.b64decode(input_text)).decode()
            result = decrypted_text
            show_result("Fernet Decryption", result)
        elif selected_option == "RSA Encryption":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            ciphertext = public_key.encrypt(
                input_text.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            result = base64.b64encode(ciphertext).decode()
            show_result("RSA Encryption", result)
        elif selected_option == "RSA Decryption":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            ciphertext = base64.b64decode(input_text)
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            result = plaintext.decode()
            show_result("RSA Decryption", result)
        elif selected_option == "ROT13 Encode":
            result = rot13_cipher(input_text)
            show_result("ROT13 Encoding", result)
        elif selected_option == "ROT13 Decode":
            result = rot13_cipher(input_text)
            show_result("ROT13 Decoding", result)
        elif selected_option == "Vigenere Cipher Encode":
            keyword = keyword_entry.get()
            result = vigenere_cipher(input_text, keyword, mode="encode")
            show_result("Vigenere Cipher Encoding", result)
        elif selected_option == "Vigenere Cipher Decode":
            keyword = keyword_entry.get()
            result = vigenere_cipher(input_text, keyword, mode="decode")
            show_result("Vigenere Cipher Decoding", result)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                result += chr((ord(char) - 97 + shift) % 26 + 97)
            else:
                result += chr((ord(char) - 65 + shift) % 26 + 65)
        else:
            result += char
    return result

def rot13_cipher(text):
    return text.encode('rot_13').decode()

def vigenere_cipher(text, keyword, mode="encode"):
    result = ""
    keyword = keyword.upper()
    keyword_index = 0

    for char in text:
        if char.isalpha():
            shift = ord(keyword[keyword_index]) - 65 if keyword else 0
            if char.islower():
                result += chr((ord(char) - 97 + shift) % 26 + 97)
            else:
                result += chr((ord(char) - 65 + shift) % 26 + 65)
            keyword_index = (keyword_index + 1) % len(keyword)
        else:
            result += char

    return result if mode == "encode" else caesar_cipher(result, -ord(keyword[0]) + 65)

def show_result(title, result):
    result_label.config(text=title, fg="green")
    output_text.set(result)
    clear_clipboard_button.config(state=tk.NORMAL)

def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(output_text.get())
    root.update()
    messagebox.showinfo("Clipboard", "Result copied to clipboard.")

def clear_fields():
    input_entry.delete(0, tk.END)
    output_text.set("")
    result_label.config(text="", fg="black")
    clear_clipboard_button.config(state=tk.DISABLED)

# GUI
root = tk.Tk()
root.title("Encoder/Decoder")
root.geometry("500x500")
root.resizable(width=False, height=False)

#Style
style = ttk.Style(root)
style.theme_use("clam")


input_label = tk.Label(root, text="Enter text:")
input_label.grid(row=0, column=0, padx=10, pady=10)
input_entry = tk.Entry(root, width=40)
input_entry.grid(row=0, column=1, padx=10, pady=10)
input_entry.bind("<Control-a>", select_all)
algorithm_label = tk.Label(root, text="Select algorithm:")
algorithm_label.grid(row=1, column=0, padx=10, pady=10)
algorithms = [
    "Base64 Encode", "Base64 Decode",
    "Base32 Encode", "Base32 Decode",
    "Caesar Cipher Encode", "Caesar Cipher Decode",
    "MD5 Hash", "SHA-1 Hash", "SHA-256 Hash",
    "Fernet Encryption", "Fernet Decryption",
    "RSA Encryption", "RSA Decryption",
    "ROT13 Encode", "ROT13 Decode",
    "Vigenere Cipher Encode", "Vigenere Cipher Decode"
]
algorithm_var = ttk.Combobox(root, values=algorithms, state="readonly")
algorithm_var.set(algorithms[0])
algorithm_var.grid(row=1, column=1, padx=10, pady=10)
algorithm_var.bind("<Control-a>", select_all)

# Shift for Caesar Cipher
shift_label = tk.Label(root, text="Shift (for Caesar Cipher):")
shift_label.grid(row=2, column=0, padx=10, pady=10)
shift_var = tk.Entry(root, width=5)
shift_var.grid(row=2, column=1, padx=10, pady=10)
shift_var.bind("<Control-a>", select_all)

# Keyword for Vigenere Cipher
keyword_label = tk.Label(root, text="Keyword (for Vigenere Cipher):")
keyword_label.grid(row=3, column=0, padx=10, pady=10)
keyword_entry = tk.Entry(root, width=15)
keyword_entry.grid(row=3, column=1, padx=10, pady=10)
keyword_entry.bind("<Control-a>", select_all)

# Output
result_label = tk.Label(root, text="", font=("Helvetica", 12, "italic"), fg="black")
result_label.grid(row=4, column=0, columnspan=2, pady=5)
output_text = tk.StringVar()
output_entry = tk.Entry(root, textvariable=output_text, width=40, state="readonly", justify="center")
output_entry.grid(row=5, column=0, columnspan=2, padx=10, pady=10, ipady=5)
output_entry.bind("<Control-a>", select_all)

# Clear button
clear_clipboard_button = tk.Button(root, text="Clear Clipboard", state=tk.DISABLED, command=clear_fields)
clear_clipboard_button.grid(row=6, column=0, columnspan=2, pady=5)

# Encode/Decode button
encode_decode_button = tk.Button(root, text="Encode/Decode", command=encode_decode)
encode_decode_button.grid(row=7, column=0, columnspan=2, pady=10)

# Copy to Clipboard button
copy_clipboard_button = tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard)
copy_clipboard_button.grid(row=8, column=0, columnspan=2, pady=10)

# Status Bar
status_bar = tk.Label(root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
status_bar.grid(row=9, column=0, columnspan=2, sticky=tk.W+tk.E)

root.mainloop()
