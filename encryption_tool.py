from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import tkinter as tk
from tkinter import messagebox
import base64
import os

def generate_key_iv():
    key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)  # 128-bit IV
    return key, iv

def encrypt(plaintext, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt(ciphertext, key, iv):
    ciphertext = base64.b64decode(ciphertext)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode('utf-8')

def encrypt_text():
    plaintext = plain_text_entry.get("1.0", tk.END).strip()
    if not plaintext:
        messagebox.showwarning("Input Error", "Please enter some plaintext.")
        return
    
    global key, iv
    key, iv = generate_key_iv()
    ciphertext = encrypt(plaintext, key, iv)
    
    cipher_text_entry.delete("1.0", tk.END)
    cipher_text_entry.insert(tk.END, ciphertext)

def decrypt_text():
    ciphertext = cipher_text_entry.get("1.0", tk.END).strip()
    if not ciphertext:
        messagebox.showwarning("Input Error", "Please enter some ciphertext.")
        return

    try:
        plaintext = decrypt(ciphertext, key, iv)
        plain_text_entry.delete("1.0", tk.END)
        plain_text_entry.insert(tk.END, plaintext)
    except Exception as e:
        messagebox.showerror("Decryption Error", "Failed to decrypt the ciphertext.")

app = tk.Tk()
app.title("AES Encryption Tool")

frame = tk.Frame(app)
frame.pack(padx=10, pady=10)

tk.Label(frame, text="Plain Text").grid(row=0, column=0, padx=5, pady=5)
plain_text_entry = tk.Text(frame, height=10, width=50)
plain_text_entry.grid(row=1, column=0, padx=5, pady=5)

tk.Label(frame, text="Cipher Text").grid(row=0, column=1, padx=5, pady=5)
cipher_text_entry = tk.Text(frame, height=10, width=50)
cipher_text_entry.grid(row=1, column=1, padx=5, pady=5)

encrypt_button = tk.Button(frame, text="Encrypt", command=encrypt_text)
encrypt_button.grid(row=2, column=0, padx=5, pady=5)

decrypt_button = tk.Button(frame, text="Decrypt", command=decrypt_text)
decrypt_button.grid(row=2, column=1, padx=5, pady=5)

app.mainloop()
