# main.py

import tkinter as tk
from tkinter import ttk, messagebox
from sparx import sparx_encrypt, sparx_decrypt

def encrypt_text():
    plain_text = entry_text.get("1.0", tk.END).strip()
    key = entry_key.get().strip()
    if not plain_text or not key:
        messagebox.showerror("Error", "Both text and key must be provided")
        return
    encrypted = sparx_encrypt(plain_text, key)
    entry_result.delete("1.0", tk.END)
    entry_result.insert("1.0", encrypted)

def decrypt_text():
    cipher_text = entry_text.get("1.0", tk.END).strip()
    key = entry_key.get().strip()
    if not cipher_text or not key:
        messagebox.showerror("Error", "Both text and key must be provided")
        return
    decrypted = sparx_decrypt(cipher_text, key)
    entry_result.delete("1.0", tk.END)
    entry_result.insert("1.0", decrypted)

# Create the main window
root = tk.Tk()
root.title("SPARX Encryption/Decryption")
root.geometry("600x400")

# Create a style
style = ttk.Style()
style.configure("TLabel", font=("Helvetica", 12))
style.configure("TButton", font=("Helvetica", 12))
style.configure("TEntry", font=("Helvetica", 12))

# Create and place the components
frame = ttk.Frame(root, padding="10 10 10 10")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

label_text = ttk.Label(frame, text="Text:")
label_text.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)

entry_text = tk.Text(frame, height=5, width=50)
entry_text.grid(row=0, column=1, padx=10, pady=10, sticky=(tk.W, tk.E))

label_key = ttk.Label(frame, text="Key:")
label_key.grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)

entry_key = ttk.Entry(frame, width=50)
entry_key.grid(row=1, column=1, padx=10, pady=10, sticky=(tk.W, tk.E))

button_encrypt = ttk.Button(frame, text="Encrypt", command=encrypt_text)
button_encrypt.grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)

button_decrypt = ttk.Button(frame, text="Decrypt", command=decrypt_text)
button_decrypt.grid(row=2, column=1, padx=10, pady=10, sticky=tk.E)

label_result = ttk.Label(frame, text="Result:")
label_result.grid(row=3, column=0, padx=10, pady=10, sticky=tk.W)

entry_result = tk.Text(frame, height=5, width=50)
entry_result.grid(row=3, column=1, padx=10, pady=10, sticky=(tk.W, tk.E))

# Start the main loop
root.mainloop()
