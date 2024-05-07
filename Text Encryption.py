# Pinnacle Lab
# Task 1 - Text Encryption

import tkinter as tk
from tkinter import ttk, messagebox
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

class EncryptionApp:
    def __init__(self,root):
        self.root = root
        self.root.title("Text Encryption Tool")

        self.algorithm_var = tk.StringVar()
        self.algorithm_var.set("AES")

        self.create_widgets()

    def create_widgets(self):
        # Algorithm selection
        algorithm_label = ttk.Label(self.root, text = "Select Algorithm")
        algorithm_combobox = ttk.Combobox(self.root, textvariable=self.algorithm_var, values=["AES","DES","RSA"])

        # Plaintext entry
        plaintext_label = ttk.Label(self.root, text="Enter Plaintext:")
        self.plaintext_entry = ttk.Entry(self.root, width= 50) 

        # Encryption button
        encrypt_button =ttk.Button(self.root, text="Encrypt",command=self.encrypt_text)

        # Ciphertext display
        ciphertext_label = ttk.Label(self.root, text="Ciphertext:")
        self.ciphertext_text = tk.Text(self.root, height=5, width=50)

        # Pack widgets
        algorithm_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        algorithm_combobox.grid(row=0, column=1, padx=5, pady=5)
        plaintext_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.plaintext_entry.grid(row=1, column=1, padx=5, pady=5)
        encrypt_button.grid(row=2, columnspan=2, padx=5, pady=5)
        ciphertext_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.ciphertext_text.grid(row=3, column=1, padx=5, pady=5) 

    def encrypt_text(self):
        algorithm = self.algorithm_var.get()
        plaintext = self.plaintext_entry.get()

        if algorithm == "AES":
            key = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_EAX)
            ciphertext, _ = cipher.encrypt_and_digest(plaintext.encode())
            self.ciphertext_text.delete(1.0, tk.END)
            self.ciphertext_text.insert(tk.END, ciphertext.hex())
        elif algorithm == "DES":
            key = get_random_bytes(8)
            cipher = DES.new(key, DES.MODE_ECB)
            plaintext += ' ' * (8 - len(plaintext) % 8)
            ciphertext = cipher.encrypt(plaintext.encode())
            self.ciphertext_text.delete(1.0, tk.END)
            self.ciphertext_text.insert(tk.END, ciphertext.hex())
        elif algorithm == "RSA":
            key = RSA.generate(2048)
            public_key = key.public_key()
            cipher = PKCS1_OAEP.new(public_key)
            ciphertext = cipher.encrypt(plaintext.encode())
            self.ciphertext_text.delete(1.0, tk.END)
            self.ciphertext_text.insert(tk.END, ciphertext.hex())
        else:
            messagebox.showerror("Error", "Invalid algorithm selected.")


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()                              