import tkinter as tk
from PIL import Image, ImageTk
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_and_encrypt_notes():
    title = title_entry.get()
    message = input_text.get("1.0", tk.END).strip()
    master_secret = master_entry_input.get()

    if not title or not message or not master_secret:
        messagebox.showwarning(title="Error", message="Please enter all information")
    else:
        message_encrypted = encode(master_secret, message)
        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f"\nTitle: {title}\nMessage: {message_encrypted}\n{'='*30}\n")
        except FileNotFoundError:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f"\nTitle: {title}\nMessage: {message_encrypted}\n{'='*30}\n")
        finally:
            title_entry.delete(0, tk.END)
            master_entry_input.delete(0, tk.END)
            input_text.delete("1.0", tk.END)

def decrypt_notes():
    message_encrypted = input_text.get("1.0", tk.END).strip()
    master_secret = master_entry_input.get()

    if not message_encrypted or not master_secret:
        messagebox.showinfo(title="Error", message="Please enter all information")
    else:
        try:
            decrypted_message = decode(master_secret, message_encrypted)
            input_text.delete("1.0", tk.END)
            input_text.insert("1.0", decrypted_message)
        except Exception as e:
            messagebox.showinfo(title="Error", message=f"Decryption failed: {e}")

# Pencere oluştur
FONT = ("Verdana", 15, "normal")
window = tk.Tk()
window.title("Secret Notes")

# Görsel ekleme
resim = ImageTk.PhotoImage(Image.open("C:/Users/90545/Desktop/top_secret.png"))
img = tk.Label(window, image=resim)
img.pack()

# Pencere arayüzü
title_label = tk.Label(text="Enter your title", font=FONT)
title_label.pack()

title_entry = tk.Entry(width=30)
title_entry.pack()

input_label = tk.Label(text="Enter your secret", font=FONT)
input_label.pack()

input_text = tk.Text(width=40, height=10)
input_text.pack()

master_secret_label = tk.Label(text="Enter master key", font=FONT)
master_secret_label.pack()

master_entry_input = tk.Entry(width=30)
master_entry_input.pack()

save_button = tk.Button(text="Save & Encrypt", command=save_and_encrypt_notes)
save_button.pack()

decrypt_button = tk.Button(text="Decrypt", command=decrypt_notes)
decrypt_button.pack()

window.geometry("600x600")
window.mainloop()

