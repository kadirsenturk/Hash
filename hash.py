#!/usr/bin/env python3
import os
import random
import time
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import string

def get_salt():
    return random.randint(1, 1000)

def get_time(file):
    return int(os.path.getmtime(file))

def make_hash(file, key, salt=None, progress=None):
    if not os.path.exists(file):
        return None, None, "File not found!"
    if salt is None:
        salt = get_salt()
    try:
        with open(file, "rb") as f:
            data = f.read()
        timestamp = get_time(file)
        combined = data + str(os.path.getsize(file)).encode() + str(salt).encode() + str(timestamp).encode() + key.encode()
        base = hashlib.sha256(combined).hexdigest()
        chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        random.seed(base)
        hash_val = ''.join(random.choice(chars) for _ in range(20))
        if progress:
            for i in range(0, len(data), 1024):
                progress['value'] = (i / len(data)) * 100
                window.update()
        return hash_val, salt, timestamp
    except:
        return None, None, "Oops, something broke!"

def save_stuff(file, hash_val, salt, timestamp, key):
    with open("integrity_check.txt", "a") as f:
        f.write(f"{file} | Hash: {hash_val} | Salt: {salt} | Time: {timestamp} | Key: {key}\n")

def check_it(file, old_hash, salt, timestamp, key):
    new_hash, _, err = make_hash(file, key, salt)
    if new_hash is None:
        return False, err
    return new_hash == old_hash, "Checked!"

def pick_file():
    file = filedialog.askopenfilename()
    if file:
        file_box.delete(0, tk.END)
        file_box.insert(0, file)

def do_hash():
    file = file_box.get()
    key = key_box.get()
    if not file or not key:
        messagebox.showerror("Hey!", "Need a file and a key!")
        return
    progress_bar['value'] = 0
    progress_bar.grid(row=2, column=2, padx=5, pady=5)
    hash_val, salt, timestamp = make_hash(file, key, progress=progress_bar)
    progress_bar.grid_remove()
    if hash_val:
        result_box.delete(1.0, tk.END)
        result_box.insert(tk.END, f"Hash: {hash_val}\nSalt: {salt} | Time: {timestamp} | Key: {key}")
        save_stuff(file, hash_val, salt, timestamp, key)
        messagebox.showinfo("Cool!", "Hash done and saved!")
    else:
        messagebox.showerror("Uh-oh", f"Hash failed: {timestamp}")

def check_file():
    file = file_box.get()
    old_hash = hash_box.get()
    salt = salt_box.get()
    timestamp = time_box.get()
    key = key_box.get()
    if not all([file, old_hash, salt, timestamp, key]):
        messagebox.showerror("Hey!", "Fill everything!")
        return
    try:
        salt = int(salt)
        timestamp = int(timestamp)
    except:
        messagebox.showerror("Nope", "Salt and Time need to be numbers!")
        return
    if len(old_hash) != 20:
        messagebox.showerror("Nope", "Hash should be 20 chars!")
        return
    ok, msg = check_it(file, old_hash, salt, timestamp, key)
    result_box.delete(1.0, tk.END)
    if ok:
        result_box.insert(tk.END, "File’s good!")
        messagebox.showinfo("Nice", "File’s safe!")
    else:
        result_box.insert(tk.END, f"File’s changed or error: {msg}")
        messagebox.showwarning("Oops", "Check failed!")

window = tk.Tk()
window.title("IntegrityVault")
window.geometry("800x500")
window.configure(bg="#2e2e2e")

# Padlock icon
try:
    window.iconbitmap("C:/Users/Alban/Documents/GitHub/Hash/padlock.ico")
except:
    pass

tk.Label(window, text="Pick File:", bg="#2e2e2e", fg="white").grid(row=0, column=0, padx=5, pady=5)
file_box = tk.Entry(window, width=60, bg="#404040", fg="white")
file_box.grid(row=0, column=1, padx=5, pady=5)
tk.Button(window, text="Browse", command=pick_file, bg="#555555", fg="white").grid(row=0, column=2, padx=5, pady=5)

tk.Label(window, text="Your Key:", bg="#2e2e2e", fg="white").grid(row=1, column=0, padx=5, pady=5)
key_box = tk.Entry(window, width=20, bg="#404040", fg="white")
key_box.grid(row=1, column=1, padx=5, pady=5)

progress_bar = ttk.Progressbar(window, length=200, mode='determinate')

tk.Button(window, text="Make Hash", command=do_hash, bg="#555555", fg="white").grid(row=2, column=1, pady=10)

tk.Label(window, text="Old Hash (20 chars):", bg="#2e2e2e", fg="white").grid(row=3, column=0, padx=5, pady=5)
hash_box = tk.Entry(window, width=30, bg="#404040", fg="white")
hash_box.grid(row=3, column=1, padx=5, pady=5)

tk.Label(window, text="Salt:", bg="#2e2e2e", fg="white").grid(row=4, column=0, padx=5, pady=5)
salt_box = tk.Entry(window, width=20, bg="#404040", fg="white")
salt_box.grid(row=4, column=1, padx=5, pady=5)

tk.Label(window, text="Time:", bg="#2e2e2e", fg="white").grid(row=5, column=0, padx=5, pady=5)
time_box = tk.Entry(window, width=20, bg="#404040", fg="white")
time_box.grid(row=5, column=1, padx=5, pady=5)

tk.Button(window, text="Check It", command=check_file, bg="#555555", fg="white").grid(row=6, column=1, pady=10)

tk.Label(window, text="Result:", bg="#2e2e2e", fg="white").grid(row=7, column=0, padx=5, pady=5)
result_box = tk.Text(window, height=5, width=60, bg="#404040", fg="white")
result_box.grid(row=7, column=1, padx=5, pady=5)

window.mainloop()