#!/usr/bin/env python3
import os
import random
import time
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
import string

def get_salt():
    return random.randint(1, 1000)

def get_time(file):
    return int(os.path.getmtime(file))

def make_hash(file, key, salt=None):
    if not os.path.exists(file):
        return None, None, "File not found!"
    if salt is None:
        salt = get_salt()
    try:
        with open(file, "rb") as f:
            data = f.read()
        timestamp = get_time(file)
        combined = (
            data +
            str(os.path.getsize(file)).encode('utf-8') +
            str(salt).encode('utf-8') +
            str(timestamp).encode('utf-8') +
            key.encode('utf-8')
        )
        base = hashlib.sha256(combined).hexdigest()
        chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        random.seed(base)
        hash_val = ''.join(random.choice(chars) for _ in range(20))
        return hash_val, salt, timestamp
    except:
        return None, None, "Something went wrong!"

def save_it(file, hash_val, salt, timestamp, key):
    with open("integrity_check.txt", "a") as f:
        f.write(f"{file} | Hash: {hash_val} | Salt: {salt} | Timestamp: {timestamp} | Key: {key}\n")

def check_file(file, old_hash, salt, timestamp, key):
    new_hash, _, error = make_hash(file, key, salt)
    if new_hash is None:
        return False, error
    return new_hash == old_hash, "Done!"

def pick_file():
    file = filedialog.askopenfilename()
    if file:
        file_box.delete(0, tk.END)
        file_box.insert(0, file)

def create_hash():
    file = file_box.get()
    key = key_box.get()
    if not file or not key:
        messagebox.showerror("Oops", "Pick a file and enter a key first!")
        return
    hash_val, salt, timestamp = make_hash(file, key)
    if hash_val:
        output = f"Hash: {hash_val}\nSalt: {salt} | Timestamp: {timestamp} | Key: {key}"
        result_box.delete(1.0, tk.END)
        result_box.insert(tk.END, output)
        save_it(file, hash_val, salt, timestamp, key)
        messagebox.showinfo("Done", "Hash created and saved!")
    else:
        messagebox.showerror("Error", f"Couldn’t make hash: {timestamp}")

def verify_file():
    file = file_box.get()
    old_hash = hash_box.get()
    salt = salt_box.get()
    timestamp = time_box.get()
    key = key_box.get()
    if not all([file, old_hash, salt, timestamp, key]):
        messagebox.showerror("Oops", "Fill in all the fields!")
        return
    try:
        salt = int(salt)
        timestamp = int(timestamp)
    except:
        messagebox.showerror("Error", "Salt and Timestamp need to be numbers!")
        return
    if len(old_hash) != 20:
        messagebox.showerror("Error", "Hash must be 20 characters!")
        return
    intact, msg = check_file(file, old_hash, salt, timestamp, key)
    result_box.delete(1.0, tk.END)
    if intact:
        result_box.insert(tk.END, "File hasn’t changed!")
        messagebox.showinfo("Result", "File is safe!")
    else:
        result_box.insert(tk.END, f"File changed or error: {msg}")
        messagebox.showwarning("Result", "File check failed!")

# Set up the window
window = tk.Tk()
window.title("KadirLock")
window.geometry("800x500")

# Add a lock icon (needs a .ico file)
try:
    window.iconbitmap("lock.ico")
except:
    pass  # If no icon file, just skip it

# File picker
tk.Label(window, text="Select File:").grid(row=0, column=0, padx=5, pady=5)
file_box = tk.Entry(window, width=60)
file_box.grid(row=0, column=1, padx=5, pady=5)
tk.Button(window, text="Browse", command=pick_file).grid(row=0, column=2, padx=5, pady=5)

# Key input
tk.Label(window, text="Your Key:").grid(row=1, column=0, padx=5, pady=5)
key_box = tk.Entry(window, width=20)
key_box.grid(row=1, column=1, padx=5, pady=5)

# Generate button
tk.Button(window, text="Generate Hash", command=create_hash).grid(row=2, column=1, pady=10)

# Check fields
tk.Label(window, text="Original Hash (20 chars):").grid(row=3, column=0, padx=5, pady=5)
hash_box = tk.Entry(window, width=30)
hash_box.grid(row=3, column=1, padx=5, pady=5)

tk.Label(window, text="Salt:").grid(row=4, column=0, padx=5, pady=5)
salt_box = tk.Entry(window, width=20)
salt_box.grid(row=4, column=1, padx=5, pady=5)

tk.Label(window, text="Timestamp:").grid(row=5, column=0, padx=5, pady=5)
time_box = tk.Entry(window, width=20)
time_box.grid(row=5, column=1, padx=5, pady=5)

tk.Button(window, text="Check Integrity", command=verify_file).grid(row=6, column=1, pady=10)

# Result area
tk.Label(window, text="Result:").grid(row=7, column=0, padx=5, pady=5)
result_box = tk.Text(window, height=5, width=60)
result_box.grid(row=7, column=1, padx=5, pady=5)

# Run the app
window.mainloop()