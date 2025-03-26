#!/usr/bin/env python3
import os
import random
import time
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
import string

def generate_salt():
    """Generate a random salt value."""
    return random.randint(1, 1000)

def get_timestamp(file_path):
    """Get the last modification timestamp of the file."""
    return int(os.path.getmtime(file_path))

def custom_hash(file_path, personal_key, salt=None):
    """Generate a custom 20-character alphanumeric hash with personal key, salt, and timestamp."""
    if not os.path.exists(file_path):
        return None, None, "File not found!"

    if salt is None:
        salt = generate_salt()

    try:
        with open(file_path, "rb") as f:
            content = f.read()

        timestamp = get_timestamp(file_path)

        # Combine file content, size, salt, timestamp, and personal key
        data = (
            content +
            str(os.path.getsize(file_path)).encode('utf-8') +
            str(salt).encode('utf-8') +
            str(timestamp).encode('utf-8') +
            personal_key.encode('utf-8')
        )

        # Generate a base hash using SHA-256
        base_hash = hashlib.sha256(data).hexdigest()

        # Define character pool: letters, digits, and special characters
        char_pool = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        random.seed(base_hash)  # Use base hash as seed for reproducibility

        # Generate a 20-character alphanumeric hash
        hash_value = ''.join(random.choice(char_pool) for _ in range(20))
        return hash_value, salt, timestamp
    except Exception as e:
        return None, None, f"Error: {str(e)}"

def save_hash(file_path, hash_value, salt, timestamp, personal_key):
    """Save the hash, salt, timestamp, and personal key to a file."""
    with open("integrity_check.txt", "a") as f:
        f.write(f"{file_path} | Hash: {hash_value} | Salt: {salt} | Timestamp: {timestamp} | Personal Key: {personal_key}\n")

def check_integrity(file_path, original_hash, salt, timestamp, personal_key):
    """Check the file's integrity with the custom hash."""
    current_hash, _, error_or_timestamp = custom_hash(file_path, personal_key, salt)
    if current_hash is None:
        return False, error_or_timestamp
    return current_hash == original_hash, "Check completed."

# GUI Functions
def select_file():
    """Open file dialog and display selected file path."""
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

def generate_hash():
    """Generate and display the 20-character hash for the selected file."""
    file_path = file_entry.get()
    personal_key = key_entry.get()

    if not file_path or not personal_key:
        messagebox.showerror("Error", "Please select a file and enter a personal key!")
        return

    hash_value, salt, timestamp_or_error = custom_hash(file_path, personal_key)
    if hash_value:
        result = f"Hash: {hash_value}\nSalt: {salt} | Timestamp: {timestamp_or_error} | Personal Key: {personal_key}"
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
        save_hash(file_path, hash_value, salt, timestamp_or_error, personal_key)
        messagebox.showinfo("Success", "20-character hash generated and saved to 'integrity_check.txt'.")
    else:
        messagebox.showerror("Error", f"Failed to generate hash: {timestamp_or_error}")

def verify_integrity():
    """Check the integrity of the selected file with the 20-character hash."""
    file_path = file_entry.get()
    original_hash = hash_entry.get()
    salt = salt_entry.get()
    timestamp = timestamp_entry.get()
    personal_key = key_entry.get()

    if not all([file_path, original_hash, salt, timestamp, personal_key]):
        messagebox.showerror("Error", "Please fill all fields!")
        return

    try:
        salt = int(salt)
        timestamp = int(timestamp)
    except ValueError:
        messagebox.showerror("Error", "Salt and Timestamp must be numbers!")
        return

    if len(original_hash) != 20:
        messagebox.showerror("Error", "Original hash must be 20 characters long!")
        return

    is_intact, message = check_integrity(file_path, original_hash, salt, timestamp, personal_key)
    result_text.delete(1.0, tk.END)
    if is_intact:
        result_text.insert(tk.END, "File is unchanged!")
        messagebox.showinfo("Result", "File integrity verified: unchanged!")
    else:
        result_text.insert(tk.END, f"File has been modified or error: {message}")
        messagebox.showwarning("Result", "File integrity check failed!")

# GUI Setup
root = tk.Tk()
root.title("Kadir's Unique File Integrity Tool")
root.geometry("600x450")

# File Selection
tk.Label(root, text="Select File:").grid(row=0, column=0, padx=5, pady=5)
file_entry = tk.Entry(root, width=50)
file_entry.grid(row=0, column=1, padx=5, pady=5)
tk.Button(root, text="Browse", command=select_file).grid(row=0, column=2, padx=5, pady=5)

# Personal Key Input
tk.Label(root, text="Personal Key:").grid(row=1, column=0, padx=5, pady=5)
key_entry = tk.Entry(root, width=20)
key_entry.grid(row=1, column=1, padx=5, pady=5)

# Generate Hash Button
tk.Button(root, text="Generate Hash", command=generate_hash).grid(row=2, column=1, pady=10)

# Integrity Check Fields
tk.Label(root, text="Original Hash (20 chars):").grid(row=3, column=0, padx=5, pady=5)
hash_entry = tk.Entry(root, width=30)
hash_entry.grid(row=3, column=1, padx=5, pady=5)

tk.Label(root, text="Salt:").grid(row=4, column=0, padx=5, pady=5)
salt_entry = tk.Entry(root, width=20)
salt_entry.grid(row=4, column=1, padx=5, pady=5)

tk.Label(root, text="Timestamp:").grid(row=5, column=0, padx=5, pady=5)
timestamp_entry = tk.Entry(root, width=20)
timestamp_entry.grid(row=5, column=1, padx=5, pady=5)

tk.Button(root, text="Check Integrity", command=verify_integrity).grid(row=6, column=1, pady=10)

# Result Display
tk.Label(root, text="Result:").grid(row=7, column=0, padx=5, pady=5)
result_text = tk.Text(root, height=5, width=50)
result_text.grid(row=7, column=1, padx=5, pady=5)

# Start the GUI
root.mainloop()