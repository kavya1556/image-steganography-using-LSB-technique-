import tkinter as tk
from tkinter import messagebox, filedialog, Toplevel, ttk
from cryptography.fernet import Fernet, InvalidToken
from PIL import Image, ImageTk
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
import threading
import os
import tkinter.simpledialog
import sqlite3
import datetime
import sys

# --- Helper Function to find bundled resources ---
def resource_path(relative_path):
    """ Get a path to a non-embedded resource, if needed """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    
    return os.path.join(base_path, relative_path)

# --- Color Palette and Fonts ---
COLOR_PRIMARY = "#2C3E50"
COLOR_SECONDARY = "#34495E"
COLOR_ACCENT = "#E74C3C"
COLOR_ACCENT_HOVER = "#C0392B"
COLOR_TEXT_PRIMARY = "white"
COLOR_TEXT_ACCENT = "white"
COLOR_INFO = "#27AE60"

FONT_TITLE = ("Arial", 18, "bold")
FONT_HEADING = ("Arial", 12, "bold")
FONT_BUTTON = ("Arial", 11, "bold")
FONT_LABEL = ("Arial", 10)
FONT_ENTRY = ("Arial", 10)

# --- Database Functions ---
DB_NAME = "steganography_logs.db"
DATABASE_PATH = os.path.join(os.path.expanduser("~"), DB_NAME) 

def init_db():
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                operation_type TEXT NOT NULL,
                source_file TEXT,
                hidden_data_type TEXT,
                result TEXT NOT NULL,
                message TEXT
            )
        ''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error during initialization: {e}")
        messagebox.showerror("Database Error", f"Could not initialize database: {e}")
    finally:
        if conn:
            conn.close()

def log_operation(operation_type, source_file, hidden_data_type, result, message):
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('''
            INSERT INTO operations (timestamp, operation_type, source_file, hidden_data_type, result, message)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp, operation_type, source_file, hidden_data_type, result, message))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error during logging: {e}")
    finally:
        if conn:
            conn.close()

# --- Core Logic Functions ---

def embed_data_in_image(image_path, data_bytes, key):
    output_path = "encoded_image.png"
    f = Fernet(key)
    encrypted_data = f.encrypt(data_bytes)
    image = Image.open(image_path).convert("RGB")
    pixels = list(image.getdata())
    width, height = image.size
    binary_secret = ''.join(format(byte, '08b') for byte in encrypted_data)
    delimiter = '1111111111111110'
    binary_secret += delimiter
    if len(binary_secret) % 3 != 0:
        binary_secret += '0' * (3 - len(binary_secret) % 3)
    if len(binary_secret) > width * height * 3:
        raise ValueError("Secret data is too long to hide in this image. Try a larger image or a smaller message.")
    index = 0
    new_pixels = []
    for r, g, b in pixels:
        if index < len(binary_secret):
            r = (r & ~1) | int(binary_secret[index])
            if index + 1 < len(binary_secret):
                g = (g & ~1) | int(binary_secret[index + 1])
            if index + 2 < len(binary_secret):
                b = (b & ~1) | int(binary_secret[index + 2])
            new_pixels.append((r, g, b))
            index += 3
        else:
            new_pixels.append((r, g, b))
    encoded_image = Image.new("RGB", (width, height))
    encoded_image.putdata(new_pixels)
    encoded_image.save(output_path)
    return output_path, key

def extract_data_from_image(file_path, key):
    try:
        f = Fernet(key.encode())
    except Exception:
        raise ValueError("Invalid key format. Please ensure it's a valid Fernet key.")
    try:
        image = Image.open(file_path).convert("RGB")
        pixels = list(image.getdata())
    except Exception:
        raise ValueError("Could not open image file. Please check the path and file type.")
    binary_secret = ""
    delimiter = '1111111111111110'
    delimiter_found = False
    for pixel in pixels:
        r, g, b = pixel
        binary_secret += str(r & 1)
        binary_secret += str(g & 1)
        binary_secret += str(b & 1)
        if delimiter in binary_secret:
            binary_secret = binary_secret[:binary_secret.find(delimiter)]
            delimiter_found = True
            break
    if not delimiter_found:
        raise ValueError("Delimiter not found. Message might be corrupted or not present in this image with this key.")
    if len(binary_secret) % 8 != 0:
        binary_secret = binary_secret + ('0' * (8 - len(binary_secret) % 8))
    secret_bytes = bytearray()
    for i in range(0, len(binary_secret), 8):
        byte_str = binary_secret[i:i+8]
        if len(byte_str) == 8:
            secret_bytes.append(int(byte_str, 2))
    try:
        original_data = f.decrypt(bytes(secret_bytes))
        return original_data
    except InvalidToken:
        raise ValueError("Decryption failed. Wrong key or corrupted data. Please check the key.")
    except Exception as e:
        raise ValueError(f"An unexpected error occurred during decryption: {e}")

def encrypt_file_data(input_file_path):
    key = Fernet.generate_key()
    f = Fernet(key)
    with open(input_file_path, "rb") as file:
        file_bytes = file.read()
    encrypted_bytes = f.encrypt(file_bytes)
    return encrypted_bytes, key

def decrypt_file_data(encrypted_file_path, key):
    try:
        f = Fernet(key.encode())
    except Exception:
        raise ValueError("Invalid key format. Please ensure it's a valid Fernet key.")
    try:
        with open(encrypted_file_path, "rb") as file:
            encrypted_bytes = file.read()
    except FileNotFoundError:
        raise ValueError(f"Encrypted file not found: {encrypted_file_path}")
    except Exception as e:
        raise ValueError(f"Error reading encrypted file: {e}")
    try:
        decrypted_bytes = f.decrypt(encrypted_bytes)
        return decrypted_bytes
    except InvalidToken:
        raise ValueError("Decryption failed. Wrong key or corrupted data. Please check the key.")
    except Exception as e:
        raise ValueError(f"An unexpected error occurred during decryption: {e}")

def send_email_custom(sender_email, smtp_password, receiver_email, key, attachment_path, subject="Encoded Data and Key"):
    server = None
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, smtp_password)
        message_body_receiver = 'The Key for Decrypting the hidden data is:\n' + key.decode()
        msg_receiver = MIMEMultipart()
        msg_receiver['From'] = sender_email
        msg_receiver['To'] = receiver_email
        msg_receiver['Subject'] = subject
        msg_receiver.attach(MIMEText(message_body_receiver, 'plain'))
        with open(attachment_path, "rb") as file:
            part = MIMEApplication(file.read(), Name=os.path.basename(attachment_path))
            part['Content-Disposition'] = f'attachment; filename="{os.path.basename(attachment_path)}"'
            msg_receiver.attach(part)
        server.send_message(msg_receiver)
        message_body_sender = f'A copy of the email with the Encoded data file has been sent to {receiver_email}.'
        msg_sender = MIMEMultipart()
        msg_sender['From'] = sender_email
        msg_sender['To'] = sender_email
        msg_sender['Subject'] = f'Confirmation: {subject} Sent'
        msg_sender.attach(MIMEText(message_body_sender, 'plain'))
        server.send_message(msg_sender)
        return True, "Email successfully sent to receiver and sender."
    except smtplib.SMTPAuthenticationError:
        return False, "SMTP Authentication Error: Incorrect email or password. For Gmail, use an App Password."
    except smtplib.SMTPConnectError:
        return False, "SMTP Connection Error: Could not connect to mail server. Check internet connection or SMTP settings."
    except Exception as e:
        return False, str(e)
    finally:
        if server:
            server.quit()

# --- GUI Helper Functions ---
def display_image_preview(image_path, preview_label, photo_image_ref):
    if not image_path:
        preview_label.config(image='')
        if photo_image_ref: photo_image_ref[0] = None
        return
    try:
        img = Image.open(image_path)
        img.thumbnail((150, 150))
        photo = ImageTk.PhotoImage(img)
        preview_label.config(image=photo)
        photo_image_ref[0] = photo
    except Exception as e:
        preview_label.config(image='')
        if photo_image_ref: photo_image_ref[0] = None
        messagebox.showerror("Image Error", f"Could not load image preview: {e}")

def browse_file(entry_widget, filetypes=None, preview_label=None, photo_image_ref=None):
    if filetypes is None:
        filetypes = [("All files", "*.*")]
    file_path = filedialog.askopenfilename(filetypes=filetypes)
    if file_path:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, file_path)
        if preview_label and photo_image_ref is not None:
            display_image_preview(file_path, preview_label, photo_image_ref)

def hide_text_threaded(image_path, message_bytes, sender, password, receiver, loading_window, progress_bar):
    hidden_data_type = "Unknown"
    try:
        progress_bar.start()
        key = Fernet.generate_key()
        output_path, _ = embed_data_in_image(image_path, message_bytes, key)
        success, email_status_message = send_email_custom(sender, password, receiver, key, output_path, subject="Encoded Text and Key")
        progress_bar.stop()
        loading_window.destroy()
        if success:
            messagebox.showinfo("Success", f"Text hidden successfully in 'encoded_image.png'.\n\n{email_status_message}")
            log_operation("Hide Text", image_path, "Text", "Success", email_status_message)
        else:
            messagebox.showerror("Email Error", f"Text hidden, but email failed to send: {email_status_message}")
            log_operation("Hide Text", image_path, "Text", "Failed", email_status_message)
    except Exception as e:
        progress_bar.stop()
        loading_window.destroy()
        messagebox.showerror("Error", str(e))
        log_operation("Hide Text", image_path, "Text", "Failed", str(e))

def hide_file_threaded(file_to_hide_path, sender, password, receiver, loading_window, progress_bar):
    try:
        progress_bar.start()
        encrypted_bytes, key = encrypt_file_data(file_to_hide_path)
        original_filename = os.path.basename(file_to_hide_path)
        output_filename = f"encrypted_secret_{original_filename}.bin"
        with open(output_filename, "wb") as f:
            f.write(encrypted_bytes)
        success, email_status_message = send_email_custom(sender, password, receiver, key, output_filename, subject="Encrypted File and Key")
        progress_bar.stop()
        loading_window.destroy()
        if success:
            messagebox.showinfo("Success", f"File encrypted successfully. Encrypted file saved as '{output_filename}'.\n\n{email_status_message}")
            log_operation("Hide File (Encrypt)", file_to_hide_path, "File", "Success", email_status_message)
        else:
            messagebox.showerror("Email Error", f"File encrypted, but email failed to send: {email_status_message}")
            log_operation("Hide File (Encrypt)", file_to_hide_path, "File", "Failed", email_status_message)
    except Exception as e:
        progress_bar.stop()
        loading_window.destroy()
        messagebox.showerror("Error", str(e))
        log_operation("Hide File (Encrypt)", file_to_hide_path, "File", "Failed", str(e))

def open_hide_file_form():
    top = Toplevel()
    top.title("Encrypt File")
    top.geometry("480x450")
    top.resizable(False, False)
    top.config(bg=COLOR_PRIMARY)
    frame = ttk.Frame(top, padding="15", style='Dark.TFrame')
    frame.pack(expand=True, fill="both")
    ttk.Label(frame, text="File to Encrypt Path:", font=FONT_LABEL, foreground=COLOR_TEXT_PRIMARY, background=COLOR_SECONDARY).grid(row=0, column=0, sticky="w", padx=10, pady=5)
    file_to_hide_entry = ttk.Entry(frame, width=35, style='Dark.TEntry', font=FONT_ENTRY)
    file_to_hide_entry.grid(row=0, column=1, pady=5, sticky="ew")
    ttk.Button(frame, text="Browse", command=lambda: browse_file(file_to_hide_entry), style='Accent.TButton').grid(row=0, column=2, padx=5, sticky="e")
    ttk.Label(frame, text="Sender Email:", font=FONT_LABEL, foreground=COLOR_TEXT_PRIMARY, background=COLOR_SECONDARY).grid(row=1, column=0, sticky="w", padx=10, pady=5)
    sender_entry = ttk.Entry(frame, width=35, style='Dark.TEntry', font=FONT_ENTRY)
    sender_entry.grid(row=1, column=1, columnspan=2, pady=5, sticky="ew")
    ttk.Label(frame, text="SMTP Password:", font=FONT_LABEL, foreground=COLOR_TEXT_PRIMARY, background=COLOR_SECONDARY).grid(row=2, column=0, sticky="w", padx=10, pady=5)
    password_entry = ttk.Entry(frame, width=35, show="*", style='Dark.TEntry', font=FONT_ENTRY)
    password_entry.grid(row=2, column=1, columnspan=2, pady=5, sticky="ew")
    ttk.Label(frame, text="Receiver Email:", font=FONT_LABEL, foreground=COLOR_TEXT_PRIMARY, background=COLOR_SECONDARY).grid(row=3, column=0, sticky="w", padx=10, pady=5)
    receiver_entry = ttk.Entry(frame, width=35, style='Dark.TEntry', font=FONT_ENTRY)
    receiver_entry.grid(row=3, column=1, columnspan=2, pady=5, sticky="ew")
    def process_hide_file():
        file_to_hide_path = file_to_hide_entry.get()
        sender = sender_entry.get()
        password = password_entry.get()
        receiver = receiver_entry.get()
        if not all([file_to_hide_path, sender, password, receiver]):
            messagebox.showerror("Error", "All fields are required.")
            log_operation("Hide File (Encrypt)", file_to_hide_path, "File", "Failed", "Missing fields")
            return
        if not os.path.exists(file_to_hide_path):
            messagebox.showerror("Error", "File to encrypt not found.")
            log_operation("Hide File (Encrypt)", file_to_hide_path, "File", "Failed", "Input file not found")
            return
        loading_window = Toplevel()
        loading_window.title("Processing...")
        loading_window.geometry("250x120")
        loading_window.transient(top)
        loading_window.grab_set()
        loading_window.config(bg=COLOR_PRIMARY)
        tk.Label(loading_window, text="Encrypting file and sending email...", padx=10, pady=10, bg=COLOR_PRIMARY, fg=COLOR_TEXT_PRIMARY).pack()
        progress_bar = ttk.Progressbar(loading_window, mode='indeterminate', length=200, style='TProgressbar')
        progress_bar.pack(pady=10)
        loading_window.update()
        thread = threading.Thread(target=hide_file_threaded, args=(file_to_hide_path, sender, password, receiver, loading_window, progress_bar))
        thread.start()
        top.wait_window(loading_window)
    ttk.Button(frame, text="Encrypt File", command=process_hide_file, style='Accent.TButton').grid(row=4, column=0, columnspan=3, pady=15)
    frame.grid_columnconfigure(1, weight=1)
    
# --- Extract File Form ---
def open_extract_file_form():
    top = Toplevel()
    top.title("Decrypt File")
    top.geometry("480x300")
    top.resizable(False, False)
    top.config(bg=COLOR_PRIMARY)
    frame = ttk.Frame(top, padding="15", style='Dark.TFrame')
    frame.pack(expand=True, fill="both")
    ttk.Label(frame, text="Encrypted File Path:", font=FONT_LABEL, foreground=COLOR_TEXT_PRIMARY, background=COLOR_SECONDARY).grid(row=0, column=0, sticky="w", padx=10, pady=5)
    encrypted_file_entry = ttk.Entry(frame, width=35, style='Dark.TEntry', font=FONT_ENTRY)
    encrypted_file_entry.grid(row=0, column=1, pady=5, sticky="ew")
    ttk.Button(frame, text="Browse", command=lambda: browse_file(encrypted_file_entry, filetypes=[("Encrypted Files", "*.bin"), ("All files", "*.*")]), style='Accent.TButton').grid(row=0, column=2, padx=5, sticky="e")
    ttk.Label(frame, text="Password (Key):", font=FONT_LABEL, foreground=COLOR_TEXT_PRIMARY, background=COLOR_SECONDARY).grid(row=1, column=0, sticky="w", padx=10, pady=5)
    key_entry = ttk.Entry(frame, width=35, style='Dark.TEntry', font=FONT_ENTRY)
    key_entry.grid(row=1, column=1, columnspan=2, pady=5, sticky="ew")
    def process_extract_file():
        encrypted_file_path = encrypted_file_entry.get()
        key = key_entry.get()
        if not all([encrypted_file_path, key]):
            messagebox.showerror("Error", "Encrypted File Path and Password (Key) are required.")
            log_operation("Extract File (Decrypt)", encrypted_file_path, "File", "Failed", "Missing fields")
            return
        if not os.path.exists(encrypted_file_path):
            messagebox.showerror("Error", "Encrypted file not found.")
            log_operation("Extract File (Decrypt)", encrypted_file_path, "File", "Failed", "Input file not found")
            return
        loading_window = Toplevel()
        loading_window.title("Processing...")
        loading_window.geometry("250x120")
        loading_window.transient(top)
        loading_window.grab_set()
        loading_window.config(bg=COLOR_PRIMARY)
        tk.Label(loading_window, text="Decrypting data...", padx=10, pady=10, bg=COLOR_PRIMARY, fg=COLOR_TEXT_PRIMARY).pack()
        progress_bar = ttk.Progressbar(loading_window, mode='indeterminate', length=200, style='TProgressbar')
        progress_bar.pack(pady=10)
        progress_bar.start()
        loading_window.update()
        try:
            decrypted_bytes = decrypt_file_data(encrypted_file_path, key)
            progress_bar.stop()
            loading_window.destroy()
            extracted_text_content = ""
            is_textual = False
            try:
                extracted_text_content = decrypted_bytes.decode('utf-8')
                non_printable_count = sum(1 for byte in decrypted_bytes if not (32 <= byte <= 126 or byte in {9, 10, 13}))
                if len(decrypted_bytes) > 0 and (non_printable_count / len(decrypted_bytes)) < 0.15:
                    is_textual = True
            except UnicodeDecodeError:
                is_textual = False
            if is_textual:
                messagebox.showinfo("File Decrypted - Message", f"File decrypted successfully.\n\n--- Decrypted Message ---\n{extracted_text_content}")
                log_operation("Extract File (Decrypt)", encrypted_file_path, "File", "Success", "Textual file content displayed")
            else:
                original_input_filename_base, _ = os.path.splitext(os.path.basename(encrypted_file_path))
                if original_input_filename_base.startswith("encrypted_secret_"):
                    temp_name = original_input_filename_base[len("encrypted_secret_"):]
                    if '.' in temp_name:
                        parts = temp_name.rsplit('.', 1)
                        suggested_filename = f"decrypted_{parts[0]}.{parts[1]}"
                    else:
                        suggested_filename = f"decrypted_{temp_name}.bin"
                else:
                    suggested_filename = f"decrypted_{original_input_filename_base}.bin"
                output_filename = suggested_filename
                counter = 1
                while os.path.exists(output_filename):
                    name_base, name_ext = os.path.splitext(suggested_filename)
                    output_filename = f"{name_base}_{counter}{name_ext}"
                    counter += 1
                with open(output_filename, "wb") as f:
                    f.write(decrypted_bytes)
                messagebox.showinfo("Success", f"File decrypted successfully.\n\nThis is a binary file (e.g., image, document, executable) and cannot be displayed directly.\nIt has been saved to:\n{os.path.abspath(output_filename)}")
                log_operation("Extract File (Decrypt)", encrypted_file_path, "File", "Success", f"Binary file saved to {output_filename}")
        except ValueError as ve:
            progress_bar.stop()
            loading_window.destroy()
            messagebox.showerror("Decryption Error", str(ve))
            log_operation("Extract File (Decrypt)", encrypted_file_path, "File", "Failed", str(ve))
        except Exception as e:
            progress_bar.stop()
            loading_window.destroy()
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
            log_operation("Extract File (Decrypt)", encrypted_file_path, "File", "Failed", str(e))
    ttk.Button(frame, text="Decrypt File", command=process_extract_file, style='Accent.TButton').grid(row=2, column=0, columnspan=3, pady=15)
    frame.grid_columnconfigure(1, weight=1)

# --- Hide Text Form ---
def open_hide_text_form():
    top = Toplevel()
    top.title("Hide Text")
    top.geometry("480x500")
    top.resizable(False, False)
    top.config(bg=COLOR_PRIMARY)
    frame = ttk.Frame(top, padding="15", style='Dark.TFrame')
    frame.pack(expand=True, fill="both")
    ttk.Label(frame, text="Image Preview:", font=FONT_LABEL, foreground=COLOR_TEXT_PRIMARY, background=COLOR_SECONDARY).grid(row=0, column=0, sticky="nw", padx=10, pady=5)
    image_preview_label = ttk.Label(frame, background=COLOR_SECONDARY, relief="solid", borderwidth=1)
    image_preview_label.grid(row=1, column=0, columnspan=3, pady=5, padx=10, sticky="ew")
    text_image_photo_ref = [None]
    ttk.Label(frame, text="Carrier Image Path:", font=FONT_LABEL, foreground=COLOR_TEXT_PRIMARY, background=COLOR_SECONDARY).grid(row=2, column=0, sticky="w", padx=10, pady=5)
    text_image_entry = ttk.Entry(frame, width=35, style='Dark.TEntry', font=FONT_ENTRY)
    text_image_entry.grid(row=2, column=1, pady=5, sticky="ew")
    ttk.Button(frame, text="Browse", command=lambda: browse_file(text_image_entry, filetypes=[("Image Files", "*.png *.jpg *.jpeg")], preview_label=image_preview_label, photo_image_ref=text_image_photo_ref), style='Accent.TButton').grid(row=2, column=2, padx=5, sticky="e")
    ttk.Label(frame, text="Message to Hide:", font=FONT_LABEL, foreground=COLOR_TEXT_PRIMARY, background=COLOR_SECONDARY).grid(row=3, column=0, sticky="w", padx=10, pady=5)
    text_message_entry = ttk.Entry(frame, width=35, style='Dark.TEntry', font=FONT_ENTRY)
    text_message_entry.grid(row=3, column=1, columnspan=2, pady=5, sticky="ew")
    ttk.Label(frame, text="Sender Email:", font=FONT_LABEL, foreground=COLOR_TEXT_PRIMARY, background=COLOR_SECONDARY).grid(row=4, column=0, sticky="w", padx=10, pady=5)
    sender_entry = ttk.Entry(frame, width=35, style='Dark.TEntry', font=FONT_ENTRY)
    sender_entry.grid(row=4, column=1, columnspan=2, pady=5, sticky="ew")
    ttk.Label(frame, text="SMTP Password:", font=FONT_LABEL, foreground=COLOR_TEXT_PRIMARY, background=COLOR_SECONDARY).grid(row=5, column=0, sticky="w", padx=10, pady=5)
    password_entry = ttk.Entry(frame, width=35, show="*", style='Dark.TEntry', font=FONT_ENTRY)
    password_entry.grid(row=5, column=1, columnspan=2, pady=5, sticky="ew")
    ttk.Label(frame, text="Receiver Email:", font=FONT_LABEL, foreground=COLOR_TEXT_PRIMARY, background=COLOR_SECONDARY).grid(row=6, column=0, sticky="w", padx=10, pady=5)
    receiver_entry = ttk.Entry(frame, width=35, style='Dark.TEntry', font=FONT_ENTRY)
    receiver_entry.grid(row=6, column=1, columnspan=2, pady=5, sticky="ew")
    def process_hide_text():
        image_path = text_image_entry.get()
        message = text_message_entry.get()
        sender = sender_entry.get()
        password = password_entry.get()
        receiver = receiver_entry.get()
        if not all([image_path, message, sender, password, receiver]):
            messagebox.showerror("Error", "All fields are required.")
            log_operation("Hide Text", image_path, "Text", "Failed", "Missing fields")
            return
        if not os.path.exists(image_path):
            messagebox.showerror("Error", "Carrier image not found.")
            log_operation("Hide Text", image_path, "Text", "Failed", "Carrier image not found")
            return
        data_to_hide = message.encode('utf-8')
        loading_window = Toplevel()
        loading_window.title("Processing...")
        loading_window.geometry("250x120")
        loading_window.transient(top)
        loading_window.grab_set()
        loading_window.config(bg=COLOR_PRIMARY)
        tk.Label(loading_window, text="Hiding text and sending email...", padx=10, pady=10, bg=COLOR_PRIMARY, fg=COLOR_TEXT_PRIMARY).pack()
        progress_bar = ttk.Progressbar(loading_window, mode='indeterminate', length=200, style='TProgressbar')
        progress_bar.pack(pady=10)
        progress_bar.start()
        loading_window.update()
        thread = threading.Thread(target=hide_text_threaded, args=(image_path, data_to_hide, sender, password, receiver, loading_window, progress_bar))
        thread.start()
        top.wait_window(loading_window)
    ttk.Button(frame, text="Hide Text", command=process_hide_text, style='Accent.TButton').grid(row=7, column=0, columnspan=3, pady=15)
    frame.grid_columnconfigure(1, weight=1)

# --- Extract Text Form ---
def open_extract_text_form():
    top = Toplevel()
    top.title("Extract Text")
    top.geometry("480x400")
    top.resizable(False, False)
    top.config(bg=COLOR_PRIMARY)
    frame = ttk.Frame(top, padding="15", style='Dark.TFrame')
    frame.pack(expand=True, fill="both")
    ttk.Label(frame, text="Image Preview:", font=FONT_LABEL, foreground=COLOR_TEXT_PRIMARY, background=COLOR_SECONDARY).grid(row=0, column=0, sticky="nw", padx=10, pady=5)
    image_preview_label = ttk.Label(frame, background=COLOR_SECONDARY, relief="solid", borderwidth=1)
    image_preview_label.grid(row=1, column=0, columnspan=3, pady=5, padx=10, sticky="ew")
    text_file_photo_ref = [None]
    ttk.Label(frame, text="Encoded Image Path:", font=FONT_LABEL, foreground=COLOR_TEXT_PRIMARY, background=COLOR_SECONDARY).grid(row=2, column=0, sticky="w", padx=10, pady=5)
    text_file_path_entry = ttk.Entry(frame, width=35, style='Dark.TEntry', font=FONT_ENTRY)
    text_file_path_entry.grid(row=2, column=1, pady=5, sticky="ew")
    ttk.Button(frame, text="Browse", command=lambda: browse_file(text_file_path_entry, filetypes=[("Image Files", "*.png *.jpg *.jpeg")], preview_label=image_preview_label, photo_image_ref=text_file_photo_ref), style='Accent.TButton').grid(row=2, column=2, padx=5, sticky="e")
    ttk.Label(frame, text="Password (Key):", font=FONT_LABEL, foreground=COLOR_TEXT_PRIMARY, background=COLOR_SECONDARY).grid(row=3, column=0, sticky="w", padx=10, pady=5)
    text_key_entry = ttk.Entry(frame, width=35, style='Dark.TEntry', font=FONT_ENTRY)
    text_key_entry.grid(row=3, column=1, columnspan=2, pady=5, sticky="ew")
    def process_extract_text():
        file_path = text_file_path_entry.get()
        key = text_key_entry.get()
        if not file_path or not key:
            messagebox.showerror("Error", "Please enter both the file path and the password (key).")
            log_operation("Extract Text", file_path, "Text", "Failed", "Missing fields")
            return
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "Encoded image not found.")
            log_operation("Extract Text", file_path, "Text", "Failed", "Encoded image not found")
            return
        loading_window = Toplevel()
        loading_window.title("Processing...")
        loading_window.geometry("250x120")
        loading_window.transient(top)
        loading_window.grab_set()
        loading_window.config(bg=COLOR_PRIMARY)
        tk.Label(loading_window, text="Extracting text...", padx=10, pady=10, bg=COLOR_PRIMARY, fg=COLOR_TEXT_PRIMARY).pack()
        progress_bar = ttk.Progressbar(loading_window, mode='indeterminate', length=200, style='TProgressbar')
        progress_bar.pack(pady=10)
        progress_bar.start()
        loading_window.update()
        try:
            original_bytes = extract_data_from_image(file_path, key)
            progress_bar.stop()
            loading_window.destroy()
            extracted_message = original_bytes.decode('utf-8', errors='replace')
            messagebox.showinfo("Decrypted Message", extracted_message)
            log_operation("Extract Text", file_path, "Text", "Success", "Text extracted successfully")
        except ValueError as ve:
            progress_bar.stop()
            loading_window.destroy()
            messagebox.showerror("Extraction Error", str(ve))
            log_operation("Extract Text", file_path, "Text", "Failed", str(ve))
        except Exception as e:
            progress_bar.stop()
            loading_window.destroy()
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
            log_operation("Extract Text", file_path, "Text", "Failed", str(e))
    ttk.Button(frame, text="Extract Text", command=process_extract_text, style='Accent.TButton').grid(row=4, column=0, columnspan=3, pady=15)
    frame.grid_columnconfigure(1, weight=1)

# --- Project Info Window ---
def show_project_info():
    info = Toplevel()
    info.title("Project Information")
    info.geometry("750x750")
    info.resizable(False, False)
    info.config(bg=COLOR_PRIMARY)
    ttk.Label(info, text="Project Information", font=FONT_TITLE, background=COLOR_PRIMARY, foreground=COLOR_TEXT_PRIMARY).pack(pady=15)
    intro_frame = ttk.Frame(info, padding="15 15 15 15", style='Dark.TFrame')
    intro_frame.pack(pady=10, padx=20, fill="x")
    intro = ("This project was developed by B Kavya, M Doni, KIRAN, DEEPIKA, RINKY as part of a "
             "Cyber Security Internship. This project is designed to Secure the Organizations in "
             "Real World from Cyber Frauds performed by Hackers.")
    ttk.Label(intro_frame, text=intro, wraplength=700, justify="left", font=FONT_LABEL, background=COLOR_SECONDARY, foreground=COLOR_TEXT_PRIMARY).pack()
    ttk.Label(info, text="Project Details", font=FONT_HEADING, background=COLOR_PRIMARY, foreground=COLOR_TEXT_PRIMARY).pack(pady=(15, 5))
    style = ttk.Style()
    style.theme_use('clam')
    style.configure("Treeview", background=COLOR_SECONDARY, foreground=COLOR_TEXT_PRIMARY, fieldbackground=COLOR_SECONDARY, rowheight=25, font=FONT_LABEL)
    style.map('Treeview', background=[('selected', COLOR_ACCENT)])
    style.configure("Treeview.Heading", background=COLOR_PRIMARY, foreground=COLOR_TEXT_PRIMARY, font=FONT_HEADING, padding=(5, 5))
    style.configure("TProgressbar", troughcolor=COLOR_SECONDARY, background=COLOR_ACCENT, lightcolor=COLOR_ACCENT, darkcolor=COLOR_ACCENT, bordercolor=COLOR_PRIMARY)
    tree_frame1 = ttk.Frame(info)
    tree_frame1.pack(pady=5, padx=20, fill="x", expand=True)
    tree1 = ttk.Treeview(tree_frame1, columns=("Field", "Value"), show="headings", height=4)
    tree1.heading("Field", text="Field")
    tree1.heading("Value", text="Value")
    tree1.column("Field", width=200, anchor="w")
    tree1.column("Value", width=500, anchor="w")
    scrollbar1 = ttk.Scrollbar(tree_frame1, orient="vertical", command=tree1.yview)
    tree1.configure(yscrollcommand=scrollbar1.set)
    scrollbar1.pack(side="right", fill="y")
    tree1.pack(side="left", fill="both", expand=True)
    data1 = [("Project Name", "Image Steganography using LSB"), ("Project Description", "Hiding Message with Encryption in image using LSB Algorithm"), ("Project Start Date", "06-JULY-2025"), ("Project End Date", "08-AUGUST-2025"), ("Project Status", "Completed"), ]
    for item in data1:
        tree1.insert("", tk.END, values=item)
    ttk.Label(info, text="Developer Details", font=FONT_HEADING, background=COLOR_PRIMARY, foreground=COLOR_TEXT_PRIMARY).pack(pady=(15, 5))
    tree_frame2 = ttk.Frame(info)
    tree_frame2.pack(pady=5, padx=20, fill="x", expand=True)
    tree2 = ttk.Treeview(tree_frame2, columns=("Name", "Employee ID", "Email"), show="headings", height=4)
    tree2.heading("Name", text="Name")
    tree2.heading("Employee ID", text="Employee ID")
    tree2.column("Name", width=200, anchor="w")
    tree2.column("Employee ID", width=150, anchor="w")
    tree2.column("Email", width=380, anchor="w")
    scrollbar2 = ttk.Scrollbar(tree_frame2, orient="vertical", command=tree2.yview)
    tree2.configure(yscrollcommand=scrollbar2.set)
    scrollbar2.pack(side="right", fill="y")
    tree2.pack(side="left", fill="both", expand=True)
    developers = [("DEEPIKA", "ST#IS#7742", "deepumanavelthi7@gmail.com"), ("RINKY", "ST#IS#7743", "mercyrinky129@gmail.com"), ("M.DONI SAIKALYANI", "ST#IS#7764", "donikalyani322@gmail.com"), ("B.KAVYA", "ST#IS#7765", "kavyabotsa94@gmail.com"), ("Kiranmaye", "ST#IS#7766", "kalakotikiranmaye570@gmail.com"), ]
    for dev in developers:
        tree2.insert("", tk.END, values=dev)
    ttk.Label(info, text="Company Details", font=FONT_HEADING, background=COLOR_PRIMARY, foreground=COLOR_TEXT_PRIMARY).pack(pady=(15, 5))
    tree_frame3 = ttk.Frame(info, )
    tree_frame3.pack(pady=5, padx=20, fill="x", expand=True)
    tree3 = ttk.Treeview(tree_frame3, columns=("Field", "Value"), show="headings", height=2)
    tree3.heading("Field", text="Field")
    tree3.heading("Value", text="Value")
    tree3.column("Field", width=200, anchor="w")
    tree3.column("Value", width=500, anchor="w")
    scrollbar3 = ttk.Scrollbar(tree_frame3, orient="vertical", command=tree3.yview)
    tree3.configure(yscrollcommand=scrollbar3.set)
    scrollbar3.pack(side="right", fill="y")
    tree3.pack(side="left", fill="both", expand=True)
    tree3.insert("", tk.END, values=("Company Name", "Supraja Technologies"))
    tree3.insert("", tk.END, values=("Email", "contact@suprajatechnologies.com"))
    close_button = ttk.Button(info, text="Close", command=info.destroy, style='Accent.TButton')
    close_button.pack(pady=20)
if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    root.title("Image Steganography!!!")
    root.geometry("450x600")
    root.resizable(False, False)
    root.config(bg=COLOR_PRIMARY)
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('TLabel', background=COLOR_PRIMARY, foreground=COLOR_TEXT_PRIMARY, font=FONT_LABEL)
    style.configure('TEntry', fieldbackground=COLOR_SECONDARY, foreground=COLOR_TEXT_PRIMARY, insertcolor=COLOR_TEXT_PRIMARY, borderwidth=1, relief="flat", font=FONT_ENTRY)
    style.map('TEntry', fieldbackground=[('focus', '#5D7C9A')])
    style.configure('TButton', background=COLOR_ACCENT, foreground=COLOR_TEXT_ACCENT, font=FONT_BUTTON, relief="flat", padding=10, borderwidth=0)
    style.map('TButton', background=[('active', COLOR_ACCENT_HOVER)], foreground=[('active', COLOR_TEXT_ACCENT)])
    style.configure('Main.TButton', width=25, padding=12)
    style.map('Main.TButton', background=[('active', COLOR_ACCENT_HOVER)], foreground=[('active', COLOR_TEXT_ACCENT)])
    style.configure('Dark.TFrame', background=COLOR_SECONDARY, borderwidth=0, relief="flat")
    style.configure('Dark.TLabel', background=COLOR_SECONDARY, foreground=COLOR_TEXT_PRIMARY, font=FONT_LABEL)
    style.configure('Dark.TEntry', fieldbackground="#46627C", foreground=COLOR_TEXT_PRIMARY, insertcolor=COLOR_TEXT_PRIMARY, borderwidth=0, relief="flat", font=FONT_ENTRY)
    style.configure("TProgressbar", troughcolor=COLOR_SECONDARY, background=COLOR_ACCENT, lightcolor=COLOR_ACCENT, darkcolor=COLOR_ACCENT, bordercolor=COLOR_PRIMARY)
    ttk.Button(root, text="Project Info", command=show_project_info, style='Main.TButton').pack(pady=(20, 10))
    ttk.Label(root, text="Image Steganography!!!", font=FONT_TITLE, background=COLOR_PRIMARY, foreground=COLOR_TEXT_PRIMARY).pack(pady=(10, 20))

    ttk.Button(root, text="Hide Text", command=open_hide_text_form, style='Main.TButton').pack(pady=10)
    ttk.Button(root, text="Extract Text", command=open_extract_text_form, style='Main.TButton').pack(pady=5)
    ttk.Button(root, text="Hide File", command=open_hide_file_form, style='Main.TButton').pack(pady=10)
    ttk.Button(root, text="Extract File", command=open_extract_file_form, style='Main.TButton').pack(pady=5)
    root.mainloop()