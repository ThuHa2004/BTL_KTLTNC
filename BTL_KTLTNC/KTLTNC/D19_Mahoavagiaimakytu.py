import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from datetime import datetime
import hashlib

# =========================
# LOG
# =========================
def ghi_log(noi_dung):
    with open("log.txt", "a", encoding="utf-8") as f:
        f.write(f"{datetime.now()} - {noi_dung}\n")

# =========================
# VALIDATE KEY
# =========================
def validate_key():
    k = entry_key.get().strip()
    algo = var_algo.get()

    if algo == "Caesar":
        if not k.isdigit():
            messagebox.showerror("Loi", "Key Caesar phai la so nguyen")
            return None
        return int(k)

    elif algo == "Vigenere":
        if not k.isalpha():
            messagebox.showerror("Loi", "Key Vigenere chi duoc chua chu cai")
            return None
        return k.upper()

    elif algo == "AES":
        if k == "":
            messagebox.showerror("Loi", "Key AES khong duoc rong")
            return None
        return k  # se encode thanh byte sau

    return None
# =========================
# CAESAR
# =========================
def caesar_encrypt(text, key):
    kq = ""
    for c in text:
        if c.isalpha():
            shift = key % 26
            if c.isupper():
                kq += chr((ord(c)-65+shift)%26+65)
            else:
                kq += chr((ord(c)-97+shift)%26+97)
        else:
            kq += c
    return kq

def caesar_decrypt(text, key):
    return caesar_encrypt(text, -key)

# =========================
# VIGENERE
# =========================
def vigenere_encrypt(text, key):
    kq=""
    key_len=len(key)
    j=0

    for c in text:
        if c.isalpha():
            shift=ord(key[j%key_len].lower())-97
            if c.isupper():
                kq+=chr((ord(c)-65+shift)%26+65)
            else:
                kq+=chr((ord(c)-97+shift)%26+97)
            j+=1
        else:
            kq+=c
    return kq

def vigenere_decrypt(text, key):
    kq=""
    key_len=len(key)
    j=0

    for c in text:
        if c.isalpha():
            shift=ord(key[j%key_len].lower())-97
            if c.isupper():
                kq+=chr((ord(c)-65-shift)%26+65)
            else:
                kq+=chr((ord(c)-97-shift)%26+97)
            j+=1
        else:
            kq+=c
    return kq

# =========================
# AES
# =========================
def aes_encrypt(text, key):
    key = hashlib.sha256(key.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return base64.b64encode(nonce + tag + ciphertext).decode()

def aes_decrypt(text, key):
    key = hashlib.sha256(key.encode()).digest()[:16]
    data = base64.b64decode(text)
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    cipher.verify(tag)
    return plaintext.decode()

# =========================
# FILE TXT
# =========================
def ma_hoa_file():
    #key = entry_key.get().strip()
    key = validate_key()
    if key is None:
        return

    if key == "":
        messagebox.showwarning("Thieu khoa", "Hay nhap khoa truoc!")
        return

    path = filedialog.askopenfilename(filetypes=[("Text file","*.txt")])
    if not path:
        return

    with open(path,"r",encoding="utf-8") as f:
        data=f.read()

    algo = var_algo.get()

    if algo == "Caesar":
        enc = caesar_encrypt(data, key)
    elif algo == "Vigenere":
        enc = vigenere_encrypt(data, key)
    else:
        enc = aes_encrypt(data, key)

    new_path = path + ".enc"
    with open(new_path,"w",encoding="utf-8") as f:
        f.write(f"{algo}\n")
        f.write(enc)

    ghi_log(f"Ma hoa file: {path} | algo={var_algo.get()}")
    messagebox.showinfo("OK", f"Da ma hoa\nFile: {new_path}")

def giai_ma_file():
    #key = entry_key.get().strip()
    key = validate_key()
    if key is None:
        return
    if key == "":
        messagebox.showwarning("Thieu khoa", "Hay nhap khoa truoc!")
        return

    path = filedialog.askopenfilename(filetypes=[("Enc file","*.enc")])
    if not path:
        return

    with open(path,"r",encoding="utf-8") as f:
        lines = f.readlines()

    algo = lines[0].strip()
    data = "".join(lines[1:])

    try:
        #algo = var_algo.get()

        if algo == "Caesar":
            dec = caesar_decrypt(data, key)
        elif algo == "Vigenere":
            dec = vigenere_decrypt(data, key)
        else:
            dec = aes_decrypt(data, key)
    except:
        messagebox.showerror("Sai khoa", "Key sai hoac file loi!")
        return

    new_path = path + ".txt"
    with open(new_path,"w",encoding="utf-8") as f:
        f.write(dec)

    ghi_log(f"Giai ma file: {path} | algo={algo}")
    messagebox.showinfo("OK", f"Da giai ma\nFile: {new_path}")

# =========================
# GUI
# =========================
def ma_hoa():
    text = txt_input.get("1.0",tk.END).strip()
    key = validate_key()
    if key is None:
        return

    algo = var_algo.get()

    if algo=="Caesar":
        kq = caesar_encrypt(text,key)
    elif algo=="Vigenere":
        kq = vigenere_encrypt(text,key)
    else:
        kq = aes_encrypt(text,key)

    txt_output.delete("1.0",tk.END)
    txt_output.insert(tk.END,kq)
    ghi_log("Ma hoa chuoi")

def giai_ma():
    text = txt_input.get("1.0",tk.END).strip()
    key = validate_key()
    if key is None:
        return
    algo = var_algo.get()

    if algo=="Caesar":
        kq = caesar_decrypt(text,key)
    elif algo=="Vigenere":
        kq = vigenere_decrypt(text,key)
    else:
        kq = aes_decrypt(text,key)

    txt_output.delete("1.0",tk.END)
    txt_output.insert(tk.END,kq)
    ghi_log("Giai ma chuoi")

root = tk.Tk()
root.title("CHUONG TRINH MA HOA - GIAI MA CHUOI KY TU")
root.geometry("760x560")
root.configure(bg="#f4f6f8")

font_title=("Segoe UI",16,"bold")
font=("Segoe UI",11)
btn_font=("Segoe UI",10,"bold")

# TITLE
tk.Label(root,text="CHUONG TRINH MA HOA - GIAI MA",
         font=font_title,bg="#f4f6f8",fg="#2c3e50").pack(pady=10)

# INPUT
frame=tk.Frame(root,bg="#f4f6f8")
frame.pack()

tk.Label(frame,text="Nhap chuoi",font=font,bg="#f4f6f8").pack()
txt_input=tk.Text(frame,height=5,width=70,font=font)
txt_input.pack(pady=5)

# KEY
tk.Label(frame,text="Khoa",font=font,bg="#f4f6f8").pack()
entry_key=tk.Entry(frame,width=30,font=font)
entry_key.pack(pady=5)

# ALGO
var_algo=tk.StringVar(value="Caesar")
tk.OptionMenu(frame,var_algo,"Caesar","Vigenere","AES").pack(pady=5)

# BUTTONS
btn_frame=tk.Frame(root,bg="#f4f6f8")
btn_frame.pack(pady=10)

tk.Button(btn_frame,text="Ma hoa",width=15,font=btn_font,bg="#3498db",fg="white",command=ma_hoa).grid(row=0,column=0,padx=5)
tk.Button(btn_frame,text="Giai ma",width=15,font=btn_font,bg="#2ecc71",fg="white",command=giai_ma).grid(row=0,column=1,padx=5)
tk.Button(btn_frame,text="Ma hoa file",width=15,font=btn_font,bg="#9b59b6",fg="white",command=ma_hoa_file).grid(row=0,column=2,padx=5)
tk.Button(btn_frame,text="Giai ma file",width=15,font=btn_font,bg="#e67e22",fg="white",command=giai_ma_file).grid(row=0,column=3,padx=5)

# OUTPUT
tk.Label(root,text="Ket qua",font=font,bg="#f4f6f8").pack()
txt_output=tk.Text(root,height=6,width=70,font=font)
txt_output.pack(pady=5)

root.mainloop()