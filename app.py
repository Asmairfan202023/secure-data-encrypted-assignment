import streamlit as st
import hashlib
import base64
import json
import os
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

# ---------------------------
# Global Constants & Setup
# ---------------------------
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

DATA_FILE = "user_data.json"
LOCK_FILE = "lockout.json"
MAX_ATTEMPTS = 3
LOCKOUT_DURATION_MINUTES = 5

# ---------------------------
# Load + Save Helpers
# ---------------------------
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file)

def load_lockout():
    if os.path.exists(LOCK_FILE):
        with open(LOCK_FILE, "r") as file:
            return json.load(file)
    return {"attempts": 0, "locked_until": None}

def save_lockout(lockout):
    with open(LOCK_FILE, "w") as file:
        json.dump(lockout, file)

# ---------------------------
# Security Functions
# ---------------------------
def pbkdf2_hash(text, salt):
    result = hashlib.pbkdf2_hmac("sha256", text.encode(), salt.encode(), 100000)
    return base64.urlsafe_b64encode(result).decode()

def encrypt_data(plaintext):
    return cipher.encrypt(plaintext.encode()).decode()

def decrypt_data(ciphertext):
    return cipher.decrypt(ciphertext.encode()).decode()

# ---------------------------
# Core User Functions
# ---------------------------
def register_user(username, password):
    data = load_data()
    if username in data:
        return False, "User already exists!"
    hashed_pass = pbkdf2_hash(password, username)
    data[username] = {"password": hashed_pass, "data": []}
    save_data(data)
    return True, "User registered successfully!"

def authenticate_user(username, password):
    data = load_data()
    if username not in data:
        return False
    return pbkdf2_hash(password, username) == data[username]["password"]

def store_user_data(username, text, passkey):
    data = load_data()
    hashed_key = pbkdf2_hash(passkey, username)
    encrypted = encrypt_data(text)
    data[username]["data"].append({"encrypted": encrypted, "passkey": hashed_key})
    save_data(data)
    return encrypted

def retrieve_user_data(username, encrypted_text, passkey):
    lockout = load_lockout()
    if is_locked(lockout):
        return "🔒 Locked out. Please wait."

    data = load_data()
    hashed_key = pbkdf2_hash(passkey, username)

    for item in data[username]["data"]:
        if item["encrypted"] == encrypted_text and item["passkey"] == hashed_key:
            lockout["attempts"] = 0
            save_lockout(lockout)
            return decrypt_data(encrypted_text)

    lockout["attempts"] += 1
    if lockout["attempts"] >= MAX_ATTEMPTS:
        lockout["locked_until"] = (datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)).isoformat()
    save_lockout(lockout)
    return f"❌ Incorrect passkey. Attempts left: {MAX_ATTEMPTS - lockout['attempts']}"

def is_locked(lockout):
    if lockout["locked_until"]:
        unlock_time = datetime.fromisoformat(lockout["locked_until"])
        if datetime.now() < unlock_time:
            return True
    return False

def admin_login(password):
    if password == "admin123":
        save_lockout({"attempts": 0, "locked_until": None})
        return True
    return False

# ---------------------------
# Streamlit UI
# ---------------------------
st.title("🔐 Enhanced Secure Data System")

menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data", "Admin"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.markdown("## 🏠 Welcome")
    st.write("Use this secure app to store and retrieve encrypted data safely.")

elif choice == "Register":
    st.subheader("👤 Register New User")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        success, msg = register_user(username, password)
        st.success(msg) if success else st.error(msg)

elif choice == "Login":
    st.subheader("🔐 User Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if authenticate_user(username, password):
            st.session_state["user"] = username
            st.success("✅ Logged in")
        else:
            st.error("❌ Invalid credentials")

elif choice == "Store Data":
    if "user" in st.session_state:
        st.subheader("📥 Store Secure Data")
        text = st.text_area("Enter data")
        passkey = st.text_input("Passkey", type="password")
        if st.button("Encrypt & Store"):
            encrypted = store_user_data(st.session_state["user"], text, passkey)
            st.success(f"✅ Encrypted and stored:\n{encrypted}")
    else:
        st.warning("⚠️ Please log in first.")

elif choice == "Retrieve Data":
    if "user" in st.session_state:
        st.subheader("📤 Retrieve Data")
        encrypted_text = st.text_area("Encrypted Text")
        passkey = st.text_input("Passkey", type="password")
        if st.button("Decrypt"):
            result = retrieve_user_data(st.session_state["user"], encrypted_text, passkey)
            if result.startswith("❌") or result.startswith("🔒"):
                st.error(result)
            else:
                st.success(f"✅ Decrypted: {result}")
    else:
        st.warning("⚠️ Please log in first.")

elif choice == "Admin":
    st.subheader("🔑 Admin Login")
    master_pass = st.text_input("Enter Admin Password", type="password")
    if st.button("Unlock"):
        if admin_login(master_pass):
            st.success("✅ Lockout reset.")
        else:
            st.error("❌ Invalid admin password.")
