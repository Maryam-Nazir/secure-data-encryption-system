# Secure Data Encryption System Using Streamlit:
import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet

# -- Setup --
DATA_FILE = 'data_store.json'
KEY_FILE = 'secret.key'
LOCKOUT_TIME = 60  # seconds
MAX_ATTEMPTS = 3
MASTER_PASSWORD = "admin789"

# -- Load or generate Fernet key --
def load_or_generate_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        return key

cipher = Fernet(load_or_generate_key())

# -- Load stored data --
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

# -- Save data to file --
def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

stored_data = load_data()

# -- Session state initialization --
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = 0

# -- Utility Functions --
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def is_locked_out():
    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
        if time.time() < st.session_state.lockout_time:
            return True
    return False

def lockout():
    st.session_state.lockout_time = time.time() + LOCKOUT_TIME

# -- Streamlit UI --
st.set_page_config(page_title="Secure Encryption App")
st.title("🛡️ Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("This app allows you to **securely store and retrieve** your sensitive data using encryption and passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    username = st.text_input("Username")
    user_data = st.text_area("Enter Data")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Encrypt & Save"):
        if username and user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data[username] = {"encrypted_text": encrypted_text, "passkey": hashed}
            save_data(stored_data)
            st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ Both fields are required.")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    if is_locked_out():
        st.error("🔒 Too many failed attempts. Please wait...")
        remaining = int(st.session_state.lockout_time - time.time())
        st.info(f"⏳ Try again in {remaining} seconds")
    else:
        username = st.text_input("Enter Username")
        passkey = st.text_input("Enter Passkey", type="password")

        if st.button("Decrypt"):
            if username in stored_data:
                hashed = hash_passkey(passkey)
                if stored_data[username]["passkey"] == hashed:
                    decrypted = decrypt_data(stored_data[username]["encrypted_text"])
                    st.success(f"✅ Decrypted Data: {decrypted}")
                    st.session_state.failed_attempts = 0
                else:
                    st.session_state.failed_attempts += 1
                    attempts_left = MAX_ATTEMPTS - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")
                    if attempts_left <= 0:
                        st.warning("🚫 Locked out for security reasons!")
                        lockout()
                        st.experimental_user()
            else:
                st.error("⚠️ Username not found!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password", type="password")
    if st.button("Login"):
        if login_pass == MASTER_PASSWORD:
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.experimental_user
        else:
            st.error("❌ Incorrect master password!")