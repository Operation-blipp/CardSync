#!/usr/bin/env python3

import requests
import json
import base64
import sys

from requests.sessions import session
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import secrets

def pkcs7_pad(text, size):
    n = size - (len(text) % size)
    text += str(n) * n
    text = text.encode('utf-8')
    return text
    
session_key = secrets.token_bytes(16)
server_key = RSA.import_key(open("mykey.pem").read())
cipher_rsa = PKCS1_OAEP.new(server_key)

#keysize 16 bytes
#nonce 12 bytes     

directive = str(sys.argv[1])
print(directive)


url = "http://127.0.0.1:5000/"

headers = {
    "Content-Type": "application/json"
}

cardUID = "C40F6C94"
cardData = base64.b64encode(open(f"Archives/{cardUID}/LatestCard", "rb").read()).decode('utf-8')
print(cardData)
    

DirectiveArguments = {
    "cardUID" : cardUID, 
    "data" : cardData,
    "dev" : "False"
}

UserPayload = {
    "IdentificationType":"PasswordHash",
    "SendBackKey":"Base64KeyData",
    "IdentificationData":{
        "HashAlgorithm":"SHA256",
        "UserName":"oskhen",
        "PasswordHash": "312433c28349f63c4f387953ff337046e794bea0f9b9ebfcb08e90046ded9c76"
    },
    "DirectiveName":directive,
    "DirectiveArguments":DirectiveArguments
}

userpayloaddata = json.dumps(UserPayload)
cipher_aes = AES.new(session_key[:16], AES.MODE_CBC)
#cipher_aes.iv = session_key[16:]
ct_bytes = cipher_aes.encrypt(pkcs7_pad(userpayloaddata, AES.block_size))

#print(f"IV: {cipher_aes.iv}, nonce: {session_key}")
#ciphertext = base64.b64encode(ct_bytes).decode('utf-8')

session_key += cipher_aes.iv

enc_session_key = cipher_rsa.encrypt(session_key)

UserEncryptedRecord = {
    "CardSync_Version":"0.1.0",
    "KeyEncryptionType":"RSA2048",
    "PayloadEncryptionType":"AES_GCM_16_12",
    "EncryptedKey": base64.b64encode(enc_session_key).decode('utf-8'),
    "EncryptedPayload": base64.b64encode(ct_bytes).decode('utf-8')
}

r = requests.post(url, headers=headers, data=json.dumps(UserEncryptedRecord))
print(f"{r} - {r.text}")

#print(base64.b64encode(ct_bytes).decode('utf-8'))
#test_aes = AES.new(session_key[:16], AES.MODE_CBC, cipher_aes.iv)
#print(test_aes.decrypt(ct_bytes))