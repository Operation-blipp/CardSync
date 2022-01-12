#!/usr/bin/env python3

import requests
import json
import base64
import sys

from requests.sessions import session
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import secrets

RSA_KEY_PATH = "mykey.pem" 

def pkcs7_pad(text, size):
    n = size - (len(text) % size)
    text += chr(n) * n
    text = text.encode('utf-8')
    return text

def pkcs7_unpad(text):
    x = (text[-1:])
    x = ord(x)
    return text[:-x]

def decryptPayload(encryptedKey, encryptedPayload):
    
    serverKey = RSA.import_key(open(RSA_KEY_PATH).read())
    rsaKey = PKCS1_OAEP.new(serverKey)
    sessionKey = rsaKey.decrypt(base64.b64decode(encryptedKey))
    #print(encryptedKey, len(encryptedKey))
    IV = sessionKey[16:]
    sessionKey = sessionKey[:16]

    aesKey = AES.new(sessionKey, AES.MODE_CBC, IV)
    data = aesKey.decrypt(base64.b64decode(encryptedPayload))
    unpad = pkcs7_unpad(data)
    formatted = json.loads(unpad.decode('utf-8'))

    return formatted
    
session_key = secrets.token_bytes(16)
server_key = RSA.import_key(open("mykey.pem").read())
cipher_rsa = PKCS1_OAEP.new(server_key)

#keysize 16 bytes
#nonce 12 bytes     

directive = str(sys.argv[1])
print(directive)


#url = "http://127.0.0.1:5000/"
url = "http://192.168.1.131:5000/"

headers = {
    "Content-Type": "application/json"
}

cardUID = "C40F6C94"
cardData = base64.b64encode(open(f"Archives/{cardUID}/LatestCard", "rb").read()).decode('utf-8')
print(cardData)
    

DirectiveArguments = {
    "CardUID" : cardUID, 
    "CardData" : cardData,
    "dev" : "False"
}

UserPayload = {
    "IdentificationType":"PasswordHash",
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
#print(AES.block_size)
ct_bytes = cipher_aes.encrypt(pkcs7_pad(userpayloaddata, AES.block_size))

#print(f"IV: {cipher_aes.iv}, nonce: {session_key}")
#ciphertext = base64.b64encode(ct_bytes).decode('utf-8')

session_key += cipher_aes.iv

enc_session_key = cipher_rsa.encrypt(session_key)

UserEncryptedRecord = {
    "CardSync_Version":"0.1.0",
    "KeyEncryptionType":"RSA2048",
    "PayloadEncryptionType":"AES_CBC_16_16",
    "EncryptedKey": base64.b64encode(enc_session_key).decode('utf-8'),
    "EncryptedPayload": base64.b64encode(ct_bytes).decode('utf-8')
}

r = requests.post(url, headers=headers, data=json.dumps(UserEncryptedRecord))

response = json.loads(r.text)

responsePayload = decryptPayload(base64.b64encode(enc_session_key).decode('utf-8'), response["EncryptedPayload"])

print(f"{r} - {r.text} - {responsePayload}")

#print(base64.b64encode(ct_bytes).decode('utf-8'))
#test_aes = AES.new(session_key[:16], AES.MODE_CBC, cipher_aes.iv)
#print(test_aes.decrypt(ct_bytes))