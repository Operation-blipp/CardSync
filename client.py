#!/usr/bin/env python3

import requests
import json
import base64

url = "http://127.0.0.1:5000/"

headers = {
    "Content-Type": "application/json"
}

UserEncryptedRecord = {
    "APINAMN_Version":"0.1.0",
    "KeyEncryptionType":"RSA2048",
    "PayloadEncryptionType":"AES_CMC",
    "EncryptedKey":"DataIBase64Format",
    "EncryptedPayload":"DataIBase64Format"
}

cardUID = "C40F6C94"
cardData = base64.b64encode(open(f"Archives/{cardUID}/LatestCard", "rb").read()).decode('utf-8')
print(cardData)
    

DirectiveArguments = {
    "user" : "oskhen", 
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
        "PasswordHash":"Base64Hash"
    },
    "DirectiveName":"uploadCard",
    "DirectiveArguments":DirectiveArguments
}

data = {
    "UserEncryptedRecord" : UserEncryptedRecord,
    "UserPayload" : UserPayload
}

r = requests.post(url, headers=headers, data=json.dumps(data))
print(f"{r} - {r.text}")