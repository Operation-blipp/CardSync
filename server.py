#!/usr/bin/env python3

from flask import Flask, request, jsonify, make_response
import sqlite3
import os
from datetime import datetime
import base64
import inspect
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from requests.sessions import session
import json

API_VERSION = "0.1.0"
CARD_SIZE = 1024
DATABASE_NAME = "userdb.db"
RSA_KEY_PATH = "mykey.pem" 
HOST = "0.0.0.0"
PORT = 5000

app = Flask(__name__)

def downloadCard(user, cardUID, root):

    if not os.path.isdir(root):
        return (False, f"Card with UID {cardUID} not found on server!")

    with open(f"{root}/LatestAccess", "r") as f:
        cardUser = f.read()
        if cardUser:
            return (False, f"Card locked by {cardUser}")
        
    
    with open(f"{root}/LatestCard", "rb") as card:
        data = card.read(CARD_SIZE)
        with open(f"{root}/LatestAccess", "w") as f:
            f.write(f"{user}")
        return (True, data)

def uploadCard(user, cardUID, data, root):

    if not os.path.isdir(root):
        return (False, f"Card with UID {cardUID} not found on server!")

    with open(f"{root}/LatestAccess", "r") as f:
        cardUser = f.read()
        if cardUser != user:
            return(False, f"Must download card before uploading!")
    
    with open(f"{root}/LatestCard", "wb") as latestCard:
        timeStamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        latestCard.write(data)
        with open(f"{root}/{timeStamp}", "wb") as f:
            f.write(data)
    
    with open(f"{root}/LatestAccess", "w") as f:
        pass

    return(True, "Card Uploaded")

def unlockCard(user, cardUID, root):

    if not os.path.isdir(root):
        return (False, f"Card with UID {cardUID} not found on server!")

    cardUser = open(f"{root}/LatestAccess", "r").read()
    if cardUser == user:
        open(f"{root}/LatestAccess", "w").close()
    else:
        with open(f"{root}/LatestAccess", "w") as f:
            f.write(f"{user}")
    
    return(True, "Card unlocked")


functionMatching = {
    "getLatest" : downloadCard,
    "uploadCard" : uploadCard,
    "unlockCard" : unlockCard,
}

expectedUserRecord = {
    "CardSync_Version" : "0.1.0",
    "KeyEncryptionType" : "RSA2048",
    "PayloadEncryptionType" : "AES_CBC_16_16"
}

def verifyUser(username, passhash):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()

    cur.execute("SELECT username, password FROM users WHERE username = ? AND password = ?", (username, passhash))
    users = cur.fetchall()
    if len(users) == 1:
        return True
    return False

def pkcs7_unpad(text):
    x = (text[-1:])
    x = ord(x)
    return text[:-x]

def decryptPayload(encryptedKey, encryptedPayload):
    
    serverKey = RSA.import_key(open(RSA_KEY_PATH).read())
    rsaKey = PKCS1_OAEP.new(serverKey)
    sessionKey = rsaKey.decrypt(base64.b64decode(encryptedKey))
    print(encryptedKey, len(encryptedKey))
    IV = sessionKey[16:]
    sessionKey = sessionKey[:16]

    aesKey = AES.new(sessionKey, AES.MODE_CBC, IV)
    data = aesKey.decrypt(base64.b64decode(encryptedPayload))
    unpad = pkcs7_unpad(data)
    formatted = json.loads(unpad.decode('utf-8'))
    return formatted


@app.route('/', methods=["GET", "POST"])
def connection():

    if not request.is_json:
        return "GTFO", 400

    jsonPayload = request.get_json()

    #UserEncryptedRecord = jsonPayload["UserEncryptedRecord"]

    print(jsonPayload)

    for item in jsonPayload:
        if item in expectedUserRecord:
            if jsonPayload[item] != expectedUserRecord[item]:
                return "Unexpected header data encountered", 400

    if jsonPayload["PayloadEncryptionType"] == expectedUserRecord["PayloadEncryptionType"]:
        UserPayload = decryptPayload(jsonPayload["EncryptedKey"], jsonPayload["EncryptedPayload"])
    else:
        return "Encryption type not supported!", 400

    directive = UserPayload["DirectiveName"]
    DirectiveArguments = UserPayload["DirectiveArguments"]

    if UserPayload["IdentificationType"] != "PasswordHash":
        return "Identification Type not supported!", 400
    


    user = UserPayload["IdentificationData"]["UserName"]
    passhash = UserPayload["IdentificationData"]["PasswordHash"]
   
    if not verifyUser(user, passhash):
        return "User not verified!", 400

    if directive == "Login":
        return "User successfully verified!", 200


    #|--- Directive handling
    l = locals()
    cardUID = DirectiveArguments["cardUID"]
    data = base64.b64decode(DirectiveArguments["data"])
    dev = DirectiveArguments["dev"]
    if dev == "True":
        root = f"Archives/dev/{cardUID}"
    else:
        root = f"Archives/{cardUID}"

    
    func = functionMatching[directive]
    args = [l[x] for x in list(inspect.signature(func).parameters.keys())]
    
    returnObject = func(*args)
    
    if returnObject[0]:
        return(returnObject[1], 200)
    else: 
        return(returnObject[1], 400)
    

def loadConfig(filepath):
    
    configData = dict()
    with open(filepath, "r") as configFile:
        
        for line in configFile.readlines():
            if line[0] == '#':
                continue
            if " = " not in line:
                continue
            lineData = line.split(" = ")
            configData[lineData[0]] = lineData[-1].strip("\n")
    
    return configData


def create_app(config_path="settings.cfg"):

    global app

    global CARD_SIZE
    global DATABASE_NAME
    global RSA_KEY_PATH
    global HOST
    global PORT

    config = loadConfig(config_path)
    CARD_SIZE = int(config["CARD_SIZE"])
    DATABASE_NAME = config["DATABASE_NAME"]
    RSA_KEY_PATH = config["RSA_KEY_PATH"]
    HOST = config["HOST"]
    PORT = int(config["PORT"])

    return app
    

if __name__ == "__main__":

    app = create_app()
    
    app.run(host=HOST, port=PORT, debug=True)
    #root = f"Archives/{cardUID}"
    #print(downloadCard("oskhen", "C40F6C94"))
    #print(uploadCard("oskhen", "C40F6C94", b"AA"))
    #con = sqlite3.connect("database.db")