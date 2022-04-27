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
PORT = 80
config_path = "settings.cfg"

requiresUID = ["getLatest", "unlockCard"]

expectedUserRecord = {
    "CardSync_Version" : "0.1.0",
    "KeyEncryptionType" : "RSA2048",
    "PayloadEncryptionType" : "AES_CBC_16_16"
}

app = Flask(__name__)

def downloadCard(user, cardUID, namespace):

    cardUID = cardUID.upper()
    if cardUID == "DEFAULT":
        cardUID = loadConfig(config_path)["DEFAULT"]


    if namespace != "":
        root = f"Archives/{namespace}/{cardUID}"
    else:
        root = f"Archives/{cardUID}"
    print(root)
    if not os.path.isdir(root):
        return ["InvalidUID"]
        #return (False, f"Card with UID {cardUID} not found on server!")

    with open(f"{root}/LatestAccess", "r") as f:
        cardUser = f.read()
        if cardUser:
            return ["CardLocked"]
            #return (False, f"Card locked by {cardUser}")
        
    
    with open(f"{root}/LatestCard", "rb") as card:
        data = card.read(CARD_SIZE)
        with open(f"{root}/LatestAccess", "w") as f:
            f.write(f"{user}")
        return ["Ok", {
            "CardData" : base64.b64encode(data).decode('utf-8')
        }]
        #return (True, data)

def uploadCard(user, data, namespace):

    cardUID = str(data[0:4].hex()).upper()

    print(f"CardUID: {cardUID}")

    if namespace != "":
        root = f"Archives/{namespace}/{cardUID}"
    else:
        root = f"Archives/{cardUID}"

    if not os.path.isdir(root):
        os.makedirs(root)
        print("Registering card..")
    else:
        #return ["InvalidUID"]
        #return (False, f"Card with UID {cardUID} not found on server!")
        with open(f"{root}/LatestAccess", "r") as f:
            cardUser = f.read()
            if cardUser != user:
                return ["CardLocked"]
                #return(False, f"Must download card before uploading!")
    
    with open(f"{root}/LatestCard", "wb") as latestCard:
        timeStamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        latestCard.write(data)
        with open(f"{root}/{timeStamp}", "wb") as f:
            f.write(data)
    
    with open(f"{root}/LatestAccess", "w") as f:
        pass

    return ["Ok"]

def unlockCard(user, cardUID, namespace):

    cardUID = cardUID.upper()
    if cardUID == "DEFAULT":
        cardUID = loadConfig(config_path)["DEFAULT"]

    if namespace != "":
        root = f"Archives/{namespace}/{cardUID}"
    else:
        root = f"Archives/{cardUID}"

    if not os.path.isdir(root):
        return ["InvalidUID"]
        #return (False, f"Card with UID {cardUID} not found on server!")

    cardUser = open(f"{root}/LatestAccess", "r").read()
    if cardUser == user:
        open(f"{root}/LatestAccess", "w").close()
    else:
        with open(f"{root}/LatestAccess", "w") as f:
            f.write(f"{user}")
    
    return ["Ok"]
    return(True, "Card unlocked")

def UploadBlippBugReport(user,DirectiveArguments):
    try:
        StackTrace = DirectiveArguments["StackTrace"]
        Log = DirectiveArguments["Log"]
        CurrentTime = datetime.strftime(datetime.now(),"%Y-%m-%d_%H-%M-%S")
        NewFile = open("Archives/bugreports/"+CurrentTime,"x")
        NewFile.write("----------------STACKTRACE---------------\n")
        NewFile.write(StackTrace)
        NewFile.write("------------------LOG--------------------\n")
        NewFile.write(Log)
        NewFile.write("-----------------USER--------------------\n")
        NewFile.write(str(user))
        NewFile.close()
    except Exception as e:
        print(str(e))
        return(["InvalidDirectiveArguments"])
    return(["Ok"])
    

functionMatching = {
    "getLatest" : downloadCard,
    "uploadCard" : uploadCard,
    "unlockCard" : unlockCard,
    "UploadBlippBugReport":UploadBlippBugReport
}

def verifyUser(username, passhash):
    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()

    cur.execute("SELECT username, password FROM users WHERE username = ? AND password = ?", (username, passhash))
    users = cur.fetchall()
    if len(users) == 1:
        return True
    return False

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
    print(formatted)
    return formatted

def encryptPayload(encryptedKey, userPayload):

    userPayloadData = json.dumps(userPayload)

    serverKey = RSA.import_key(open(RSA_KEY_PATH).read())
    rsaKey = PKCS1_OAEP.new(serverKey)
    sessionKey = rsaKey.decrypt(base64.b64decode(encryptedKey))

    IV = sessionKey[16:]
    sessionKey = sessionKey[:16]

    aesKey = AES.new(sessionKey, AES.MODE_CBC, IV)

    encryptedData = aesKey.encrypt(pkcs7_pad(userPayloadData, AES.block_size))

    return base64.b64encode(encryptedData).decode('utf-8')

def returnPayload(encryptedKey, statusCode, directiveResponse=dict()):

    ServerEncryptedRecord = {
        "EncryptionStatus" : "Ok",
        "EncryptedPayload" : "",
    }

    ServerPayload = {
        "StatusCode" : statusCode,
        "DirectiveResponse" : directiveResponse,
    }

    encryptedPayload = encryptPayload(encryptedKey, ServerPayload)

    ServerEncryptedRecord["EncryptedPayload"] = encryptedPayload

    return json.dumps(ServerEncryptedRecord)

@app.route('/', methods=["GET", "POST"])
def connection():

    if not request.is_json:
        return "GTFO", 400

    jsonPayload = request.get_json()

    #UserEncryptedRecord = jsonPayload["UserEncryptedRecord"]

    print(jsonPayload)

    encryptedKey = jsonPayload["EncryptedKey"]

    if jsonPayload["PayloadEncryptionType"] == expectedUserRecord["PayloadEncryptionType"]:
        UserPayload = decryptPayload(encryptedKey, jsonPayload["EncryptedPayload"])
    else:
        return json.dumps({
            "EncryptionStatus" : "InvalidPayloadEncryptionType",
            "EncryptedPayload" : dict(),
        })

    directive = UserPayload["DirectiveName"]
    DirectiveArguments = UserPayload["DirectiveArguments"]

    if UserPayload["IdentificationType"] != "PasswordHash":
        return returnPayload(encryptedKey, "InvalidIdentificationType")

    user = UserPayload["IdentificationData"]["UserName"]
    passhash = UserPayload["IdentificationData"]["PasswordHash"]
   
    if not verifyUser(user, passhash):
        return returnPayload(encryptedKey, "InvalidCredentials")

    if directive == "Login":
        return returnPayload(encryptedKey, "Ok")

    #|--- Directive handling

    if directive in requiresUID:
        cardUID = DirectiveArguments["CardUID"].upper()

    try:
        namespace = DirectiveArguments["Namespace"]
    except KeyError:
        namespace = ""

    if directive == "uploadCard":
        data = base64.b64decode(DirectiveArguments["CardData"])

    l = locals()
    
    func = functionMatching[directive]
    args = [l[x] for x in list(inspect.signature(func).parameters.keys())]
    
    returnObject = func(*args)
    print(returnObject)

    if len(returnObject) == 1:
        return returnPayload(encryptedKey, returnObject[0])
    else:
        return returnPayload(encryptedKey, returnObject[0], returnObject[1])
    
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

def create_app(pathToConfig="settings.cfg"):

    global app

    global CARD_SIZE
    global DATABASE_NAME
    global RSA_KEY_PATH
    global HOST
    global PORT
    global config_path

    config_path = pathToConfig

    config = loadConfig(pathToConfig)
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
