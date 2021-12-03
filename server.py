#!/usr/bin/env python3

from flask import Flask, request, jsonify, make_response
import sqlite3
import os
from datetime import datetime
import base64
import inspect
import distutils

CARD_SIZE = 1024
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

@app.route('/', methods=["GET", "POST"])
def connection():

    jsonPayload = request.get_json()
    UserPayload = jsonPayload["UserPayload"]
    directive = UserPayload["DirectiveName"]
    DirectiveArguments = UserPayload["DirectiveArguments"]

    user = UserPayload["IdentificationData"]["UserName"]
    cardUID = DirectiveArguments["cardUID"]
    data = base64.b64decode(DirectiveArguments["data"])
    dev = DirectiveArguments["dev"]
    if dev == "True":
        root = f"Archives/dev/{cardUID}"
    else:
        root = f"Archives/{cardUID}"

    l = locals()
    func = functionMatching[directive]
    args = [l[x] for x in list(inspect.signature(func).parameters.keys())]
    
    returnObject = func(*args)
    
    if returnObject[0]:
        return(returnObject[1], 200)
    else: 
        return(returnObject[1], 400)

if __name__ == "__main__":
    app.run()
    #root = f"Archives/{cardUID}"
    #print(downloadCard("oskhen", "C40F6C94"))
    #print(uploadCard("oskhen", "C40F6C94", b"AA"))
    #con = sqlite3.connect("database.db")
    
