#!/usr/bin/env python3

import re
from flask import Flask, request, jsonify, make_response
import sqlite3
import os
from datetime import datetime

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

@app.route('/', methods=["GET", "POST"])
def hello_world():

    req = request.get_json()
    print(req)

    return ('Hello World!', 200)

if __name__ == "__main__":
    app.run()
    #root = f"Archives/{cardUID}"
    #print(downloadCard("oskhen", "C40F6C94"))
    #print(uploadCard("oskhen", "C40F6C94", b"AA"))
    #con = sqlite3.connect("database.db")
    pass
