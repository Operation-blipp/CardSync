#!/usr/bin/env python3

import requests
import json

url = "http://127.0.0.1:5000/"

headers = {
    "Content-Type": "application/json"
}

data = {
    "user":"oskhen",
    "data":"C40F6C94"
}

r = requests.post(url, headers=headers, data=json.dumps(data))
print(r)