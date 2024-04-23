import sys
import getpass
import requests
import json
import click
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
#from Crypto.Protocol.KDF import PBKDF2

configFile = "passtorconfig"
session_cookie = ""
username_hash = ""

def authenticate(address, username, masterPass):
    session = requests.Session()
    loginData = {'username': username, 'password': masterPass}
    loginData = json.dumps(loginData)
    resp = session.post(address + "/login", data=loginData, headers={'Content-Type': 'application/json'})
    
    global session_cookie
    session_cookie = resp.cookies["session"]
#    print(resp.status_code)

    return resp.status_code == 200

def newRecord():
    # Authenticate with server
    # Hash values
    # Encrypt password
    # Send to server
    session = requests.Session()
    onionAddress, privateKey = get_config()
    print("newrecordsessionscookie")
    print(session_cookie)
    resp = session.get(onionAddress, cookies={'username': username_hash, 'session': session_cookie})
    print(resp.status_code)
    exit()

def listRecords():
    pass

def getRecord():
    pass

def removeRecord():
    pass

def changeRecord():
    pass

def get_config():
    try:
        with open(configFile, "r") as config:
            onionAddress = config.readline()
            privateKey = config.readline()
    except Exception:
        print("Config file couldn't be read.")
        exit()
    return (onionAddress, privateKey)

def login():
    global username_hash
    onionAddress, privateKey = get_config()
    usernameHasher = SHA256.new()
    passwordHasher = SHA256.new()
    usernameHasher.update(bytes(input("Username: "), "UTF-8"))
    username_hash = usernameHasher.hexdigest()
    password = getpass.getpass("Password: ")
    return authenticate(onionAddress, username_hash, password)

def commands():
    print("l = List records")
    print("g = Get record")
    print("n = New record")
    print("d = Delete record")

    # connect
    # authenticate
    # what to do?
    # do the things
    # elif etc.
    

if (login()):
    while True:
        command = input("Enter command: ")
        # cli here
        if (command == "h" or command == "help"):
            commands()
        elif (command == "l"):
            listRecords()
        newRecord()

