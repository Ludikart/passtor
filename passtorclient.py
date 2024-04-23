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

def newRecord(onionAddress, privateKey):
    session = requests.Session()
    recordType = input("What is this record for?: ")
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    recordData = {'type': recordType, 'uname': username, 'pass': password}
    sure = input("Are you sure? (Y/n): ")
    if (sure == "Y" or sure == "" or sure == "y"):
        resp = session.post(onionAddress + "/newrecord", data=recordData, cookies={'username': username_hash, 'session': session_cookie})
        print(resp.status_code)
    else:
        return

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

def login(onionAddress):
    global username_hash
    usernameHasher = SHA256.new()
    passwordHasher = SHA256.new()
    usernameHasher.update(bytes(input("Username: "), "UTF-8"))
    username_hash = usernameHasher.hexdigest()
    password = getpass.getpass("Password: ")
    return authenticate(onionAddress, username_hash, password)

def logout(onionAddress):
    exit()

def commands(): # List available commands for the user
    print("l = List records")
    print("g = Get record")
    print("n = New record")
    print("d = Delete record")
    print("c = Change record")

def main():
    onionAddress, privateKey = get_config()
    if (login(onionAddress)):
        # Basic command line interface
        while True:
            command = input("Enter command: ")
            if (command == "h" or command == "help"):
                commands()
            elif (command == "g"):
                getRecord(onionAddress, privateKey)
            elif (command == "l"):
                listRecords(onionAddress, privateKey)
            elif (command == "n"):
                newRecord(onionAddress, privateKey)
            elif (command == "d"):
                removeRecord(onionAddress, privateKey)
            elif (command == "c"):
                changeRecord(onionAddress, privateKey)
            elif (command == "q"):
                logout()

main()
