import sys
import getpass
import requests
import json
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512

configFile = "passtorconfig"
session_cookie = ""
username_hash = ""

global database

def authenticate(address, username, masterPass):
    session = requests.Session()
    loginData = {'username': username, 'password': masterPass}
    loginData = json.dumps(loginData)
    resp = session.post(address + "/login", data=loginData, headers={'Content-Type': 'application/json'})
    
    global session_cookie
    print(resp.cookies['session'])
    session_cookie = resp.cookies['session']

    return resp.status_code == 200

def listRecords():
    global database
    print(database.keys)

def newrecord():
    global database
    key = input("Type of record: ")
    user = input("Username: ")
    password = getpass.getpass("Password: ")
    if(input("Are you sure you want to add this?[y/n]" == y)):
        database.append(item)
    return

def logout(onionAddress):
    exit()

def get_db(onionAddress, filename, encryptionkey):
    # If logged in, check update from server
    # Read database file
    # Decrypt

    global database
    with open(filename, "wb") as file:
        filedata = file.read()
        # decrypt here
        database = json.loads(filedata)
        return

    return

# Add encryption key as variable
def save_database(onionAddress, dbfileName, encryptionkey):
    # If logged in, send updated database file
    # else show error message
    # 
    global database
    with open(dbfilename, 'wb') as file:
        datastream = json.dumps(database)
        # Encryption here
        file.write(bytes(datastream, 'utf-8'))
    
    if (logged_in):
        with open(dbfilename, 'rb') as file:
            response = requests.post(onionAddress, files={'db': file})
    else:
        print("Database couldn't be sent to server, please try to log in again.")

    return

def get_config():
    try:
        with open(configFile, "r") as config:
            onionAddress = config.readline()
            privateKey = config.readline()
    except Exception:
        print("Config file couldn't be read.")
        exit()
    return (onionAddress, privateKey)

def derivekey(password, privatekey):
    key = PBKDF2(bytes(password, 'utf-8'), bytes(privatekey, 'utf-8'), 32, count=1000000, hmac_hash_module=SHA512)
    return key

# Try database update
# Decrypt database
# cli
def main():
    filename = "encrypteddb"

    logged_in = False
    onionAddress, privateKey = get_config()
    usernameHasher = SHA256.new()
    usernameHasher.update(bytes(input("Username: "), "UTF-8"))
    username_hash = usernameHasher.hexdigest()
    password = getpass.getpass("Password: ")

    logged_in = authenticate(onionAddress, username_hash, password)
    
    encryption_key = derivekey(password, privateKey)
    database = get_db(encryption_key, logged_in)

        # Basic command line interface
    while True:
        command = input("Enter command: ")
        if (command == "h" or command == "help"):
            commands()
        elif (command == "l"):
            listRecords()
        elif (command == "n"):
            newRecord()
        elif (command == "d"):
            removeRecord()
        elif (command == "c"):
            changeRecord()
        elif (command == "q"):
            logout(onionAddress)
        elif (command == "t"):
            test(onionAddress)
        elif (command == "s"):
            save_database(onionAddress, filename, encryption_key)

main()
