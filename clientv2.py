import sys
import getpass
import requests
import json
import argon2
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512, SHA256

configFile = "passtorconfig"
session_cookie = ""
username_hash = ""

global database
database = {"test": ("test1", "test2")}

def register(address, usernamehash, password):
    if os.file.exists(usernamehash + "user"):
        print("User already exists")
        return

    hasher = argon2.PasswordHasher()
    with open(usernamehash + "user", "w") as hashfile:
        hashfile.write(hasher.hash(password))
    return

def authenticate(address, username, masterPass):
    session = requests.Session()
    loginData = {'username': username, 'password': masterPass}
    loginData = json.dumps(loginData)
    try:
        resp = session.post(address + "/login", data=loginData, headers={'Content-Type': 'application/json'})
    except:
        print("Couldn't connect to server")
        return False
    
    global session_cookie
    print(resp.cookies['session'])
    session_cookie = resp.cookies['session']

    return resp.status_code == 200

def listRecords():
    global database
    print(database.keys())

def newRecord():
    global database
    key = input("Type of record: ")
    if(key in database):
        print("Record already exists, please use c-option or use different record type")
        return
    user = input("Username: ")
    password = getpass.getpass("Password: ")
    if(input("Are you sure you want to add this?[y/n]") == 'y' and key not in database):
        database[key] = (user, password)
    return

def logout(onionAddress):
    exit()

def get_db(onionAddress, loggedin, filename, encryptionkey):
    # If logged in, check update from server
    # Read database file
    # Decrypt

    global database
    with open(filename, "r") as file:
        filedata = file.read()
        # decrypt here
        database = json.loads(filedata)
        return

    return

# Add encryption key as variable
def save_database(onionAddress, dbfileName, encryptionkey, loggedin):
    # If logged in, send updated database file
    # else show error message
    # 
    global database
    with open(dbfileName, 'wb') as file:
        datastream = json.dumps(database)
        # Encryption here
        file.write(bytes(datastream, 'utf-8'))
    
    if (loggedin):
        with open(dbfilename, 'rb') as file:
            response = requests.post(onionAddress, files={'db': file})
    else:
        print("Database couldn't be sent to server, please try to log in again.")

    return

def get_config(usernamehash):
    try:
        with open(usernamehash, "r") as config:
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
    usernameHasher = SHA256.new()
    usernameHasher.update(bytes(input("Username: "), "UTF-8"))
    username_hash = usernameHasher.hexdigest()
    password = getpass.getpass("Password: ")
    onionAddress, privateKey = get_config(username_hash)

    logged_in = authenticate(onionAddress, username_hash, password)
    
    encryption_key = derivekey(password, privateKey)
    database = get_db(onionAddress, logged_in, filename, encryption_key)

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
