import sys
import getpass
import requests
import json
import argon2
from os.path import exists
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512, SHA256
from Crypto.Random import get_random_bytes

configFile = "passtorconfig"
session_cookie = ""
username_hash = ""

global database
database = {}

# Creates a key file and database file
# Register new user on the server
# 
# TODO Should it be possible to make local only users?
def register(address, usernamehash, password):
    if exists(usernamehash + ".user"):
        print("User already exists")
        return False

    session = requests.Session()
    userdata = {'username': usernamehash, 'password': password}
    print(password)
    userdata = json.dumps(userdata)
    try:
        resp = session.post(address + "/register", data=userdata, headers={'Content-Type': 'application/json'})
        if resp.status_code == 409: # User already exists
            return False
    except:
        print("Couldn't connect to server")
    


    # Create random 256bit key and write it to file
    privatekey = get_random_bytes(32)
    with open(usernamehash + ".user", 'wb') as keyfile:
        keyfile.write(privatekey)
        
    # Create the database file
    with open(usernamehash, 'wb') as dbfile:
        pass

    # TODO Ask for server password and authenticate with server
    return True

# Logs the user onto the server
def login(address, usernamehash, password):
    with open(usernamehash + ".user", 'rb') as keyfile:
        privatekey = keyfile.read()

    encryptionkey = derivekey(password, privatekey)

    session = requests.Session()
    loginData = {'username': usernamehash, 'password': password}
    loginData = json.dumps(loginData)
    try:
        resp = session.post(address + "/login", data=loginData, headers={'Content-Type': 'application/json'})
    except:
        print("Couldn't connect to server")
        return False, encryptionkey
    
    global session_cookie
    session_cookie = resp.cookies['session']

    return resp.status_code == 200, encryptionkey

def listRecords():
    global database
    for key in database:
        print(key)
    return

def getRecord():
    recordtype = input("Search: ")
    global database
    if recordtype in database:
        print("Username: " + database[recordtype][0])
        print("Password: " + database[recordtype][1])
    else:
        print("Record not found")
    return

def newRecord():
    global database
    key = input("Title: ")
    if(key in database):
        print("Record already exists, please use the change command or a different title")
        return False
    user = input("Username: ")
    password = getpass.getpass("Password: ")
    if(input("Are you sure you want to add this?[y/n]") == 'y' and key not in database):
        database[key] = (user, password)
        return True
    else:
        return False

def removeRecord():
    recordtitle = input("Search: ")
    global database
    if recordtitle in database:
        if (input("Are you sure you want to delete" + recordtitle + "? [y/n]: ") == "y"):
            del database[recordtitle]
            return True
    return False

def logout(onionAddress):
    session = requests.Session()
    global session_cookie
    response = session.get(onionAddress + "/logout", cookies={'session': session_cookie})
    exit()

def get_db(onionAddress, loggedin, filename, encryptionkey):

    # If logged in, check update from server
    if (loggedin):
        global session_cookie
        session = requests.Session()
        response = session.get(onionAddress, cookies={'username': filename, 'session': session_cookie})
        if response.status_code == 200:
            with open(filename, "wb") as dbfile:
                dbfile.write(response.content)
                # Decryption
                iv_and_ct = response.content
                iv = iv_and_ct[:16]
                ct = iv_and_ct[16:]
                cipher = AES.new(encryptionkey, AES.MODE_CBC, iv)
                database = json.loads(unpad(cipher.decrypt(ct), AES.block_size))
            return database
                
    # Read database file if there was no update from server
    with open(filename, "rb") as file:
        # Decryption
        iv_and_ct = file.read()
        iv = iv_and_ct[:16]
        ct = iv_and_ct[16:]
        cipher = AES.new(encryptionkey, AES.MODE_CBC, iv)
        database = json.loads(unpad(cipher.decrypt(ct), AES.block_size))

        # If file is empty, return empty dict
        if (filedata == b''):
            database = {}
        else:
            database = json.loads(filedata)

    return database

def save_database(onionAddress, loggedin, dbfileName, encryptionkey):
    # If logged in, send updated database file
    # else show error message
    # 
    global database
    with open(dbfileName, 'wb') as dbfile:
        datastream = bytes(json.dumps(database), 'utf-8')
        # Encryption
        cipher = AES.new(encryptionkey, AES.MODE_CBC)
        ct = cipher.encrypt(pad(datastream, AES.block_size))
        iv = cipher.iv
        dbfile.write(iv + ct)
    
    if (loggedin):
        with open(dbfileName, 'rb') as file:
            response = requests.post(onionAddress, files={'db': file}, cookies={'username': dbfileName, 'session': session_cookie})
    else:
        print("Database couldn't be sent to server, please try to log in again.")

    return

# Basically just for getting the address
def get_config(fileName):
    try:
        with open(fileName, "r") as config:
            line = config.readline()
    except Exception:
        print("Config file couldn't be read.")
        exit()
    return line

def derivekey(password, privatekey):
    key = PBKDF2(bytes(password, 'utf-8'), privatekey, 32, count=1000000, hmac_hash_module=SHA512)
    return key

# Try database update
# Decrypt database
# cli
def main():
    logged_in = False
    usernameHasher = SHA256.new()
    usernameHasher.update(bytes(input("Username: "), "UTF-8"))
    username_hash = usernameHasher.hexdigest()
    password = getpass.getpass("Password: ")
    onionAddress = get_config(configFile)

    global database
    # Option to register new user
    if (len(sys.argv) > 1 and sys.argv[1] == '-r'):
        if register(onionAddress, username_hash, password):
            database = {}
            logged_in, encryption_key = login(onionAddress, username_hash, password)
            save_database(onionAddress, logged_in, username_hash, encryption_key)
            exit()
    
    logged_in, encryption_key = login(onionAddress, username_hash, password)

    database = get_db(onionAddress, logged_in, username_hash, encryption_key)

    # Basic command line interface
    while True:
        command = input("Enter command: ")
        if (command == "h" or command == "help"):
            commands()
        elif (command == "l"):
            listRecords()
        elif (command == "g"):
            getRecord()
        elif (command == "n"):
            if newRecord():
                save_database(onionAddress, logged_in, username_hash, encryption_key)
        elif (command == "d"):
            if removeRecord():
                save_database(onionAddress, logged_in, username_hash, encryption_key)
        elif (command == "c"):
            changeRecord()
        elif (command == "q"):
            logout(onionAddress)
        elif (command == "t"):
            test(onionAddress)
        elif (command == "s"):
            save_database(onionAddress, logged_in, username_hash, encryption_key)

main()
