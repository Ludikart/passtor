import sys
import getpass
import requests
import json
import argon2
from os.path import exists
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512, SHA256
from Crypto.Random import get_random_bytes

configFile = "passtorconfig"
session_cookie = ""
username_hash = ""

global database
database = {}

# Register new user
# Creates a key file and password hash file
# 
# TODO registering with server. Should it be possible to make local only users?
def register(address, usernamehash, password):
    if exists(usernamehash + ".user"):
        print("User already exists")
        return False

    session = requests.Session()
    userdata = {'username': usernamehash, 'password': password}
    userdata = json.dumps(userdata)
    try:
        resp = session.post(address + "/register", data=userdata, headers={'Content-Type': 'application/json'})
        if resp.status_code == 409: # User already exists
            return False
    except:
        print("Couldn't connect to server")
    

    #try:
    hasher = argon2.PasswordHasher()
    passwordhash = hasher.hash(password)
    with open(usernamehash + ".user", 'wb') as hashfile:
#        hashfile.write(bytes(passwordhash + '\n', 'utf-8'))
        hashfile.write(get_random_bytes(32))
        
    # Create the database file
    with open(usernamehash, 'wb') as dbfile:
        pass

    #except:
     #   print("Password hashing failed")
      #  exit()
    

    # Ask for server password and register with server
    return True

#def login(address, usernamehash, password):
#        phash = hashfile.readline().decode('utf-8')
    
#    phash = phash[:-1] # remove endline character
#    passwordHasher = argon2.PasswordHasher()
#    result = passwordHasher.verify(phash, password)
#    return server_login(address, usernamehash, password), encryptionkey

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
    print(resp.cookies['session'])
    session_cookie = resp.cookies['session']

    return resp.status_code == 200, encryptionkey

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
    if (loggedin):
        global session_cookie
        session = requests.Session()
        response = session.get(onionAddress, cookies={'username': filename, 'session': session_cookie})
        if response.status_code == 200:
            with open(filename, "wb") as dbfile:
                dbfile.write(response.content)
            # decrypt here
            database = json.loads(response.content)
            return database
                
    # Read database file if there was no update from server
    with open(filename, "rb") as file:
        filedata = file.read()
        # decrypt here

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

    # Option to register new user
    if (len(sys.argv) > 1 and sys.argv[1] == '-r'):
        if not register(onionAddress, username_hash, password):
            exit()

    
    logged_in, encryption_key = login(onionAddress, username_hash, password)

    global database
    database = get_db(onionAddress, logged_in, username_hash, encryption_key)

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
            save_database(onionAddress, logged_in, username_hash, encryption_key)

main()
