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

def get_tor_session():
    session = requests.session()
    # Tor uses the 9050 port as the default socks port
    session.proxies = {'http':  'socks5h://127.0.0.1:9050',
                       'https': 'socks5h://127.0.0.1:9050'}
    return session

# Creates a key file and database file
# Register new user on the server
# 
# TODO Should it be possible to make local only users?
def register(address, usernamehash, password):
    if exists(usernamehash + ".user"):
        print("User already exists")
        return False

    session = get_tor_session()
    userdata = {'username': usernamehash, 'password': password}
    userdata = json.dumps(userdata)
    print("Registering...")
    try:
        resp = session.post(address + "/register", data=userdata, headers={'Content-Type': 'application/json'})
        if resp.status_code == 409: # User already exists
            return False
    except:
        sys.exit("Couldn't connect to server")
    


    # Create random 256bit key and write it to file
    privatekey = get_random_bytes(32)
    with open(usernamehash + ".user", 'wb') as keyfile:
        keyfile.write(privatekey)
        
    # Create the database file
    with open(usernamehash, 'wb') as dbfile:
        pass

    print("Registration successful")
    return True

# Logs the user onto the server
def login(address, usernamehash, password):
    print("Logging in...")
    try:
        with open(usernamehash + ".user", 'rb') as keyfile:
            privatekey = keyfile.read()
    except FileNotFoundError:
        sys.exit("User's keyfile not found")

    encryptionkey = derivekey(password, privatekey)

    session = get_tor_session()
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

# Lists titles of all records in the user's database
def listRecords():
    global database
    for key in database:
        print(key)
    return

# Fetches a record by title and shows the associated username and password
def getRecord():
    recordtype = input("Search: ")
    global database
    if recordtype in database:
        print("Username: " + database[recordtype][0])
        print("Password: " + database[recordtype][1])
    else:
        print("Record not found")
    return

# Queries the user for the title, username and password of a record and adds it to the database
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

# Queries the user for the title of a record to be removed and removes it
def removeRecord():
    recordtitle = input("Search: ")
    global database
    if recordtitle in database:
        if (input("Are you sure you want to delete" + recordtitle + "? [y/n]: ") == "y"):
            del database[recordtitle]
            return True
    return False

def commands():
    print("Commands:\n\
         n = New record\n \
        l = List records\n \
        g = Get record\n \
        d = Delete record\n \
        s = Save database\n \
        q = Log out and quit")

# Sends logout reques to server and exits the client
def logout(loggedin, onionAddress):
    if loggedin:
        session = get_tor_session()
        global session_cookie
        print("Logging out...")
        response = session.get(onionAddress + "/logout", cookies={'session': session_cookie})
    sys.exit(0)

# Fetches updates from the server, decrypts and returns the database in dict form
def get_db(onionAddress, loggedin, filename, encryptionkey):

    # If logged in, check update from server
    if (loggedin):
        global session_cookie
        session = get_tor_session()
        print("Fetching database update...")
        response = session.get(onionAddress, cookies={'username': filename, 'session': session_cookie})
        if response.status_code == 200:
            with open(filename, "wb") as dbfile:
                print("Writing to file")
                dbfile.write(response.content)
                # Decryption
                iv_and_ct = response.content
                iv = iv_and_ct[:16]
                ct = iv_and_ct[16:]
                try:
                    cipher = AES.new(encryptionkey, AES.MODE_CBC, iv)
                    database = json.loads(unpad(cipher.decrypt(ct), AES.block_size))
                except:
                    sys.exit("Couldn't decrypt database, please check your password")
                        
            print("Database update successful")
            return database
                
    # Read database file if there was no update from server
    try:
        with open(filename, "rb") as file:
            # Decryption
            iv_and_ct = file.read()
            iv = iv_and_ct[:16]
            ct = iv_and_ct[16:]
            try:
                cipher = AES.new(encryptionkey, AES.MODE_CBC, iv)
                database = json.loads(unpad(cipher.decrypt(ct), AES.block_size))
            except:
                sys.exit("Couldn't decrypt database, please check your password")
    except FileNotFoundError:
        sys.exit("Database file not found")

    return database

# Encrypts and writes the database to file
# If logged in, also sends the file to the server
def save_database(onionAddress, loggedin, dbfileName, encryptionkey):
    global database
    with open(dbfileName, 'wb') as dbfile:
        datastream = bytes(json.dumps(database), 'utf-8')
        # Encryption
        cipher = AES.new(encryptionkey, AES.MODE_CBC)
        ct = cipher.encrypt(pad(datastream, AES.block_size))
        iv = cipher.iv
        dbfile.write(iv + ct)
        print("Database saved to file")
    
    if (loggedin):
        with open(dbfileName, 'rb') as file:
            print("Sending...")
            session = get_tor_session()
            response = session.post(onionAddress, files={'db': file}, cookies={'username': dbfileName, 'session': session_cookie})
            if response.status_code == 200:
                print("Database sent to server")
            else:
                print("Database saving failed")
    else:
        print("Database couldn't be sent to server, please try to log in again.")

    return

# Basically just for getting the server address
def get_config(fileName):
    try:
        with open(fileName, "r") as config:
            line = config.readline()
    except Exception:
        sys.exit("Config file couldn't be read.")
    return line

# Derives the actual encryption key from the password, using the user's 'private key' as pepper
def derivekey(password, privatekey):
    key = PBKDF2(bytes(password, 'utf-8'), privatekey, 32, count=1000000, hmac_hash_module=SHA512)
    return key

def main():
    logged_in = False # Indicates whether the server connection has been established
    global database
    
    # Usernames are hashed, although they shouldn't be visible to anyone regardless
    usernameHasher = SHA256.new()
    usernameHasher.update(bytes(input("Username: "), "UTF-8"))
    username_hash = usernameHasher.hexdigest()

    password = getpass.getpass("Password: ")

    onionAddress = get_config(configFile)

    # Command line option to register new user
    if (len(sys.argv) > 1 and sys.argv[1] == '-r'):
        if register(onionAddress, username_hash, password):
            database = {}
            logged_in, encryption_key = login(onionAddress, username_hash, password)
            save_database(onionAddress, logged_in, username_hash, encryption_key)
            sys.exit(0)
        else:
            print("Registration failed")
    
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
        elif (command == "q"):
            logout(logged_in, onionAddress)
        elif (command == "s"):
            save_database(onionAddress, logged_in, username_hash, encryption_key)

main()
