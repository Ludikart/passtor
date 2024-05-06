import sys
import getpass
import requests
import json
from Crypto.Cipher import AES

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
#    print(resp.status_code)

    return resp.status_code == 200

def login(onionAddress):
    return authenticate(onionAddress, username_hash, password)

def logout(onionAddress):
    exit()

def get_db(onionAddress, privateKey, passWord):
    # If logged in, check update from server
    # Read database file
    # Derive key from privatekey and password
    # Decrypt
    # return dict
    pass

def save_database(onionAddress):
    # If logged in, send updated database file
    # else show error message
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

# Try database update
# Decrypt database
# cli
def main():
    onionAddress, privateKey = get_config()
    usernameHasher = SHA256.new()
    usernameHasher.update(bytes(input("Username: "), "UTF-8"))
    username_hash = usernameHasher.hexdigest()
    password = getpass.getpass("Password: ")

    global logged_in 
    if (authenticate(onionAddress, username_hash, password)):
        logged_in = True
        print("Logged in to server")
    else:
        print("Not connected to server")
        logged_in = False
    
    database = get_db(password)
        # Basic command line interface
    while True:
        command = input("Enter command: ")
        if (command == "h" or command == "help"):
            commands()
        elif (command == "l"):
            listRecords(privateKey)
        elif (command == "n"):
            newRecord(privateKey)
        elif (command == "d"):
            removeRecord(privateKey)
        elif (command == "c"):
            changeRecord(privateKey)
        elif (command == "q"):
            logout(onionAddress)
        elif (command == "t"):
            test(onionAddress)

main()
