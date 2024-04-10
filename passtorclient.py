import sys
import getpass
import requests
import json
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
#from Crypto.Protocol.KDF import PBKDF2

configFile = "passtorconfig"

def authenticate(address, username, masterPass):
    session = requests.Session()
    #print(session.get(address + "/login"))
    loginData = {'username': username, 'password': masterPass}
    loginData = json.dumps(loginData)
    #print(loginData)
    resp = session.post(address + "/login", data=loginData, headers={'Content-Type': 'application/json'})

    print(resp)

    return session

def register(onionAddress, userName, masterPass):

    session = requests.Session()
    print(session.cookies.get_dict())

    # send them over
    pass

def newListing(listingType, userName, password):
    # Authenticate with server
    # Hash values
    # Encrypt password
    # Send to server
    pass

def changePassword(listingType, userName, newPassword):
    pass

def main():
    # connect
    # authenticate
    # what to do?
    # do the things
    # elif etc.


    try:
        with open(configFile, "r") as config:
            onionAddress = config.readline()
            privateKey = config.readline()
    except Exception:
        print("Config file couldn't be read.")
        exit()


    usernameHasher = SHA256.new()
    passwordHasher = SHA256.new()
    usernameHasher.update(bytes(input("Username: "), "UTF-8"))
    username = usernameHasher.hexdigest()
    passwordhasher.update(bytes(getpass.getpass("Password: "), "UTF-8"))
    password = passwordHasher.hexdigest()
    if sys.argv[0] == "-r":
        register(onionAddress, username, password)
    else:
        authenticate(onionAddress, username, password)

main()