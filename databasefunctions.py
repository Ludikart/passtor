import sqlite3
import argon2
import click
from Crypto.Hash import SHA256

DATABASE_FILE = "passtorDatabase.db"
INIT_SCRIPT = "schema.sql"

@click.group()
def cli():
    pass

def addListing(listingType, userName, passWord):
    # Save to database
    pass

def changePassword(listingType, userName, newPassword):
    pass

def removeListing(listingType):
    pass

def removeUser(listingType, userName):
    pass

def getRecords(userID):
    pass

@cli.command()
def hello():
    click.echo("Hello")
    print("hello")

@cli.command()
@click.option('--user', prompt="Username")
@click.option('--password', prompt="Password")
def newuser(user, password):
    db = sqlite3.connect(DATABASE_FILE, detect_types=sqlite3.PARSE_DECLTYPES)
    cur = db.cursor()

    usernameHasher = SHA256.new()
    userHash = usernameHasher.update(bytes(user, 'UTF-8'))

    passwordHasher = argon2.PasswordHasher()
    passwordHash = passwordHasher.hash(password)

    tup = (userHash, passwordHash)
    cur.execute("INSERT INTO user (username, pass) VALUES (?,?)", tup)
    db.commit()

@cli.command()
def initdb():
    db = sqlite3.connect(DATABASE_FILE, detect_types=sqlite3.PARSE_DECLTYPES)
    cur = db.cursor()
    with open(INIT_SCRIPT) as script:
        cur.executescript(script.read())

if __name__ == '__main__':
    cli()