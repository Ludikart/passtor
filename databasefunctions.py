import sqlite3
import argon2
import click
from Crypto.Hash import SHA256

DATABASE_FILE = "passtorDatabase.db"
INIT_SCRIPT = "schema.sql"

@click.group()
def cli():
    pass

@cli.command()
def listusers():
    db = sqlite3.connect(DATABASE_FILE, detect_types=sqlite3.PARSE_DECLTYPES)
    cur = db.cursor()

    res = cur.execute("SELECT * FROM user")
    click.echo(res.fetchall())


def addListing(listingType, userName, passWord):
    # Save to database
    pass

def changePassword(listingType, userName, newPassword):
    pass

def removeListing(listingType):
    pass

@cli.command()
@click.option('--username', prompt="Username")
def removeuser(username):
    db = sqlite3.connect(DATABASE_FILE, detect_types=sqlite3.PARSE_DECLTYPES)
    cur = db.cursor()

    usernameHasher = SHA256.new()
    usernameHasher.update(bytes(username, 'UTF-8'))
    userHash = usernameHasher.hexdigest() 

    cur.execute("DELETE FROM user WHERE username = ?", (userHash,))
    db.commit()

def getRecords(userID):
    pass

@cli.command()
def hello():
    click.echo("Hello")

@cli.command()
@click.option('--user', prompt="Username")
@click.option('--password', prompt="Password")
def newuser(user, password):
    db = sqlite3.connect(DATABASE_FILE, detect_types=sqlite3.PARSE_DECLTYPES)
    cur = db.cursor()

    usernameHasher = SHA256.new()
    usernameHasher.update(bytes(user, 'UTF-8'))
    userHash = usernameHasher.hexdigest() 

    passwordHasher = argon2.PasswordHasher()
    passwordHash = passwordHasher.hash(password)

    cur.execute("INSERT INTO user (username, pass) VALUES (?,?)",(userHash, passwordHash))
    db.commit()

@cli.command()
def initdb():
    db = sqlite3.connect(DATABASE_FILE, detect_types=sqlite3.PARSE_DECLTYPES)
    cur = db.cursor()
    with open(INIT_SCRIPT) as script:
        cur.executescript(script.read())

if __name__ == '__main__':
    cli()