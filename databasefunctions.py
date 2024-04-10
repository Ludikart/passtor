import sqlite3

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

def newUser(userHash, passwordHash):
    db = sqlite3.connect("passtorDatabase.db", detect_types=sqlite3.PARSE_DECLTYPES)
    cur = db.cursor()
    tup = (userHash, passwordHash)
    cur.execute("INSERT INTO user (username, pass) VALUES (?,?)", tup)
    db.commit()

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db

def init_db():
    db = get_db()

    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))


newUser("lassi2", "abc4137492ac")