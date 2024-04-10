import os
import shutil
import argon2
import json
import sqlite3
import databasefunctions
import click

#from stem.control import Controller
from flask import Flask
from flask import current_app, session, request, redirect, url_for, g

app = Flask(__name__)

app.config['DATABASE'] = "passtorDatabase.db"

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

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
    pass

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
#        g.db.row_factory = sqlite3.Row

    return g.db

@app.cli.command('register_user')
def register_user():
    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT INTO user (username, pass) VALUES ('lassi', 'passw0rd')")
    db.commit()
    res = cur.execute("SELECT * FROM user")
    rows = res.fetchall()
    #print(res)
    #print(res.fetchall())
    print(rows)
    print(rows[0])

@app.cli.command('init_db')
def init_db():
    db = get_db()

    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

@app.route("/login")
def login_get():
    if 'username' in session:
        print(session['username'])
        print(request.cookies)
        return request.cookies

@app.post("/login")
def login_post():
    #session['username'] = request.data['username']
    if request.is_json:
        passwordHasher = argon2.PasswordHasher()
        requestData = request.get_json()
        print(requestData.get('username'))
        print(requestData.get('password'))
        session["username"] = requestData.get('username')
    #return redirect(url_for('login'))
    return redirect(url_for('login_get'))

"""
@app.route("/register", methods=['GET', 'POST'])
def register():
    pass
    if request.is_json:
        passwordHasher = argon2.PasswordHasher()
        requestData = request.get_json()
        passwordHash = passwordHasher.hash(requestData.get('username'))
        userName = requestData.get('password')
"""