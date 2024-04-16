import os
import shutil
import argon2
import json
import sqlite3
import databasefunctions
import click
from Crypto.Hash import SHA256

#from stem.control import Controller
from flask import Flask
from flask import current_app, session, request, redirect, url_for, g

app = Flask(__name__)

app.config['DATABASE'] = "passtorDatabase.db"

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

def addListing(listingType, userName, passWord):
    # Save to database
    pass

def removeListing(listingType):
    pass

def getRecords(userID):
    pass

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
#        g.db.row_factory = sqlite3.Row

    return g.db

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
        db = get_db()
        passwordHasher = argon2.PasswordHasher()
        requestData = request.get_json()
        usernameHash = requestData.get('username')
        password = requestData.get('password')
        cursor = db.cursor()
        result = cursor.execute("SELECT pass FROM user where username = (?)", (usernameHash,))
        passwordHash = result.fetchone()[0]

        if passwordHasher.verify(passwordHash, password):
            print("success")
        session["username"] = requestData.get('username')
    return redirect(url_for('login_get'))
