import os
import datetime
import shutil
import argon2
import json
import sqlite3
import databasefunctions
import click
from Crypto.Hash import SHA256

#from stem.control import Controller
from flask import Flask
from flask import current_app, session, request, redirect, url_for, g, send_file

app = Flask(__name__)

app.config['DATABASE'] = "passtorDatabase.db"

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

@app.post("/newrecord")
def newRecord():
    usernameHash = request.cookies.get('username')

    if 'username' in session and request.is_json:
        requestData = request.get_json()
        recordType = requestData.get('type')
        userName = requestData.get('uname')
        passWord = requestData.get('pass')
        db = get_db()
        cursor = db.cursor()
        result = cursor.execute("SELECT id FROM user where username = (?)", (usernameHash,))
        user_id = result.fetchone()[0]
        result = cursor.execute("INSERT INTO record (user_id, recordtype, username, pass) VALUES (?, ?, ?, ?)", (user_id, recordType, userName, passWord))
        db.commit()
        return "Ok", 200
    return "Unauthorized", 401

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

    return g.db

@app.get("/")
def get_database():
    usernameHash = request.cookies.get('username')
    print(session['username'])
    if 'username' in session:
        last_modified_time = os.path.getmtime(usernameHash)
        last_modified_datetime = datetime.datetime.utcfromtimestamp(last_modified_time)
        response = send_file(usernameHash)
        response.last_modified = last_modified_datetime
        return response
    return "Unauthorized", 401

@app.post("/")
def update_database():
    usernameHash = request.cookies.get('username')
    print(session['username'])
    if 'username' in session:
        dbfile = request.files['db']
        dbfile.save('serverdatafile')
        return "Ok", 200
    return "Unauthorized", 401

"""
@app.route("/login")
def login_get():
    if 'username' in session:
        print(session['username'])
        return request.cookies
"""

@app.post("/login")
def login_post():
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

        session['username'] = usernameHash
        return "Ok", 200 
    return "<p>ok</p>"

@app.post("/test")
def test():
    usernameHash = request.cookies.get('username')

    print(usernameHash)
    print(session[usernameHash])
    print(request.cookies.get('session'))
    if session[usernameHash] == request.cookies.get('session') and request.is_json:
        print("authenticated")
        return 200
    return 401
 