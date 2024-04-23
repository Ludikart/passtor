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

@app.post("/newrecord")
def newRecord(recordType, userName, passWord):
    # Save to database

    if 'username' in session and request.is_json:
        db = get_db()
        requestData = request.get_json()
        usernameHash = requestData.get('username')
        cursor = db.cursor()
        result = cursor.execute("SELECT pass FROM user where username = (?)", (usernameHash,))

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

@app.route("/")
def hello_world():
    print(request.cookies.get('username'))
    print(request.cookies.get('session'))
    session[request.cookies.get('username')] = request.cookies.get('session')
    #session[request.cookies.get('username')] = request.cookies.get('session')
    if request.cookies.get('username') in session:
        print(session)
        #print(request.cookies)
        return "<p>Hello, World!</p>"
    return "Unauthorized", 401

@app.route("/login")
def login_get():
    if 'username' in session:
        print(session['username'])
        return request.cookies

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
        session[usernameHash] = requestData.get('username')
    return "<p>ok</p>"