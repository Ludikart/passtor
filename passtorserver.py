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
    if 'username' in session:
        dbfile = request.files['db']
        dbfile.save(usernameHash)
        return "Ok", 200
    return "Unauthorized", 401

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
            session['username'] = usernameHash
            return "Ok", 200 
        else:
            return "Unauthorized", 401
    return "Bad request", 400

# TODO Add server password so only known users can register user accounts
# TODO Make sure you can't create a new user with the same name and access the old database
@app.post("/register")
def register():
    if request.is_json:
        db = get_db()
        passwordHasher = argon2.PasswordHasher()
        requestData = request.get_json()
        usernameHash = requestData.get('username')
        password = requestData.get('password')
        passwordHash = passwordHasher.hash(password)
        cursor = db.cursor()
        try:
            result = cursor.execute("INSERT INTO user (username, pass) VALUES (?,?)",(usernameHash, passwordHash))
            db.commit()
        except sqlite3.IntegrityError:
            return "Conflict", 409
        return "Ok", 200
    return "Bad request", 400
 
@app.get("/logout")
def logout():
    session.pop('username')
    return "Ok", 200