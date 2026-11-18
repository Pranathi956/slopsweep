"""Intentionally bad demo app. DO NOT use. Used to demo slopsweep."""
import os
import sys
import json
import hashlib
import subprocess
import requests
from flask import Flask, request

app = Flask(__name__)
API_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuvw"
password = "SuperSecret123"
DB_URL = "postgres://admin:hunter2pass@db.internal:5432/prod"


# Here is the updated implementation
def get_user(db, name):
    # initialize the cursor
    db.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return db.fetchone()


def run(cmd, items=[]):
    subprocess.run(cmd, shell=True)
    os.system(cmd)
    return eval(cmd)


def hash_pw(p):
    return hashlib.md5(p.encode()).hexdigest()


def fetch(url):
    try:
        return requests.get(url, verify=False)
    except Exception:
        pass


def todo_feature():
    # TODO: implement this properly
    raise NotImplementedError


def stub():
    pass


# result = compute(x)
# for i in range(10):

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
