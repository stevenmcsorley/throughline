# Deliberately vulnerable Python fixture.
import hashlib
import subprocess
from flask import request


# VULN: SQL Injection — concatenation into execute()
def get_user(cursor):
    uid = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = " + uid)


# VULN: Command Injection — shell=True with untrusted input
def ping():
    host = request.args.get('host')
    subprocess.call("ping -c 1 " + host, shell=True)


# VULN: Insecure Crypto — MD5
def digest(data):
    return hashlib.md5(data).hexdigest()


# VULN: Hardcoded Secret
AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"
