# Idiomatic, safe Python. Any finding here is a false positive.
import hashlib
import os
import subprocess
from flask import request

ALLOWED_HOSTS = {"api.internal.example"}


def get_user(cursor):
    # Parameterized — the driver binds the value.
    cursor.execute("SELECT * FROM users WHERE id = %s", (request.args.get('id'),))


def ping():
    # Argument list, no shell.
    host = request.args.get('host')
    if host in ALLOWED_HOSTS:
        subprocess.run(["ping", "-c", "1", host], shell=False, check=False)


def digest(data):
    return hashlib.sha256(data).hexdigest()


# This comment mentions a password = "example" but declares nothing.
API_KEY = os.environ.get("API_KEY")
