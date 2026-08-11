from flask import request
import subprocess


def start_job():
    binary = request.headers.get("X-Job")
    subprocess.Popen(binary, shell=True)
    return "started"
