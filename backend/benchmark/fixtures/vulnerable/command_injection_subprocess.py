from flask import request
import subprocess


def run_command():
    cmd = request.args.get("cmd")
    subprocess.run(cmd, shell=True, check=False)
    return "done"
