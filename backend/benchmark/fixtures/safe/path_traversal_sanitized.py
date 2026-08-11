from flask import request
import os


def safe_download():
    filename = request.args.get("file")
    safe_name = os.path.basename(filename)
    with open(safe_name, "r") as handle:
        return handle.read()
