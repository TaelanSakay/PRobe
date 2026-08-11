from flask import request
import os


def upload_handler():
    upload_path = request.files.get("file")
    if upload_path is not None:
        target = os.path.join("/tmp", upload_path.filename)
        with open(target, "rb") as handle:
            handle.read()
    return "uploaded"
