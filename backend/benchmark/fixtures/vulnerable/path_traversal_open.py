from flask import request


def download_file():
    filename = request.args.get("file")
    with open(filename, "r") as handle:
        return handle.read()
