from flask import request


def normalize(name):
    return name.split("/")[-1]


def safe_download():
    filename = request.args.get("file")
    safe_name = normalize(filename)
    with open(safe_name, "r") as handle:
        return handle.read()
