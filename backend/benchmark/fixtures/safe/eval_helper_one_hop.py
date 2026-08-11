from flask import request


def helper(value):
    return value


def run_safe():
    user_input = request.args.get("expr")
    payload = helper(user_input)
    eval(payload)
    return "ok"
