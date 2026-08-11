from flask import request


def run_template():
    expression = request.form.get("expr")
    eval(expression)
    return "rendered"
