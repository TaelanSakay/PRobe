import os


def run_safe_eval():
    expression = os.getenv("APP_MODE")
    eval(expression)
    return "ok"
