from flask import request


def search_users():
    search_term = request.args.get("search")
    statement = "SELECT * FROM users WHERE name = '" + search_term + "'"
    cursor = object()
    cursor.execute(statement)
    return "done"
