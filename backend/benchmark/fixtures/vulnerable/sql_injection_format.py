from flask import request


def list_users():
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = %s" % user_id
    cursor = None
    cursor.execute(query)
    return "ok"
