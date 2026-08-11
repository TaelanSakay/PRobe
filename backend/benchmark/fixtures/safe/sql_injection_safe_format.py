from flask import request


def safe_search():
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = %s"
    cursor = object()
    cursor.execute(query, (user_id,))
    return "ok"
