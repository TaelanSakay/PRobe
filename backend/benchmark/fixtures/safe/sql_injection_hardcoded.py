import sqlite3


def fetch_user():
    user_id = "42"
    query = "SELECT * FROM users WHERE id = %s" % user_id
    connection = sqlite3.connect(":memory:")
    connection.execute(query)
    return "ok"
