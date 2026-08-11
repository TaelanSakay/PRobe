def helper(value):
    return "static payload"


def run_safe():
    payload = helper("ignored")
    eval(payload)
    return "ok"
