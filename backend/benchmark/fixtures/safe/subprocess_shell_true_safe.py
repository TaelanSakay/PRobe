import subprocess


def run_safe_process():
    command = ["echo", "hello"]
    subprocess.run(command, shell=False, check=False)
    return "done"
