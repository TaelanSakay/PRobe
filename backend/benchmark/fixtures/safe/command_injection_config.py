import os
import subprocess


def run_safe_command():
    command = os.getenv("APP_COMMAND")
    subprocess.run(command, shell=True, check=False)
    return "done"
