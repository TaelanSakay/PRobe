import subprocess


def run_safe_command():
    command = "echo hello"
    subprocess.run(command, shell=True, check=False)
    return "done"
