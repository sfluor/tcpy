import subprocess


def setup_virt_interf() -> None:
    subprocess.check_output(["ip", "link", "set", "dev", "tap0", "up"])
    subprocess.check_output(["ip", "route", "add", "dev", "tap0", "10.0.0.0/24"])
