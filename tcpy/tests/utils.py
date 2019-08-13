import subprocess
from multiprocessing import Process

from tcpy.stack import start_stack


def start_test_stack() -> Process:
    p = Process(target=start_stack)
    p.start()
    return p


def setup_virt_interf() -> None:
    subprocess.check_output(["ip", "link", "set", "dev", "tap0", "up"])
    subprocess.check_output(["ip", "route", "add", "dev", "tap0", "10.0.0.0/24"])
