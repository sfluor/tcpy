import os
import subprocess
from typing import List

from tcpy.stack import Stack


def setup_virt_interf() -> None:
    subprocess.check_output(["ip", "link", "set", "dev", "tap0", "up"])
    subprocess.check_output(["ip", "route", "add", "dev", "tap0", "10.0.0.0/24"])


def run_cmd_with_stack(cmd: List[str]) -> None:
    if not os.geteuid() == 0:
        print("Only root can run this test, skipping it for now...")
        return

    print("Starting the stack...")
    s = Stack()
    s.start()

    print("Starting the virtual interface...")
    setup_virt_interf()

    # Calling the command to test
    subprocess.check_output(cmd)

    s.stop()
