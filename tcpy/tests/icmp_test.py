import os
import subprocess

from tcpy.stack import Stack

from .utils import setup_virt_interf


def test_arping() -> None:
    if not os.geteuid() == 0:
        print("Only root can run this test, skipping it for now...")
        return

    print("Starting the stack...")
    s = Stack()
    s.start()

    print("Starting the virtual interface...")
    setup_virt_interf()

    # Calling ping
    subprocess.check_output(["ping", "-c3", "10.0.0.4"])

    s.stop()
