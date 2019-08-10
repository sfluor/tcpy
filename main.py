#!/usr/bin/env python
# -*- coding: utf-8 -*-

from tcpy.stack import start_stack

TEST_IP = "10.0.0.4"
TEST_MAC = "aa:bb:cc:dd:ee:ff"

if __name__ == "__main__":
    start_stack(TEST_IP, TEST_MAC, "tap%d")
