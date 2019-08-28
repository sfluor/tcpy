# tcpy

A WIP TCP/IP stack, it's highly inspired by [saminiir posts about coding a TCP/IP stack](https://www.saminiir.com/lets-code-tcp-ip-stack-1-ethernet-arp/).

For now only ARP, ICMP and TCP handshake is supported.

# Testing

to run the stack you can do:

`./tcpy-stack` as root and then up the virtual interface and add the route for it by doing:

`ip link set dev tap0 up && ip route add dev tap0 10.0.0.0/24` (replacing `tap0` by the name prompted when running the `tcpy-stack` script).


to run the tests:
`pipenv run python -m pytest tcpy/tests -v -s`

Some tests require to be run as root (to start the stack) for those you can do:
`pipenv run sudo python -m pytest tcpy/tests -v -s`

TODOs:
- improve readme
- docs on linting/testing
- implement socket API for TCP
- benchmarks to compare with the native stack

