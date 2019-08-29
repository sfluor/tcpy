import socket as std_socket

from .constants import SocketState


class Socket:

    """Socket representation"""

    def __init__(
        self,
        family: int = std_socket.AF_INET,
        typ: int = std_socket.SOCK_STREAM,
        proto: int = 0,
    ):
        """Inits a new socket

        :family: family for the socket (defaults to AF_INET)
        :typ: type of the socket (defaults to SOCK_STREAM, used for TCP)
        :proto: protocol for the socket (defaults to 0 for IPPROTO_TCP)

        """

        self._family = family
        self._typ = typ
        self._state: SocketState = SocketState.UNCONNECTED
        self._proto = proto
        # TODO figure out this, since we are not using a file descriptor
        self._fd = 1234

        # TODO raise error if family / type / proto are not supported
