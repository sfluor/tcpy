class Sock:

    """Abstract Sock representation, should not be used directly but inherited"""

    def __init__(self, proto: int, state: int):
        """Inits a new sock

        :proto: protocol used
        :state: current state
        """

        self.proto = proto
        self.state = state
        self.sport: int = 0
        self.dport: int = 0
        self.saddr: int = 0
        self.daddr: int = 0

    # TODO better type for addr to support multiple use cases
    def connect(self, addr: str) -> None:
        """connect the socket to the given destination address.
        this should be implemented by the child class

        :addr: the address to connect to

        """
        raise NotImplementedError("connect is not implemented")

    def write(self, data: bytes) -> int:
        """writes the given data to the socket, to be import module
        this should be implemented by the child class

        :data: bytes to write to the socket
        :returns: the number of bytes written

        """
        raise NotImplementedError("write is not implemented")

    def read(self, size: int) -> bytes:
        """reads at most <size> bytes from the socket
        this should be implemented by the child class

        :size: max number of bytes to read from the socket
        :returns: raw bytes read from the socket

        """
        raise NotImplementedError("read is not implemented")

    def close(self) -> None:
        """closes the socket connection
        this should be implemented by the child class

        """
        raise NotImplementedError("close is not implemented")

    def abort(self) -> None:
        """aborts the socket connection
        this should be implemented by the child class

        """
        raise NotImplementedError("abort is not implemented")
