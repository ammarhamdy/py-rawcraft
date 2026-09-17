import socket
from types import TracebackType
from typing import Self


class ICMPSender:
    """Manages raw socket lifecycle and packet transmission for ICMP."""

    def __init__(self, timeout: float = 2.0) -> None:
        self.timeout = timeout
        self._socket: socket.socket | None = None

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def open(self) -> None:
        """Create and configure the raw ICMP socket."""
        if self._socket is not None:
            return

        try:
            self._socket = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_ICMP,
            )
            self._socket.settimeout(self.timeout)
        except PermissionError as exc:
            raise PermissionError(
                "Raw sockets require administrative/root privileges."
            ) from exc

    def send(self, destination: str, packet: bytes) -> int:
        """Transmit raw bytes to the specified destination host/IP."""
        if self._socket is None:
            raise RuntimeError("Socket is closed. Call open() or use a context manager.")

        # Port number is ignored for raw ICMP, 0 or 1 is conventional
        return self._socket.sendto(packet, (destination, 1))

    def close(self) -> None:
        """Safely close the underlying raw socket."""
        if self._socket is not None:
            self._socket.close()
            self._socket = None
