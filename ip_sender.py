from socket import socket
from types import TracebackType
from typing import Self


class RawIPSender:
    """Manages raw Layer-3 transmission with custom IP headers."""

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
        if self._socket is not None:
            return

        try:
            # IPPROTO_RAW allows custom Layer 3 IP assembly
            self._socket = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_RAW,
            )
            # Enable IP_HDRINCL to instruct kernel not to create its own IP header
            self._socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self._socket.settimeout(self.timeout)
        except PermissionError as exc:
            raise PermissionError("Raw sockets require root/admin privileges.") from exc

    def send(self, destination_ip: str, raw_ip_packet: bytes) -> int:
        if self._socket is None:
            raise RuntimeError("Socket is closed. Call open() or use a context manager.")
        # Port is unused in raw Layer-3 routing; 0 is conventional
        return self._socket.sendto(raw_ip_packet, (destination_ip, 0))

    def close(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None