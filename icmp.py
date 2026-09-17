import os
import struct
import time
from dataclasses import dataclass, field

from utils import calculate_checksum

ICMP_HEADER_STRUCT = "!BBHHH"

def generate_linux_payload(total_payload_len: int = 56) -> bytes:
    """
    Generate a payload compatible with the timestamp layout used by
    Linux iputils ping on typical 64-bit Linux systems.
    """
    now_ns = time.time_ns()

    tv_sec, remainder = divmod(now_ns, 1_000_000_000)
    tv_usec = remainder // 1_000

    timestamp = struct.pack("<qq", tv_sec, tv_usec)

    remaining_len = max(0, total_payload_len - len(timestamp))
    pattern = bytes((0x10 + i) & 0xFF for i in range(remaining_len))

    return timestamp + pattern


@dataclass(frozen=True)
class ICMPPacket:
    """An ICMP packet."""
    icmp_type: int = 8  # Echo Request
    icmp_code: int = 0
    identifier: int = field(default_factory=lambda: os.getpid() & 0xFFFF)
    sequence: int = 1
    payload: bytes = b"ping_test"

    def __post_init__(self) -> None:
        if not 0 <= self.icmp_type <= 0xFF:
            raise ValueError("icmp_type must fit in 8 bits")

        if not 0 <= self.icmp_code <= 0xFF:
            raise ValueError("icmp_code must fit in 8 bits")

        if not 0 <= self.identifier <= 0xFFFF:
            raise ValueError("identifier must fit in 16 bits")

        if not 0 <= self.sequence <= 0xFFFF:
            raise ValueError("sequence must fit in 16 bits")

    def build(self) -> bytes:
        """Assembles an ICMP packet with a valid checksum."""
        # Checksum calculation header (checksum initialized to 0)
        dummy_header = struct.pack(
            ICMP_HEADER_STRUCT,
            self.icmp_type,
            self.icmp_code,
            0,
            self.identifier,
            self.sequence,
        )

        checksum = calculate_checksum(dummy_header + self.payload)

        # Final header insertion
        header = struct.pack(
            ICMP_HEADER_STRUCT,
            self.icmp_type,
            self.icmp_code,
            checksum,
            self.identifier,
            self.sequence,
        )

        return header + self.payload

