import os
import socket
import struct
from dataclasses import dataclass, field

from utils import calculate_checksum

# Formats: Network byte order (Big-Endian !)
# IPv4 Header: Version/IHL (1B), DSCP/ECN (1B), Total Length (2B), ID (2B),
#              Flags/Fragment (2B), TTL (1B), Protocol (1B), Checksum (2B), Src (4B), Dst (4B)
IPV4_HEADER_STRUCT = "!BBHHHBBH4s4s"

@dataclass
class IPv4Packet:
    source_ip: str
    destination_ip: str
    payload: bytes
    ttl: int = 64
    protocol: int = socket.IPPROTO_ICMP
    packet_id: int = field(default_factory=lambda: os.getpid() & 0xFFFF)

    def build(self) -> bytes:
        """Constructs an IPv4 header prefixed to the payload with a valid checksum."""
        version_ihl = (4 << 4) | 5  # IPv4, 5 x 32-bit words (20 bytes)
        tos = 0
        total_length = 20 + len(self.payload)
        flags_fragment = 0  # No flags, fragment offset 0

        src_bytes = socket.inet_aton(self.source_ip)
        dst_bytes = socket.inet_aton(self.destination_ip)

        # 1. Build header with 0 checksum
        dummy_header = struct.pack(
            IPV4_HEADER_STRUCT,
            version_ihl,
            tos,
            total_length,
            self.packet_id,
            flags_fragment,
            self.ttl,
            self.protocol,
            0,
            src_bytes,
            dst_bytes,
        )

        # 2. Compute IPv4 checksum (covers only the IPv4 header)
        ip_checksum = calculate_checksum(dummy_header)

        # 3. Assemble complete header with checksum
        header = struct.pack(
            IPV4_HEADER_STRUCT,
            version_ihl,
            tos,
            total_length,
            self.packet_id,
            flags_fragment,
            self.ttl,
            self.protocol,
            ip_checksum,
            src_bytes,
            dst_bytes,
        )

        return header + self.payload