
def calculate_checksum(data: bytes) -> int:
    """Standard Internet Checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    
    checksum_sum = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))

    while checksum_sum >> 16:
        checksum_sum = (checksum_sum & 0xFFFF) + (checksum_sum >> 16)

    return (~checksum_sum) & 0xFFFF
