from icmp import ICMPPacket
from ip_sender import RawIPSender
from ip_v4 import IPv4Packet

if __name__ == '__main__' :    
    # 1. Build the ICMP payload (8B header + 56B data)
    icmp_bytes = ICMPPacket(sequence=1).build()

    # 2. Encapsulate inside custom IPv4 header
    ip_packet = IPv4Packet(
        source_ip="192.168.1.42",       # Custom source IP
        destination_ip="192.168.1.255",    # Target destination IP
        payload=icmp_bytes,
    ).build()

    # 3. Transmit the complete Layer-3 datagram
    with RawIPSender() as sender:
        bytes_sent = sender.send(destination_ip="192.168.1.1", raw_ip_packet=ip_packet)
        print(f"Sent {bytes_sent} bytes (20B IP + 64B ICMP).")
    

