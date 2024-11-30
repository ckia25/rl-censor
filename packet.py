from scapy.all import TCP, IP, Raw, raw, Packet
import socket

def compute_checksum(packet):
    packet[TCP].chksum = None
    return packet.__class__(bytes(packet))


def compute_checksum_data(data):
    print(data)
    """Compute the 16-bit checksum for the given data."""
    if len(data) % 2 != 0:  # If odd length, pad with a zero byte
        data += b'\x00'

    checksum = 0
    for i in range(0, len(data), 2):
        # Combine two bytes into one 16-bit word
        word = (data[i] << 8) + data[i + 1]
        checksum += word
        # Wrap around if overflow occurs
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # One's complement of the final sum
    return ~checksum & 0xFFFF

def compute_ip_tcp_checksums(packet):
    """
    Compute IP and TCP checksums manually for a given Scapy packet.
    Args:
        packet: A Scapy packet with IP and TCP layers.
    Returns:
        tuple: (ip_checksum, tcp_checksum)
    """
    # Compute IP checksum
    ip_raw = bytes(packet[IP])  # Get raw bytes of the IP header
    ip_raw_zeroed = ip_raw[:10] + b'\x00\x00' + ip_raw[12:]  # Zero out the checksum
    ip_checksum = compute_checksum_data(ip_raw_zeroed)

    # Compute TCP checksum
    if TCP in packet:
        tcp_raw = bytes(packet[TCP])  # Get raw bytes of the TCP header + payload
        tcp_length = len(tcp_raw)

        # Construct pseudo-header
        pseudo_header = (
            socket.inet_aton(packet[IP].src) +  # Convert Source IP to binary
            socket.inet_aton(packet[IP].dst) +  # Convert Destination IP to binary
            b'\x00' +  # Zero padding
            bytes([packet[IP].proto]) +  # Protocol (6 for TCP)
            tcp_length.to_bytes(2, "big")  # TCP length (header + payload)
        )

        # Concatenate pseudo-header and TCP segment
        tcp_raw_with_pseudo = pseudo_header + tcp_raw
        tcp_raw_with_pseudo_zeroed = tcp_raw_with_pseudo[:16] + b'\x00\x00' + tcp_raw_with_pseudo[18:]  # Zero out checksum
        tcp_checksum = compute_checksum_data(tcp_raw_with_pseudo_zeroed)
    else:
        tcp_checksum = None

    return ip_checksum, tcp_checksum


def compute_ip_chksm(packet):
    if IP in packet and TCP in packet:
        packet[IP].chksum = None
        recalculated_checksum = IP(raw(packet[IP]))[IP].chksum
        packet[IP].chksum = recalculated_checksum
    return recalculated_checksum

    

def compute_tcp_chksm(packet):
    if IP in packet and TCP in packet:
        packet[TCP].chksum = None
        recalculated_checksum = (IP(raw(packet[IP])) / TCP(raw(packet[TCP])))[TCP].chksum
        packet[TCP].chksum = recalculated_checksum
    return recalculated_checksum



def packet_summary(packet: Packet) -> str:
    """
    Extract specific fields from a Scapy packet and return them in a single line.
    
    Args:
        packet (Packet): Scapy packet.
        
    Returns:
        str: A string with extracted fields (IP addresses, ports, flags, checksum, sequence number).
    """
    fields = []

    # Extract IP addresses (src and dst)
    if packet.haslayer("IP"):
        fields.append(f"IP.src={packet[IP].src}")
        fields.append(f"IP.dst={packet[IP].dst}")
    else:
        fields.append("IP.src=N/A")
        fields.append("IP.dst=N/A")
    
    # Extract ports (source and destination)
    if packet.haslayer("TCP"):
        fields.append(f"TCP.sport={packet[TCP].sport}")
        fields.append(f"TCP.dport={packet[TCP].dport}")
        # TCP flags
        fields.append(f"TCP.flags={packet[TCP].flags}")
        # TCP checksum
        fields.append(f"TCP.chksum={packet[TCP].chksum}")
        # TCP sequence number
        fields.append(f"TCP.seq={packet[TCP].seq}")
    else:
        fields.extend(["TCP.sport=N/A", "TCP.dport=N/A", "TCP.flags=N/A", "TCP.chksum=N/A", "TCP.seq=N/A"])
    
    print(" | ".join(fields))