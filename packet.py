from scapy.all import TCP, IP, Raw, raw, Packet
import socket

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
        fields.append(f'TCP.ttl={packet[IP].ttl}')
        if Raw in packet:    
            fields.append(f"Payload={packet[Raw].load.decode(errors='ignore')}")
    else:
        fields.extend(["TCP.sport=N/A", "TCP.dport=N/A", "TCP.flags=N/A", "TCP.chksum=N/A", "TCP.seq=N/A"])
    
    print(" | ".join(fields))