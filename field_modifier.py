from scapy.all import Raw, IP, TCP
import socket
import struct
from packet import compute_ip_tcp_checksums


fields = {
    0: 'src_ip',        # Encoded IP address as an integer
    1: 'dst_ip',        # Encoded IP address as an integer
    2: 'src_port',      # Source port number
    3: 'dst_port',      # Destination port number
    4: 'sn',            # Sequence number
    5: 'chksum_ip',     # IP checksum
    6: 'chksum_tcp',    # TCP checksum
    7: 'rst_flag',      # RST flag (1 if set, 0 otherwise)
    8: 'fin_flag',      # FIN flag (1 if set, 0 otherwise)
    9: 'send',          # NOT IMPLEMENTED will send if (+) won't send if (-)
}

def ip_to_int(ip_address):
    """Converts an IP address to its integer representation."""
    return struct.unpack("!I", socket.inet_aton(ip_address))[0]

def int_to_ip(val):
    """Converts an integer back to an IP address."""
    return socket.inet_ntoa(struct.pack("!I", int(val)))

# Modifier functions
def mod_src_ip(val, packet):
    if val >= 0:
        packet[IP].src = int_to_ip(val)
    return packet

def mod_dst_ip(val, packet):
    if val >= 0:
        packet[IP].dst = int_to_ip(val)
    return packet

def mod_src_port(val, packet):
    if val >= 0:
        packet[TCP].sport = int(val)
    return packet

def mod_dst_port(val, packet):
    if val >= 0:
        packet[TCP].dport = int(val)
    return packet

def mod_sn(val, packet):
    if val >= 0:
        packet[TCP].seq = int(val)
    return packet

def mod_chksum_ip(val, packet):
    if val >= 0:
        packet[IP].chksum = int(val)
    return packet

def mod_chksum_tcp(val, packet):
    packet[TCP].chksum = int(val)
    return packet

def mod_rst_flag(val, packet):
    packet[TCP].flags = packet[TCP].flags | 0x04 if val else packet[TCP].flags & ~0x04
    return packet

def mod_fin_flag(val, packet):
    packet[TCP].flags = packet[TCP].flags | 0x01 if val else packet[TCP].flags & ~0x01
    return packet

field_functions = {
    'src_ip': mod_src_ip,
    'dst_ip': mod_dst_port,
    'src_port': mod_src_port,
    'dst_port': mod_dst_port,
    'sn': mod_sn,
    'chksum_ip': mod_chksum_ip,
    'chksum_tcp': mod_chksum_tcp,
    'rst_flag': mod_rst_flag,
    'fin_flag': mod_fin_flag,
    'send': None
}

def modify_packet_pipeline(vector, packet):
    packet = packet.copy()
    recompute_ip_chksm = False
    recompute_tcp_chksm = False
    for i, val in enumerate(vector):
        field = fields[i]
        if field == 'chksum_ip' and val < 0:
            recompute_ip_chksm = True
        elif field == 'chksum_tcp' and val < 0:
            recompute_tcp_chksm = True
        else:
            packet = field_functions[field](val, packet)
    
    if recompute_tcp_chksm and recompute_ip_chksm:
        packet[TCP].chksum = None
        packet[IP].chksum = None
        ip_chksm, tcp_chksm = compute_ip_tcp_checksums(packet)
        packet[TCP].chksum = tcp_chksm
        packet[IP].chksum = ip_chksm
    elif recompute_ip_chksm:
        packet[IP].chksum = None
        ip_chksm, tcp_chksm = compute_ip_tcp_checksums(packet)
        packet[IP].chksum = ip_chksm
    elif recompute_tcp_chksm:
        packet[TCP].chksum = None
        ip_chksm, tcp_chksm = compute_ip_tcp_checksums(packet)
        packet[TCP].chksum = ip_chksm
    return packet