from scapy.all import Raw, IP, TCP
import socket
import struct
from packet import compute_ip_chksm, compute_tcp_chksm


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
    9: 'syn_flag',       # SYN flag (1 if set, 0 ow)
    10: 'duplicate',
    11: 'frag_offs'
}

def ip_to_int(ip_address):
    """Converts an IP address to its integer representation."""
    return struct.unpack("!I", socket.inet_aton(ip_address))[0]

def int_to_ip(val):
    """Converts an integer back to an IP address."""
    return socket.inet_ntoa(struct.pack("!I", int(val)%4294967295))

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
        packet[TCP].sport = int(val)%65536
    return packet

def mod_dst_port(val, packet):
    if val >= 0:
        packet[TCP].dport = int(val)%65536
    return packet

def mod_sn(val, packet):
    if val >= 0:
        packet[TCP].seq = int(val)%70000
    return packet

def mod_chksum_ip(val, packet):
    packet[IP].chksum = int(val)%65536
    return packet

def mod_chksum_tcp(val, packet):
    packet[TCP].chksum = int(val)%65536
    return packet

def mod_rst_flag(val, packet):
    packet[TCP].flags.R = True if val > 0 else False
    return packet

def mod_fin_flag(val, packet):
    packet[TCP].flags.F = True if val > 0 else False
    return packet

def mod_syn_flag(val, packet):
    packet[TCP].flags.S = True if val > 0 else False
    return packet

# NEVER USED
def mod_duplicate(val, packet):
    return packet

# NOT IMPLEMENTED
def mod_frag_offs(val, packet):
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
    'syn_flag': mod_syn_flag,
    'duplicate': mod_duplicate,
    'frag_offs': mod_frag_offs,
    'send': None
}

def modify_packet_pipeline(vector, packet, at_capacity):
    packet = packet.copy()
    
    duplicate_packet = packet.copy()
    recompute_ip_chksm = False
    recompute_tcp_chksm = False
    output_packets = [packet]
    for i, val in enumerate(vector):
        field = fields[i]
        if field == 'chksum_ip' and (val <= 0 or val is None):
            recompute_ip_chksm = True
        elif field == 'chksum_tcp' and (val <= 0 or val is None):
            recompute_tcp_chksm = True
        elif field == 'duplicate' and not at_capacity and (val > 0 or val is None):
            output_packets.append(duplicate_packet)
        else:
            packet = field_functions[field](val, packet)
    if recompute_ip_chksm:
        compute_ip_chksm(packet)
    if recompute_tcp_chksm:
        compute_tcp_chksm(packet)
    output_packets[0] = packet
    return output_packets