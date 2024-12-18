from scapy.all import IP, TCP, Raw, raw
import socket
import struct
import numpy as np
import torch
from field_modifier import modify_packet_pipeline
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
    11: 'load',
    12: 'ttl',
    13: 'frag_offs'
}

PACKET_SIZE = 13
NUM_PACKETS = 2

def ip_to_int(ip_address):
    return struct.unpack("!I", socket.inet_aton(ip_address))[0]

def create_k_empty_response_packets(k):
    packets = []
    packet = IP(src="0.0.0.0", dst="0.0.0.0") / TCP(sport=0, dport=0, seq=0)
    compute_tcp_chksm(packet)
    compute_ip_chksm(packet)

    packets.append(packet)
    for i in range(k-1):
        packets.append(packet.copy())
    return packets

def fill_packets(packets, n=NUM_PACKETS):
    full_packets = []
    for packet in packets:
        full_packets.append(packet)
    if len(packets) == n:
        return full_packets
    for packet in create_k_empty_response_packets(k=n-len(packets)):
        full_packets.append(packet)
    
    return full_packets

def encode_packet(packet, num_packets=0):
    vector = [0] * PACKET_SIZE  # Update size to match expanded fields

    if IP in packet:
        ip_layer = packet[IP]
        # Convert IP addresses to integers
        vector[0] = ip_to_int(ip_layer.src)
        vector[1] = ip_to_int(ip_layer.dst)
        # Add IP checksum directly as an integer
        vector[5] = 0 if ip_layer.chksum is None else ip_layer.chksum
        vector[12] = packet[IP].ttl
        vector[10] = num_packets * 1000

    if TCP in packet:
        tcp_layer = packet[TCP]
        vector[2] = tcp_layer.sport  # Source port
        vector[3] = tcp_layer.dport  # Destination port
        vector[4] = tcp_layer.seq  # Sequence number
        # Add TCP checksum directly as an integer
        vector[6] = 0 if tcp_layer.chksum is None else tcp_layer.chksum
        vector[7] = 1000 if tcp_layer.flags.R else -1000  # RST flag 
        vector[8] = 1000 if tcp_layer.flags.F else -1000  # FIN flag
        vector[9] = 1000 if tcp_layer.flags.S else -1000  # SYN flag
        
    if Raw in packet:
        if packet[Raw] == 'turtle':
            vector[11] = 1000
        else:
            vector[11] == -1000


    return np.array(vector)


def encode_state(base_packet, packets, response_packets):
    vectors = []
    vectors.append(encode_packet(base_packet))
    for packet in fill_packets(packets):
        vectors.append(encode_packet(packet, len(packets)))
    for response_packet in response_packets[:NUM_PACKETS]:
        vectors.append(encode_packet(response_packet))
    for i in range(NUM_PACKETS - len(response_packets)):
        vectors.append(encode_packet(create_k_empty_response_packets(1)[0]))
    # return torch.tensor(np.stack(vectors)).float().reshape((2*NUM_PACKETS+1)*PACKET_SIZE,)
    return torch.tensor(np.stack(vectors)).float().view(-1)


def decode_output(base_packet, packets, outputs, mask_outputs, duplicate=True): 
    for i, mo in enumerate(mask_outputs):
        if mo < 0:
            outputs[i] = -10 
    vectors = (outputs).reshape(-1, PACKET_SIZE)
    vectors = vectors[:len(packets)]
    modified_packets = []
    num_new_packets = 0
    if duplicate == False:
        at_capacity = True
    else:
        at_capacity = False
    for vector, packet in zip(vectors, packets):
        at_capacity = num_new_packets + len(packets) >= NUM_PACKETS or at_capacity
        for i, p in enumerate(decode_vector(vector, packet, base_packet, at_capacity)):
            num_new_packets += 1 if i > 0 else 0
            modified_packets.append(p)
    return modified_packets


def decode_vector(vector, packet, base_packet, at_capacity):
    return modify_packet_pipeline(vector, packet, at_capacity)


if __name__ == '__main__':
    pkt = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=1234, dport=80, seq=1001, flags="SR")

    vector = encode_packet(pkt)
    print('*'*73)
    print()
    print('Tested ENCODE PACKET RESULT:', vector)
    print()

    outputs = np.array([156.345, 2324.346, 809.345, -54.34, 34.1, 2325.4, 523.4, -23, 92.3, 1, 1, 1])
    modified_packets = decode_vector(outputs, pkt, None, False)
    print('*'*73)
    print()
    print('Tested decode_vector: ',modified_packets)
    print()
