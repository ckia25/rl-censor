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
    9: 'send',          # NOT IMPLEMENTED will send if (+) won't send if (-)
}

PACKET_SIZE = 9
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

def encode_packet(packet):
    vector = [0] * PACKET_SIZE  # Update size to match expanded fields

    if IP in packet:
        ip_layer = packet[IP]
        # Convert IP addresses to integers
        vector[0] = ip_to_int(ip_layer.src)
        vector[1] = ip_to_int(ip_layer.dst)
        # Add IP checksum directly as an integer
        vector[5] = ip_layer.chksum

    if TCP in packet:
        tcp_layer = packet[TCP]
        vector[2] = tcp_layer.sport  # Source port
        vector[3] = tcp_layer.dport  # Destination port
        vector[4] = tcp_layer.seq  # Sequence number
        # Add TCP checksum directly as an integer
        vector[6] = tcp_layer.chksum
        vector[7] = 1 if tcp_layer.flags.R else 0  # RST flag (1 if set)
        vector[8] = 1 if tcp_layer.flags.F else 0  # FIN flag (1 if set)

    return np.array(vector)


def encode_state(base_packet, packets, response_packets):
    vectors = []
    vectors.append(encode_packet(base_packet))
    for packet in packets:
        vectors.append(encode_packet(packet))
    for response_packet in response_packets:
        vectors.append(encode_packet(response_packet))
    for i in range(NUM_PACKETS - len(response_packets)):
        vectors.append(create_k_empty_response_packets(1)[0])
    return torch.tensor(np.stack(vectors)).float().reshape((2*NUM_PACKETS+1)*PACKET_SIZE,)


def decode_output(base_packet, packets, outputs):  
    vectors = (outputs).reshape(NUM_PACKETS, PACKET_SIZE)
    modified_packets = []
    for vector, packet in zip(vectors, packets):
        modified_packet = decode_vector(vector, packet, base_packet)
        modified_packets.append(modified_packet)
    return modified_packets


def decode_vector(vector, packet, base_packet):
    return modify_packet_pipeline(vector, packet)


if __name__ == '__main__':
    pkt = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=1234, dport=80, seq=1001, flags="SR")

    vector = encode_packet(pkt)
    print('*'*73)
    print()
    print('Tested ENCODE PACKET RESULT:', vector)
    print()

    outputs = np.array([156.345, 2324.346, 809.345, -54.34, 34.1, 2325.4, 523.4, -23, 92.3])
    modified_packet = decode_vector(outputs, pkt, None)
    print('*'*73)
    print()
    print('Tested decode_vector: ',modified_packet)
    print()
