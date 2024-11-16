from scapy.all import IP, TCP, Raw, raw 


fields = {
    0: 'src_ip', # (+) original | (-) changed
    1: 'dst_ip', # (+) original | (-) changed
    2: 'src_port', # (+) original | (-) changed
    3: 'dst_port', # (+) original | (-) changed
    4: 'sn', # (+) correct | (-) incorrect
    5: 'chksum_ip', # (+) correct | (-) incorrect
    6: 'chksum_tcp', # (+) correct | (-) incorrect
    7: 'rst_flag', # (+) set | (-) unset
    8: 'fin_flag', # (+) set | (-) unset
}


# Duplicate a scapy packet n times and outputs a vector that represents the 
# n packets in state space
def original_encoding(n):
    return [1]*(n*len(fields.keys()))



# takes as input the current list of packets
# checks the values of the fields in comparison to the original packet fields
def encode_packets(original_packet, packets):
    src_ip = original_packet[IP].src       # Source IP address
    dst_ip = original_packet[IP].dst       # Destination IP address
    src_port = original_packet[TCP].sport  # Source port
    dst_port = original_packet[TCP].dport  # Destination port
    sequence_number = original_packet[TCP].seq  # Sequence number
    chksum_ip = original_packet[IP].chksum # IP checksum
    chksum_tcp = original_packet[TCP].chksum  # TCP checksum
    rst_flag = 'R' in original_packet[TCP].flags # RST flag
    fin_flag = 'F' in original_packet[TCP].flags # FIN flag




# takes the state space vector and decodes it into the n scapy packets that compose it
def decode_packets(original_packet, network_outputs, n):
    pass