from scapy.all import TCP, IP, raw

class MockServer():
    
    def __init__(self, ip, port):
        self.server_ip = ip
        self.server_port = port        

    def verify_port(self, packet):
        if TCP in packet:
            if packet[TCP].dport == self.server_port:
                return True
        return False
    
    def verify_ip(self, packet):
        if IP in packet:
            if packet[IP].dst == self.server_ip:
                return True
        return False

    def verify_tcp_checksum(packet):
        if IP in packet and TCP in packet:
            original_checksum = packet[TCP].chksum
            packet[TCP].chksum = 0
            recalculated_checksum = (IP(raw(packet[IP])) / TCP(raw(packet[TCP])))[TCP].chksum
            return original_checksum == recalculated_checksum
        return False
    
    def has_reset_flags(packet):
        if packet["TCP"].sprintf('%TCP.flags%') in ["R", "RA", "F"]:
            return True
        return False
    
    
    def process_packets(self, packets):
        pass

