# mockclient.py
from scapy.all import IP, TCP, Raw, raw
from packet import compute_tcp_chksm, compute_ip_chksm

class MockClient:
    def __init__(self, ip, dst_ip, src_port, dst_port):
        """
        Initialize the MockClient with a mock IP address.
        
        :param mock_ip: The mock IP address for the client.
        """
        self.ip = ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port

    def create_forbidden_packet(self, forbidden_word):
        ip_layer = IP(src=self.ip, dst=self.dst_ip)
        tcp_layer = TCP(sport=self.src_port, dport=self.dst_port)
        payload = forbidden_word
        packet = ip_layer / tcp_layer / payload
        compute_ip_chksm(packet)
        compute_tcp_chksm(packet)
        return packet
    
    def apply_strategy(self, packet, strategy):
        packets = strategy.apply(packet)
        return packets
    
    def send_packets_with_strategy(self, strategy, forbidden_word):
        return self.apply_strategy(self.create_forbidden_packet(forbidden_word), strategy)


    def verify_destination(self, packet):
        if IP in packet:
            print(packet[IP].dst)
            if packet[IP].dst == self.ip:
                return True
        return False

    def recieve_packets(self, packets, forbidden_word):
        reward = -1000
        for packet in packets:
            if not self.verify_destination(packet):
                continue
            # print(packet.summary())
            # print('payload: ',self.get_payload(packet))
            # print('*'*73)
            if self.get_payload(packet) == forbidden_word:
                reward += 2000
        return reward

    def get_payload(self, packet):
        """
        Parse paylaod out of the given scapy packet.
        """
        try:
            return packet[Raw].load.decode(errors="ignore")
        except Exception:
            return ''
        
    def compute_checksum(self, packet):
        if IP in packet and TCP in packet:
            original_checksum = packet[TCP].chksum
            packet[TCP].chksum = None
            recalculated_checksum = (IP(raw(packet[IP])) / TCP(raw(packet[TCP])))[TCP].chksum
            packet[TCP].chksum = recalculated_checksum

