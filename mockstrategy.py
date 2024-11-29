from scapy.all import IP, TCP, Raw, raw
from packet import compute_tcp_chksm
class MockStrategy():

    def __init__(self):
        pass

    def apply(self, packet):
        return self.strategy2(packet)

    
    def strategy1(self, packet):
        packets = []
        copy_packet = packet.copy()
        copy_packet[TCP].chksum=1
        copy_packet[TCP].flags = 'F'
        packets.append(packet)
        packets.append(copy_packet)
        return packets
    
    def strategy2(self, packet):
        packets = []
        copy_packet = packet.copy()
        copy_packet[TCP].chksum=1
        copy_packet[TCP].flags = 'F'
        copy_packet[IP].src = '10.1.0.1'
        compute_tcp_chksm(copy_packet)
        packets.append(packet)
        packets.append(copy_packet)
        return packets


    

    