from scapy.all import IP, TCP, Raw, raw
from packet import compute_tcp_chksm
class MockStrategy():

    def __init__(self):
        pass

    def apply(self, packet):
        return self.strategy1(packet)

    
    def strategy1(self, packet):
        packets = []
        copy_packet = packet.copy()
        copy_packet[TCP].flags = 'R'
        copy_packet[TCP].chksum = 36679
        copy_packet[TCP].seq = 0
        
        
        packet[TCP].flags='S'
        
        packet[TCP].seq=2337
        compute_tcp_chksm(packet)
        packets.append(copy_packet)
        packets.append(packet)
        return packets
    
    def strategy2(self, packet):
        packets = []
        copy_packet = packet.copy()
        copy_packet[TCP].chksum=1
        copy_packet[TCP].flags = 'F'
        # compute_tcp_chksm(copy_packet)
        packets.append(copy_packet)
        packets.append(packet)
        return packets
    
    def strategy3(self, packet):
        packets = []
        packets.append(packet)
        packets.append(packet.copy())
        return packets



    

    