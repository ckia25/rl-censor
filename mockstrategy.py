from scapy.all import IP, TCP, Raw, raw
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
        packets.append(copy_packet)
        packets.append(packet)
        return packets
    
    def strategy2(self, packet):
        packets = []
        copy_packet = packet.copy()
        copy_packet[TCP].chksum=1
        copy_packet[TCP].flags = 'F'
        copy_packet[IP].src = '10.1.0.1'
        packets.append(copy_packet)
        packets.append(packet)
        return packets


    

    