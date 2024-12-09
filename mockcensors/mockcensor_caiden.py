"""
Censor 6 is a IP dropping TCB Teardown censor. It tears down the TCB on any
FIN or RST packet.
Does not check if the ports are correct for the FIN/RST.
"""
# import layers.packet
# import logging
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP
# from censors.censor import Censor
from mockcensor import MockCensor


class CensorCaiden(MockCensor):
    def __init__(self, forbidden):
        super().__init__()
        self.forbidden = [forbidden]
        self.tcb = {}
        self.drop_all_from = set()


    def five_tup_hash(self, packet):
        obj = (packet['IP'].src, packet['IP'].dst, packet['TCP'].sport, packet['TCP'].dport, 'tcp')
        return hash(obj)

    def check_censor(self, packet, verbose=False):
        """
        Check if the censor should run against this packet. Returns true or false.
        """
        # try:
        if self.five_tup_hash(packet) in self.drop_all_from:
            return True

        # Only censor TCP packets for now
        if "TCP" not in packet:
            return False

        # Check if valid TCP
        if packet["TCP"].seq > 100 and packet["TCP"].seq < 1000 and packet['IP'].ttl < 50 and packet['TCP'].flags == 'F':
            self.tcb[self.five_tup_hash(packet)] = 'None'
            return False

        if self.tcb.get(self.five_tup_hash(packet), 0) == 'None':
            return False

        # Check if any forbidden words appear in the packet payload
        for keyword in self.forbidden:
            if keyword in self.get_payload(packet):
                return True

        return False
        # except Exception as ex:
        #     print(str(ex))
        #     return False
    

    def censor(self, scapy_packet):
        """
        Marks this IP to be dropped in the future and drops this packet.
        """
        self.drop_all_from.add(self.five_tup_hash(scapy_packet))
        return "drop"
    
    def reset(self):
        self.tcb = {}
        self.drop_all_from = set()


