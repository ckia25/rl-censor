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
        self.tcb = 0
        self.drop_all_from = None

    def check_censor(self, packet, verbose=False):
        """
        Check if the censor should run against this packet. Returns true or false.
        """
        # try:
        if self.drop_all_from == packet["IP"].src:
            return True

        # Only censor TCP packets for now
        if "TCP" not in packet:
            return False

        # Check if valid TCP
        if packet["TCP"].seq > 100 and packet['TCP'].flags == 'F':
            self.tcb = None
            return False

        if self.tcb is None:
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
        self.drop_all_from = scapy_packet["IP"].src
        return "drop"
    
    def reset(self):
        self.tcb = 0
        self.drop_all_from = None


