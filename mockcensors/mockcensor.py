import socket
socket.setdefaulttimeout(1)
import logging
import random
import os
from scapy.all import send, IP, TCP, Raw

# Note that censor.py lives in censors, so we need an extra dirname() call to get
# to the project root
BASEPATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class MockCensor(object):
    def __init__(self):
        """
        Setup censor attributes and logging.
        """
        self.queue = []

    def clear_queue(self):
        self.queue = []
    
    def mysend(self, packet):
        self.queue.append(packet)

    def get_payload(self, packet):
        """
        Parse paylaod out of the given scapy packet.
        """
        try:
            return packet[Raw].load.decode(errors="ignore")
        except Exception:
            return ''

    def callback(self, packet):
        # try:
        scapy_packet = packet
        action = "accept"
        # Check if the packet should be censored
        if self.check_censor(scapy_packet):
            # If so, trigger the censoring itself (drop packet, send RST, etc)
            action = self.censor(scapy_packet)

        if action == "drop":
            self.drop(packet)
        else:
            self.accept(packet)
        # except Exception as ex:
        #     print(str(ex))
    
    def accept(self, packet):
        self.mysend(packet)
    
    def drop(self, packet):
        pass

    def get_client_queue(self):
        return self.client_queue
    
    def get_server_queue(self):
        return self.server_queue
    

    def reset(self):
        pass

    def monitor_packets(self, packets):
        try:
            for packet in packets:
                self.callback(packet)
            return self.queue
        finally:
            self.clear_queue()
            self.reset()
         

