import sys
import os
sys.path.append(os.path.abspath('./mockcensors'))
from mockcensor6 import Censor6
from mockcensor_caiden import CensorCaiden
from mocktcpserver import MockTCPServer
from mockclient import MockClient
from mockstrategy import MockStrategy
from mocknetwork import MockNetwork
from mockcensor_clara import AdvancedCensor
import torch

class Evaluator():

    def __init__(self,
                censor_index=0, 
                forbidden_word='turtle', 
                server_ip='127.0.0.1', 
                server_port=65432, 
                client_ip='10.10.10.10', 
                client_port=12345):
        
        self.forbidden_word = forbidden_word
        self.server_ip = server_ip
        self.client_ip = client_ip
        self.server_port = server_port
        self.client_port = client_port

        if censor_index == 1:
            self.censor = CensorCaiden(forbidden_word)
        elif censor_index == 2:
            self.censor = AdvancedCensor(forbidden_word)
        else:
            self.censor = Censor6(forbidden_word)
            
        self.server = MockTCPServer(
            server_ip=server_ip,
            server_port=server_port
        )
        self.client = MockClient(
            ip=client_ip,
            dst_ip=server_ip,
            src_port=client_port,
            dst_port=server_port
        )
        self.network = MockNetwork(self.client, self.server, self.censor)
        
    # strategy is a function that when applied to the base packet will output n packets modified packets
    def evaluate(self, packets):
        reward, response_packets = self.network.test_packets(packets, self.forbidden_word) 
        return reward, response_packets
    
    def get_base_packet(self):
        return self.client.create_forbidden_packet(forbidden_word=self.forbidden_word)
    

    def get_strategy(self):
        return self.strategy