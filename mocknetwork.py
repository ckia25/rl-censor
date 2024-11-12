from scapy.all import IP, TCP
from mockclient import MockClient
from mockcensors.mockcensor import MockCensor
from mockserver import MockServer
from mockstrategy import MockStrategy

class MockNetwork():
    
    def __init__(self, client: MockClient, server: MockServer, censor: MockCensor) -> None:
        self.client = client
        self.server = server
        self.censor = censor
        
        self.iptable = {client.ip:'client', server.server_ip:'server'}


    def test_strategy(self, strategy: MockStrategy, forbidden_word):
        client_packets = self.client.send_packets_with_strategy(strategy, forbidden_word)
        censor_queue = self.censor.monitor_packets(client_packets)
        client_queue = []
        server_queue = []

        for packet in censor_queue:
            host = self.iptable.get(packet[IP].dst, False)
            if host == 'server':
                server_queue.append(packet)
            elif host == 'client':
                client_queue.append(packet)
        server_acks = self.server.process_packets(server_queue)
    
        for packet in server_acks:
            host = self.iptable.get(packet[IP].dst, False)
            if host == 'client':
                client_queue.append(packet)
    
        reward = self.client.recieve_packets(client_queue, forbidden_word)
        return reward




    

        



            