
import sys
import os
sys.path.append(os.path.abspath('./mockcensors'))
from mockcensor6 import Censor6
from mocktcpserver import MockTCPServer
from mockclient import MockClient
from mockstrategy import MockStrategy
from mocknetwork import MockNetwork


forbidden_word = 'turtle'
censor = Censor6(forbidden_word)
server = MockTCPServer(
    server_ip='127.0.0.1',
    server_port=65432
)
client = MockClient(
    ip='10.10.10.10',
    dst_ip='127.0.0.1',
    src_port=12345,
    dst_port=65432
)
strategy = MockStrategy()
network = MockNetwork(client, server, censor)
reward = network.test_strategy(strategy, forbidden_word)

print('Reward:', reward)