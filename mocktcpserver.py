from scapy.all import IP, TCP, Raw, raw

class MockTCPServer:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.expected_seq = None  # To track expected sequence numbers

    def process_packets(self, packets):
        responses = []
        for packet in packets:
            response = self.receive_packet(packet)
            if response:
                if type(response) == type([]):
                    for pkt in response:
                        responses.append(pkt)
                else:
                    responses.append(response)
        return responses
    
    def receive_packet(self, packet):
        # Check if the packet is a TCP packet destined for this server
        if IP in packet and TCP in packet:
            if packet[IP].dst == self.server_ip and packet[TCP].dport == self.server_port:
                # Verify the TCP checksum
                if not self.verify_tcp_checksum(packet):
                    print("Checksum verification failed. Packet is corrupted.")
                    return self.send_reset(packet)  # Send a reset if checksum fails

                # Process the packet normally if checksum is valid
                print("Checksum is valid. Processing packet.")
                
                # Handle the packet according to its flags
                if packet[TCP].flags == "S":  # SYN - connection request
                    return self.handle_syn(packet)
                elif packet[TCP].flags == "PA":  # ACK + PSH - standard data packet
                    return self.handle_data(packet)
                elif packet[TCP].flags == "F":  # FIN - connection close request
                    return self.handle_fin(packet)
            else:
                # Send a reset if packet is not intended for this server
                return self.send_reset(packet)
        return None

    def verify_tcp_checksum(self, packet):
        if IP in packet and TCP in packet:
            # Get the original checksum
            original_checksum = packet[TCP].chksum

            # Temporarily set the checksum field to zero for recalculation
            packet[TCP].chksum = None

            # Recalculate the checksum
            recalculated_packet = IP(raw(packet[IP])) / TCP(raw(packet[TCP]))
            recalculated_checksum = recalculated_packet[TCP].chksum

            # Restore the original checksum in the packet
            packet[TCP].chksum = original_checksum

            # Return True if checksums match, False otherwise
            return original_checksum == recalculated_checksum
        return False

    def handle_syn(self, packet):
        self.expected_seq = packet[TCP].seq + 1  # Set next expected sequence number
        syn_ack_packet = IP(src=self.server_ip, dst=packet[IP].src) / \
                         TCP(sport=self.server_port, dport=packet[TCP].sport, 
                             seq=1000, ack=self.expected_seq, flags="SA")
        
        # Echo the packet data
        echo_packet = IP(src=self.server_ip, dst=packet[IP].src) / \
                        TCP(sport=self.server_port, dport=packet[TCP].sport, 
                            seq=1000, ack=self.expected_seq, flags="PA") / \
                        (packet[Raw].load if Raw in packet else "")
        
        return [syn_ack_packet, echo_packet]

    def handle_data(self, packet):
        if self.expected_seq and packet[TCP].seq == self.expected_seq:
            # Simulate data acknowledgment
            self.expected_seq += len(packet[Raw].load) if Raw in packet else 1
            ack_packet = IP(src=self.server_ip, dst=packet[IP].src) / \
                         TCP(sport=self.server_port, dport=packet[TCP].sport, 
                             seq=1000, ack=self.expected_seq, flags="A")
            
            # Echo the packet data
            echo_packet = IP(src=self.server_ip, dst=packet[IP].src) / \
                          TCP(sport=self.server_port, dport=packet[TCP].sport, 
                              seq=1000, ack=self.expected_seq, flags="PA") / \
                          (packet[Raw].load if Raw in packet else "")
            
            return [ack_packet, echo_packet]  # Send acknowledgment and echo the data
        else:
            # If sequence number doesn't match, send RST for corruption
            return self.send_reset(packet)

    def handle_fin(self, packet):
        fin_ack_packet = IP(src=self.server_ip, dst=packet[IP].src) / \
                         TCP(sport=self.server_port, dport=packet[TCP].sport,
                             seq=1000, ack=packet[TCP].seq + 1, flags="FA")
        return fin_ack_packet

    def send_reset(self, packet):
        rst_packet = IP(src=self.server_ip, dst=packet[IP].src) / \
                     TCP(sport=self.server_port, dport=packet[TCP].sport, 
                         seq=0, ack=packet[TCP].seq + 1, flags="R")
        print("Sent RST due to unexpected packet or sequence.")
        return rst_packet
