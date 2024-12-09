from mockcensor import MockCensor
from scapy.all import raw, IP, TCP
import time
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname("mockcensor_clara.py"), '..')))
from packet import compute_tcp_chksm

class AdvancedCensor(MockCensor):
    def __init__(self, forbidden):
        super().__init__()
        self.forbidden = [forbidden]
        self.tcbs = []
        self.flagged_ips = []
        self.resynchronize = {}
        self.packet_history = {}  # To track packet timing and behavior
        self.behavior_threshold = 3  # Max suspicious packets before flagging

    def check_censor(self, packet):
        """
        Check if the censor should run against this packet.
        Returns True (block) or False (allow).
        """
        # print("At beginning of check censor")
        # try:
            # Track timing and sequence behavior
        src_ip = packet["IP"].src
    

        if src_ip not in self.packet_history:
            self.packet_history[src_ip] = []
        self.packet_history[src_ip].append(packet)

        # Check for suspicious packet timing (e.g., too fast)
        if len(self.packet_history[src_ip]) > 3:
            self.flagged_ips.append(src_ip)
            return True
            # time_deltas = [self.packet_history[src_ip][i] - self.packet_history[src_ip][i - 1] 
            #                 for i in range(1, len(self.packet_history[src_ip]))]
            # avg_time_delta = sum(time_deltas) / len(time_deltas)

            # if avg_time_delta < 0.01:  # Example threshold
            #     self.flagged_ips.append(src_ip)
            #     return True

            # self.packet_history[src_ip].pop(0)  # Maintain sliding window
        # print("Suspicious packet timing passed")

        # Check flagged IPs
        if src_ip in self.flagged_ips:
            return True
        # print("Flagged IPs check passed")

        # Only censor TCP packets
        if "TCP" not in packet:
            return False
        # print("This is a TCP packet")

        # Validate checksums
        reported_chksum = packet["TCP"].chksum
        del packet["TCP"].chksum
        calculated_chksum = compute_tcp_chksm(packet)
        # print("reported checksum: ", reported_chksum, " calculated checksum: ", calculated_chksum)
        if reported_chksum != calculated_chksum:
            return False
        if reported_chksum == 0 or reported_chksum == 65535:
            return False
        # print("Checksum check passed")

        # Check TCB and resynchronization state
        tcb = self.get_matching_tcb(packet)
        if (tcb and self.resynchronize.get((tcb["src"], tcb["dst"], tcb["sport"], tcb["dport"]), False)) or \
            (not tcb and packet["TCP"].sprintf('%TCP.flags%') in ["S"]):
            tcb = self.update_or_create_tcb(packet, tcb)
            return False
        # print("Resynchronization check passed")

        # Handle teardown flags
        if tcb and packet["TCP"].sprintf('%TCP.flags%') in ["R", "F"]:
            self.resynchronize[(tcb["src"], tcb["dst"], tcb["sport"], tcb["dport"])] = True

        # Update TCB sequence number
        if tcb:
            tcb["seq"] += len(self.get_payload(packet))

        # Obfuscation detection: Reject packets with payloads that appear encoded
        payload = self.get_payload(packet)
        if any(ord(char) > 127 for char in payload):  # Detect non-ASCII characters
            return True
        # print("Encoded payload check passed")

        # Check forbidden keywords in payload
        # print("Entering forbidden keyword check", flush=True)
        for keyword in self.forbidden:
            # print(f"Checking payload: {payload}", flush=True)
            if keyword in payload:
                # print(f"Keyword found in payload: {payload}", flush=True)
                return True
        # print("Forbidden keyword check passed")

        return False
        # except Exception as e:
        #     self.logger.exception("Exception caught by Advanced Censor", exc_info=e)
        #     return False

    def censor(self, scapy_packet):
        """
        Adds client and server IPs to flagged IP list and sends RST packets.
        """
        if scapy_packet["IP"].src not in self.flagged_ips:
            self.flagged_ips.append(scapy_packet["IP"].src)
        if scapy_packet["IP"].dst not in self.flagged_ips:
            self.flagged_ips.append(scapy_packet["IP"].dst)

        client_ip_rst = IP(src=scapy_packet[IP].dst, dst=scapy_packet[IP].src)
        client_tcp_rst = TCP(
            dport=scapy_packet[TCP].sport,
            sport=scapy_packet[TCP].dport,
            ack=scapy_packet[TCP].seq + len(str(scapy_packet[TCP].payload)),
            seq=scapy_packet[TCP].ack,
            flags="R"
        )
        client_rst = client_ip_rst / client_tcp_rst

        for _ in range(0, 3):
            self.mysend(client_rst)

        return "block"
    
    def get_matching_tcb(self, packet):
        """
        Checks if the packet matches the stored TCB.
        """
        for tcb in self.tcbs:

            if (packet["IP"].src == tcb["src"] and \
                packet["IP"].dst == tcb["dst"] and \
                packet["TCP"].sport == tcb["sport"] and \
                packet["TCP"].dport == tcb["dport"] and \
                packet["TCP"].seq == tcb["seq"]):
                return tcb
        return None

    def update_or_create_tcb(self, packet, tcb):
        """Create or update TCB with new connection details."""
        if not tcb:
            tcb = {}
        tcb.update({
            "src": packet["IP"].src,
            "dst": packet["IP"].dst,
            "sport": packet["TCP"].sport,
            "dport": packet["TCP"].dport,
            "seq": packet["TCP"].seq + 1 if packet["TCP"].sprintf('%TCP.flags%') in ["S"] else len(self.get_payload(packet))
        })
        self.tcbs.append(tcb)
        self.resynchronize[(tcb["src"], tcb["dst"], tcb["sport"], tcb["dport"])] = False
        return tcb

    def reset(self):
        self.tcbs = []
        self.flagged_ips = []
        self.resynchronize = {}
        self.packet_history = {}
