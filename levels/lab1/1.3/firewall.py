import pydivert
import threading
import logging
from scapy.all import *
from common import *

RET_VAL_BLOCK_PACKET = True

class Firewall(Component):
    def __init__(self, event_queue, block_ips):
        self._block_ips = block_ips

        Component.__init__(self, event_queue, 'Firewall', [self._divert_proc])

    def _divert_proc(self):
        with pydivert.WinDivert() as windivert:
            for packet in windivert:  # Waits here for the next packet
                if RET_VAL_BLOCK_PACKET == self._handle_packet(packet):
                    # Block!
                    continue

                # Let packet pass through
                try:
                    windivert.send(packet)
                except OSError:
                    pass

    def _detect_malicious_ip(self, packet, scapy_packet):
        if packet.src_addr in self._block_ips:
            direction = 'Incoming'
            addr = packet.src_addr
        elif packet.dst_addr in self._block_ips:
            direction = 'Outgoing'
            addr = packet.dst_addr
        else:
            return 

        self.send_event({"kind": "blocked_malicious_ip",
                    "direction": direction,
                    "addr": addr})
        return RET_VAL_BLOCK_PACKET

    def _handle_packet(self, packet):
        # We have existing code that uses scapy and it's generally more flexible to use
        # But also keep the windivert packet because it has useful info (direction)
        try:
            scapy_packet = IP(bytes(packet.raw))
        except:
            return 
            
        results = [self._detect_malicious_ip(packet, scapy_packet)]

        if any(results):
            return RET_VAL_BLOCK_PACKET
