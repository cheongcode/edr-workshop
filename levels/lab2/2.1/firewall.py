import pydivert
import threading
import logging
from scapy.all import *
from common import *

RET_VAL_BLOCK_PACKET = True

def get_listeners():
    """
    Get all currently listening ports and their associated processes.

    :return: A list of dicts e.g. {'port': 80, 'pid': 2308}.
    """
    listeners = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == psutil.CONN_LISTEN:
            procname = get_process_name(conn.pid)
            if 'docker' in procname or 'wslrelay' in procname:
                continue

            listener = {'port': conn.laddr.port, 'pid': conn.pid}
            if listener not in listeners:
                listeners.append(listener)

    return listeners

class Firewall(Component):
    def __init__(self, event_queue, block_ips):
        self._block_ips = block_ips

        Component.__init__(self, event_queue, 'Firewall', [self._divert_proc, self._periodic_checks])

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

    def _periodic_checks(self):
        # Initialize state
        self._listeners = get_listeners()

        while True:
            # Check periodically
            time.sleep(1)
            self._periodic_check_listeners()

    def _periodic_check_listeners(self):
        current_listeners = get_listeners()
        for listener in current_listeners:
            if listener not in self._listeners:
                self.send_event({"kind": "new_listener_detected",
                            "port": listener['port'], "pid": listener['pid']})
        self._listeners = current_listeners

    def _detect_malicious_ip(self, packet, scapy_packet):
        if packet.src_addr in self._block_ips:
            direction = 'Incoming'
            addr = packet.src_addr
            if TCP in scapy_packet:
                local_port = scapy_packet[TCP].dport
        elif packet.dst_addr in self._block_ips:
            direction = 'Outgoing'
            addr = packet.dst_addr
            if TCP in scapy_packet:
                local_port = scapy_packet[TCP].sport
        else:
            return 

        if TCP in scapy_packet:
            pid = find_pid_by_lport(local_port)
        else:
            pid = None
        self.send_event({"kind": "blocked_malicious_ip",
                        "direction": direction,
                        "addr": addr,
                        "pid": pid})
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
