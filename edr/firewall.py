"""Network monitor.

Level 1.2  block Lazarus C2 IP
Level 1.5  new TCP listeners (interactive allow/kill)
Level 2.1  attribute C2 packets to a PID and kill that process
Level 2.2  HTTP deep packet inspection / stream reassembly
"""
import logging
import os
import time

from common import *
from streams import StreamTracker

try:
    import pydivert
except ImportError:
    pydivert = None

try:
    from scapy.all import IP, TCP
except ImportError:
    IP = TCP = None

RET_VAL_BLOCK_PACKET = True


def get_listeners():
    """Return [{'port': 80, 'pid': 2308}, ...] for current TCP listeners."""
    listeners = []
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        connections = []
        for proc in psutil.process_iter(['pid']):
            try:
                connections.extend(proc.net_connections(kind="inet"))
            except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError):
                continue

    for conn in connections:
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
        self._block_ips = set(block_ips)
        self._stream_tracker = StreamTracker()
        # Level 2.2 — watch HTTP responses (server source port 80)
        self._stream_tracker.start_tracking(
            {"sport": 80}, self._on_http_server_finished)

        Component.__init__(
            self, event_queue, 'Firewall',
            [self._divert_proc, self._periodic_checks],
        )

    def _divert_proc(self):
        if pydivert is None or os.name != 'nt':
            logging.warning(
                "WinDivert is Windows-only; packet blocking / DPI is disabled"
            )
            return

        with pydivert.WinDivert() as windivert:
            for packet in windivert:
                if RET_VAL_BLOCK_PACKET == self._handle_packet(packet):
                    continue
                try:
                    windivert.send(packet)
                except OSError:
                    pass

    def _periodic_checks(self):
        self._listeners = get_listeners()
        while True:
            time.sleep(1)
            self._periodic_check_listeners()

    def _periodic_check_listeners(self):
        # Level 1.5
        current_listeners = get_listeners()
        for listener in current_listeners:
            if listener not in self._listeners:
                self.send_event({
                    "kind": "new_listener_detected",
                    "port": listener['port'],
                    "pid": listener['pid'],
                })
        self._listeners = current_listeners

    def _detect_malicious_ip(self, packet, scapy_packet):
        # Level 1.2 block + Level 2.1 PID attribution
        local_port = None
        if packet.src_addr in self._block_ips:
            direction = 'Incoming'
            addr = packet.src_addr
            if TCP is not None and TCP in scapy_packet:
                local_port = scapy_packet[TCP].dport
        elif packet.dst_addr in self._block_ips:
            direction = 'Outgoing'
            addr = packet.dst_addr
            if TCP is not None and TCP in scapy_packet:
                local_port = scapy_packet[TCP].sport
        else:
            return

        if TCP is not None and TCP in scapy_packet and local_port is not None:
            pid = find_pid_by_lport(local_port)
        else:
            pid = None

        self.send_event({
            "kind": "blocked_malicious_ip",
            "direction": direction,
            "addr": addr,
            "pid": pid,
        })
        return RET_VAL_BLOCK_PACKET

    def _on_http_server_finished(self, data, stream_id, pid):
        # Level 2.2 / 2.3 — hash the HTTP body and record the downloader
        if b"\r\n\r\n" not in data:
            return
        headers_end = data.find(b"\r\n\r\n") + 4
        http_body = data[headers_end:]
        payload_hash = calculate_hash(http_body)
        self.send_event({
            "kind": "http_download",
            "hash": payload_hash,
            "pid": pid,
            "serveraddr": stream_id.src,
            "port": stream_id.sport,
        })

    def _detect_deep_packet_analysis(self, packet, scapy_packet):
        if TCP is not None and scapy_packet.haslayer(TCP):
            self._stream_tracker.process_packet(scapy_packet, packet.is_outbound)

    def _handle_packet(self, packet):
        if IP is None:
            return
        try:
            scapy_packet = IP(bytes(packet.raw))
        except Exception:
            return

        results = [
            self._detect_malicious_ip(packet, scapy_packet),
            self._detect_deep_packet_analysis(packet, scapy_packet),
        ]
        if any(results):
            return RET_VAL_BLOCK_PACKET
