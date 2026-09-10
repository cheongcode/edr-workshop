"""Level 2.2 — reassemble TCP streams so HTTP response bodies can be hashed."""
import logging

try:
    from scapy.all import IP, TCP, Raw
except ImportError:
    IP = TCP = Raw = None

from common import find_pid_by_lport


class StreamId:
    def __init__(self, src, dst, sport, dport):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport

    @classmethod
    def from_packet(cls, packet):
        return cls(packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)

    def is_match(self, stream_id_filter):
        for field, value in stream_id_filter.items():
            if getattr(self, field) != value:
                return False
        return True

    def __hash__(self):
        return hash((self.src, self.dst, self.sport, self.dport))

    def __str__(self):
        return '{}:{} -> {}:{}'.format(self.src, self.sport, self.dst, self.dport)

    def __eq__(self, other):
        return hash(self) == hash(other)


class Stream:
    def __init__(self, on_finish, initial_seq):
        self._segments = {}
        self._on_finish = on_finish
        self._pid = None
        self._initial_seq = initial_seq + 1

    def process_packet(self, packet, is_outgoing):
        """Returns True when stream has been completed."""
        if not self._pid:
            if is_outgoing:
                self._pid = find_pid_by_lport(packet[TCP].sport)
            else:
                self._pid = find_pid_by_lport(packet[TCP].dport)

        if packet.haslayer(Raw):
            self._segments[packet[TCP].seq - self._initial_seq] = packet[Raw].load

        if 'F' in packet[TCP].flags or 'R' in packet[TCP].flags:
            logging.debug("Stream finished: {}".format(StreamId.from_packet(packet)))
            self._on_finish(self._reassemble(), StreamId.from_packet(packet), self._pid)
            return True

    def _reassemble(self):
        data = b''
        for seq, chunk in dict(sorted(self._segments.items())).items():
            if seq != len(data):
                logging.error("TCP stream reassembly error - possibly overlapping segments...")
                return b''
            data += chunk
        return data


def reassemble_segments(segments):
    """Pure helper used by tests: {relative_seq: bytes} -> payload or b'' on gap."""
    data = b''
    for seq, chunk in dict(sorted(segments.items())).items():
        if seq != len(data):
            return b''
        data += chunk
    return data


class StreamTracker:
    def __init__(self):
        self._tcp_streams = {}
        self._filters = []

    def start_tracking(self, stream_id_filter, on_finish, once=False):
        logging.debug("Started tracking: {}. once = {}".format(stream_id_filter, once))
        self._filters.append({
            "filter": stream_id_filter,
            "on_finish": on_finish,
            "once": once,
        })

    def process_packet(self, packet, is_outgoing):
        if TCP is None or not packet.haslayer(TCP):
            return

        stream_id = StreamId.from_packet(packet)
        if 'S' in packet[TCP].flags:
            f = self._filter_match(stream_id)
            if f:
                if f['once']:
                    self._filters.remove(f)
                logging.debug("New stream: {}".format(stream_id))
                self._tcp_streams[stream_id] = Stream(f['on_finish'], packet[TCP].seq)
        elif stream_id in self._tcp_streams:
            if self._tcp_streams[stream_id].process_packet(packet, is_outgoing):
                del self._tcp_streams[stream_id]

    def _filter_match(self, stream_id):
        for f in self._filters:
            if stream_id.is_match(f["filter"]):
                return f
        return None
