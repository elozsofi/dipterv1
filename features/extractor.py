# features = [
#    duration,
#    packet_count,
#    byte_count,
#    avg_packet_size,
#    packets_per_second,
#    bytes_per_second,
#    protocol,              # encode later
#    direction_ratio        # uplink / downlink
# ]

from scapy.all import rdpcap
import numpy as np


def extract_features_from_pcap(pcap_path):
    packets = rdpcap(pcap_path)

    if len(packets) == 0:
        return None

    timestamps = []
    sizes = []
    protocols = []

    for pkt in packets:
        timestamps.append(pkt.time)
        sizes.append(len(pkt))

        if pkt.haslayer("TCP"):
            protocols.append(6)
        elif pkt.haslayer("UDP"):
            protocols.append(17)
        else:
            protocols.append(0)

    duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
    packet_count = len(packets)
    byte_count = sum(sizes)
    avg_packet_size = np.mean(sizes)

    packets_per_second = packet_count / duration if duration > 0 else 0
    bytes_per_second = byte_count / duration if duration > 0 else 0

    # protocol encoding (simple)
    protocol = max(set(protocols), key=protocols.count)

    return [
        duration,
        packet_count,
        byte_count,
        avg_packet_size,
        packets_per_second,
        bytes_per_second,
        protocol,
    ]