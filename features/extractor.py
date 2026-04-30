import numpy as np
from datetime import datetime


def safe_div(a, b):
    return a / b if b != 0 else 0


def parse_timestamp(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def extract_features_from_service(service, flow_id):
    try:
        rx_bytes = service.get("RX bytes", 0)
        tx_bytes = service.get("TX bytes", 0)
        rx_packets = service.get("RX packets", 0)
        tx_packets = service.get("TX packets", 0)

        total_bytes = rx_bytes + tx_bytes
        total_packets = rx_packets + tx_packets

        # time
        t1 = service.get("RX first timestamp")
        t2 = service.get("RX latest timestamp")

        if t1 and t2:
            duration = (parse_timestamp(t2) - parse_timestamp(t1)).total_seconds()
        else:
            duration = 0.001

        # rates
        bytes_per_sec = safe_div(total_bytes, duration)
        packets_per_sec = safe_div(total_packets, duration)
        rx_bytes_ps = safe_div(rx_bytes, duration)
        tx_bytes_ps = safe_div(tx_bytes, duration)

        # ratios
        dir_ratio_bytes = safe_div(tx_bytes, rx_bytes + 1)
        dir_ratio_packets = safe_div(tx_packets, rx_packets + 1)

        # QoS
        jitter = service.get("Jitter (ms)", 0)
        rtt = service.get("RTT (ms)", 0)
        loss = service.get("RX packet loss", 0) + service.get("TX packet loss", 0)

        packet_loss_ratio = safe_div(loss, total_packets + 1)

        # distribution proxy
        avg_pkt_size = safe_div(total_bytes, total_packets + 1)
        variance_proxy = avg_pkt_size * (1 + dir_ratio_packets)

        # protocol + port
        proto = 1 if "TCP" in flow_id else 0

        try:
            dst_port = int(flow_id.split(":")[-1].split()[0])
        except:
            dst_port = 0

        # SNI
        sni = service.get("SNI", "")
        sni_present = 1 if sni else 0
        sni_length = len(sni) if sni else 0

        return [
            rx_bytes,
            tx_bytes,
            rx_packets,
            tx_packets,
            total_bytes,
            total_packets,
            duration,
            bytes_per_sec,
            packets_per_sec,
            rx_bytes_ps,
            tx_bytes_ps,
            dir_ratio_bytes,
            dir_ratio_packets,
            jitter,
            rtt,
            packet_loss_ratio,
            avg_pkt_size,
            variance_proxy,
            proto,
            dst_port,
            sni_present,
            sni_length
        ]

    except Exception:
        return None