import ipaddress
from datetime import datetime


APP_INSTAGRAM = 0
APP_SPOTIFY = 1
APP_YOUTUBE = 2
APP_TIKTOK = 3
APP_WHATSAPP = 4


# =========================
# Known ip nets (not cdn)
# =========================

GOOGLE_NETS = [
    "8.8.8.0/24",
    "8.34.208.0/20",
    "8.35.192.0/20",
    "34.64.0.0/10",
    "35.184.0.0/13",
    "35.192.0.0/12",
    "64.233.160.0/19",
    "66.102.0.0/20",
    "74.125.0.0/16",
    "108.177.8.0/21",
    "142.250.0.0/15",
    "172.217.0.0/16",
    "173.194.0.0/16",
    "209.85.128.0/17",
    "216.58.192.0/19",
    "216.239.32.0/19",
]

META_NETS = [
    "31.13.24.0/21",
    "31.13.64.0/18",
    "45.64.40.0/22",
    "57.144.0.0/14",
    "66.220.144.0/20",
    "69.63.176.0/20",
    "69.171.224.0/19",
    "74.119.76.0/22",
    "102.132.96.0/20",
    "129.134.0.0/16",
    "157.240.0.0/16",
    "173.252.64.0/18",
    "179.60.192.0/22",
    "185.60.216.0/22",
]

TIKTOK_NETS = [
    "47.88.0.0/13",
    "47.89.0.0/16",
    "103.136.220.0/23",
    "161.117.0.0/16",
]

SPOTIFY_NETS = [
    "35.186.224.0/20",
    "35.190.247.0/24",
    "104.154.127.0/24",
]

GOOGLE_IPS = [ipaddress.ip_network(x) for x in GOOGLE_NETS]
META_IPS = [ipaddress.ip_network(x) for x in META_NETS]
TIKTOK_IPS = [ipaddress.ip_network(x) for x in TIKTOK_NETS]
SPOTIFY_IPS = [ipaddress.ip_network(x) for x in SPOTIFY_NETS]


# =========================
# App-specific ports
# =========================

WHATSAPP_PORTS = {
    3478,   # STUN/TURN
    34784,
    45395,
    5222,   # XMPP
    5223,
    5228,
    5242,
}

SPOTIFY_PORTS = {
    4070,
    57621,
}

TIKTOK_PORTS = {
    3480,
}

YOUTUBE_PORTS = {
    1935,   # RTMP
}

META_PORTS = {
    5222,
    5223,
}


# =========================
# Helpers
# =========================

def parse_timestamp(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def safe_ip(flow_id):
    try:
        return flow_id.rsplit(":", 1)[0]
    except Exception:
        return ""


def safe_port(flow_id):
    try:
        return int(flow_id.rsplit(":", 1)[1].split()[0])
    except Exception:
        return 0


def ip_in_ranges(ip_str, ranges):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in ranges)
    except Exception:
        return False


# =========================
# Main classifier
# =========================

def classify(service, flow_id):

    dst_port = safe_port(flow_id)
    ip = safe_ip(flow_id)

    sni = service.get("SNI", "")
    sni_lower = sni.lower()

    rx_bytes = service.get("RX bytes", 0)
    tx_bytes = service.get("TX bytes", 0)

    rx_packets = service.get("RX packets", 0)
    tx_packets = service.get("TX packets", 0)

    total_bytes = rx_bytes + tx_bytes
    total_packets = rx_packets + tx_packets

    t1 = parse_timestamp(service.get("RX first timestamp"))
    t2 = parse_timestamp(service.get("RX latest timestamp"))

    duration = 0.001

    if t1 and t2:
        duration = max((t2 - t1).total_seconds(), 0.001)

    bytes_per_sec = total_bytes / duration
    packets_per_sec = total_packets / duration

    avg_pkt_size = total_bytes / (total_packets + 1)

    dir_ratio = tx_bytes / (rx_bytes + 1)

    # =========================================================
    # 1. STRONGEST SIGNAL: SNI
    # =========================================================

    if sni_lower:

        # YouTube / Googlevideo
        if (
            "youtube" in sni_lower or
            "googlevideo" in sni_lower or
            "ytimg" in sni_lower
        ):
            return APP_YOUTUBE

        # Spotify
        if (
            "spotify" in sni_lower or
            "scdn" in sni_lower
        ):
            return APP_SPOTIFY

        # Instagram
        if (
            "instagram" in sni_lower or
            "cdninstagram" in sni_lower
        ):
            return APP_INSTAGRAM

        # WhatsApp
        if (
            "whatsapp" in sni_lower or
            "whatsapp.net" in sni_lower
        ):
            return APP_WHATSAPP

        # TikTok
        if (
            "tiktok" in sni_lower or
            "byteoversea" in sni_lower or
            "ibyteimg" in sni_lower or
            "muscdn" in sni_lower
        ):
            return APP_TIKTOK

    # =========================================================
    # 2. NON-CDN IP INFRASTRUCTURE RULES
    # =========================================================

    # TikTok
    if ip_in_ranges(ip, TIKTOK_IPS):
        return APP_TIKTOK

    # Spotify
    if ip_in_ranges(ip, SPOTIFY_IPS):
        return APP_SPOTIFY

    # Meta traffic
    if ip_in_ranges(ip, META_IPS):

        # WhatsApp specific ports
        if dst_port in WHATSAPP_PORTS:
            return APP_WHATSAPP

        # High upload ratio -> chat/video
        if dir_ratio > 0.25:
            return APP_WHATSAPP

        return APP_INSTAGRAM

    # Google infra
    if ip_in_ranges(ip, GOOGLE_IPS):

        # Heavy downstream streaming
        if bytes_per_sec > 50000:
            return APP_YOUTUBE

    # =========================================================
    # 3. PORT-BASED RULES
    # =========================================================

    if dst_port in WHATSAPP_PORTS:
        return APP_WHATSAPP

    if dst_port in SPOTIFY_PORTS:
        return APP_SPOTIFY

    if dst_port in TIKTOK_PORTS:
        return APP_TIKTOK

    if dst_port in YOUTUBE_PORTS:
        return APP_YOUTUBE

    # =========================================================
    # 4. TRAFFIC PATTERN RULES
    # =========================================================

    # YouTube:
    # large sustained downstream
    if (
        bytes_per_sec > 80000 and
        avg_pkt_size > 900 and
        dir_ratio < 0.15
    ):
        return APP_YOUTUBE

    # Spotify:
    # medium bitrate sustained stream
    if (
        20000 < bytes_per_sec < 90000 and
        avg_pkt_size > 700 and
        dir_ratio < 0.20
    ):
        return APP_SPOTIFY

    # Instagram:
    # mixed interactive media traffic
    if (
        10000 < bytes_per_sec < 70000 and
        0.05 < dir_ratio < 0.50
    ):
        return APP_INSTAGRAM

    # WhatsApp:
    # smaller interactive bidirectional flows
    if (
        packets_per_sec < 150 and
        avg_pkt_size < 700 and
        dir_ratio > 0.15
    ):
        return APP_WHATSAPP

    # =========================================================
    # 5. BURST-BASED FALLBACK
    # LAST RESORT ONLY
    # =========================================================

    if bytes_per_sec > 100000:
        return APP_YOUTUBE

    if bytes_per_sec > 40000:
        return APP_SPOTIFY

    if bytes_per_sec > 15000:
        return APP_INSTAGRAM

    return APP_WHATSAPP