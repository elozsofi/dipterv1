# nDPI inspired
# https://github.com/ntop/ndpi/

def classify_rule_based(features_dict):
    """
    features_dict: dictionary
    (features from JSON)
    """

    # --- unpack ---
    rx_bytes = features_dict.get("rx_bytes", 0)
    tx_bytes = features_dict.get("tx_bytes", 0)
    rx_packets = features_dict.get("rx_packets", 0)
    tx_packets = features_dict.get("tx_packets", 0)

    duration = features_dict.get("duration", 1)

    jitter = features_dict.get("jitter", 0)
    rtt = features_dict.get("rtt", 0)

    protocol = features_dict.get("protocol", 0)
    dst_port = features_dict.get("dst_port", 0)

    sni = features_dict.get("sni", "").lower()

    # --- derived ---
    total_bytes = rx_bytes + tx_bytes
    total_packets = rx_packets + tx_packets

    bytes_per_sec = total_bytes / duration if duration > 0 else 0
    packets_per_sec = total_packets / duration if duration > 0 else 0

    direction_ratio = tx_bytes / (rx_bytes + 1)

    avg_packet_size = total_bytes / (total_packets + 1)

    # =========================
    # SNI BASED (STRONGEST)
    # =========================
    if sni:
        if "youtube" in sni or "googlevideo" in sni:
            return "youtube"

        if "whatsapp" in sni:
            return "whatsapp"

        if "facebook" in sni or "fbcdn" in sni:
            return "facebook"

        if "instagram" in sni:
            return "instagram"

        if "tiktok" in sni or "byteoversea" in sni:
            return "tiktok"

    # =========================
    # PORT + PROTOCOL HINT
    # =========================
    if dst_port == 443:
        # HTTPS → tovább megyünk statisztikára
        pass
    elif dst_port in [3478, 3479]:
        return "whatsapp"  # STUN / VoIP jelleg
    elif dst_port == 1935:
        return "youtube"   # RTMP (ritkább, de jellegzetes)

    # =========================
    # TRAFFIC PATTERN
    # =========================

    # YouTube / streaming
    if (
        bytes_per_sec > 500_000 and
        direction_ratio < 0.2 and
        duration > 5
    ):
        return "youtube"

    # WhatsApp (chat/voice)
    if (
        avg_packet_size < 300 and
        packets_per_sec > 5 and
        bytes_per_sec < 100_000
    ):
        return "whatsapp"

    # TikTok (burst + frequent UDP)
    if (
        protocol == 17 and
        bytes_per_sec > 300_000 and
        duration < 60
    ):
        return "tiktok"

    # Instagram (middle-range streaming + more balanced direction)
    if (
        100_000 < bytes_per_sec < 500_000 and
        duration < 30
    ):
        return "instagram"

    # Facebook (lightweight, more balanced)
    if (
        avg_packet_size < 800 and
        bytes_per_sec < 200_000
    ):
        return "facebook"

    # =========================
    # DEFAULT
    # =========================
    return "unknown"