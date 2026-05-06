def classify(service, flow_id):
    # Extract features from service and flow_id
    dst_port = 0
    try:
        dst_port = int(flow_id.split(":")[-1].split()[0])
    except:
        pass

    sni = service.get("SNI", "")
    sni_present = 1 if sni else 0
    sni_length = len(sni) if sni else 0

    # Estimate bytes_per_sec from service data
    rx_bytes = service.get("RX bytes", 0)
    tx_bytes = service.get("TX bytes", 0)
    total_bytes = rx_bytes + tx_bytes

    t1 = service.get("RX first timestamp")
    t2 = service.get("RX latest timestamp")
    duration = 0.001
    if t1 and t2:
        from datetime import datetime
        try:
            t1_dt = datetime.fromisoformat(t1.replace("Z", "+00:00"))
            t2_dt = datetime.fromisoformat(t2.replace("Z", "+00:00"))
            duration = (t2_dt - t1_dt).total_seconds()
        except:
            pass

    bytes_per_sec = total_bytes / duration if duration > 0 else 0

    ip = flow_id.rsplit(":", 1)[0]

    # Primary: SNI-based classification
    sni_lower = sni.lower()
    if "spotify" in sni_lower:
        return 1
    if "youtube" in sni_lower or "googlevideo" in sni_lower:
        return 2
    if "instagram" in sni_lower:
        return 0
    if "tiktok" in sni_lower:
        return 3
    if "whatsapp" in sni_lower:
        return 4

    # Fallback: always give a prediction based on traffic/port
    if dst_port == 443:
        if bytes_per_sec > 60000:
            return 2  # YouTube
        elif bytes_per_sec > 30000:
            return 1  # Spotify
        elif bytes_per_sec > 10000:
            return 0  # Instagram
        else:
            return 3  # TikTok
    else:
        return 4  # WhatsApp

    # IP-based hints
    ip_lower = ip.lower()
    if "face" in ip_lower or "31.13." in ip or "157.240." in ip or "173.252." in ip:
        return 0  # Instagram/WhatsApp

    return 4  # Default