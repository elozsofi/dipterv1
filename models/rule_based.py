def classify(features):
    dst_port = features[19]
    sni_present = features[20]
    sni_length = features[21]
    bytes_per_sec = features[7]

    # YouTube (heavy streaming)
    if dst_port == 443 and bytes_per_sec > 80000:
        return 2

    # Spotify (steady medium bitrate)
    if sni_present and 20 < sni_length < 60 and 20000 < bytes_per_sec < 120000:
        return 1

    # Instagram (bursty, medium traffic)
    if 10000 < bytes_per_sec < 80000:
        return 0

    # TikTok (short bursts, high variance)
    if bytes_per_sec > 40000 and features[14] > 500:  # packet variance proxy
        return 3

    # WhatsApp (low traffic)
    if bytes_per_sec < 10000:
        return 4

    return -1