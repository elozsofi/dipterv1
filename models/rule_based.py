def classify_rule_based(features):
    duration, _, _, _, _, bytes_per_second, _ = features

    if duration > 10 and bytes_per_second > 100000:
        return "youtube"

    return "unknown"