# dataset loader

import os
from features.extractor import extract_features_from_pcap


APPS = ["youtube", "facebook", "whatsapp", "instagram", "tiktok"]


def load_dataset(data_dir="data"):
    X = []
    y = []

    for app in APPS:
        app_dir = os.path.join(data_dir, app)

        if not os.path.exists(app_dir):
            continue

        for file in os.listdir(app_dir):
            if not file.endswith(".pcap"):
                continue

            path = os.path.join(app_dir, file)

            features = extract_features_from_pcap(path)
            if features is None:
                continue

            X.append(features)
            y.append(app)

    return X, y