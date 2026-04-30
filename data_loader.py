import json
import os
from features.extractor import extract_features_from_service

LABEL_MAP = {
    "instagram": 0,
    "spotify": 1,
    "youtube": 2,
    "tiktok": 3,
    "whatsapp": 4
}


def load_json_file(path):
    with open(path, "r") as f:
        content = f.read().strip()

    objects = []
    buffer = ""
    depth = 0

    for char in content:
        buffer += char

        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1

        if depth == 0 and buffer.strip():
            try:
                objects.append(json.loads(buffer))
            except Exception as e:
                print(f"[ERROR] Failed parsing chunk: {e}")
            buffer = ""

    return objects


def parse_services(json_obj):
    services = json_obj.get("Services", {})
    parsed = []

    for key, value in services.items():
        parsed.append({
            "flow_id": key,
            "data": value
        })

    return parsed

def build_dataset(data_dir):
    X = []
    y = []

    for label_name in os.listdir(data_dir):
        label_path = os.path.join(data_dir, label_name)

        if not os.path.isdir(label_path):
            continue

        label = LABEL_MAP.get(label_name.lower())
        if label is None:
            continue

        for file in os.listdir(label_path):
            if not file.endswith(".json"):
                continue

            file_path = os.path.join(label_path, file)
            json_objects = load_json_file(file_path)
            print(f"[INFO] {file}: {len(json_objects)} JSON objects")

            for json_obj in json_objects:
                services = parse_services(json_obj)

                for s in services:
                    features = extract_features_from_service(
                        s["data"], s["flow_id"]
                    )
                    if features is not None:
                        X.append(features)
                        y.append(label)
                        print(f"[DATASET] X={len(X)}, y={len(y)}")

    return X, y