import json
import os
from data_loader import load_json_file

def simplify_sni(sni):
    """
    Simplify SNI names to their core domain.
    """
    sni_lower = sni.lower()
    if '.spotify.com' in sni_lower:
        return 'spotify.com'
    elif '.tiktok.com' in sni_lower or 'tiktokv.com' in sni_lower:
        return 'tiktok.com'
    elif '.youtube.com' in sni_lower or 'googlevideo.com' in sni_lower:
        return 'youtube.com'
    elif '.instagram.com' in sni_lower:
        return 'instagram.com'
    elif '.whatsapp.com' in sni_lower:
        return 'whatsapp.com'
    else:
        return sni  # unchanged if not matching

def process_json_file(file_path):
    """
    Process a single JSON file: load objects, simplify SNI in services, and save back.
    """
    json_objects = load_json_file(file_path)
    modified = False

    for obj in json_objects:
        services = obj.get("Services", {})
        for flow_id, service in services.items():
            if "SNI" in service:
                original_sni = service["SNI"]
                simplified_sni = simplify_sni(original_sni)
                if simplified_sni != original_sni:
                    service["SNI"] = simplified_sni
                    modified = True
                    print(f"[MODIFIED] {file_path}: {original_sni} -> {simplified_sni}")

    if modified:
        # Write back the modified JSON objects
        with open(file_path, 'w') as f:
            for obj in json_objects:
                json.dump(obj, f, indent=2)
                f.write('\n')  # separate objects
        print(f"[SAVED] {file_path}")

def main():
    data_dir = "data"
    for label_name in os.listdir(data_dir):
        label_path = os.path.join(data_dir, label_name)
        if not os.path.isdir(label_path):
            continue
        for file in os.listdir(label_path):
            if not file.endswith(".json"):
                continue
            file_path = os.path.join(label_path, file)
            process_json_file(file_path)

if __name__ == "__main__":
    main()