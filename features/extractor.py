import csv
import os


def count_lines_containing(filename, keyword):
    if not os.path.exists(filename):
        return 0

    count = 0
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            if keyword in line:
                count += 1
    return count


def persistence_flag(filename):
    if not os.path.exists(filename):
        return 0

    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            if "New persistence entry detected" in line:
                return 1
    return 0


def extract_features(label):
    features = {
        "process_count": count_lines_containing(
            "process_log.txt",
            "New child process detected"
        ),
        "network_connections": count_lines_containing(
            "network_log.txt",
            "Outbound connection detected"
        ),
        "persistence_detected": persistence_flag(
            "persistence_log.txt"
        ),
        "label": label
    }

    return features


def save_to_dataset(features, dataset_path="data/dataset.csv"):
    file_exists = os.path.exists(dataset_path)

    os.makedirs("data", exist_ok=True)

    with open(dataset_path, "a", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=features.keys()
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(features)
