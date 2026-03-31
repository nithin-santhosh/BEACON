import os
import csv


def append_case_index(
    case_dir,
    timestamp,
    pid,
    verdict,
    risk_level,
    report_filename
):
    """
    Append an entry to case_index.csv for a given case.
    """

    index_path = os.path.join(case_dir, "case_index.csv")
    file_exists = os.path.exists(index_path)

    with open(index_path, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # Write header once
        if not file_exists:
            writer.writerow([
                "timestamp",
                "pid",
                "verdict",
                "risk_level",
                "report_file"
            ])

        writer.writerow([
            timestamp,
            pid,
            verdict,
            risk_level,
            report_filename
        ])
