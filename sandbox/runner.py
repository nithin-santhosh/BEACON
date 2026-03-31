import subprocess
import time
import logging

from monitor.process_monitor import monitor_process
from monitor.network_monitor import monitor_network
from monitor.persistence_monitor import read_run_keys, monitor_persistence
from features.extractor import extract_features, save_to_dataset
from detection.heuristics import heuristic_classify


# ---------------- EXECUTION LOGGER ----------------
exec_logger = logging.getLogger("execution")
exec_logger.setLevel(logging.INFO)

exec_handler = logging.FileHandler("execution_log.txt")
exec_formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(message)s"
)
exec_handler.setFormatter(exec_formatter)

exec_logger.addHandler(exec_handler)
exec_logger.propagate = False
# --------------------------------------------------

def reset_logs():
    open("process_log.txt", "w").close()
    open("network_log.txt", "w").close()
    open("persistence_log.txt", "w").close()

def run_sample(sample_path, label):
    ...
    reset_logs()
    exec_logger.info(f"Starting sample: {sample_path}")

    before_registry = read_run_keys()

    process = subprocess.Popen(sample_path)
    pid = process.pid
    exec_logger.info(f"Sample PID: {pid}")

    time.sleep(2)

    monitor_process(pid, duration=15)
    monitor_network(pid, duration=15)

    after_registry = read_run_keys()
    monitor_persistence(before_registry, after_registry)

    # Feature extraction
    features = extract_features(label)
    save_to_dataset(features)

    # Heuristic classification
    decision, reason = heuristic_classify(features)
    exec_logger.info(f"Heuristic result: {decision} ({reason})")

    exec_logger.info("Execution monitoring complete")

    return pid


if __name__ == "__main__":
    # Example benign test
    sample_path = r"C:\Windows\System32\notepad.exe"
    run_sample(sample_path, label=0)
