import psutil
import time
import logging


# ---------------- PROCESS LOGGER ----------------
process_logger = logging.getLogger("process")
process_logger.setLevel(logging.INFO)

handler = logging.FileHandler("process_log.txt")
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(message)s"
)
handler.setFormatter(formatter)

process_logger.addHandler(handler)
process_logger.propagate = False
# -----------------------------------------------


def monitor_process(pid, duration=10):
    try:
        parent = psutil.Process(pid)
        process_logger.info(
            f"Monitoring PID {pid} ({parent.name()})"
        )

        start_time = time.time()
        known_children = set()

        while time.time() - start_time < duration:
            children = parent.children(recursive=True)

            for child in children:
                if child.pid not in known_children:
                    known_children.add(child.pid)
                    process_logger.info(
                        f"New child process detected: "
                        f"PID={child.pid}, Name={child.name()}"
                    )

            time.sleep(1)

    except psutil.NoSuchProcess:
        process_logger.warning("Target process terminated")

    process_logger.info("Process monitoring finished")
