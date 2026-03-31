import psutil
import time
import logging


# ---------------- NETWORK LOGGER ----------------
network_logger = logging.getLogger("network")
network_logger.setLevel(logging.INFO)

handler = logging.FileHandler("network_log.txt")
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(message)s"
)
handler.setFormatter(formatter)

network_logger.addHandler(handler)
network_logger.propagate = False
# -----------------------------------------------


def monitor_network(pid, duration=10):
    try:
        proc = psutil.Process(pid)
        network_logger.info(f"Monitoring network for PID {pid}")

        start_time = time.time()
        seen_connections = set()

        while time.time() - start_time < duration:
            connections = proc.connections(kind="inet")

            for conn in connections:
                if conn.raddr:
                    key = (conn.raddr.ip, conn.raddr.port)
                    if key not in seen_connections:
                        seen_connections.add(key)
                        network_logger.info(
                            f"Outbound connection detected: "
                            f"{conn.raddr.ip}:{conn.raddr.port}"
                        )

            time.sleep(1)

    except psutil.NoSuchProcess:
        network_logger.warning("Process terminated")

    network_logger.info("Network monitoring finished")
