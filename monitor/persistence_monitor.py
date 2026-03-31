import winreg
import logging


# ---------------- PERSISTENCE LOGGER ----------------
persistence_logger = logging.getLogger("persistence")
persistence_logger.setLevel(logging.INFO)

handler = logging.FileHandler("persistence_log.txt")
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(message)s"
)
handler.setFormatter(formatter)

persistence_logger.addHandler(handler)
persistence_logger.propagate = False
# ---------------------------------------------------


RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\Run")
]


def read_run_keys():
    entries = {}

    for hive, path in RUN_KEYS:
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            i = 0
            while True:
                name, value, _ = winreg.EnumValue(key, i)
                entries[f"{hive}-{name}"] = value
                i += 1
        except FileNotFoundError:
            continue
        except OSError:
            pass

    return entries


def monitor_persistence(before, after):
    persistence_logger.info("Checking persistence mechanisms")

    new_entries = set(after.items()) - set(before.items())

    if not new_entries:
        persistence_logger.info("No persistence changes detected")
    else:
        for key, value in new_entries:
            persistence_logger.warning(
                f"New persistence entry detected: {key} -> {value}"
            )
