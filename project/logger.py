import logging
import sys
from pathlib import Path

already_set_up = False

def init_logging(log_dir):
    global already_set_up
    if already_set_up:
        return

    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "analyzer.log"

    formatter = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(file_handler)
    root.addHandler(console_handler)

    already_set_up = True

def get_logger(name):
    return logging.getLogger(name)
