import logging
import sys
import argparse
from pymcuprog.deviceinfo import deviceinfo

from .gdbstub import GDBStub
logger = logging.getLogger(__name__)


def clamp(val: int, min_val: int, max_val: int) -> int:
    return min_val if val < min_val else max_val if val > max_val else val


def log_filter_edbg(r: logging.LogRecord) -> bool:
    return not (r.levelno == logging.DEBUG and r.name.startswith("pyedbglib"))


def log_filter_mcu(r: logging.LogRecord) -> bool:
    return not (r.levelno == logging.INFO and r.name.startswith("pymcuprog"))


def log_filter_trace(r: logging.LogRecord) -> bool:
    return not (r.levelno == logging.DEBUG and r.name.endswith("trace"))


def setup_logging(verbose_level: int) -> None:
    # output INFO and below to STDOUT
    log_out = logging.StreamHandler(sys.stdout)
    log_out.addFilter(lambda r: r.levelno <= logging.INFO)
    log_out.setLevel(logging.INFO)

    # output WARNING and above to STDERR
    log_err = logging.StreamHandler(sys.stderr)
    log_err.setLevel(logging.WARNING)

    filter_settings = [
        (logging.INFO,  [log_filter_edbg, log_filter_mcu, log_filter_trace]),   # normal
        (logging.DEBUG, [log_filter_edbg, log_filter_mcu]),                     # -v
        (logging.DEBUG, [log_filter_edbg]),                                     # -vv
        (logging.DEBUG, []),                                                    # -vvv
    ]

    level = clamp(verbose_level, 0, len(filter_settings)-1)
    log_out.setLevel(filter_settings[level][0])
    for f in filter_settings[level][1]:
        log_out.addFilter(f)

    logging.basicConfig(level=logging.DEBUG, handlers=[log_out, log_err])


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="pyavrdbg",
        description="GDB Remote Stub for AVR targets using UPDI over CMSIS-DAP"
    )

    parser.add_argument("-t", "--target", required=True, help="Target device name ('help' to list)")
    parser.add_argument("-H", "--host", default="127.0.0.1", help="Address to bind to (default: %(default)s)")
    parser.add_argument("-P", "--port", default=1234, type=int, help="Port to listen on (default: %(default)s)")
    parser.add_argument("-v", "--verbose", default=0, action="count", help="Additional debug logging")

    args = parser.parse_args()
    setup_logging(args.verbose)

    if args.target == "help":
        print("Supported targets:")
        for dev in sorted(deviceinfo.get_supported_devices()):
            info = deviceinfo.getdeviceinfo(dev)
            if info and info["architecture"] in ["avr8", "avr8x"]:
                print(f" {dev}")
        return 1

    try:
        info = deviceinfo.getdeviceinfo(args.target)
        logger.debug("Target info:")
        for k, v in info.items():
            logger.debug(" %s: %s", k, v)
    except ImportError:
        logger.error("Part not found: %s", args.target)
        return 1

    gdb = GDBStub(args.target, args.host, args.port)
    gdb.listen_for_connection()
    return 0
