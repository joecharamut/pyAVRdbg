import logging
import sys
import argparse
from pymcuprog.deviceinfo import deviceinfo

import gdbstub


def clamp(val: int, min_val: int, max_val: int) -> int:
    return min_val if val < min_val else max_val if val > max_val else val


def setup_logging(verbose_level: int) -> None:
    # output INFO and below to STDOUT
    log_out = logging.StreamHandler(sys.stdout)
    log_out.addFilter(lambda r: r.levelno <= logging.INFO)
    log_out.setLevel(logging.INFO)

    # output WARNING and above to STDERR
    log_err = logging.StreamHandler(sys.stderr)
    log_err.setLevel(logging.WARNING)

    def edbg_filter(r: logging.LogRecord):
        return not (r.levelno == logging.DEBUG and r.name.startswith("pyedbglib"))

    def mcu_filter(r: logging.LogRecord):
        return not (r.levelno == logging.INFO and r.name.startswith("pymcuprog"))

    def trace_filter(r: logging.LogRecord):
        return not (r.levelno == logging.DEBUG and r.name.endswith("trace"))

    filter_settings = [
        (logging.INFO,  [edbg_filter, mcu_filter, trace_filter]),    # normal
        (logging.DEBUG, [edbg_filter, mcu_filter]),                  # -v
        (logging.DEBUG, [edbg_filter]),                              # -vv
        (logging.DEBUG, []),                                         # -vvv
    ]

    level = clamp(verbose_level, 0, len(filter_settings)-1)
    log_out.setLevel(filter_settings[level][0])
    for f in filter_settings[level][1]:
        log_out.addFilter(f)

    logging.basicConfig(level=logging.DEBUG, handlers=[log_out, log_err])


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="pyAVRdbg",
    )

    parser.add_argument("-t", "--target", required=True, metavar="NAME", help="Target device name ('help' to list)")
    parser.add_argument("-H", "--host", default="127.0.0.1", help="Address to bind to (default: %(default)s)")
    parser.add_argument("-P", "--port", default=1234, type=int, help="Port to listen on (default: %(default)s)")
    parser.add_argument("-v", "--verbose", default=0, action="count", help="Additional debug logging")

    args = parser.parse_args()
    setup_logging(args.verbose)

    if args.target == "help":
        devices = deviceinfo.get_supported_devices()
        devices.sort()

        supported = []
        for d in devices:
            info = deviceinfo.getdeviceinfo(d)
            if info["architecture"] in ["avr8", "avr8x"]:
                supported.append(d)

        print("Supported targets:")
        for d in supported:
            print(f" {d}")
        return 1

    try:
        logging.debug("Target info: %s", deviceinfo.getdeviceinfo(args.target))
    except ImportError:
        logging.error("Part not found: %s", args.target)
        return 1

    gdb = gdbstub.GDBStub(args.target, args.host, args.port)
    gdb.listen_for_connection()
    return 0


if __name__ == "__main__":
    sys.exit(main())
