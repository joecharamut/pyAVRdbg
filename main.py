import logging
import sys
import argparse
from pymcuprog.deviceinfo import deviceinfo

import gdbstub


def setup_logging(verbose_level: int) -> None:
    log_out = logging.StreamHandler(sys.stdout)
    log_out.addFilter(lambda r: r.levelno <= logging.INFO)
    log_out.setLevel(logging.INFO)

    log_err = logging.StreamHandler(sys.stderr)
    log_err.setLevel(logging.WARNING)

    if verbose_level == 1:
        def log_filter(record: logging.LogRecord):
            if record.levelno == logging.DEBUG:
                return not record.name.startswith("pyedbglib")
            if record.levelno == logging.INFO:
                return not record.name.startswith("pymcuprog")
            return 0

        log_out.setLevel(logging.DEBUG)
        log_out.addFilter(log_filter)
    elif verbose_level >= 2:
        log_out.setLevel(logging.DEBUG)

    logging.basicConfig(handlers=[log_out, log_err])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="pyAVRdbg")

    parser.add_argument("-p", "--part", required=True, help="AVR Device to Debug")
    parser.add_argument("-H", "--host", default="127.0.0.1", help="GDB Listening Address")
    parser.add_argument("-P", "--port", type=int, default=12555, help="GDB Listening Port")
    parser.add_argument("-v", "--verbose", action="count", help="Additional debug logging")

    args = parser.parse_args()
    setup_logging(args.verbose)

    if args.part == "help" or args.part == "":
        logging.error("todo: list supported devices")
        exit(1)

    try:
        deviceinfo.getdeviceinfo(args.part)
    except ImportError:
        logging.error("Part not found: %s", args.part)
        exit(1)

    gdb = gdbstub.GDBStub(args.part, args.host, args.port)
    gdb.listen_for_connection()
    exit()
