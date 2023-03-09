import logging
import sys
import argparse
from pymcuprog.deviceinfo import deviceinfo

import gdbstub


# monkey-patch logging to add trace logging
logging.TRACE = 5  # noqa
logging.addLevelName(logging.TRACE, "TRACE")  # noqa
logging.Logger.trace = lambda inst, msg, *args, **kwargs: inst.log(logging.TRACE, msg, *args, **kwargs)  # noqa
logging.trace = lambda msg, *args, **kwargs: logging.log(logging.TRACE, msg, *args, **kwargs)  # noqa


def setup_logging(verbose_level: int) -> None:
    # output INFO and below to STDOUT
    log_out = logging.StreamHandler(sys.stdout)
    log_out.addFilter(lambda r: r.levelno <= logging.INFO)
    log_out.setLevel(logging.INFO)

    # output WARNING and above to STDERR
    log_err = logging.StreamHandler(sys.stderr)
    log_err.setLevel(logging.WARNING)

    edbg_filter = lambda r: not (r.levelno == logging.DEBUG and r.name.startswith("pyedbglib"))
    mcu_filter = lambda r: not (r.levelno == logging.INFO and r.name.startswith("pymcuprog"))

    if verbose_level == 0:
        log_out.setLevel(logging.INFO)
        log_out.addFilter(edbg_filter)
        log_out.addFilter(mcu_filter)
    elif verbose_level == 1:
        # -v = some debug logging
        log_out.setLevel(logging.DEBUG)
        log_out.addFilter(edbg_filter)
        log_out.addFilter(mcu_filter)
    elif verbose_level == 2:
        # -vv = more debug
        log_out.setLevel(logging.DEBUG)
        log_out.addFilter(edbg_filter)
    else:
        # -vvv = even more debug messages (also include hid messages from edbg)
        log_out.setLevel(logging.DEBUG)

    logging.basicConfig(level=logging.DEBUG, handlers=[log_out, log_err])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="pyAVRdbg",
    )

    parser.add_argument("-t", "--target", required=True, metavar="NAME", help="Target device name ('help' to list)")
    parser.add_argument("-H", "--host", default="127.0.0.1", help="Address to bind to (default: %(default)s)")
    parser.add_argument("-P", "--port", type=int, default=1234, help="Port to listen on (default: %(default)s)")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Additional debug logging")

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
        exit(0)

    try:
        deviceinfo.getdeviceinfo(args.target)
    except ImportError:
        logging.error("Part not found: %s", args.target)
        exit(1)

    gdb = gdbstub.GDBStub(args.target, args.host, args.port)
    gdb.listen_for_connection()
    exit()
