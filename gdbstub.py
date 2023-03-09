import logging
import re
import signal
import struct
from socket import socket, AF_INET, SOCK_STREAM
from select import select
from types import FrameType
from typing import Dict, Callable, Optional
import enum

from pyedbglib.protocols import avr8protocol
from pymcuprog.deviceinfo import deviceinfo

from debugger import Debugger


logger = logging.getLogger(__name__)


def calc_checksum(data: str | bytes) -> int:
    if isinstance(data, str):
        data = data.encode("ascii")
    return sum(data) % 256


class Signal(enum.IntEnum):
    NONE = 0
    SIGHUP = 1
    SIGINT = 2
    SIGQUIT = 3
    SIGILL = 4
    SIGTRAP = 5
    SIGABRT = 6


class GDBStub:
    ACK = "+"
    NACK = "-"
    PACKET_SIZE = 4096

    def __init__(self, device_name: str, host: str, port: int) -> None:
        self.dev = deviceinfo.getdeviceinfo(device_name)
        self.mem = deviceinfo.DeviceMemoryInfo(self.dev)

        try:
            self.dbg = Debugger(device_name)
        except AttributeError:
            raise RuntimeError("Could not open debugger") from None

        self.address = (host, port)
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.conn = None

        self.last_packet = None
        self.last_signal = Signal.NONE

        self.send_ack = True
        self.extended_mode = False

    def signal_handler(self, _sig: int, _frame: Optional[FrameType]) -> None:
        logger.info("Received Ctrl+C, quitting")
        self.quit()

    def listen_for_connection(self) -> None:
        self.dbg.stop()
        self.dbg.clear_all_sw_breakpoint()
        self.dbg.clear_hw_breakpoint()

        while self.dbg.poll_events():
            # consume pending events
            pass

        logger.info("Waiting for GDB session on %s:%s", self.address[0], self.address[1])
        signal.signal(signal.SIGINT, self.signal_handler)

        self.sock.bind(self.address)
        self.sock.listen()

        self.conn, addr = self.sock.accept()
        self.conn.setblocking(False)

        logger.info("GDB Connected: %s", addr)
        try:
            while True:
                readable, _, _ = select([self.conn], [], [], 0.5)
                for c in readable:
                    if data := c.recv(GDBStub.PACKET_SIZE):
                        logger.debug("<- %s", data)
                        self.handle_packet(data)

                while event := self.dbg.poll_events():
                    print(event)
                    event_type, pc, break_cause = event
                    if event_type == avr8protocol.Avr8Protocol.EVT_AVR8_BREAK and break_cause == 1:
                        self.send_halt_reply(Signal.SIGTRAP)
        except Exception as exc:
            self.quit(exc)

    def quit(self, exc: Optional[Exception] = None) -> None:
        self.dbg.cleanup()
        if self.conn:
            self.conn.close()
        self.sock.close()
        if exc:
            raise exc
        exit(0)

    def send(self, packet_data: str, raw: bool = False) -> None:
        self.last_packet = packet_data

        check = calc_checksum(packet_data)
        if not raw:
            message = f"${packet_data}#{check:02x}"
        else:
            message = packet_data

        logger.debug("-> %s", message)
        self.conn.sendall(message.encode("ascii"))

    def handle_packet(self, data: bytes) -> None:
        if data == b"\x03":
            logger.info("Interrupt request received")
            self.interrupt_target()
            return

        data = data.decode("ascii")
        for packet_data, checksum in re.findall(r"\$([^#]*)#([0-9a-f]{2})", data):
            if int(checksum, 16) != calc_checksum(packet_data):
                logger.error(f"Received invalid packet: '{data}'")
                if self.send_ack:
                    self.send(GDBStub.NACK, raw=True)
            else:
                if self.send_ack:
                    self.send(GDBStub.ACK, raw=True)
                self.handle_command(packet_data)

    def interrupt_target(self, reason: Optional[Signal] = Signal.SIGINT) -> None:
        self.dbg.stop()
        self.send_halt_reply(reason)

    def handle_command(self, command: str) -> None:
        command_handlers: Dict[str, Callable[[str], None]] = {
            "?": self.handle_halt_query,
            "!": self.handle_extended_enable,
            "q": self.handle_query,
            "Q": self.handle_query_set,
            "s": self.handle_step,
            "c": self.handle_continue,
            "Z": self.handle_add_break,
            "z": self.handle_remove_break,
            "m": self.handle_read_mem,
            "M": self.handle_write_mem,
            "g": self.handle_read_regs,
            "G": self.handle_write_regs,
            "k": self.handle_kill,
            "p": self.handle_read_one_reg,
            "P": self.handle_write_one_reg,
            "r": self.handle_reset,
            "R": self.handle_restart,
            "v": self.handle_v_command,
            "D": self.handle_detach,
        }

        key = command[0]
        if key in command_handlers:
            # pop off the key character
            command_handlers[key](command[1:])
        else:
            # unknown command reply
            self.send("")

    def send_halt_reply(self, sig: Optional[Signal] = None) -> None:
        if sig:
            self.last_signal = sig
        self.send(f"S{self.last_signal:02x}")

    def handle_halt_query(self, _command: str) -> None:
        self.send_halt_reply()

    def handle_extended_enable(self, _command: str) -> None:
        self.extended_mode = True
        self.send("OK")

    def handle_query(self, command: str) -> None:
        # https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html
        if command[0] in ["C", "P", "L"]:
            # qC, qP, qL packets are other format and used for threading so not needed
            self.send("")
            return

        name, _, rest = command.partition(":")

        if name == "Supported":
            features = rest.split(";")
            logger.debug("GDB reports supporting %s", features)
            self.send(f"PacketSize={GDBStub.PACKET_SIZE};QStartNoAckMode+")
        elif name == "Attached":
            # qAttached: "0" -- 'The remote server created a new process.'
            self.send("0")
        elif name == "Offsets":
            # todo: report offsets from device_info?
            self.send("Text=8000;Data=3E00;Bss=3E00")
        elif name == "Symbol":
            self.send("OK")
        else:
            self.send("")

    def handle_query_set(self, command: str) -> None:
        name, _, rest = command.partition(":")
        if name == "StartNoAckMode":
            self.send_ack = False
            self.send("OK")
        else:
            self.send("")

    def handle_step(self, command: str) -> None:
        # TODO: Make s behavior more in line with GDB docs
        # "addr is address to resume. If addr is omitted, resume at same address."
        if len(command):
            addr = int(command, 16)
            logger.debug("s cmd=%s addr=0x%04x", command, addr)
        self.dbg.step()
        self.send_halt_reply(Signal.SIGTRAP)

    def handle_continue(self, command: str) -> None:
        if len(command):
            addr = int(command, 16)
            logger.debug("c cmd=%s addr=0x%04x", command, addr)
        self.dbg.run()
        # polledEvent = dbg.pollEvent()
        # Check if its still running, report back SIGTRAP when break.
        # while polledEvent == None:
        #    polledEvent = dbg.pollEvent()
        # debug_check_running = dbg.readRunningState()
        # while debug_check_running:
        #    debug_check_running = dbg.readRunningState()
        # sendPacket(socket, SIGTRAP)

    def handle_add_break(self, command: str) -> None:
        bp_type, addr, kind = command.split(",")
        addr = int(addr, 16)
        if bp_type == "0":
            # SW breakpoint
            self.dbg.set_sw_breakpoint(addr)
            self.send("OK")
        elif bp_type == "1":
            # HW breakpoint
            self.dbg.set_hw_breakpoint(addr)
            self.send("OK")
        else:
            # Not Supported
            self.send("")

    def handle_remove_break(self, command: str) -> None:
        bp_type, addr, kind = command.split(",")
        addr = int(addr, 16)
        if bp_type == "0":
            # SW breakpoint
            self.dbg.clear_sw_breakpoint(addr)
            self.send("OK")
        elif bp_type == "1":
            # HW breakpoint
            self.dbg.clear_hw_breakpoint()
            self.send("OK")
        else:
            # Not Supported
            self.send("")

    def handle_read_mem(self, command: str) -> None:
        addr, size = command.split(",")
        addr = int(addr, 16)
        size = int(size, 16)
        data = self.dbg.read_mem(addr, size)

        if data:
            self.send(data.hex())
        else:
            # todo: report error correctly
            self.send("E00")

    def handle_write_mem(self, command: str) -> None:
        # M addr,length:XX...
        addr, _, command = command.partition(",")
        size, _, command = command.partition(":")
        addr = int(addr, 16)
        size = int(size, 16)
        data = bytearray.fromhex(command)

        if len(data) != size:
            self.send("E00")
            return

        if self.dbg.write_mem(addr, data):
            self.send("OK")
        else:
            # todo: report error correctly
            self.send("E00")

    def handle_read_regs(self, _command: str) -> None:
        reg_string = self.dbg.read_regfile().hex() + self.dbg.read_sreg().hex() + self.dbg.read_sp().hex()
        self.send(reg_string)

    def handle_write_regs(self, command: str) -> None:
        new_regs = bytearray.fromhex(command)
        try:
            self.dbg.write_regfile(new_regs[0:31])
            self.send("OK")
        except Exception as exc:
            self.send("E00")
            logger.error("Caught exception on register write: %s", exc, exc_info=True)

    def handle_kill(self, _command: str) -> None:
        self.dbg.reset()

    def handle_read_one_reg(self, command: str) -> None:
        reg_num = int(command, 16)
        if reg_num < 32:
            # General Regs: R0-R31
            reg = self.dbg.read_regfile()[reg_num]
            self.send(f"{reg:02x}")
        elif reg_num == 34:
            # GDB register 34 = PC
            pc = self.dbg.read_pc()
            pc_bytes = struct.pack("<I", ((pc << 1) & 0xFFFFFFFF))
            self.send(pc_bytes.hex())
        else:
            logger.error(f"Unhandled register read! {reg_num=}")
            self.send("")

    def handle_write_one_reg(self, command: str) -> None:
        reg_num, val = command.split("=")
        reg_num = int(reg_num, 16)
        val = int(val, 16)

        regfile = self.dbg.read_regfile()
        regfile[reg_num] = val
        try:
            self.dbg.write_regfile(regfile)
            self.send("OK")
        except Exception as exc:
            self.send("E00")
            logger.error("Caught exception on register write: %s", exc, exc_info=True)

    def handle_reset(self, _command: str) -> None:
        self.dbg.reset()

    def handle_restart(self, _command: str) -> None:
        if self.extended_mode:
            self.dbg.reset()

    def handle_v_command(self, command: str) -> None:
        action = command
        rest = ""

        if "?" in command:
            action, _, rest = command.partition("?")
        elif ";" in command:
            action, _, rest = command.partition(";")

        logger.warning("todo: impl v command %s %s", action, rest)
        self.send("")

    def handle_detach(self, _command: str) -> None:
        self.dbg.detach()
        self.send("OK")
        self.quit()
