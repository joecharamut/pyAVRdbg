import logging
import re
import signal
import struct
from socket import socket, AF_INET, SOCK_STREAM
from select import select
from types import FrameType
from typing import Dict, Callable, Optional, Tuple, List
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

    def signal_handler(self, _sig: int, _frame: Optional[FrameType]) -> None:
        print("You pressed Ctrl+C!")
        self.quit()

    def listen_for_connection(self) -> None:
        self.dbg.stop()
        self.dbg.breakpointSWClearAll()
        self.dbg.breakpointHWClear()

        while self.dbg.pollEvent():
            # consume pending events
            pass

        logger.info(f"Waiting for GDB session on {self.address[0]}:{self.address[1]}")
        signal.signal(signal.SIGINT, self.signal_handler)

        self.sock.bind(self.address)
        self.sock.listen()

        self.conn, addr = self.sock.accept()
        self.conn.setblocking(False)

        print(f"GDB Connected: {addr}")
        try:
            while True:
                readable, _, _ = select([self.conn], [], [], 0.5)
                for c in readable:
                    if data := c.recv(4096):
                        print(f"<- {data}")
                        self.handle_packet(data)

                while event := self.dbg.pollEvent():
                    print(event)
                    event_type, pc, break_cause = event
                    if event_type == avr8protocol.Avr8Protocol.EVT_AVR8_BREAK and break_cause == 1:
                        self.last_signal = Signal.SIGTRAP
                        self.send(f"S{self.last_signal:02x}")
        except Exception as exc:
            self.quit(exc)

    def quit(self, exc: Optional[Exception] = None) -> None:
        self.dbg.cleanup()
        self.conn.close()
        self.sock.close()
        if exc:
            raise exc
        exit(0)

    def send(self, packet_data: str, raw: bool = False) -> None:
        self.last_packet = packet_data

        check = calc_checksum(packet_data.encode("ascii"))
        if not raw:
            message = f"${packet_data}#{check:02x}"
        else:
            message = packet_data

        print(f"-> {message}")
        self.conn.sendall(message.encode("ascii"))

    def handle_packet(self, data: bytes) -> None:
        if data == b"\x03":
            print("Received Break!")
            self.dbg.stop()
            self.last_signal = Signal.SIGINT
            self.send(f"S{self.last_signal:02x}")
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
            "R": self.handle_restart,
        }

        key = command[0]
        if key in command_handlers:
            # pop off the key character
            command_handlers[key](command[1:])
        else:
            # unknown command reply
            self.send("")

    def handle_halt_query(self, _command: str) -> None:
        self.send(f"S{self.last_signal:02x}")

    def handle_extended_enable(self, _command: str) -> None:
        self.send("OK")

    def handle_query(self, command: str) -> None:
        # https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html
        if command[0] in ["C", "P", "L"]:
            # qC, qP, qL packets are older format
            self.send("")
            return

        name, _, rest = command.partition(":")

        if name == "Supported":
            self.send("PacketSize=10000000000;QStartNoAckMode+")
        elif name == "Attached":
            # qAttached: "0" -- 'The remote server created a new process.'
            self.send("0")
        elif name == "Offsets":
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
            print(f"{command=} {addr=:02x}")
        self.dbg.step()
        self.last_signal = Signal.SIGTRAP
        self.send(f"S{self.last_signal:02x}")

    def handle_continue(self, command: str) -> None:
        if len(command):
            addr = int(command, 16)
            print(f"{command=} {addr=:02x}")
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
        bp_type = command[0]
        _, addr, length = command.split(",")
        addr = int(addr, 16)
        if bp_type == "0":
            # SW breakpoint
            self.dbg.breakpointSWSet(addr)
            self.send("OK")
        elif bp_type == "1":
            # HW breakpoint
            self.dbg.breakpointHWSet(addr)
            self.send("OK")
        else:
            # Not Supported
            self.send("")

    def handle_remove_break(self, command: str) -> None:
        bp_type = command[0]
        _, addr, length = command.split(",")
        addr = int(addr, 16)
        if bp_type == "0":
            # SW breakpoint
            self.dbg.breakpointSWClear(addr)
            self.send("OK")
        elif bp_type == "1":
            # HW breakpoint
            self.dbg.breakpointHWClear()
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
            self.send("".join([format(b, "02x") for b in data]))
        else:
            # todo: report error correctly
            self.send("E00")

    def handle_write_mem(self, command: str) -> None:
        # Maddr,length:XX...
        addr, _, command = command.partition(",")
        size, _, command = command.partition(":")
        addr = int(addr, 16)
        size = int(size, 16)
        data = bytearray.fromhex(command)

        if self.dbg.write_mem(addr, data):
            self.send("OK")
        else:
            # todo: report error correctly
            self.send("E00")


    def handle_read_regs(self, _command: str) -> None:
        regs = self.dbg.readRegs()
        sreg = self.dbg.readSREG()
        sp = self.dbg.readStackPointer()

        reg_string = ""
        for r in regs:
            reg_string += f"{r:02x}"
        for r in sreg:
            reg_string += f"{r:02x}"
        for r in sp:
            reg_string += f"{r:02x}"
        self.send(reg_string)

    def handle_write_regs(self, command: str) -> None:
        # todo: implement
        new_register_data = command
        print(new_register_data)
        self.send("")

    def handle_kill(self, _command: str) -> None:
        self.dbg.reset()

    def handle_read_one_reg(self, command: str) -> None:
        reg_num = int(command, 16)
        if reg_num < 32:
            # General Regs: R0-R31
            reg = self.dbg.readRegs()[reg_num]
            self.send(f"{reg:02x}")
        elif reg_num == 34:
            # GDB register 34 = PC
            pc = self.dbg.readProgramCounter()
            print(pc)
            pc <<= 1
            # print(pc)
            pc_bytes = struct.pack("<I", (pc & 0xFFFFFFFF))
            pc_str = "".join([format(x, "02x") for x in pc_bytes])
            print(pc_str)
            self.send(pc_str)
        else:
            self.send("")

    def handle_write_one_reg(self, command: str) -> None:
        pass

    def handle_restart(self, _command: str) -> None:
        self.dbg.reset()



