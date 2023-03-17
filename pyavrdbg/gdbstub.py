import re
import struct
import sys
from signal import signal, Signals
from socket import socket, AF_INET, SOCK_STREAM, SHUT_RDWR
from select import select
from typing import Dict, Callable, Optional

from pyedbglib.protocols.avr8protocol import Avr8Protocol
from pymcuprog.deviceinfo import deviceinfo

from .debugger import Debugger

import logging
logger = logging.getLogger(__name__)
packet_logger = logger.getChild("trace")


class GDBStub:
    ACK = "+"
    NACK = "-"
    PACKET_SIZE = 4096

    conn: Optional[socket]
    sock: Optional[socket]

    @staticmethod
    def checksum(data: str | bytes) -> int:
        if isinstance(data, str):
            data = data.encode("ascii")
        return sum(data) % 256

    def __init__(self, device_name: str, host: str, port: int) -> None:
        self.dev_info = deviceinfo.getdeviceinfo(device_name)
        self.mem_info = deviceinfo.DeviceMemoryInfo(self.dev_info)

        try:
            self.dbg = Debugger(device_name)
        except (AttributeError, RuntimeError):
            logger.error("Could not open debugger")
            sys.exit(1)

        self.address = (host, port)
        self.sock = None
        self.conn = None

        self.last_packet = None
        self.last_signal = Signals.SIGTRAP

        self.send_ack = True
        self.extended_mode = False

        self.waiting_for_break = False

    def signal_handler(self, _sig, _frame) -> None:
        logger.info("Received Ctrl+C, quitting")
        self.quit()

    def listen_for_connection(self) -> None:
        self.dbg.stop()
        self.dbg.clear_all_sw_breakpoint()
        self.dbg.clear_hw_breakpoint()
        self.dbg.reset()

        while self.dbg.poll_events():
            # consume pending events
            pass

        signal(Signals.SIGINT, self.signal_handler)

        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.bind(self.address)
            self.sock = sock
        except OSError as exc:
            logger.error("Error binding to %s:%s (%s)", self.address[0], self.address[1], str(exc))
            self.quit(exit_code=1)

        logger.info("Waiting for GDB session on %s:%s", self.address[0], self.address[1])
        self.sock.listen()

        self.conn, addr = self.sock.accept()
        self.conn.setblocking(False)

        logger.info("GDB Connected: %s", addr)
        try:
            while True:
                readable, _, _ = select([self.conn], [], [], 0.1)
                for c in readable:
                    if data := c.recv(GDBStub.PACKET_SIZE):
                        packet_logger.debug("<- %s", data.replace(b"\x03", b"[0x03]").decode("ascii"))
                        self.handle_packet(data)

                while event := self.dbg.poll_events():
                    if event[0] == Avr8Protocol.EVT_AVR8_BREAK:
                        if self.waiting_for_break:
                            self.waiting_for_break = False
                            self.send_halt_reply(Signals.SIGTRAP)
        except Exception as exc:
            self.quit(exc)

    def quit(self, exc: Optional[Exception] = None, exit_code: int = 0) -> None:
        self.dbg.cleanup()
        if self.conn:
            try:
                self.conn.shutdown(SHUT_RDWR)
                self.conn.close()
            except OSError:
                pass
        if self.sock:
            try:
                self.sock.shutdown(SHUT_RDWR)
                self.sock.close()
            except OSError:
                pass
        if exc:
            raise exc
        sys.exit(exit_code)

    def send(self, packet_data: str, raw: bool = False) -> None:
        self.last_packet = packet_data

        if not raw:
            check = GDBStub.checksum(packet_data)
            message = f"${packet_data}#{check:02x}"
        else:
            message = packet_data

        packet_logger.debug("-> %s", message)
        self.conn.sendall(message.encode("ascii"))

    def handle_packet(self, data: bytes) -> None:
        if data == b"\x03":
            logger.info("Interrupt request received")
            if self.waiting_for_break:
                self.waiting_for_break = False
                self.dbg.stop()
                self.send_halt_reply(Signals.SIGINT)
            return

        data = data.decode("ascii")
        for packet_data, checksum in re.findall(r"\$([^#]*)#([0-9a-f]{2})", data):
            if int(checksum, 16) != GDBStub.checksum(packet_data):
                logger.error(f"Received invalid packet: '{data}'")
                if self.send_ack:
                    self.send(GDBStub.NACK, raw=True)
            else:
                if self.send_ack:
                    self.send(GDBStub.ACK, raw=True)
                self.handle_command(packet_data)

    def interrupt_target(self, reason: Optional[Signals] = Signals.SIGINT) -> None:
        self.dbg.stop()
        self.send_halt_reply(reason)

    def wait_for_break(self):
        while True:
            if event := self.dbg.poll_events():
                print(event)
                if event[0] == Avr8Protocol.EVT_AVR8_BREAK:
                    break

    def handle_command(self, command: str) -> None:
        command_handlers: Dict[str, Callable[[str], None]] = {
            "?": self.handle_halt_query,
            # "!": self.handle_extended_enable,
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
            # "v": self.handle_v_command,
            "D": self.handle_detach,
        }

        key = command[0]
        if key in command_handlers:
            # pop off the key character
            command_handlers[key](command[1:])
        else:
            # unknown command reply
            self.send("")

    def send_halt_reply(self, sig: Optional[Signals] = None) -> None:
        if sig:
            self.last_signal = sig
        sig_val = self.last_signal if self.last_signal else 0
        self.send(f"S{sig_val:02x}")

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
            stub_features = [
                f"PacketSize={GDBStub.PACKET_SIZE:x}",
                "QStartNoAckMode+",
            ]
            self.send(";".join(stub_features))
        elif name == "Attached":
            # qAttached: "0" -- 'The remote server created a new process.'
            self.send("0")
        elif name == "Offsets":
            flash_addr = self.mem_info.memory_info_by_name("flash")["address"]
            sram_addr = self.mem_info.memory_info_by_name("internal_sram")["address"]
            self.send(f"Text={flash_addr:x};Data={sram_addr:x};Bss={sram_addr:x}")
        elif name == "Symbol":
            self.send("OK")
        elif name.startswith("Rcmd"):
            name, _, cmd = name.partition(",")
            command = "".join([chr(b) for b in bytearray.fromhex(cmd)])
            logger.debug("qRcmd: %s", command)
            output = self.handle_monitor_command(command)
            if output:
                self.send(output.encode("ascii").hex())
            elif output is not None:
                self.send("OK")
            else:
                self.send("")
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
        self.waiting_for_break = True

    def handle_continue(self, command: str) -> None:
        if len(command):
            addr = int(command, 16)
            logger.debug("c cmd=%s addr=0x%04x", command, addr)
        self.dbg.run()
        self.waiting_for_break = True

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
            self.send("E00")

    def handle_write_mem(self, command: str) -> None:
        # M addr,length:XX...
        addr, _, rest = command.partition(",")
        size, _, data = rest.partition(":")
        addr = int(addr, 16)
        size = int(size, 16)
        data = bytearray.fromhex(data)

        if len(data) != size:
            self.send("E00")
            return

        if self.dbg.write_mem(addr, data):
            self.send("OK")
        else:
            self.send("E00")

    def handle_read_regs(self, _command: str) -> None:
        reg_string = self.dbg.read_regfile().hex() + self.dbg.read_sreg().hex() + self.dbg.read_sp().hex()
        self.send(reg_string)

    def handle_write_regs(self, command: str) -> None:
        new_regs = bytearray.fromhex(command)
        if self.dbg.write_regfile(new_regs[0:31]):
            self.send("OK")
        else:
            self.send("E00")

    def handle_kill(self, _command: str) -> None:
        self.dbg.reset()
        # todo: extended mode might not want to quit
        logger.info("GDB issued reset, assuming quit")
        self.quit()

    def handle_read_one_reg(self, command: str) -> None:
        reg_num = int(command, 16)
        if reg_num < 32:
            # General Regs: R0-R31
            reg = self.dbg.read_regfile()[reg_num]
            self.send(f"{reg:02x}")
        elif reg_num == 32:
            # 'R32' = SREG
            sreg = self.dbg.read_sreg()
            self.send(sreg.hex())
        elif reg_num == 33:
            # 'R33' = SP
            sp = self.dbg.read_sp()
            self.send(sp.hex())
        elif reg_num == 34:
            # 'R34' = PC
            pc = self.dbg.read_pc()
            pc += 0x8000
            pc_bytes = struct.pack("<I", pc)
            self.send(pc_bytes.hex())
        else:
            logger.error(f"Undefined register read! {reg_num=}")
            self.send("")

    def handle_write_one_reg(self, command: str) -> None:
        reg_num, val = command.split("=")
        reg_num = int(reg_num, 16)
        val = int(val, 16)

        try:
            if reg_num < 32:
                regfile = self.dbg.read_regfile()
                regfile[reg_num] = val
                self.dbg.write_regfile(regfile)
                self.send("OK")
            else:
                logger.error(f"Undefined register write! {reg_num=}")
                self.send("")
        except Exception as exc:
            logger.error("Caught exception on register write: %s", exc, exc_info=True)
            self.send("E00")

    def handle_restart(self, _command: str) -> None:
        if self.extended_mode:
            self.dbg.reset()
            self.last_signal = Signals.SIGKILL
        else:
            logger.error("Got restart ('RXX') packet while not in extended mode!")
            self.send("")

    def handle_v_command(self, command: str) -> None:
        action = command
        rest = ""

        if "?" in command:
            action, _, rest = command.partition("?")
        elif ";" in command:
            action, _, rest = command.partition(";")

        if command == "Cont?":
            self.send("vCont")
        elif action == "Cont":
            self.send("")
        elif action == "Kill":
            self.dbg.reset()
            # self.wait_for_break()

            self.last_signal = Signals.SIGKILL
            self.fake_pid = int(rest, 16)
            self.send("OK")
        elif action == "Run":
            self.dbg.reset()
            self.send_halt_reply(Signals.SIGTRAP)
        else:
            logger.warning("Unhandled v command: %s %s", action, rest)
            self.send("")

    def handle_detach(self, _command: str) -> None:
        self.dbg.detach()
        self.send("OK")
        self.quit()

    def handle_monitor_command(self, command: str) -> Optional[str]:
        if command == "help":
            return "Hello, world!\n"
        elif command == "reset":
            self.dbg.reset()
            self.wait_for_break()
            return ""
        else:
            return None
