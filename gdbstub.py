import logging
import signal
from socket import socket, AF_INET, SOCK_STREAM
from select import select
from types import FrameType
from typing import Dict, Callable, Optional

from pyedbglib.protocols import avr8protocol
from pymcuprog.deviceinfo import deviceinfo

from debugger import Debugger


logger = logging.getLogger(__name__)
SIGTRAP = "S05"


class GDBStub:
    def __init__(self, device_name: str, host: str, port: int) -> None:
        self.dev = deviceinfo.getdeviceinfo(device_name)
        self.dbg = Debugger(device_name)
        self.host = host
        self.port = port
        self.conn = None
        self.last_packet = None
        self.last_signal = "S00"

    def signal_handler(self, sig: int, frame: Optional[FrameType]):
        print("You pressed Ctrl+C!")
        self.dbg.cleanup()
        exit(0)

    def listen_for_connection(self) -> None:
        self.dbg.stop()
        self.dbg.breakpointSWClearAll()
        self.dbg.breakpointHWClear()

        # consume pending events
        while _event := self.dbg.pollEvent():
            pass

        logger.info(f"Waiting for GDB session on {self.host}:{self.port}")
        signal.signal(signal.SIGINT, self.signal_handler)

        with socket(AF_INET, SOCK_STREAM) as sock:
            sock.bind((self.host, self.port))
            sock.listen()
            conn, addr = sock.accept()
            conn.setblocking(False)
            with conn:
                print(f"Client connected: {addr}")
                self.conn = conn
                while True:
                    # wait for conn to be readable
                    ready = select([conn], [], [], 0.5)
                    if ready[0]:
                        data = conn.recv(1024)
                        if len(data) > 0:
                            print("RX: " + data.decode("ascii"))
                            self.handle_packet(data)
                    if event := self.dbg.pollEvent():
                        print(event)
                        event_type, pc, break_cause = event
                        if event_type == avr8protocol.Avr8Protocol.EVT_AVR8_BREAK and break_cause == 1:
                            self.send(SIGTRAP)
                            self.last_signal = SIGTRAP

    def send(self, packet_data: str) -> None:
        self.last_packet = packet_data
        checksum = sum(packet_data.encode("ascii")) % 256
        message = f"${packet_data}#{checksum:02x}"
        print(f"TX: {message}")
        self.conn.sendall(message.encode("ascii"))

    def handle_packet(self, data: bytes) -> None:
        ascii_data = data.decode("ascii")
        if ascii_data.count("$") > 0:
            for _ in range(ascii_data.count("$")):
                checksum = ascii_data.split("#")[1][:2]
                packet_data = ascii_data.split("$")[1].split("#")[0]
                if int(checksum, 16) != sum(packet_data.encode("ascii")) % 256:
                    print("Invalid Checksum!")
                    self.conn.sendall(b"-")
                    print("TX: -")
                else:
                    self.conn.sendall(b"+")
                    print("TX: +")
                    self.handle_command(packet_data)
        elif data == b"\x03":
            self.dbg.stop()
            self.conn.sendall(b"+")
            print("TX: +")

    def handle_command(self, command: str) -> None:
        command_handlers: Dict[str, Callable[[str], None]] = {
            "?": self.handle_halt_query,
            "q": self.handle_query,
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
        }

        key = command[0]
        if key in command_handlers:
            # pop off the key character
            command_handlers[key](command[1:])
        else:
            # unknown command reply
            self.send("")

    def handle_halt_query(self, _command: str) -> None:
        self.send(self.last_signal)

    def handle_query(self, command: str) -> None:
        if len(command) == 0:
            self.send("")
        elif command == "Attached":
            self.send("0")
        elif "Supported" in command:
            # Since we are using a tcp connection we do not want to split up messages into different packets, so packetsize is set absurdly large
            self.send("PacketSize=10000000000")
        elif "Symbol::" in command:
            self.send("OK")
        elif "C" == command[0]:
            self.send("")
        elif "Offsets" in command:
            self.send("Text=000;Data=000;Bss=000")
        else:
            self.send("")

    def handle_step(self, command: str) -> None:
        # TODO: Make s behavior more in line with GDB docs
        # "addr is address to resume. If addr is omitted, resume at same address."
        if len(command):
            addr = int(command, 16)
            print(f"{command=} {addr=:02x}")
        self.dbg.step()
        self.send(SIGTRAP)
        self.last_signal = SIGTRAP

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
        pass

    def handle_write_mem(self, command: str) -> None:
        pass

    def handle_read_regs(self, command: str) -> None:
        pass

    def handle_write_regs(self, command: str) -> None:
        pass

    def handle_kill(self, command: str) -> None:
        pass

    def handle_read_one_reg(self, command: str) -> None:
        pass

    def handle_write_one_reg(self, command: str) -> None:
        pass





