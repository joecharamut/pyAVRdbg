import struct
from typing import Optional

from pyedbglib.hidtransport.hidtransportfactory import hid_transport
from pyedbglib.protocols.avr8protocol import Avr8Protocol
from pyedbglib.protocols.housekeepingprotocol import Jtagice3HousekeepingProtocol
from pyedbglib.protocols.jtagice3protocol import Jtagice3Protocol, Jtagice3ResponseError

from pymcuprog.deviceinfo import deviceinfo
from pymcuprog.nvmupdi import NvmAccessProviderCmsisDapUpdi

import logging
logger = logging.getLogger(__name__)


class Debugger:
    def __init__(self, device_name) -> None:
        # Make a connection
        self.transport = hid_transport()
        self.transport.disconnect()
        # Connect
        self.transport.connect()
        self.device_info = deviceinfo.getdeviceinfo(device_name)
        self.memory_info = deviceinfo.DeviceMemoryInfo(self.device_info)
        self.housekeeper = Jtagice3HousekeepingProtocol(self.transport)
        self.housekeeper.start_session()
        self.device = NvmAccessProviderCmsisDapUpdi(self.transport, self.device_info)
        # self.device.avr.deactivate_physical()
        self.device.avr.activate_physical()
        # Start debug by attaching (live)
        self.device.avr.protocol.attach()

    def poll_events(self) -> Optional[tuple]:
        """
        Poll for events from the target device

        The AVR8 protocol only defines like 2 events but there can be other ones I guess

        :returns: None | Tuple of (event id, event data...) if there was an event
        """
        event = self.device.avr.protocol.poll_events()
        if not event:
            return None

        logger.debug("Received event: (%s bytes) [%s]", len(event), " ".join([f"{b:02x}" for b in event]))

        if event[0] == Jtagice3Protocol.HANDLER_AVR8_GENERIC:
            event = event[1:]
            if event[0] == Avr8Protocol.EVT_AVR8_BREAK:
                event_id, pc, cause, ext_info = struct.unpack("<BIBH", event)
                pc = (pc << 1) & 0xFFFFFFFF  # pc is a word addr, convert to byte addr
                logger.info("Received EVT_AVR8_BREAK(id=0x%x, pc=0x%08x, cause=0x%x, ext=0x%x)", event_id, pc, cause, ext_info)
                return event_id, pc, cause, ext_info
            else:
                logger.debug("Unknown generic event: (id=0x%02x, data=%s)", event[0], event[1:])
                return None
        else:
            logger.warning(f"Unknown event type: 0x{event[0]:02x}")
            return None

    # Memory interaction

    def read_mem(self, address: int, count: int) -> Optional[bytearray]:
        """
        Read data from target memory

        :param address: starting address to read from
        :param count: count of bytes to read
        :returns: Data read or None if unable to
        """
        logger.info(f"Reading {count} bytes from address 0x{address:04x}")
        mem_type = self.memory_info.memory_info_by_address(address)
        if not mem_type:
            return None

        name = mem_type["name"]
        base = mem_type["address"]
        read_size = mem_type["read_size"]
        logger.debug(f"Address 0x{address:04x} is {name} [base: 0x{base:04x}, read_size: {read_size}]")

        offset = address - base
        start_align = offset % read_size
        data = self.device.read(mem_type, offset - start_align, count + start_align)
        return data[start_align:count+start_align]

    def write_mem(self, address: int, data: bytes) -> bool:
        """
        Write data to target memory

        :param address: starting address to write to
        :param data: data to write
        :returns: True if write succeeds
        """
        logger.info(f"Writing {len(data)} bytes to address 0x{address:04x}")
        mem_type = self.memory_info.memory_info_by_address(address)
        if not mem_type:
            return False

        name = mem_type["name"]
        base = mem_type["address"]
        print(mem_type)
        logger.debug(f"Address 0x{address:04x} is {name} [base: 0x{base:04x}]")

        if name == "flash":
            # prevent flash writes
            return False

        offset = address - base
        self.device.write(mem_type, offset, data)
        return True

    # General debugging

    def attach(self, do_break=False) -> None:
        """
        Attach debugger to target

        :param do_break: break target on attach
        """
        self.device.avr.protocol.attach(do_break)

    def detach(self) -> None:
        """
        Detach debugger from target
        """
        self.device.avr.protocol.detach()

    # Flow control
    def reset(self) -> None:
        """
        Reset the target and hold it in reset
        """
        self.device.avr.protocol.reset()
    
    def step(self) -> None:
        """
        Single-step the target

        Generates a BREAK event when step complete
        """
        self.device.avr.protocol.step()
    
    def stop(self) -> None:
        """
        Requests target to halt

        Generates a BREAK event when stopped
        """
        self.device.avr.protocol.stop()

    def run(self) -> None:
        """
        Resume target execution
        """
        self.device.avr.protocol.run()

    def run_to(self, address: int) -> None:
        """
        Run to given address

        Generates a BREAK even if it reaches the address

        :param address: the (byte) address to run to
        """
        word_address = address >> 1
        self.device.avr.protocol.run_to(word_address)

    def read_running_state(self) -> bool:
        """
        Read if target is running

        :returns: True if target is running
        """
        # Debug interface to see what state the avr is in.
        running = bool(self.device.avr.protocol.get_byte(
            Avr8Protocol.AVR8_CTXT_TEST,
            Avr8Protocol.AVR8_TEST_TGT_RUNNING
        ))
        # logging.info(f"Running state is {str(running)}")
        return running

    # Registers

    def read_regfile(self) -> bytearray:
        """
        Read the target's register file (R0-R31)

        :returns: (1 byte * 32 registers) as bytearray
        """
        return bytearray(self.device.avr.protocol.regfile_read())

    def write_regfile(self, regs: bytes) -> bool:
        """
        Write the target's register file (R0-R31)

        :param regs: new register file (32 bytes of data)
        :returns: True if successful
        """
        try:
            response = self.device.avr.protocol.regfile_write(regs)
            print(response)
            return True
        except ValueError:
            logger.error("write_regfile requires 32 bytes of registers (%s provided)", len(regs))
            return False
        except Jtagice3ResponseError as exc:
            logger.error("write_regfile: Exception %s (Code %s)", str(exc), exc.code)
            return False

    def read_pc(self) -> int:
        """
        Read target PC

        :returns: PC byte address
        """
        # Returned as a word not a byte
        pc = self.device.avr.protocol.program_counter_read()
        # convert to byte address
        pc = (pc << 1) & 0xFFFFFFFF
        return pc

    def write_pc(self, pc: int) -> None:
        """
        Write target PC

        :param pc: PC byte address
        """
        # target expects PC as word address
        pc = pc >> 1
        self.device.avr.protocol.program_counter_write(pc)

    def read_sreg(self) -> bytearray:
        """
        Read target SREG memory

        :returns: target SREG
        """
        # todo: add write_sreg
        # SREG is 1 byte of IO memory, not a real register
        return bytearray(self.device.avr.protocol.memory_read(
            Avr8Protocol.AVR8_MEMTYPE_OCD,
            Avr8Protocol.AVR8_MEMTYPE_OCD_SREG,
            1
        ))

    def read_sp(self) -> bytearray:
        """
        Read target stack pointer

        :returns: target SP
        """
        # todo: add write_sp
        return bytearray(self.device.avr.stack_pointer_read())

    # SoftwareBreakpoints EDBG expects these addresses in bytes
    # Multiple SW breakpoints can be defined by shifting 4 bytes to the left
    def set_sw_breakpoint(self, address: int) -> None:
        """
        Set software breakpoint on target

        todo: Multiple SW breakpoints supported by shifting left 4 bytes (?)

        :param address: byte address of breakpoint
        """
        self.device.avr.protocol.software_breakpoint_set(address)
    
    def clear_sw_breakpoint(self, address: int) -> None:
        """
        Clear a software breakpoint on target

        todo: multiple sw breakpoint support

        :param address: byte address to clear breakpoint from
        """
        self.device.avr.protocol.software_breakpoint_clear(address)

    def clear_all_sw_breakpoint(self) -> None:
        """
        Clear all software breakpoints on target
        """
        self.device.avr.protocol.software_breakpoint_clear_all()
    
    # HardwareBreakpoints EDBG expects these addresses in words
    def set_hw_breakpoint(self, address: int) -> None:
        """
        Set hardware breakpoint on target

        todo: some targets support multiple hw breakpoints

        :param address: byte address of breakpoint
        """
        # target expects word address
        word_address = address >> 1
        self.device.avr.breakpoint_set(word_address)

    def clear_hw_breakpoint(self) -> None:
        """
        Clear hardware breakpoint on target
        """
        self.device.avr.breakpoint_clear()
    
    # Cleanup code for detaching target
    def cleanup(self) -> None:
        """
        Detach target and clean up debugging interface
        """
        # End debugging:
        # halt target
        self.device.avr.protocol.stop()
        # clear any breakpoints
        self.device.avr.protocol.software_breakpoint_clear_all()
        self.device.avr.breakpoint_clear()
        # detach debugger from target
        self.device.avr.protocol.detach()

        # Stop debug session:
        # deactivate target physical interface
        self.device.avr.deactivate_physical()
        # stop housekeeper (debugger session sign-off)
        self.housekeeper.end_session()
        # disconnect from debugger
        self.transport.disconnect()
