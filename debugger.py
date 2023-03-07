from typing import Optional, Any

from pyedbglib.hidtransport.hidtransportfactory import hid_transport
from pyedbglib.protocols.avrcmsisdap import AvrCommand
from pyedbglib.protocols import housekeepingprotocol
from pyedbglib.protocols import avr8protocol

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
        self.memoryinfo = deviceinfo.DeviceMemoryInfo(self.device_info)
        self.housekeeper = housekeepingprotocol.Jtagice3HousekeepingProtocol(self.transport)
        self.housekeeper.start_session()
        self.device = NvmAccessProviderCmsisDapUpdi(self.transport, self.device_info)
        # self.device.avr.deactivate_physical()
        self.device.avr.activate_physical()
        # Start debug by attaching (live)
        self.device.avr.protocol.attach()

    def pollEvent(self) -> Optional[bytearray]:
        event = self.device.avr.protocol.poll_events()
        # Verifying data is an event
        if event and event[0] == AvrCommand.AVR_EVENT:
            size = int.from_bytes(event[1:3], byteorder="big")
            if size > 0:
                # event received
                event_array = event[3:(size+1+3)]
                SOF = event_array[0]
                protocol_version = event_array[1:2]
                sequence_id = event_array[2:4]
                protocol_handler_id = event_array[4:5]
                payload = event_array[5:]

                event_id = payload[0]
                logging.debug(f"Received event: {event_id}")
                if event_id == avr8protocol.Avr8Protocol.EVT_AVR8_BREAK:
                    pc = int.from_bytes(payload[1:5], byteorder="little")
                    break_cause = payload[5]
                    extended_info = payload[6:]
                    logging.info(f"Received break event (PC=0x{pc:04x}, {break_cause=}, {extended_info=})")
                    return (avr8protocol.Avr8Protocol.EVT_AVR8_BREAK, pc, break_cause)
                else:
                    logging.warning("Unknown event: " + event_id)
        return None

    # Memory interaction

    def read_mem(self, address: int, count: int) -> Optional[bytes]:
        logger.info(f"Reading {count} bytes from address 0x{address:04x}")
        mem_type = self.memoryinfo.memory_info_by_address(address)
        if not mem_type:
            return None

        name = mem_type["name"]
        base = mem_type["address"]
        read_size = mem_type["read_size"]
        logger.debug(f"Address 0x{address:04x} is {name} [base: 0x{base:04x}, read_size: {read_size}]")

        offset = address - base
        align = offset % read_size
        data = self.device.read(mem_type, offset - align, count + align)
        return data[align:]

    def write_mem(self, address: int, data: bytes) -> bool:
        logger.info(f"Writing {len(data)} bytes to address 0x{address:04x}")
        mem_type = self.memoryinfo.memory_info_by_address(address)
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
        self.device.avr.protocol.attach(do_break)

    def detach(self) -> None:
        self.device.avr.protocol.detach()

    # Flow control
    def reset(self) -> None:
        self.device.avr.protocol.reset()
    
    def step(self) -> None:
        self.device.avr.protocol.step()
    
    def stop(self) -> None:
        self.device.avr.protocol.stop()

    def run(self) -> None:
        self.device.avr.protocol.run()

    def run_to(self, address: int) -> None:
        word_address = address >> 1
        self.device.avr.protocol.run_to(word_address)

    def read_running_state(self) -> bool:
        # Debug interface to see what state the avr is in.
        running = bool(self.device.avr.protocol.get_byte(
            avr8protocol.Avr8Protocol.AVR8_CTXT_TEST,
            avr8protocol.Avr8Protocol.AVR8_TEST_TGT_RUNNING
        ))
        logging.info(f"Running state is {str(running)}")
        return running

    # Registers

    def read_regfile(self) -> bytearray:
        return self.device.avr.protocol.regfile_read()

    def write_regfile(self, regs: bytearray) -> Any:
        return self.device.avr.protocol.regfile_write(regs)

    def read_pc(self) -> int:
        # Returned as a word not a byte
        return self.device.avr.protocol.program_counter_read()

    def write_pc(self, new_pc) -> None:
        self.device.avr.protocol.program_counter_write(new_pc)

    def read_sreg(self) -> bytearray:
        # SREG is 1 byte of IO memory, not a real register
        return self.device.avr.protocol.memory_read(
            avr8protocol.Avr8Protocol.AVR8_MEMTYPE_OCD,
            avr8protocol.Avr8Protocol.AVR8_MEMTYPE_OCD_SREG,
            1
        )

    def read_sp(self) -> bytearray:
        return self.device.avr.stack_pointer_read()

    # SoftwareBreakpoints EDBG expects these addresses in bytes
    # Multiple SW breakpoints can be defined by shifting 4 bytes to the left
    def set_sw_breakpoint(self, address) -> None:
        self.device.avr.protocol.software_breakpoint_set(address)
    
    def clear_sw_breakpoint(self, address: int) -> None:
        self.device.avr.protocol.software_breakpoint_clear(address)

    def clear_all_sw_breakpoint(self) -> None:
        self.device.avr.protocol.software_breakpoint_clear_all()
    
    # HardwareBreakpoints EDBG expects these addresses in words
    def set_hw_breakpoint(self, address: int) -> None:
        word_address = address >> 1
        self.device.avr.breakpoint_set(word_address)

    def clear_hw_breakpoint(self) -> None:
        self.device.avr.breakpoint_clear()
    
    # Cleanup code for detaching target
    def cleanup(self) -> None:
        # and end debug
        self.device.avr.protocol.stop()
        self.device.avr.protocol.software_breakpoint_clear_all()
        self.device.avr.breakpoint_clear()
        self.device.avr.protocol.detach()
        # Stop session
        # avr.stop()
        self.device.avr.deactivate_physical()
        # Unwind the stack
        self.housekeeper.end_session()
        self.transport.disconnect()
    
    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.cleanup()
