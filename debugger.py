from typing import Optional

from pyedbglib.hidtransport.hidtransportfactory import hid_transport
from pyedbglib.protocols import housekeepingprotocol
from pyedbglib.protocols import housekeepingprotocol
from pyedbglib.protocols import avr8protocol
from pyedbglib.protocols import avr8protocolerrors

# Retrieve device info
from pymcuprog.deviceinfo import deviceinfo

# Construct an NVM provider
from pymcuprog.nvmupdi import NvmAccessProviderCmsisDapUpdi

from pyedbglib.protocols.avrcmsisdap import AvrCommand, AvrCommandError
from pyedbglib.protocols.jtagice3protocol import Jtagice3Command

import logging
import threading
import time
import asyncio

# logging.basicConfig(level=logging.INFO,handlers=[logging.StreamHandler()])
logger = logging.getLogger(__name__)


class Debugger():

    def __init__(self, DeviceName):
        # Make a connection
        self.transport = hid_transport()
        self.transport.disconnect()
        # Connect
        self.transport.connect()
        self.deviceInf = deviceinfo.getdeviceinfo(DeviceName)
        self.memoryinfo = deviceinfo.DeviceMemoryInfo(self.deviceInf)
        self.housekeeper = housekeepingprotocol.Jtagice3HousekeepingProtocol(self.transport)
        self.housekeeper.start_session()
        self.device = NvmAccessProviderCmsisDapUpdi(self.transport, self.deviceInf)
        #self.device.avr.deactivate_physical()
        self.device.avr.activate_physical()
        # Start debug by attaching (live)
        self.device.avr.protocol.attach()
        #threading.Thread(target=pollingThread, args=(self.eventReciver,)).start()
    
    def pollEvent(self):
        #eventRegister = self.eventReciver.poll_events()
        eventRegister = self.device.avr.protocol.poll_events()
        # logging.info(eventRegister)
        if eventRegister and eventRegister[0] == AvrCommand.AVR_EVENT: # Verifying data is an event
            size = int.from_bytes(eventRegister[1:3], byteorder='big')
            if size != 0:
                #event recived
                logging.info("Event recived")
                eventarray = eventRegister[3:(size+1+3)]
                SOF = eventarray[0]
                protocol_version = eventarray[1:2]
                sequence_id = eventarray[2:4]
                protocol_handler_id = eventarray[4:5]
                payload = eventarray[5:]
                #logging.info(eventarray)
                if payload[0] == avr8protocol.Avr8Protocol.EVT_AVR8_BREAK:
                    event_id = payload[0]
                    #event_version = payload[1]
                    pc = payload[1:5]
                    break_cause = payload[5]
                    extended_info = payload[6:]
                    print("PC: ", end="")
                    print(int.from_bytes(pc, byteorder='little'))
                    logging.info("Recived break event")
                    return (avr8protocol.Avr8Protocol.EVT_AVR8_BREAK, int.from_bytes(pc, byteorder='little'), break_cause)
                else:
                    logging.info("Unknown event: " + payload[0])
                    return None
                
            else:
                logging.info("No event")
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

    def attach(self, do_break=False):
            self.device.avr.protocol.attach(do_break)

    def detach(self):
            self.device.avr.protocol.detach()

    # Flow controll
    def reset(self):
            self.device.avr.protocol.reset()
    
    def step(self):
            self.device.avr.protocol.step() 
    
    def stop(self):
            self.device.avr.protocol.stop()

    def run(self):
            self.device.avr.protocol.run()

    def runTo(self, address):
        wordAddress = int(address/2)
        self.device.avr.protocol.run_to(wordAddress)

    def readStackPointer(self):
        return self.device.avr.stack_pointer_read()

    def readSREG(self):
        return self.device.avr.protocol.memory_read(avr8protocol.Avr8Protocol.AVR8_MEMTYPE_OCD, 0x1C, 0x01)

    def readRunningState(self):
        # Debug interface to see what state the avr is in.
        AVR8_CTXT_TEST = 0x80
        AVR8_TEST_TGT_RUNNING = 0x00
        running = bool(self.device.avr.protocol.get_byte(AVR8_CTXT_TEST, AVR8_TEST_TGT_RUNNING))
        logging.info("AVR running state " + str(running))
        return running


    # Register and programcounter
    def readRegs(self):
        return self.device.avr.protocol.regfile_read()

    def writeRegs(self, regs):
        return self.device.avr.protocol.regile_write(regs)

    def readProgramCounter(self):
        # Returned as a word not a byte
        return self.device.avr.protocol.program_counter_read()

    def writeProgramCounter(self, programCounter):
            self.device.avr.protocol.program_counter_write(programCounter)

    # SoftwareBreakpoints EDBG expects these addresses in bytes
    # Multiple SW breakpoints can be defined by shifting 4 bytes to the left
    def breakpointSWSet(self, address):
            self.device.avr.protocol.software_breakpoint_set(address)
    
    def breakpointSWClear(self, address):
            self.device.avr.protocol.software_breakpoint_clear(address)

    def breakpointSWClearAll(self):
            self.device.avr.protocol.software_breakpoint_clear_all()
    
    # HardwareBreakpoints EDBG expects these addresses in words
    def breakpointHWSet(self, address):
        wordAddress = int(address/2)
        self.device.avr.breakpoint_set(wordAddress)

    def breakpointHWClear(self):
            self.device.avr.breakpoint_clear()
    
    # Cleanup code for detatching target
    def cleanup(self):
        # and end debug
        self.device.avr.protocol.stop()
        self.device.avr.protocol.software_breakpoint_clear_all()
        self.device.avr.breakpoint_clear()
        self.device.avr.protocol.detach()
        # Stop session
        #avr.stop()
        self.device.avr.deactivate_physical()
        # Unwind the stack
        self.housekeeper.end_session()
        self.transport.disconnect()
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.cleanup()

