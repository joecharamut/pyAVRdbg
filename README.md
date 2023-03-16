# pyAVRdbg
An attempt at making a GDB RSP server for AVR debuggers using [pymcuprog](https://pypi.org/project/pymcuprog/) and [pyedbglib](https://pypi.org/project/pyedbglib/).

This is primarily for the new UPDI devices but other protocols supported by pymcuprog could be made to work.

## Current Features
- Stepping
- Memory manipulation (viewing and modifying variables)
- Hardware and software breakpoints
- Reading Registers (including SREG, Stack pointer and program counter)*

*Writing is possible it is just not implemented yet.

## Python Requirements

- pymcuprog
- pyedbglib

## Installation

- Run `pip install --user pyavrdbg` *(not yet published to pypi)
- Install `avr-gdb` (package repos or from source)
  - If on Windows, consider using [WSL](https://en.wikipedia.org/wiki/Windows_Subsystem_for_Linux)

## Usage

### Starting server
1. Ensure debugger/kit is connected
2. If not installed via pip, cd to the directory where pyavrdbg is
3. run `python -m pyavrdbg [args]`
   - Required: `-t target` (e.g. attiny804, attiny202, etc)
   - Optional: `-P port` (Default: `1234`)
   - Optional: `-H host` (Default: `127.0.0.1`)

### GDB
1. `avr-gdb program.elf`
2. (gdb) `target remote host:port`
    - Can be abbreviated for localhost as `target remote :port`

## Currently Supported Devices
These are all the currently supported devices per 03.06.2020. This list is wholly dependent on pymcuprog's device support since this RSP server only uses general library calls in pymcuprog. As mentioned before ISP devices might also be supported in the future.
| Protocol | Device Name |
|:--------:|:-----------:|
| UPDI     | atmega4808* |
|          | atmega4809  |
|          | attiny416*  |
|          | attiny817*  |
|          | attiny1607* |
|          | attiny1627* |
|          | attiny3217* |
|          | avr128da28* |
|          | avr128da48  |
|          | avr128db48* |

*Devices are untested but will most likely work.

## Thanks
A huge thanks to Microchip for making pymcuprog available 

## Some useful links for reference for development
- https://www.embecosm.com/appnotes/ean4/embecosm-howto-rsp-server-ean4-issue-2.html#id3033520
- https://ftp.gnu.org/old-gnu/Manuals/gdb/html_node/gdb_toc.html
- https://onlinedocs.microchip.com/pr/GUID-33422CDF-8B41-417C-9C31-E4521ADAE9B4-en-US-2/index.html
- https://github.com/mbedmicro/pyOCD/tree/master/pyocd
- https://developer.apple.com/library/archive/documentation/DeveloperTools/gdb/gdb/gdb_33.html
- http://ww1.microchip.com/downloads/en/DeviceDoc/50002630A.pdf
