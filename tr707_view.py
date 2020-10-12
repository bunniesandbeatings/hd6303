import struct

from binaryninja.binaryview import BinaryView
from binaryninja.log import (log_error, log_warn)
from binaryninja.types import Symbol
from binaryninja.enums import (SegmentFlag, SymbolType, SectionSemantics)
from binaryninja.architecture import Architecture

import traceback

START_OF_BINARY = 0x0000
START_OF_PROGRAM_ROM = 0x8000
START_OF_PROGRAM_ROM_MIRROR = 0xc000
LENGTH_OF_PROGRAM_ROM = 0x4000
HEADER = b"\xb6\x10\x00\xb6\x10\x00"


class TR707View(BinaryView):
    name = "TR707"
    long_name = "Roland TR707 Program Rom"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture['m6803'].standalone_platform

    @classmethod
    def is_valid_for_data(self, data):
        """ assumes the first operation is to reset the LCD """
        rom = data.read(0, LENGTH_OF_PROGRAM_ROM)

        if rom[0:6] != HEADER:
            return False

        if len(rom) < LENGTH_OF_PROGRAM_ROM:
            log_warn("Found 707 ROM, but it's too short. Must be $%.x bytes" % LENGTH_OF_PROGRAM_ROM)
            return False

        return True

    def init(self):
        try:

            rom_flags = SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable | SegmentFlag.SegmentDenyWrite
            self.add_auto_segment(
                START_OF_PROGRAM_ROM,
                LENGTH_OF_PROGRAM_ROM,
                START_OF_BINARY,
                LENGTH_OF_PROGRAM_ROM,
                rom_flags
            )

            # and the Program ROM mirror
            self.add_auto_segment(
                START_OF_PROGRAM_ROM_MIRROR,
                LENGTH_OF_PROGRAM_ROM,
                START_OF_BINARY,
                LENGTH_OF_PROGRAM_ROM,
                rom_flags
            )

            self.add_auto_section(
                "program",
                START_OF_PROGRAM_ROM_MIRROR,
                LENGTH_OF_PROGRAM_ROM,
                SectionSemantics.ReadOnlyCodeSectionSemantics
            )

            # self.add_auto_section(
            #     "zero page ram",
            #     0x040,
            #     0xbf,
            #     SectionSemantics.ReadWriteDataSectionSemantics,
            # )

            self.add_auto_section(
                "interrupt_vectors",
                0x00EA,
                0x15,
                SectionSemantics.ReadOnlyDataSectionSemantics,
            )


            start = struct.unpack(">H", self.read(0xfffe, 2))[0]

            nmi = struct.unpack(">H", self.read(0xfffc, 2))[0]
            trap = struct.unpack(">H", self.read(0xffee, 2))[0]
            swi = struct.unpack(">H", self.read(0xfffa, 2))[0]
            irq1 = struct.unpack(">H", self.read(0xfff8, 2))[0]
            irq2 = struct.unpack(">H", self.read(0xffea, 2))[0]
            ici = struct.unpack(">H", self.read(0xfff6, 2))[0]
            oci = struct.unpack(">H", self.read(0xfff5, 2))[0]
            toi = struct.unpack(">H", self.read(0xfff3, 2))[0]
            cmi = struct.unpack(">H", self.read(0xffec, 2))[0]
            sio = struct.unpack(">H", self.read(0xfff0, 2))[0]

            # ordered with the prefered label last.
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, ici, "_ici"))
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, oci, "_oci"))
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, toi, "_toi"))
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, cmi, "_cmi"))
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, sio, "_sio"))
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, swi, "_swi"))
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, irq2, "_irq2"))
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, irq1, "_irq1"))
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, trap, "_trap"))
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, nmi, "_nmi"))
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, start, "_start"))

            self.add_function(ici)
            self.add_function(oci)
            self.add_function(toi)
            self.add_function(cmi)
            self.add_function(sio)
            self.add_function(swi)
            self.add_function(irq2)
            self.add_function(irq1)
            self.add_function(trap)
            self.add_function(nmi)
            self.add_entry_point(start)

            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0002, "PORT_1_DATA", full_name="Port 1 Data"))

            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0001, "PORT_2_DIR", full_name="Port 2 Data Direction Register"))
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0003, "PORT_2_DATA", full_name="Port 2 Data"))
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0004, "PORT_3_DIR", full_name="Port 3 Data Direction Register"))
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0006, "PORT_3_DATA", full_name="Port 3 Data"))

            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0007, "PORT_4_DATA", full_name="Port 4 Data"))

            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0014, "PORT_5_CTRL", full_name="RAM/Port 5 Control Register"))
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0015, "PORT_5_DATA", full_name="Port 5 Data"))

            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0016, "PORT_6_DIR", full_name="Port 6 Data Direction Register"))
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0017, "PORT_6_DATA", full_name="Port 6 Data"))

            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0018, "PORT_7_DATA", full_name="Port 7 Data"))

            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0008, "TIMER_STATUS_1", full_name="Timer Control/Status Register 1"))
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x000f, "TIMER_STATUS_2", full_name="Timer Control/Status Register 2"))
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x001b, "TIMER_STATUS_3", full_name="Timer Control/Status Register 3"))
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x001d, "TIMER_2_UPCOUNT", full_name="Timer 2 Up Counter"))  # Don't use this on the 707

            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x001c, "TIME_CONSTANT", full_name="Time Constant Register"))

            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0009, "COUNTER_H", full_name="Free Running counter(MSB)"))
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x000a, "COUNTER_L", full_name="Free Running counter(LSB)"))

            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x000b, "OUT_COMP_1_H", full_name="Output compare register 1(MSB)"))
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x000c, "OUT_COMP_1_L", full_name="Output compare register 1(LSB)"))

            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0019, "OUT_COMP_2_H", full_name="Output compare register 2(MSB)"))
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x001a, "OUT_COMP_2_L", full_name="Output compare register 2(LSB)"))

            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x000d, "IN_CAP_H", full_name="Input Capture Register(MSB)"))
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x000e, "IN_CAP_L", full_name="Input Capture Register(LSB)"))

            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0010, "RATE_REG", full_name="Rate/Mode control register"))

            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0011, "USART_CTRL", full_name="Tx/Rx USART Control Register"))

            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0012, "USART_RX", full_name="USART RX Data Register"))
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x0013, "USART_TX", full_name="USART TX Data Register"))

            return True

        except:
            log_error(traceback.format_exc())
            return False

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return START_OF_PROGRAM_ROM_MIRROR

    def perform_get_address_size(self):
        return 8
