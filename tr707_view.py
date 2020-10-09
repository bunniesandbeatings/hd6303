from binaryninja.binaryview import BinaryView
from binaryninja.log import log_error
from binaryninja.types import Symbol
from binaryninja.enums import (SegmentFlag, SymbolType)
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
            print("Found 707 ROM, but it's too short. Must be $%.x bytes" % LENGTH_OF_PROGRAM_ROM)
            return False

        return True

    def init(self):
        try:

            rom_flags = SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable  # | SegmentFlag.SegmentContainsCode
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

            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, START_OF_PROGRAM_ROM, "_start"))
            self.add_entry_point(START_OF_PROGRAM_ROM)

            return True
        except:
            log_error(traceback.format_exc())
            return False

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return START_OF_PROGRAM_ROM

    def perform_get_address_size(self):
        return 8
