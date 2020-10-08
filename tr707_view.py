from binaryninja.binaryview import BinaryView
from binaryninja.log import log_error
from binaryninja.enums import (SegmentFlag)
from binaryninja.architecture import Architecture
import traceback


class TR707View(BinaryView):
    name = "TR707"
    long_name = "Roland TR707 Program Rom"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture['m6803'].standalone_platform

    @classmethod
    def is_valid_for_data(self, data):
        """ assumes the first operation is to reset the LCD """

        header = data.read(0, 6)
        print("Header: ", header)
        if len(header) < 6:
            return False
        return header == b"\xb6\x10\x00\xb6\x10\x00"

    def init(self):
        try:
            # Add the ROM
            self.add_auto_segment(0x8000, 0x4000, 0, 0x4000,
                                  SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable | SegmentFlag.SegmentContainsCode)

            # and it's mirror
            self.add_auto_segment(0xc000, 0x4000, 0, 0x4000,
                                  SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable | SegmentFlag.SegmentContainsCode)

            self.add_entry_point(0x8000)

            return True
        except:
            log_error(traceback.format_exc())
            return False

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0x8000


