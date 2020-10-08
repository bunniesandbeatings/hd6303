import struct
import traceback
import os

from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
# from binaryninja.lowlevelil import LowLevelILLabel, LLIL_TEMP
from binaryninja.binaryview import BinaryView
# from binaryninja.types import Symbol
from binaryninja.log import log_error
from binaryninja.enums import (BranchType, InstructionTextTokenType,
                               LowLevelILOperation, LowLevelILFlagCondition, FlagRole, SegmentFlag, SymbolType,
                               Endianness)

# 2-3 compatibility
from binaryninja import range

NONE = 0
IMMED = 1
DIR = 2
EXTND = 3
INDXD = 4
INHER = 5
REL = 6


def il_operand_none():
    pass


def il_operand_extend(il, value):
    il.load(1, il.const_pointer(2, value))


TEXT_OPCODE = lambda opcode: InstructionTextToken(InstructionTextTokenType.OpcodeToken, "%-7s " % opcode)


instructions = {
    0x01: {
        "label": "nop",
        "length": 1,
        "operand": INHER,
        "tokens": lambda operand: [
            TEXT_OPCODE("nop")
        ],
        "operandIL": il_operand_none,
        "instructionIL": lambda il, operand: il.nop(),
    },
    0xb6: {
        "label": "ldaa",
        "length": 3,
        "operand": EXTND,
        "tokens": lambda operand: [
            TEXT_OPCODE("ldaa"),
            InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.4x" % operand, operand)
        ],
        "operandIL": il_operand_extend,
        "instructionIL": lambda il, operand: il.set_reg(1, "a", operand, flags="nzv"),
    }
}


def word_as_ord(word):
    return struct.unpack("<H", word)[0]


def parse_instruction(data, address):
    instruction = instructions.get(data[0], None)
    if not instruction:
        instruction = {
            "label": "???",
            "length": 1,
            "tokens": lambda _: None,
            "operandIL": None,
            "instructionIL": None,
        }
    print(instruction)

    length = instruction["length"]

    value = None
    if length > 1:
        value = word_as_ord(data[1:length])

    return instruction, value


class M6803(Architecture):
    name = "m6803"
    address_size = 2
    default_int_size = 1
    instr_alignment = 1
    max_instr_length = 3
    endianness = Endianness.BigEndian

    regs = {
        # Stack Pointer
        'sp': RegisterInfo('sp', 2),

        # program counter
        'pc': RegisterInfo('pc', 2),

        # Index register
        "x": RegisterInfo("x", 1),

        # Accumulator
        'd': RegisterInfo('a', 2),
        'a': RegisterInfo('a', 2, 0),
        'b': RegisterInfo('a', 2, 1),

        'ccr': RegisterInfo('ccr', 1)

    }

    stack_pointer = 'sp'

    flags = ["h", "i", "n", "z", "v", "c"]
    flag_roles = {
        "h": FlagRole.HalfCarryFlagRole,
        "i": FlagRole.SpecialFlagRole,  # Interrupt
        "n": FlagRole.NegativeSignFlagRole,
        "z": FlagRole.ZeroFlagRole,
        "v": FlagRole.OverflowFlagRole,
        "c": FlagRole.CarryFlagRole,
    }

    flag_write_types = ["*", "nzvc", "z", "nzv", "hnzvc", "c", "i", "v"]

    flags_written_by_flag_write_type = {
        "*": ["h", "i", "n", "z", "v", "c"],
        "nzvc": ["n", "z", "v", "c"],
        "z": ["z"],
        "nzv": ["n", "z", "v"],
        "hnzvc": ["h", "n", "z", "v", "c"],
        "c": ["c"],
        "i": ["i"],
        "v": ["v"],
    }

    # flags_required_for_flag_condition = {
    #     LowLevelILFlagCondition.LLFC_NEG: ["n"],
    #     LowLevelILFlagCondition.LLFC_POS: ["n"],
    #     LowLevelILFlagCondition.LLFC_O: ["v"],
    #     LowLevelILFlagCondition.LLFC_NO: ["v"],
    #     LowLevelILFlagCondition.LLFC_E: ["z"],
    #     LowLevelILFlagCondition.LLFC_NE: ["z"],
    #     LowLevelILFlagCondition.LLFC_ULT: ["n", "v"],
    #     LowLevelILFlagCondition.LLFC_ULE: ["z", "n", "v"],
    #     LowLevelILFlagCondition.LLFC_UGE: ["v", "n"],
    #     LowLevelILFlagCondition.LLFC_UGT: ["z", "n", "v"],
    # }

    def convert_to_nop(self, data, address):
        return b"\x01" * len(data)

    def get_instruction_info(self, data, address):
        instruction, _ = parse_instruction(data, address)

        result = InstructionInfo()
        result.length = instruction["length"]

        return result

    def get_instruction_text(self, data, address):
        instruction, value = parse_instruction(data, address)
        token_function = instruction["tokens"]

        if token_function is None:
            return None

        length = instruction["length"]

        tokens = token_function(value)
        return tokens, length

    # def get_instruction_low_level_il(self, data, address, il):
    #     instruction, value = parse_instruction(data, address)
    #
    #     operand = instruction["operandIL"](il, value)
    #     instruction_il = instruction["instructionIL"](il, operand)
    #
    #     if isinstance(instruction_il, list):
    #         for i in instruction_il:
    #             il.append(i)
    #     elif instruction_il is not None:
    #         il.append(instruction_il)
    #
    #     return instruction["length"]


# ------example code

#
# 	def decode_instruction(self, data, address):
# 		if len(data) < 1:
# 			return None, None, None, None
# 		opcode = ord(data[0:1])
# 		instr = InstructionNames[opcode]
# 		if instr is None:
# 			return None, None, None, None
#
# 		operand = InstructionOperandTypes[opcode]
# 		length = 1 + OperandLengths[operand]
# 		if len(data) < length:
# 			return None, None, None, None
#
# 		if OperandLengths[operand] == 0:
# 			value = None
# 		elif operand == REL:
# 			value = (address + 2 + struct.unpack("b", data[1:2])[0]) & 0xffff
# 		elif OperandLengths[operand] == 1:
# 			value = ord(data[1:2])
# 		else:
# 			value = struct.unpack("<H", data[1:3])[0]
#
# 		return instr, operand, length, value
#
# 	def get_instruction_info(self, data, address):
# 		instr, operand, length, value = self.decode_instruction(data, addr)
# 		if instr is None:
# 			return None
#
# 		result = InstructionInfo()
# 		result.length = length
# 		if instr == "jmp":
# 			if operand == ADDR:
# 				result.add_branch(BranchType.UnconditionalBranch, struct.unpack("<H", data[1:3])[0])
# 			else:
# 				result.add_branch(BranchType.UnresolvedBranch)
# 		elif instr == "jsr":
# 			result.add_branch(BranchType.CallDestination, struct.unpack("<H", data[1:3])[0])
# 		elif instr in ["rti", "rts"]:
# 			result.add_branch(BranchType.FunctionReturn)
# 		if instr in ["bcc", "bcs", "beq", "bmi", "bne", "bpl", "bvc", "bvs"]:
# 			dest = (addr + 2 + struct.unpack("b", data[1:2])[0]) & 0xffff
# 			result.add_branch(BranchType.TrueBranch, dest)
# 			result.add_branch(BranchType.FalseBranch, addr + 2)
# 		return result
#
# 	def get_instruction_text(self, data, addr):
# 		instr, operand, length, value = self.decode_instruction(data, addr)
# 		if instr is None:
# 			return None
#
# 		tokens = []
# 		tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "%-7s " % instr.replace("@", "")))
# 		tokens += OperandTokens[operand](value)
# 		return tokens, length
#
# 	def get_instruction_low_level_il(self, data, addr, il):
# 		instr, operand, length, value = self.decode_instruction(data, addr)
# 		if instr is None:
# 			return None
#
# 		operand = OperandIL[operand](il, value)
# 		instr = InstructionIL[instr](il, operand)
# 		if isinstance(instr, list):
# 			for i in instr:
# 				il.append(i)
# 		elif instr is not None:
# 			il.append(instr)
#
# 		return length
#
# 	def get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il):
# 		if flag == 'c':
# 			if (op == LowLevelILOperation.LLIL_SUB) or (op == LowLevelILOperation.LLIL_SBB):
# 				# Subtraction carry flag is inverted from the commom implementation
# 				return il.not_expr(0, self.get_default_flag_write_low_level_il(op, size, FlagRole.CarryFlagRole, operands, il))
# 			# Other operations use a normal carry flag
# 			return self.get_default_flag_write_low_level_il(op, size, FlagRole.CarryFlagRole, operands, il)
# 		return Architecture.get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il)
#
# 	def is_never_branch_patch_available(self, data, addr):
# 		if (data[0:1] == b"\x10") or (data[0:1] == b"\x30") or (data[0:1] == b"\x50") or (data[0:1] == b"\x70") or (data[0:1] == b"\x90") or (data[0:1] == b"\xb0") or (data[0:1] == b"\xd0") or (data[0:1] == b"\xf0"):
# 			return True
# 		return False
#
# 	def is_invert_branch_patch_available(self, data, addr):
# 		if (data[0:1] == b"\x10") or (data[0:1] == b"\x30") or (data[0:1] == b"\x50") or (data[0:1] == b"\x70") or (data[0:1] == b"\x90") or (data[0:1] == b"\xb0") or (data[0:1] == b"\xd0") or (data[0:1] == b"\xf0"):
# 			return True
# 		return False
#
# 	def is_always_branch_patch_available(self, data, addr):
# 		return False
#
# 	def is_skip_and_return_zero_patch_available(self, data, addr):
# 		return (data[0:1] == b"\x20") and (len(data) == 3)
#
# 	def is_skip_and_return_value_patch_available(self, data, addr):
# 		return (data[0:1] == b"\x20") and (len(data) == 3)
#
# 	def convert_to_nop(self, data, addr):
# 		return b"\xea" * len(data)
#
# 	def never_branch(self, data, addr):
# 		if (data[0:1] == b"\x10") or (data[0:1] == b"\x30") or (data[0:1] == b"\x50") or (data[0:1] == b"\x70") or (data[0:1] == b"\x90") or (data[0:1] == b"\xb0") or (data[0:1] == b"\xd0") or (data[0:1] == b"\xf0"):
# 			return b"\xea" * len(data)
# 		return None
#
# 	def invert_branch(self, data, addr):
# 		if (data[0:1] == b"\x10") or (data[0:1] == b"\x30") or (data[0:1] == b"\x50") or (data[0:1] == b"\x70") or (data[0:1] == b"\x90") or (data[0:1] == b"\xb0") or (data[0:1] == b"\xd0") or (data[0:1] == b"\xf0"):
# 			return chr(ord(data[0:1]) ^ 0x20) + data[1:]
# 		return None
#
# 	def skip_and_return_value(self, data, addr, value):
# 		if (data[0:1] != b"\x20") or (len(data) != 3):
# 			return None
# 		return b"\xa9" + chr(value & 0xff) + b"\xea"

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
            hdr = self.parent_view.read(0, 16)

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


TR707View.register()

M6803.register()
