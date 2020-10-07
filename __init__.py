import struct
import traceback
import os

from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
# from binaryninja.lowlevelil import LowLevelILLabel, LLIL_TEMP
# from binaryninja.binaryview import BinaryView
# from binaryninja.types import Symbol
# from binaryninja.log import log_error
# from binaryninja.enums import (BranchType, InstructionTextTokenType,
#                                LowLevelILOperation, LowLevelILFlagCondition, FlagRole, SegmentFlag, SymbolType)

# 2-3 compatibility
from binaryninja import range

NONE = 0
IMMED = 1
DIR = 2
EXTND = 3
INDXD = 4
INHER = 5
REL = 6

instructions = []

instructions[0x01] = {
    "label": "nop",
    "length": 1,
    "operand": INHER
}


def parse_instruction(data, addr):
    instruction = instructions[data[0]]
    if instruction == None
        instruction = {
            length: 1
        }
    return instruction


class M6502(Architecture):
    name = "6502"
    address_size = 2
    default_int_size = 1
    instr_alignment = 1
    max_instr_length = 3

    def convert_to_nop(self, data, addr):
        return b"\x01" * len(data)

    def get_instruction_info(self, data, addr):
        instruction = parse_instruction(data, addr)

        result = InstructionInfo()
        result.length = 1

        return result


# 	regs = {
# 		"a": RegisterInfo("a", 1),
# 		"x": RegisterInfo("x", 1),
# 		"y": RegisterInfo("y", 1),
# 		"s": RegisterInfo("s", 1)
# 	}
# 	stack_pointer = "s"
# 	flags = ["c", "z", "i", "d", "b", "v", "s"]
# 	flag_write_types = ["*", "czs", "zvs", "zs"]
# 	flag_roles = {
# 		"c": FlagRole.SpecialFlagRole,  # Not a normal carry flag, subtract result is inverted
# 		"z": FlagRole.ZeroFlagRole,
# 		"v": FlagRole.OverflowFlagRole,
# 		"s": FlagRole.NegativeSignFlagRole
# 	}
# 	flags_required_for_flag_condition = {
# 		LowLevelILFlagCondition.LLFC_UGE: ["c"],
# 		LowLevelILFlagCondition.LLFC_ULT: ["c"],
# 		LowLevelILFlagCondition.LLFC_E: ["z"],
# 		LowLevelILFlagCondition.LLFC_NE: ["z"],
# 		LowLevelILFlagCondition.LLFC_NEG: ["s"],
# 		LowLevelILFlagCondition.LLFC_POS: ["s"]
# 	}
# 	flags_written_by_flag_write_type = {
# 		"*": ["c", "z", "v", "s"],
# 		"czs": ["c", "z", "s"],
# 		"zvs": ["z", "v", "s"],
# 		"zs": ["z", "s"]
# 	}
#
# 	def decode_instruction(self, data, addr):
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
# 			value = (addr + 2 + struct.unpack("b", data[1:2])[0]) & 0xffff
# 		elif OperandLengths[operand] == 1:
# 			value = ord(data[1:2])
# 		else:
# 			value = struct.unpack("<H", data[1:3])[0]
#
# 		return instr, operand, length, value
#
# 	def get_instruction_info(self, data, addr):
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


M6502.register()
