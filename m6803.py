import struct
from binaryninja.log import log_error

from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import (BranchType, InstructionTextTokenType,
                               FlagRole, SymbolType,
                               Endianness)


# NONE = 0
# IMMED = 1
# DIR = 2
# EXTND = 3
# INDXD = 4
# INHER = 5
# REL = 6

# def il_operand_none():
#     pass
#
#
# def il_operand_extend(il, value):
#     il.load(1, il.const_pointer(2, value))
#

def operand_word_address(operand):
    return [
        InstructionTextToken(
            InstructionTextTokenType.PossibleAddressToken,
            "$%.4x" % operand,
            operand
        )
    ]


def operand_byte_address(operand):
    return [
        InstructionTextToken(
            InstructionTextTokenType.PossibleAddressToken,
            "$%.2x" % operand,
            operand
        )
    ]


def operand_token_extended(operand):
    return operand_word_address(operand)


def operand_token_immediate_word(operand):
    return operand_word_address(operand)


def operand_token_immediate_byte(operand):
    return operand_byte_address(operand)


def operand_token_inherent(operand):
    return operand_token_none(operand)


def operand_token_none(operand):
    return []


instructions = {
    0x01: {"label": "nop", "length": 1, "tokenFn": operand_token_none},
    0x5f: {"label": "clrb", "length": 1, "tokenFn": operand_token_inherent},
    0x86: {"label": "ldaa", "length": 2, "tokenFn": operand_token_immediate_byte},
    0x8e: {"label": "lds", "length": 3, "tokenFn": operand_token_immediate_word},
    0xb6: {"label": "ldaa", "length": 3, "tokenFn": operand_token_extended},
    0xc6: {"label": "ldab", "length": 2, "tokenFn": operand_token_immediate_byte},
    0xce: {"label": "ldx", "length": 3, "tokenFn": operand_token_immediate_word},
    0xfd: {"label": "std", "length": 3, "tokenFn": operand_token_extended},
}


def word_as_ord(word):
    return struct.unpack(">H", word)[0]


def parse_instruction(data, address):
    instruction = instructions.get(data[0], None)
    if not instruction:
        instruction = {
            "label": "???",
            "length": 1,
            "tokenFn": lambda data: [],
        }
    length = instruction["length"]

    value = None
    if length == 2:
        value = ord(data[1:2])
    elif length == 3:
        value = word_as_ord(data[1:length])

    return instruction, value


def text_opcode(label):
    return InstructionTextToken(InstructionTextTokenType.OpcodeToken, "%-7s " % label)


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

        if instruction is None:
            return None

        print(instruction)

        token_function = instruction["tokenFn"]
        length = instruction["length"]
        label = instruction["label"]
        tokens = [text_opcode(label)]
        tokens += token_function(value)

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
