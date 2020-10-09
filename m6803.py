import struct

from binaryninja.log import log_error, log_debug

from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import (BranchType, InstructionTextTokenType,
                               FlagRole, SymbolType,
                               Endianness)
from typing import (Callable, Tuple, Optional)

OperandFunction = Callable[[int], any]  # FIXME: can we build a Token base type?


# def il_operand_none():
#     pass
#
#
# def il_operand_extend(il, value):
#     il.load(1, il.const_pointer(2, value))
#


def operand_word_address():
    return 2, lambda operand: [
        InstructionTextToken(
            InstructionTextTokenType.PossibleAddressToken,
            "$%.4x" % operand,
            operand
        )
    ]


def operand_byte_address():
    return 1, lambda operand: [
        InstructionTextToken(
            InstructionTextTokenType.PossibleAddressToken,
            "$%.2x" % operand,
            operand
        )
    ]


def operand_byte():
    return 1, lambda operand: [
        InstructionTextToken(InstructionTextTokenType.TextToken, "#"),
        InstructionTextToken(
            InstructionTextTokenType.IntegerToken,
            "$%.2x" % operand,
            operand
        )
    ]


def operand_word():
    return 2, lambda operand: [
        InstructionTextToken(InstructionTextTokenType.TextToken, "#"),
        InstructionTextToken(
            InstructionTextTokenType.IntegerToken,
            "$%.4x" % operand,
            operand
        )
    ]


def operand_token_indexed():
    return 1, lambda operand: [
        InstructionTextToken(
            InstructionTextTokenType.PossibleAddressToken,
            "$%.2x" % operand,
            operand
        ),
        InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, "x")
    ]


def operand_token_direct_memory():
    return 2, lambda operand: [
        InstructionTextToken(InstructionTextTokenType.TextToken, "#"),
        InstructionTextToken(
            InstructionTextTokenType.IntegerToken,
            "$%.2x" % (operand >> 8),
            operand
        ),
        InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
        InstructionTextToken(
            InstructionTextTokenType.PossibleAddressToken,
            "$%.2x" % (operand & 0xff),
            operand
        ),
    ]


def operand_token_immediate_indexed():
    return 2, lambda operand: [
        InstructionTextToken(InstructionTextTokenType.TextToken, "#"),
        InstructionTextToken(
            InstructionTextTokenType.IntegerToken,
            "$%.2x" % (operand >> 8),
            operand
        ),
        InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
        InstructionTextToken(
            InstructionTextTokenType.PossibleAddressToken,
            "$%.2x" % (operand & 0xff),
            operand
        ),
        InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, "x")
    ]


OPERAND_TYPE_NONE = 0
OPERAND_TYPE_IMMEDIATE = 0


def operand_token_none():
    return 0, lambda: []


def operand_token_extended():
    return operand_word_address()


def operand_token_immediate_word():
    return operand_word()


def operand_token_immediate_byte():
    return operand_byte()


def operand_token_inherent():
    return operand_token_none()


def operand_token_relative():
    return operand_byte_address()


def operand_token_direct():
    return operand_byte_address()


instructions = {
    0x00: {},
    0x01: {"label": "nop", "token": operand_token_inherent()},
    0x02: {},
    0x03: {},
    0x04: {"label": "lsrd", "token": operand_token_inherent()},
    0x05: {"label": "asld", "token": operand_token_inherent()},
    0x06: {"label": "tap", "token": operand_token_inherent()},
    0x07: {"label": "tpa", "token": operand_token_inherent()},
    0x08: {"label": "inx", "token": operand_token_inherent()},
    0x09: {"label": "dex", "token": operand_token_inherent()},
    0x0a: {"label": "clv", "token": operand_token_inherent()},
    0x0b: {"label": "sev", "token": operand_token_inherent()},
    0x0c: {"label": "clc", "token": operand_token_inherent()},
    0x0d: {"label": "sec", "token": operand_token_inherent()},
    0x0e: {"label": "cli", "token": operand_token_inherent()},
    0x0f: {"label": "sei", "token": operand_token_inherent()},
    0x10: {"label": "sba", "token": operand_token_inherent()},
    0x11: {"label": "cba", "token": operand_token_inherent()},
    0x12: {},
    0x13: {},
    0x14: {},
    0x15: {},
    0x16: {"label": "tab", "token": operand_token_inherent()},
    0x17: {"label": "tba", "token": operand_token_inherent()},
    0x18: {"label": "xgdx", "token": operand_token_inherent()},  # HD8303
    0x19: {"label": "daa", "token": operand_token_inherent()},
    0x1a: {"label": "slp", "token": operand_token_inherent()},  # HD8303
    0x1b: {"label": "aba", "token": operand_token_inherent()},
    0x1c: {},
    0x1d: {},
    0x1e: {},
    0x1f: {},
    0x20: {"label": "bra", "token": operand_token_relative()},
    0x21: {"label": "brn", "token": operand_token_relative()},
    0x22: {"label": "bhi", "token": operand_token_relative()},
    0x23: {"label": "bls", "token": operand_token_relative()},
    0x24: {"label": "bcc", "token": operand_token_relative()},
    0x25: {"label": "bcs", "token": operand_token_relative()},
    0x26: {"label": "bne", "token": operand_token_relative()},
    0x27: {"label": "beq", "token": operand_token_relative()},
    0x28: {"label": "bvc", "token": operand_token_relative()},
    0x29: {"label": "bvs", "token": operand_token_relative()},
    0x2a: {"label": "bpl", "token": operand_token_relative()},
    0x2b: {"label": "bmi", "token": operand_token_relative()},
    0x2c: {"label": "bge", "token": operand_token_relative()},
    0x2d: {"label": "blt", "token": operand_token_relative()},
    0x2e: {"label": "bgt", "token": operand_token_relative()},
    0x2f: {"label": "ble", "token": operand_token_relative()},
    0x30: {"label": "tsx", "token": operand_token_inherent()},
    0x31: {"label": "ins", "token": operand_token_inherent()},
    0x32: {"label": "pula", "token": operand_token_inherent()},
    0x33: {"label": "pulb", "token": operand_token_inherent()},
    0x34: {"label": "des", "token": operand_token_inherent()},
    0x35: {"label": "txs", "token": operand_token_inherent()},
    0x36: {"label": "psha", "token": operand_token_inherent()},
    0x37: {"label": "pshb", "token": operand_token_inherent()},
    0x38: {"label": "pulx", "token": operand_token_inherent()},
    0x39: {"label": "rts", "token": operand_token_inherent()},
    0x3a: {"label": "abx", "token": operand_token_inherent()},
    0x3b: {"label": "rti", "token": operand_token_inherent()},
    0x3c: {"label": "pshx", "token": operand_token_inherent()},
    0x3d: {"label": "mul", "token": operand_token_inherent()},
    0x3e: {"label": "wai", "token": operand_token_inherent()},
    0x3f: {"label": "swi", "token": operand_token_inherent()},
    0x40: {"label": "nega", "token": operand_token_inherent()},
    0x41: {},
    0x42: {},
    0x43: {"label": "coma", "token": operand_token_inherent()},
    0x44: {"label": "lsra", "token": operand_token_inherent()},
    0x45: {},
    0x46: {"label": "rora", "token": operand_token_inherent()},
    0x47: {"label": "asra", "token": operand_token_inherent()},
    0x48: {"label": "asla", "token": operand_token_inherent()},
    0x49: {"label": "rola", "token": operand_token_inherent()},
    0x4a: {"label": "deca", "token": operand_token_inherent()},
    0x4b: {},
    0x4c: {"label": "inca", "token": operand_token_inherent()},
    0x4d: {"label": "tsta", "token": operand_token_inherent()},
    0x4e: {},
    0x4f: {"label": "clra", "token": operand_token_inherent()},
    0x50: {"label": "negb", "token": operand_token_inherent()},
    0x51: {},
    0x52: {},
    0x53: {"label": "comb", "token": operand_token_inherent()},
    0x54: {"label": "lsrb", "token": operand_token_inherent()},
    0x55: {},
    0x56: {"label": "rorb", "token": operand_token_inherent()},
    0x57: {"label": "asrb", "token": operand_token_inherent()},
    0x58: {"label": "aslb", "token": operand_token_inherent()},
    0x59: {"label": "rolb", "token": operand_token_inherent()},
    0x5a: {"label": "decb", "token": operand_token_inherent()},
    0x5b: {},
    0x5c: {"label": "incb", "token": operand_token_inherent()},
    0x5d: {"label": "tstb", "token": operand_token_inherent()},
    0x5e: {},
    0x5f: {"label": "clrb", "token": operand_token_inherent()},
    0x60: {"label": "neg", "token": operand_token_indexed()},
    0x61: {"label": "aim", "token": operand_token_immediate_indexed()},  # HD8303
    0x62: {"label": "oim", "token": operand_token_immediate_indexed()},  # HD8303
    0x63: {"label": "com", "token": operand_token_indexed()},
    0x64: {"label": "lsr", "token": operand_token_indexed()},
    0x65: {"label": "eim", "token": operand_token_immediate_indexed()},  # HD8303
    0x66: {"label": "ror", "token": operand_token_indexed()},
    0x67: {"label": "asr", "token": operand_token_indexed()},
    0x68: {"label": "asl", "token": operand_token_immediate_indexed()},  # HD8303
    0x69: {"label": "rol", "token": operand_token_indexed()},
    0x6a: {"label": "dec", "token": operand_token_indexed()},
    0x6b: {"label": "tim", "token": operand_token_indexed()},
    0x6c: {"label": "inc", "token": operand_token_indexed()},
    0x6d: {"label": "tst", "token": operand_token_indexed()},
    0x6e: {"label": "jmp", "token": operand_token_indexed()},  # FIXME in IL and unresolved
    0x6f: {"label": "clr", "token": operand_token_indexed()},
    0x70: {"label": "neg", "token": operand_token_extended()},
    0x71: {"label": "aim", "token": operand_token_direct_memory()},  # HD8303
    0x72: {"label": "oim", "token": operand_token_direct_memory()},  # HD8303
    0x73: {"label": "com", "token": operand_token_extended()},
    0x74: {"label": "lsr", "token": operand_token_extended()},
    0x75: {"label": "eim", "token": operand_token_direct_memory()},  # HD8303
    0x76: {"label": "ror", "token": operand_token_extended()},
    0x77: {"label": "asr", "token": operand_token_extended()},
    0x78: {"label": "asl", "token": operand_token_extended()},
    0x79: {"label": "rol", "token": operand_token_extended()},
    0x7a: {"label": "dec", "token": operand_token_extended()},
    0x7b: {"label": "tim", "token": operand_token_direct_memory()},  # HD8303
    0x7c: {"label": "inc", "token": operand_token_extended()},
    0x7d: {"label": "tst", "token": operand_token_extended()},
    0x7e: {"label": "jmp", "token": operand_token_extended()},
    0x7f: {"label": "clr", "token": operand_token_extended()},
    0x80: {"label": "suba", "token": operand_token_immediate_byte()},
    0x81: {"label": "cmpa", "token": operand_token_immediate_byte()},
    0x82: {"label": "sbca", "token": operand_token_immediate_byte()},
    0x83: {"label": "subd", "token": operand_token_immediate_word()},
    0x84: {"label": "anda", "token": operand_token_immediate_byte()},
    0x85: {"label": "bita", "token": operand_token_immediate_byte()},
    0x86: {"label": "ldaa", "token": operand_token_immediate_byte()},
    0x87: {},
    0x88: {"label": "eora", "token": operand_token_immediate_byte()},
    0x89: {"label": "adca", "token": operand_token_immediate_byte()},
    0x8a: {"label": "oraa", "token": operand_token_immediate_byte()},
    0x8b: {"label": "adda", "token": operand_token_immediate_byte()},
    0x8c: {"label": "cpx", "token": operand_token_immediate_word()},
    0x8d: {"label": "bsr", "token": operand_token_relative()},
    0x8e: {"label": "lds", "token": operand_token_immediate_word()},
    0x8f: {},
    0x90: {"label": "suba", "token": operand_token_direct()},
    0x91: {"label": "cmpa", "token": operand_token_direct()},
    0x92: {"label": "sbca", "token": operand_token_direct()},
    0x93: {"label": "subd", "token": operand_token_direct()},
    0x94: {"label": "anda", "token": operand_token_direct()},
    0x95: {"label": "bita", "token": operand_token_direct()},
    0x96: {"label": "ldaa", "token": operand_token_direct()},
    0x97: {"label": "staa", "token": operand_token_direct()},
    0x98: {"label": "eora", "token": operand_token_direct()},
    0x99: {"label": "adca", "token": operand_token_direct()},
    0x9a: {"label": "oraa", "token": operand_token_direct()},
    0x9b: {"label": "adda", "token": operand_token_direct()},
    0x9c: {"label": "cpx", "token": operand_token_direct()},
    0x9d: {"label": "jsr", "token": operand_token_direct()},
    0x9e: {"label": "lds", "token": operand_token_direct()},
    0x9f: {"label": "sts", "token": operand_token_direct()},
    0xa0: {"label": "suba", "token": operand_token_indexed()},
    0xa1: {"label": "cmpa", "token": operand_token_indexed()},
    0xa2: {"label": "sbca", "token": operand_token_indexed()},
    0xa3: {"label": "subd", "token": operand_token_indexed()},
    0xa4: {"label": "anda", "token": operand_token_indexed()},
    0xa5: {"label": "bita", "token": operand_token_indexed()},
    0xa6: {"label": "ldaa", "token": operand_token_indexed()},
    0xa7: {"label": "staa", "token": operand_token_indexed()},
    0xa8: {"label": "eora", "token": operand_token_indexed()},
    0xa9: {"label": "adca", "token": operand_token_indexed()},
    0xaa: {"label": "oraa", "token": operand_token_indexed()},
    0xab: {"label": "adda", "token": operand_token_indexed()},
    0xac: {"label": "cpx", "token": operand_token_indexed()},
    0xad: {"label": "jsr", "token": operand_token_indexed()},  # FIXME in IL and unresolved
    0xae: {"label": "lds", "token": operand_token_indexed()},
    0xaf: {"label": "sts", "token": operand_token_indexed()},
    0xb0: {"label": "suba", "token": operand_token_extended()},
    0xb1: {"label": "cmpa", "token": operand_token_extended()},
    0xb2: {"label": "sbca", "token": operand_token_extended()},
    0xb3: {"label": "subd", "token": operand_token_extended()},
    0xb4: {"label": "anda", "token": operand_token_extended()},
    0xb5: {"label": "bita", "token": operand_token_extended()},
    0xb6: {"label": "ldaa", "token": operand_token_extended()},
    0xb7: {"label": "staa", "token": operand_token_extended()},
    0xb8: {"label": "eora", "token": operand_token_extended()},
    0xb9: {"label": "adca", "token": operand_token_extended()},
    0xba: {"label": "oraa", "token": operand_token_extended()},
    0xbb: {"label": "adda", "token": operand_token_extended()},
    0xbc: {"label": "cpx", "token": operand_token_extended()},
    0xbd: {"label": "jsr", "token": operand_token_extended()},
    0xbe: {"label": "lds", "token": operand_token_extended()},
    0xbf: {"label": "sts", "token": operand_token_extended()},
    0xc0: {"label": "subb", "token": operand_token_immediate_byte()},
    0xc1: {"label": "cmpb", "token": operand_token_immediate_byte()},
    0xc2: {"label": "sbcb", "token": operand_token_immediate_byte()},
    0xc3: {"label": "addd", "token": operand_token_immediate_word()},
    0xc4: {"label": "andb", "token": operand_token_immediate_byte()},
    0xc5: {"label": "bitb", "token": operand_token_immediate_byte()},
    0xc6: {"label": "ldab", "token": operand_token_immediate_byte()},
    0xc7: {},
    0xc8: {"label": "eorb", "token": operand_token_immediate_byte()},
    0xc9: {"label": "adcb", "token": operand_token_immediate_byte()},
    0xca: {"label": "orab", "token": operand_token_immediate_byte()},
    0xcb: {"label": "addb", "token": operand_token_immediate_byte()},
    0xcc: {"label": "ldd", "token": operand_token_immediate_word()},
    0xcd: {},
    0xce: {"label": "ldx", "token": operand_token_immediate_word()},
    0xcf: {},
    0xd0: {"label": "subb", "token": operand_token_direct()},
    0xd1: {"label": "cmpb", "token": operand_token_direct()},
    0xd2: {"label": "sbcb", "token": operand_token_direct()},
    0xd3: {"label": "addd", "token": operand_token_direct()},
    0xd4: {"label": "andb", "token": operand_token_direct()},
    0xd5: {"label": "bitb", "token": operand_token_direct()},
    0xd6: {"label": "ldab", "token": operand_token_direct()},
    0xd7: {"label": "stab", "token": operand_token_direct()},
    0xd8: {"label": "eorb", "token": operand_token_direct()},
    0xd9: {"label": "adcb", "token": operand_token_direct()},
    0xda: {"label": "orab", "token": operand_token_direct()},
    0xdb: {"label": "addb", "token": operand_token_direct()},
    0xdc: {"label": "ldd", "token": operand_token_direct()},
    0xdd: {"label": "std", "token": operand_token_direct()},
    0xde: {"label": "ldx", "token": operand_token_direct()},
    0xdf: {"label": "stx", "token": operand_token_direct()},
    0xe0: {"label": "subb", "token": operand_token_indexed()},
    0xe1: {"label": "cmpb", "token": operand_token_indexed()},
    0xe2: {"label": "sbcb", "token": operand_token_indexed()},
    0xe3: {"label": "addd", "token": operand_token_indexed()},
    0xe4: {"label": "andb", "token": operand_token_indexed()},
    0xe5: {"label": "bitb", "token": operand_token_indexed()},
    0xe6: {"label": "ldab", "token": operand_token_indexed()},
    0xe7: {"label": "stab", "token": operand_token_indexed()},
    0xe8: {"label": "eorb", "token": operand_token_indexed()},
    0xe9: {"label": "adcb", "token": operand_token_indexed()},
    0xea: {"label": "orab", "token": operand_token_indexed()},
    0xeb: {"label": "addb", "token": operand_token_indexed()},
    0xec: {"label": "ldd", "token": operand_token_indexed()},
    0xed: {"label": "std", "token": operand_token_indexed()},
    0xee: {"label": "ldx", "token": operand_token_indexed()},
    0xef: {"label": "stx", "token": operand_token_indexed()},
    0xf0: {"label": "subb", "token": operand_token_extended()},
    0xf1: {"label": "cmpb", "token": operand_token_extended()},
    0xf2: {"label": "sbcb", "token": operand_token_extended()},
    0xf3: {"label": "addd", "token": operand_token_extended()},
    0xf4: {"label": "andb", "token": operand_token_extended()},
    0xf5: {"label": "bitb", "token": operand_token_extended()},
    0xf6: {"label": "ldab", "token": operand_token_extended()},
    0xf7: {"label": "stab", "token": operand_token_extended()},
    0xf8: {"label": "eorb", "token": operand_token_extended()},
    0xf9: {"label": "adcb", "token": operand_token_extended()},
    0xfa: {"label": "orab", "token": operand_token_extended()},
    0xfb: {"label": "addb", "token": operand_token_extended()},
    0xfc: {"label": "ldd", "token": operand_token_extended()},
    0xfd: {"label": "std", "token": operand_token_extended()},
    0xfe: {"label": "ldx", "token": operand_token_extended()},
    0xff: {"label": "stx", "token": operand_token_extended()},
}
branching_instructions = [
    "bra", "brn", "bhi", "bls",
    "bcc", "bcs", "bne", "beq",
    "bvc", "bvs", "bpl", "bmi",
    "bge", "blt", "bgt", "ble",
    "bsr",
]


def word_as_ord(word):
    return struct.unpack(">H", word)[0]


def parse_instruction(data: any, address: any) -> Tuple[str, int, Optional[int], OperandFunction]:
    log_debug("Parsing opcode: %.2x" % data[0])

    instruction = instructions.get(data[0], None)
    if not instruction:
        instruction = {
            "label": "???",
            "token": operand_token_none(),
        }
    else:
        log_debug("Instruction Found: %s" % instruction["label"])

    label = instruction["label"]
    length = instruction["token"][0]
    operand = instruction["token"][1]

    value = None
    if length == 1:
        value = ord(data[1:2])
    elif length == 2:
        value = word_as_ord(data[1:length + 1])

    # TODO: consider moving destination address here for branches etc.
    return label, length, value, operand


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

    def convert_to_nop(self, data, address):
        return b"\x01" * len(data)

    def get_instruction_info(self, data: bytes, address: int):
        label, length, value, _ = parse_instruction(data, address)

        if label == "???":
            return None

        result = InstructionInfo()
        result.length = 1 + length

        if label in branching_instructions:
            relative = struct.unpack("b", data[1:2])[0]

            # Does branching wrap at EOM/BOM? would anyone put branches there anyway?
            destination = (address + relative + 2) & 0xffff

            log_debug("Branch '%s' destination $%.4x" % (label, destination))
            result.add_branch(BranchType.TrueBranch, destination)
            result.add_branch(BranchType.FalseBranch, address + result.length)
        elif label == "jsr":
            result.add_branch(BranchType.CallDestination, value)
        elif label == "jmp":
            result.add_branch(BranchType.UnconditionalBranch, value)

        return result

    def get_instruction_text(self, data, address) -> [[any], int]:
        label, length, value, operand = parse_instruction(data, address)

        if label == "???":
            return None

        if value is not None:
            log_debug("Value: %.4x" % value)

        tokens = [text_opcode(label)]
        if value is not None:
            tokens += operand(value)

        return tokens, 1 + length

    # Keeps log output quiet
    def get_instruction_low_level_il(self, data, address, il):
        label, length, value, operand = parse_instruction(data, address)

        return 1 + length

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
