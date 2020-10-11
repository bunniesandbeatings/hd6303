import struct

from binaryninja.log import log_error, log_debug

from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import (BranchType, InstructionTextTokenType,
                               FlagRole, SymbolType,
                               Endianness, LowLevelILFlagCondition)
from typing import (Callable, Tuple, Optional)
from enum import Enum, auto

Tokenizer = Callable[[int], any]  # FIXME: can we build a Token base type?


# def il_operand_none():
#     pass
#
#
# def il_operand_extend(il, value):
#     il.load(1, il.const_pointer(2, value))
#

class AddressingMode(Enum):
    NONE = auto()
    INHERENT = auto()  # opc
    EXTENDED = auto()  # opc $10FF
    IMMEDIATE_WORD = auto()  # opc #$10FF
    IMMEDIATE_BYTE = auto()  # opc #$FF
    IMMEDIATE_INDEXED = auto()  # opc #$FF,$33,x    [ see AIM, OIM, EIM, TIM opcodes ]
    INDEXED = auto()  # opc #$FF,x
    RELATIVE = auto()  # opc $<xx>         where $<xx> is within a signed byte of the current PC
    DIRECT = auto()  # opc $CA           Zero Page
    DIRECT_MEMORY = auto()  # opc #$FF,$33      Zero Page [ see AIM, OIM, EIM, TIM opcodes ]


operand_detail = dict()

operand_detail[AddressingMode.NONE] = [0, lambda: []]
operand_detail[AddressingMode.INHERENT] = [0, lambda: []]
operand_detail[AddressingMode.EXTENDED] = [
    2,
    lambda operand: [
        InstructionTextToken(
            InstructionTextTokenType.PossibleAddressToken,
            "$%.4x" % operand,
            operand
        )
    ]
]

operand_detail[AddressingMode.IMMEDIATE_WORD] = [
    2,
    lambda operand: [
        InstructionTextToken(InstructionTextTokenType.TextToken, "#"),
        InstructionTextToken(
            InstructionTextTokenType.IntegerToken,
            "$%.4x" % operand,
            operand
        )
    ]
]
operand_detail[AddressingMode.IMMEDIATE_BYTE] = [
    1,
    lambda operand: [
        InstructionTextToken(InstructionTextTokenType.TextToken, "#"),
        InstructionTextToken(
            InstructionTextTokenType.IntegerToken,
            "$%.2x" % operand,
            operand
        )
    ]
]

operand_detail[AddressingMode.IMMEDIATE_INDEXED] = [
    2,
    lambda operand: [
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
]

operand_detail[AddressingMode.INDEXED] = [
    1,
    lambda operand: [
        InstructionTextToken(
            InstructionTextTokenType.PossibleAddressToken,
            "$%.2x" % operand,
            operand
        ),
        InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, "x")
    ]

]

operand_detail[AddressingMode.RELATIVE] = [
    1, lambda operand: [
        InstructionTextToken(
            InstructionTextTokenType.PossibleAddressToken,
            "$%.2x" % operand,
            operand
        )
    ]
]

operand_detail[AddressingMode.DIRECT] = operand_detail[AddressingMode.RELATIVE]

operand_detail[AddressingMode.DIRECT_MEMORY] = [
    2,
    lambda operand: [
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
]


def get_operand(mode: AddressingMode):
    return operand_detail[mode]


il_operand_detail = dict()
il_operand_detail[AddressingMode.NONE] = lambda il, value: None
il_operand_detail[AddressingMode.INHERENT] = lambda il, value: None
il_operand_detail[AddressingMode.EXTENDED] = lambda il, value: il.const_pointer(2, value)
il_operand_detail[AddressingMode.IMMEDIATE_BYTE] = lambda il, value: il.const(1, value)
il_operand_detail[AddressingMode.IMMEDIATE_WORD] = lambda il, value: il.const(2, value)


# il_operand_detail[AddressingMode.IMMEDIATE_INDEXED] = lambda il, value: il.const_pointer(2, value)


def get_il_operand(mode: AddressingMode):
    return il_operand_detail.get(mode, None)


il_instructions = {
    "ldaa": lambda il, operand, mode: il.set_reg(1, "a", operand, flags="nzv"),
    "ldab": lambda il, operand, mode: il.set_reg(1, "b", operand, flags="nzv"),
    "tpa": lambda il, operand, mode: il.set_reg(2, "a", il.reg(2, "ccr")),
    "tap": lambda il, operand, mode: il.set_reg(2, "ccr", il.reg(2, "a")),
    # "sei": lambda il, operand, mode: il.set_flag("i", il.const(0, 1)),
    # "jsr": lambda il, operand: il.call(operand),
    # "rts": lambda il, operand: il.ret(il.add(2, il.pop(2), il.const(2, 1))), # FIXME
}


def get_il_instruction(instruction: str):
    return il_instructions.get(instruction, None)


instructions = {
    0x00: {},
    0x01: {"label": "nop", "mode": AddressingMode.INHERENT},
    0x02: {},
    0x03: {},
    0x04: {"label": "lsrd", "mode": AddressingMode.INHERENT},
    0x05: {"label": "asld", "mode": AddressingMode.INHERENT},
    0x06: {"label": "tap", "mode": AddressingMode.INHERENT},
    0x07: {"label": "tpa", "mode": AddressingMode.INHERENT},
    0x08: {"label": "inx", "mode": AddressingMode.INHERENT},
    0x09: {"label": "dex", "mode": AddressingMode.INHERENT},
    0x0a: {"label": "clv", "mode": AddressingMode.INHERENT},
    0x0b: {"label": "sev", "mode": AddressingMode.INHERENT},
    0x0c: {"label": "clc", "mode": AddressingMode.INHERENT},
    0x0d: {"label": "sec", "mode": AddressingMode.INHERENT},
    0x0e: {"label": "cli", "mode": AddressingMode.INHERENT},
    0x0f: {"label": "sei", "mode": AddressingMode.INHERENT},
    0x10: {"label": "sba", "mode": AddressingMode.INHERENT},
    0x11: {"label": "cba", "mode": AddressingMode.INHERENT},
    0x12: {},
    0x13: {},
    0x14: {},
    0x15: {},
    0x16: {"label": "tab", "mode": AddressingMode.INHERENT},
    0x17: {"label": "tba", "mode": AddressingMode.INHERENT},
    0x18: {"label": "xgdx", "mode": AddressingMode.INHERENT},  # HD8303
    0x19: {"label": "daa", "mode": AddressingMode.INHERENT},
    0x1a: {"label": "slp", "mode": AddressingMode.INHERENT},  # HD8303
    0x1b: {"label": "aba", "mode": AddressingMode.INHERENT},
    0x1c: {},
    0x1d: {},
    0x1e: {},
    0x1f: {},
    0x20: {"label": "bra", "mode": AddressingMode.RELATIVE},
    0x21: {"label": "brn", "mode": AddressingMode.RELATIVE},
    0x22: {"label": "bhi", "mode": AddressingMode.RELATIVE},
    0x23: {"label": "bls", "mode": AddressingMode.RELATIVE},
    0x24: {"label": "bcc", "mode": AddressingMode.RELATIVE},
    0x25: {"label": "bcs", "mode": AddressingMode.RELATIVE},
    0x26: {"label": "bne", "mode": AddressingMode.RELATIVE},
    0x27: {"label": "beq", "mode": AddressingMode.RELATIVE},
    0x28: {"label": "bvc", "mode": AddressingMode.RELATIVE},
    0x29: {"label": "bvs", "mode": AddressingMode.RELATIVE},
    0x2a: {"label": "bpl", "mode": AddressingMode.RELATIVE},
    0x2b: {"label": "bmi", "mode": AddressingMode.RELATIVE},
    0x2c: {"label": "bge", "mode": AddressingMode.RELATIVE},
    0x2d: {"label": "blt", "mode": AddressingMode.RELATIVE},
    0x2e: {"label": "bgt", "mode": AddressingMode.RELATIVE},
    0x2f: {"label": "ble", "mode": AddressingMode.RELATIVE},
    0x30: {"label": "tsx", "mode": AddressingMode.INHERENT},
    0x31: {"label": "ins", "mode": AddressingMode.INHERENT},
    0x32: {"label": "pula", "mode": AddressingMode.INHERENT},
    0x33: {"label": "pulb", "mode": AddressingMode.INHERENT},
    0x34: {"label": "des", "mode": AddressingMode.INHERENT},
    0x35: {"label": "txs", "mode": AddressingMode.INHERENT},
    0x36: {"label": "psha", "mode": AddressingMode.INHERENT},
    0x37: {"label": "pshb", "mode": AddressingMode.INHERENT},
    0x38: {"label": "pulx", "mode": AddressingMode.INHERENT},
    0x39: {"label": "rts", "mode": AddressingMode.INHERENT},
    0x3a: {"label": "abx", "mode": AddressingMode.INHERENT},
    0x3b: {"label": "rti", "mode": AddressingMode.INHERENT},
    0x3c: {"label": "pshx", "mode": AddressingMode.INHERENT},
    0x3d: {"label": "mul", "mode": AddressingMode.INHERENT},
    0x3e: {"label": "wai", "mode": AddressingMode.INHERENT},
    0x3f: {"label": "swi", "mode": AddressingMode.INHERENT},
    0x40: {"label": "nega", "mode": AddressingMode.INHERENT},
    0x41: {},
    0x42: {},
    0x43: {"label": "coma", "mode": AddressingMode.INHERENT},
    0x44: {"label": "lsra", "mode": AddressingMode.INHERENT},
    0x45: {},
    0x46: {"label": "rora", "mode": AddressingMode.INHERENT},
    0x47: {"label": "asra", "mode": AddressingMode.INHERENT},
    0x48: {"label": "asla", "mode": AddressingMode.INHERENT},
    0x49: {"label": "rola", "mode": AddressingMode.INHERENT},
    0x4a: {"label": "deca", "mode": AddressingMode.INHERENT},
    0x4b: {},
    0x4c: {"label": "inca", "mode": AddressingMode.INHERENT},
    0x4d: {"label": "tsta", "mode": AddressingMode.INHERENT},
    0x4e: {},
    0x4f: {"label": "clra", "mode": AddressingMode.INHERENT},
    0x50: {"label": "negb", "mode": AddressingMode.INHERENT},
    0x51: {},
    0x52: {},
    0x53: {"label": "comb", "mode": AddressingMode.INHERENT},
    0x54: {"label": "lsrb", "mode": AddressingMode.INHERENT},
    0x55: {},
    0x56: {"label": "rorb", "mode": AddressingMode.INHERENT},
    0x57: {"label": "asrb", "mode": AddressingMode.INHERENT},
    0x58: {"label": "aslb", "mode": AddressingMode.INHERENT},
    0x59: {"label": "rolb", "mode": AddressingMode.INHERENT},
    0x5a: {"label": "decb", "mode": AddressingMode.INHERENT},
    0x5b: {},
    0x5c: {"label": "incb", "mode": AddressingMode.INHERENT},
    0x5d: {"label": "tstb", "mode": AddressingMode.INHERENT},
    0x5e: {},
    0x5f: {"label": "clrb", "mode": AddressingMode.INHERENT},
    0x60: {"label": "neg", "mode": AddressingMode.INDEXED},
    0x61: {"label": "aim", "mode": AddressingMode.IMMEDIATE_INDEXED},  # HD8303
    0x62: {"label": "oim", "mode": AddressingMode.IMMEDIATE_INDEXED},  # HD8303
    0x63: {"label": "com", "mode": AddressingMode.INDEXED},
    0x64: {"label": "lsr", "mode": AddressingMode.INDEXED},
    0x65: {"label": "eim", "mode": AddressingMode.IMMEDIATE_INDEXED},  # HD8303
    0x66: {"label": "ror", "mode": AddressingMode.INDEXED},
    0x67: {"label": "asr", "mode": AddressingMode.INDEXED},
    0x68: {"label": "asl", "mode": AddressingMode.INDEXED},
    0x69: {"label": "rol", "mode": AddressingMode.INDEXED},
    0x6a: {"label": "dec", "mode": AddressingMode.INDEXED},
    0x6b: {"label": "tim", "mode": AddressingMode.IMMEDIATE_INDEXED},  # HD8303
    0x6c: {"label": "inc", "mode": AddressingMode.INDEXED},
    0x6d: {"label": "tst", "mode": AddressingMode.INDEXED},
    0x6e: {"label": "jmp", "mode": AddressingMode.INDEXED},  # FIXME in IL
    0x6f: {"label": "clr", "mode": AddressingMode.INDEXED},
    0x70: {"label": "neg", "mode": AddressingMode.EXTENDED},
    0x71: {"label": "aim", "mode": AddressingMode.DIRECT_MEMORY},  # HD8303
    0x72: {"label": "oim", "mode": AddressingMode.DIRECT_MEMORY},  # HD8303
    0x73: {"label": "com", "mode": AddressingMode.EXTENDED},
    0x74: {"label": "lsr", "mode": AddressingMode.EXTENDED},
    0x75: {"label": "eim", "mode": AddressingMode.DIRECT_MEMORY},  # HD8303
    0x76: {"label": "ror", "mode": AddressingMode.EXTENDED},
    0x77: {"label": "asr", "mode": AddressingMode.EXTENDED},
    0x78: {"label": "asl", "mode": AddressingMode.EXTENDED},
    0x79: {"label": "rol", "mode": AddressingMode.EXTENDED},
    0x7a: {"label": "dec", "mode": AddressingMode.EXTENDED},
    0x7b: {"label": "tim", "mode": AddressingMode.DIRECT_MEMORY},  # HD8303
    0x7c: {"label": "inc", "mode": AddressingMode.EXTENDED},
    0x7d: {"label": "tst", "mode": AddressingMode.EXTENDED},
    0x7e: {"label": "jmp", "mode": AddressingMode.EXTENDED},
    0x7f: {"label": "clr", "mode": AddressingMode.EXTENDED},
    0x80: {"label": "suba", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x81: {"label": "cmpa", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x82: {"label": "sbca", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x83: {"label": "subd", "mode": AddressingMode.IMMEDIATE_WORD},
    0x84: {"label": "anda", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x85: {"label": "bita", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x86: {"label": "ldaa", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x87: {},
    0x88: {"label": "eora", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x89: {"label": "adca", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x8a: {"label": "oraa", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x8b: {"label": "adda", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x8c: {"label": "cpx", "mode": AddressingMode.IMMEDIATE_WORD},
    0x8d: {"label": "bsr", "mode": AddressingMode.RELATIVE},
    0x8e: {"label": "lds", "mode": AddressingMode.IMMEDIATE_WORD},
    0x8f: {},
    0x90: {"label": "suba", "mode": AddressingMode.DIRECT},
    0x91: {"label": "cmpa", "mode": AddressingMode.DIRECT},
    0x92: {"label": "sbca", "mode": AddressingMode.DIRECT},
    0x93: {"label": "subd", "mode": AddressingMode.DIRECT},
    0x94: {"label": "anda", "mode": AddressingMode.DIRECT},
    0x95: {"label": "bita", "mode": AddressingMode.DIRECT},
    0x96: {"label": "ldaa", "mode": AddressingMode.DIRECT},
    0x97: {"label": "staa", "mode": AddressingMode.DIRECT},
    0x98: {"label": "eora", "mode": AddressingMode.DIRECT},
    0x99: {"label": "adca", "mode": AddressingMode.DIRECT},
    0x9a: {"label": "oraa", "mode": AddressingMode.DIRECT},
    0x9b: {"label": "adda", "mode": AddressingMode.DIRECT},
    0x9c: {"label": "cpx", "mode": AddressingMode.DIRECT},
    0x9d: {"label": "jsr", "mode": AddressingMode.DIRECT},
    0x9e: {"label": "lds", "mode": AddressingMode.DIRECT},
    0x9f: {"label": "sts", "mode": AddressingMode.DIRECT},
    0xa0: {"label": "suba", "mode": AddressingMode.INDEXED},
    0xa1: {"label": "cmpa", "mode": AddressingMode.INDEXED},
    0xa2: {"label": "sbca", "mode": AddressingMode.INDEXED},
    0xa3: {"label": "subd", "mode": AddressingMode.INDEXED},
    0xa4: {"label": "anda", "mode": AddressingMode.INDEXED},
    0xa5: {"label": "bita", "mode": AddressingMode.INDEXED},
    0xa6: {"label": "ldaa", "mode": AddressingMode.INDEXED},
    0xa7: {"label": "staa", "mode": AddressingMode.INDEXED},
    0xa8: {"label": "eora", "mode": AddressingMode.INDEXED},
    0xa9: {"label": "adca", "mode": AddressingMode.INDEXED},
    0xaa: {"label": "oraa", "mode": AddressingMode.INDEXED},
    0xab: {"label": "adda", "mode": AddressingMode.INDEXED},
    0xac: {"label": "cpx", "mode": AddressingMode.INDEXED},
    0xad: {"label": "jsr", "mode": AddressingMode.INDEXED},  # FIXME in IL
    0xae: {"label": "lds", "mode": AddressingMode.INDEXED},
    0xaf: {"label": "sts", "mode": AddressingMode.INDEXED},
    0xb0: {"label": "suba", "mode": AddressingMode.EXTENDED},
    0xb1: {"label": "cmpa", "mode": AddressingMode.EXTENDED},
    0xb2: {"label": "sbca", "mode": AddressingMode.EXTENDED},
    0xb3: {"label": "subd", "mode": AddressingMode.EXTENDED},
    0xb4: {"label": "anda", "mode": AddressingMode.EXTENDED},
    0xb5: {"label": "bita", "mode": AddressingMode.EXTENDED},
    0xb6: {"label": "ldaa", "mode": AddressingMode.EXTENDED},
    0xb7: {"label": "staa", "mode": AddressingMode.EXTENDED},
    0xb8: {"label": "eora", "mode": AddressingMode.EXTENDED},
    0xb9: {"label": "adca", "mode": AddressingMode.EXTENDED},
    0xba: {"label": "oraa", "mode": AddressingMode.EXTENDED},
    0xbb: {"label": "adda", "mode": AddressingMode.EXTENDED},
    0xbc: {"label": "cpx", "mode": AddressingMode.EXTENDED},
    0xbd: {"label": "jsr", "mode": AddressingMode.EXTENDED},
    0xbe: {"label": "lds", "mode": AddressingMode.EXTENDED},
    0xbf: {"label": "sts", "mode": AddressingMode.EXTENDED},
    0xc0: {"label": "subb", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xc1: {"label": "cmpb", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xc2: {"label": "sbcb", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xc3: {"label": "addd", "mode": AddressingMode.IMMEDIATE_WORD},
    0xc4: {"label": "andb", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xc5: {"label": "bitb", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xc6: {"label": "ldab", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xc7: {},
    0xc8: {"label": "eorb", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xc9: {"label": "adcb", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xca: {"label": "orab", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xcb: {"label": "addb", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xcc: {"label": "ldd", "mode": AddressingMode.IMMEDIATE_WORD},
    0xcd: {},
    0xce: {"label": "ldx", "mode": AddressingMode.IMMEDIATE_WORD},
    0xcf: {},
    0xd0: {"label": "subb", "mode": AddressingMode.DIRECT},
    0xd1: {"label": "cmpb", "mode": AddressingMode.DIRECT},
    0xd2: {"label": "sbcb", "mode": AddressingMode.DIRECT},
    0xd3: {"label": "addd", "mode": AddressingMode.DIRECT},
    0xd4: {"label": "andb", "mode": AddressingMode.DIRECT},
    0xd5: {"label": "bitb", "mode": AddressingMode.DIRECT},
    0xd6: {"label": "ldab", "mode": AddressingMode.DIRECT},
    0xd7: {"label": "stab", "mode": AddressingMode.DIRECT},
    0xd8: {"label": "eorb", "mode": AddressingMode.DIRECT},
    0xd9: {"label": "adcb", "mode": AddressingMode.DIRECT},
    0xda: {"label": "orab", "mode": AddressingMode.DIRECT},
    0xdb: {"label": "addb", "mode": AddressingMode.DIRECT},
    0xdc: {"label": "ldd", "mode": AddressingMode.DIRECT},
    0xdd: {"label": "std", "mode": AddressingMode.DIRECT},
    0xde: {"label": "ldx", "mode": AddressingMode.DIRECT},
    0xdf: {"label": "stx", "mode": AddressingMode.DIRECT},
    0xe0: {"label": "subb", "mode": AddressingMode.INDEXED},
    0xe1: {"label": "cmpb", "mode": AddressingMode.INDEXED},
    0xe2: {"label": "sbcb", "mode": AddressingMode.INDEXED},
    0xe3: {"label": "addd", "mode": AddressingMode.INDEXED},
    0xe4: {"label": "andb", "mode": AddressingMode.INDEXED},
    0xe5: {"label": "bitb", "mode": AddressingMode.INDEXED},
    0xe6: {"label": "ldab", "mode": AddressingMode.INDEXED},
    0xe7: {"label": "stab", "mode": AddressingMode.INDEXED},
    0xe8: {"label": "eorb", "mode": AddressingMode.INDEXED},
    0xe9: {"label": "adcb", "mode": AddressingMode.INDEXED},
    0xea: {"label": "orab", "mode": AddressingMode.INDEXED},
    0xeb: {"label": "addb", "mode": AddressingMode.INDEXED},
    0xec: {"label": "ldd", "mode": AddressingMode.INDEXED},
    0xed: {"label": "std", "mode": AddressingMode.INDEXED},
    0xee: {"label": "ldx", "mode": AddressingMode.INDEXED},
    0xef: {"label": "stx", "mode": AddressingMode.INDEXED},
    0xf0: {"label": "subb", "mode": AddressingMode.EXTENDED},
    0xf1: {"label": "cmpb", "mode": AddressingMode.EXTENDED},
    0xf2: {"label": "sbcb", "mode": AddressingMode.EXTENDED},
    0xf3: {"label": "addd", "mode": AddressingMode.EXTENDED},
    0xf4: {"label": "andb", "mode": AddressingMode.EXTENDED},
    0xf5: {"label": "bitb", "mode": AddressingMode.EXTENDED},
    0xf6: {"label": "ldab", "mode": AddressingMode.EXTENDED},
    0xf7: {"label": "stab", "mode": AddressingMode.EXTENDED},
    0xf8: {"label": "eorb", "mode": AddressingMode.EXTENDED},
    0xf9: {"label": "adcb", "mode": AddressingMode.EXTENDED},
    0xfa: {"label": "orab", "mode": AddressingMode.EXTENDED},
    0xfb: {"label": "addb", "mode": AddressingMode.EXTENDED},
    0xfc: {"label": "ldd", "mode": AddressingMode.EXTENDED},
    0xfd: {"label": "std", "mode": AddressingMode.EXTENDED},
    0xfe: {"label": "ldx", "mode": AddressingMode.EXTENDED},
    0xff: {"label": "stx", "mode": AddressingMode.EXTENDED},
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


def parse_instruction(data: any) -> Tuple[Optional[str], int, Optional[int], Optional[Tokenizer], AddressingMode]:
    instruction = instructions.get(data[0], None)

    if not instruction:
        return None, 1, None, None, AddressingMode.NONE

    label = instruction["label"]
    mode = instruction["mode"]
    length, tokenizer = get_operand(mode)

    operand_value = None
    if length == 1:
        operand_value = ord(data[1:2])
    elif length == 2:
        operand_value = word_as_ord(data[1:length + 1])

    # TODO: consider moving destination address here for branches etc.
    return label, length, operand_value, tokenizer, mode


def opcode_token(label):
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
        'd': RegisterInfo('d', 2),
        'a': RegisterInfo('d', 1, 0),
        'b': RegisterInfo('d', 1, 1),

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
        label, length, operand_value, _, mode = parse_instruction(data)

        if label is None:
            return None

        result = InstructionInfo()
        result.length = 1 + length

        if label in branching_instructions:  # Always Relative Addressing Mode
            relative = struct.unpack("b", data[1:2])[0]
            # Does branching wrap at EOM/BOM? would anyone put branches there anyway?
            destination = (address + relative + 2) & 0xffff

            result.add_branch(BranchType.TrueBranch, destination)
            result.add_branch(BranchType.FalseBranch, address + result.length)

        elif label == "jsr":
            if mode == AddressingMode.EXTENDED:
                result.add_branch(BranchType.CallDestination, operand_value)
            else:
                result.add_branch(BranchType.UnresolvedBranch)

        elif label == "jmp":
            if mode == AddressingMode.EXTENDED:
                result.add_branch(BranchType.UnconditionalBranch, operand_value)
            else:
                result.add_branch(BranchType.UnresolvedBranch)

        elif label in ["rts", "rti"]:
            result.add_branch(BranchType.FunctionReturn)

        return result

    def get_instruction_text(self, data, address) -> [[any], int]:
        label, length, operand_value, tokenizer, _ = parse_instruction(data)

        if label is None:
            return None

        tokens = [opcode_token(label)]
        if operand_value is not None:
            tokens += tokenizer(operand_value)

        return tokens, 1 + length

    def get_instruction_low_level_il(self, data, address, il):
        label, operand_length, operand_value, tokenizer, mode = parse_instruction(data)

        length = operand_length+1
        il_operand_fn = get_il_operand(mode)

        # FIXME: remove after full impl.
        if il_operand_fn is None:
            log_debug("Operand: '%s' not implemented" % mode)
            return length

        log_debug("Operand: '%s'" % mode)

        il_operand = il_operand_fn(il, operand_value)

        il_instruction_fn = get_il_instruction(label)
        # FIXME: remove after full impl.
        if il_instruction_fn is None:
            log_debug("Instr: '%s' not implemented" % label)
            il.append(il.nop())
            return length

        log_debug("Instr: '%s'" % label)
        il_instruction = il_instruction_fn(il, il_operand, mode)

        if isinstance(il_instruction, list):
            for i in il_instruction:
                il.append(i)
        elif il_instruction is not None:
            il.append(il_instruction)

        return length

    # def get_instruction_low_level_il(self, data, address, il):
    #     label, length, operand_value, tokenizer, mode = parse_instruction(data)
    #
    #     return length + 1


    flags_required_for_flag_condition = {
        LowLevelILFlagCondition.LLFC_NEG: ["n"],
        LowLevelILFlagCondition.LLFC_POS: ["n"],
        LowLevelILFlagCondition.LLFC_O: ["v"],
        LowLevelILFlagCondition.LLFC_NO: ["v"],
        LowLevelILFlagCondition.LLFC_E: ["z"],
        LowLevelILFlagCondition.LLFC_NE: ["z"],
        LowLevelILFlagCondition.LLFC_ULT: ["n", "v"],
        LowLevelILFlagCondition.LLFC_ULE: ["z", "n", "v"],
        LowLevelILFlagCondition.LLFC_UGE: ["v", "n"],
        LowLevelILFlagCondition.LLFC_UGT: ["z", "n", "v"],
    }
