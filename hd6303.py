import struct

from binaryninja.log import log_error, log_debug
from binaryninja.types import Type
from binaryninja import IntrinsicInfo, Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import (
    BranchType, InstructionTextTokenType,
    FlagRole, SymbolType,
    Endianness, LowLevelILFlagCondition, LowLevelILOperation)
from binaryninja.lowlevelil import LowLevelILFunction, LowLevelILLabel, LLIL_TEMP

from typing import (Callable, Tuple, Optional)
from enum import Enum, auto

ARCHITECTURE_STRING = 'HD6303'

try:
    import os
    if os.environ['PYDEV_ENV'] == "development":
        import pydevd_pycharm
        pydevd_pycharm.settrace('localhost', port=33333, stdoutToServer=True, stderrToServer=True, suspend=False)
except:
    pass

Tokenizer = Callable[[int], any]  # FIXME: can we build a Token base type?


class AddressingMode(Enum):
    NONE = auto()
    INHERENT = auto()  # opc
    EXTENDED = auto()  # opc $10FF
    IMMEDIATE_WORD = auto()  # opc #$10FF
    IMMEDIATE_BYTE = auto()  # opc #$FF
    INDEXED = auto()  # opc #$FF,x
    RELATIVE = auto()  # opc $<xx>         where $<xx> is within a signed byte of the current PC
    DIRECT = auto()  # opc $CA           Zero Page
    DIRECT_IMMEDIATE = auto()  # opc #$FF,$33      Zero Page [ see AIM, OIM, EIM, TIM opcodes ]
    INDEXED_IMMEDIATE = auto()  # opc #$FF,$33,x    [ see AIM, OIM, EIM, TIM opcodes ]


ILInstructionGenerator = Callable[[LowLevelILFunction, any, AddressingMode], any]

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

operand_detail[AddressingMode.INDEXED_IMMEDIATE] = [
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
    1,
    lambda operand: [
        InstructionTextToken(
            InstructionTextTokenType.PossibleAddressToken,
            "$%.2x" % operand,
            operand
        )
    ]
]

operand_detail[AddressingMode.DIRECT] = [
    1,
    lambda operand: [
        InstructionTextToken(
            InstructionTextTokenType.PossibleAddressToken,
            "$%.2x" % operand,
            operand
        )
    ]
]

operand_detail[AddressingMode.DIRECT_IMMEDIATE] = [
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
il_operand_detail[AddressingMode.DIRECT] = lambda il, value: il.const_pointer(1, value)
il_operand_detail[AddressingMode.IMMEDIATE_BYTE] = lambda il, value: il.const(1, value)
il_operand_detail[AddressingMode.IMMEDIATE_WORD] = lambda il, value: il.const(2, value)
il_operand_detail[AddressingMode.INDEXED] = lambda il, value: il.load(2, il.add(2, il.const(1, value), il.reg(2, "x")))
il_operand_detail[AddressingMode.RELATIVE] = lambda il, value: il.const_pointer(2, value)
il_operand_detail[AddressingMode.DIRECT_IMMEDIATE] = lambda il, value: [
    il.const(1, value >> 8),
    il.const_pointer(1, value & 0xff)
]
il_operand_detail[AddressingMode.INDEXED_IMMEDIATE] = lambda il, value: [
    il.const(1, value >> 8),
    il.load(2, il.add(2, il.const(1, value & 0xff), il.reg(2, "x")))
]


def get_il_operand(mode: AddressingMode):
    return il_operand_detail.get(mode, None)


def cond_branch(il, condition, dest):
    true_branch = None

    if il[dest].operation == LowLevelILOperation.LLIL_CONST:
        true_branch = il.get_label_for_address(Architecture[ARCHITECTURE_STRING], il[dest].constant)

    if true_branch is None:
        true_branch = LowLevelILLabel()
        indirect = True
    else:
        indirect = False

    false_branch = LowLevelILLabel()

    il.append(il.if_expr(condition, true_branch, false_branch))

    if indirect:
        il.mark_label(true_branch)
        il.append(il.jump(dest))

    il.mark_label(false_branch)


def jump(il, operand):
    label = None
    if il[operand].operation == LowLevelILOperation.LLIL_CONST:
        label = il.get_label_for_address(Architecture[ARCHITECTURE_STRING], il[dest].constant)
    if label is None:
        il.append(il.jump(operand))
    else:
        il.append(il.goto(label))
    return None


def rti(il, operand, mode):
    il.append(il.set_reg(1, "ccr", il.pop(1), flags="*"))
    il.append(il.set_reg(1, "b", il.pop(1)))
    il.append(il.set_reg(1, "a", il.pop(1)))
    il.append(il.set_reg(2, "x", il.pop(2)))
    return il.ret(il.pop(2))


def push_state(il):
    il.append(il.set_reg(2, "p", il.add(2, il.reg(2, "p"), il.const(1, 1))))
    il.append(il.push(1, il.reg(1, "pcl")))
    il.append(il.push(1, il.reg(1, "pch")))
    il.append(il.push(1, il.reg(1, "xl")))
    il.append(il.push(1, il.reg(1, "xh")))
    il.append(il.push(1, il.reg(1, "a")))
    il.append(il.push(1, il.reg(1, "b")))
    il.append(il.push(1, il.or_expr(1, il.reg(1, "ccr"), il.const(1, 0b11000000))))


def software_interrupt(il, operand, mode):
    push_state(il)
    il.append(il.set_flag("i",1))
    il.set_reg(2, "p", il.load(2, il.const_pointer(2, 0xFFFA)))
    return None


def wait_for_interrupt(il, operand, mode):
    push_state(il)
    return None


def load_or_immediate(size, il, mode, operand):
    if mode in [AddressingMode.IMMEDIATE_BYTE, AddressingMode.IMMEDIATE_WORD]:
        return operand

    return il.load(size, operand)


il_instructions = {
    "aba": lambda il, operand, mode: il.set_reg(1, "a", il.add(1, il.reg(1, "a"), il.reg(1, "b")), flags="hnzvc"),
    "abx": lambda il, operand, mode: il.set_reg(2, "x", il.add(2, il.reg(2, "x"), il.reg(1, "b")), flags="hnzvc"),
    "adca": lambda il, operand, mode: il.set_reg(1, "a", il.add_carry(1, il.reg(1, "a"), load_or_immediate(1, il, mode, operand), il.flag("c")), flags="hnzvc"),
    "adcb": lambda il, operand, mode: il.set_reg(1, "b", il.add_carry(1, il.reg(1, "b"), load_or_immediate(1, il, mode, operand), il.flag("c")), flags="hnzvc"),
    "adda": lambda il, operand, mode: il.set_reg(1, "a", il.add(1, il.reg(1, "a"), load_or_immediate(1, il, mode, operand)), flags="hnzvc"),
    "addb": lambda il, operand, mode: il.set_reg(1, "b", il.add(1, il.reg(1, "b"), load_or_immediate(1, il, mode, operand)), flags="hnzvc"),
    "addd": lambda il, operand, mode: il.set_reg(2, "d", il.add(2, il.reg(2, "d"), load_or_immediate(2, il, mode, operand)), flags="nzvc"),
    "anda": lambda il, operand, mode: il.set_reg(1, "a", il.and_expr(1, il.reg(1, "a"), load_or_immediate(1, il, mode, operand), flags="nzvc")),
    "andb": lambda il, operand, mode: il.set_reg(1, "a", il.and_expr(1, il.reg(1, "a"), load_or_immediate(1, il, mode, operand), flags="nzvc")),
    "asl": lambda il, operand, mode: il.store(1, operand, il.shift_left(1, il.load(1, operand), il.const(1, 1), flags="nzvc")),
    "asla": lambda il, operand, mode: il.set_reg(1, "a", il.shift_left(1, il.reg(1, "a"), il.const(1, 1), flags="nzvc")),
    "aslb": lambda il, operand, mode: il.set_reg(1, "b", il.shift_left(1, il.reg(1, "b"), il.const(1, 1), flags="nzvc")),
    "asld": lambda il, operand, mode: il.set_reg(2, "d", il.shift_left(2, il.reg(2, "d"), il.const(1, 1), flags="nzvc")),
    "asr": lambda il, operand, mode: il.store(1, operand, il.arith_shift_right(1, il.load(1, operand), il.const(1, 1), flags="nzvc")),
    "asra": lambda il, operand, mode: il.set_reg(1, "a", il.arith_shift_right(1, il.reg(1, "a"), il.const(1, 1), flags="nzvc")),
    "asrb": lambda il, operand, mode: il.set_reg(1, "b", il.arith_shift_right(1, il.reg(1, "b"), il.const(1, 1), flags="nzvc")),
    "bcc": lambda il, operand, mode: cond_branch(il, il.compare_equal(1, il.flag("c"), il.const(0, 0)), operand),
    "bcs": lambda il, operand, mode: cond_branch(il, il.compare_equal(1, il.flag("c"), il.const(0, 1)), operand),
    "beq": lambda il, operand, mode: cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_E), operand),
    "bge": lambda il, operand, mode: cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_UGE), operand),
    "bgt": lambda il, operand, mode: cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_UGT), operand),
    "bhi": lambda il, operand, mode: cond_branch(il, il.compare_equal(0, il.or_expr(0, il.flag("c"), il.flag("z")), il.const(0, 0)), operand),
    "bita": lambda il, operand, mode: il.and_expr(1, il.reg(1, "a"), load_or_immediate(1, il, mode, operand), flags="nzv"),
    "bitb": lambda il, operand, mode: il.and_expr(1, il.reg(1, "b"), load_or_immediate(1, il, mode, operand), flags="nzv"),
    "ble": lambda il, operand, mode: cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_ULE), operand),
    "bls": lambda il, operand, mode: cond_branch(il, il.compare_equal(0, il.or_expr(0, il.flag("c"), il.flag("z")), il.const(0, 1)), operand),
    "blt": lambda il, operand, mode: cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_ULT), operand),
    "bmi": lambda il, operand, mode: cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_NEG), operand),
    "bne": lambda il, operand, mode: cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_NE), operand),
    "bpl": lambda il, operand, mode: cond_branch(il, il.not_expr(0, il.flag_condition(LowLevelILFlagCondition.LLFC_NEG)), operand),
    "bra": lambda il, operand, mode: jump(il, operand),
    "brn": lambda il, operand, mode: il.nop(),
    "bsr": lambda il, operand, mode: il.call(operand),  # Essentially, a Relative addressing version of JSR.
    "bvc": lambda il, operand, mode: cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_NO), operand),
    "bvs": lambda il, operand, mode: cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_O), operand),
    "cba": lambda il, operand, mode: il.sub(1, il.reg(1, "a"), il.reg(1, "b"), flags="nzvc"),
    "clc": lambda il, operand, mode: il.set_flag("c", il.const(0, 0)),
    "cli": lambda il, operand, mode: il.set_flag("i", il.const(0, 0)),
    "clr": lambda il, operand, mode: il.store(1, operand, il.const(1, 0), flags="nzvc"),
    "clra": lambda il, operand, mode: il.set_reg(1, "a", il.const(1, 0), flags="nzvc"),
    "clrb": lambda il, operand, mode: il.set_reg(1, "b", il.const(1, 0), flags="nzvc"),
    "clv": lambda il, operand, mode: il.set_flag("v", il.const(0, 0)),
    "cmpa": lambda il, operand, mode: il.sub(1, il.reg(1, "a"), load_or_immediate(1, il, mode, operand), flags="nzvc"),
    "cmpb": lambda il, operand, mode: il.sub(1, il.reg(1, "b"), load_or_immediate(1, il, mode, operand), flags="nzvc"),
    "com": lambda il, operand, mode: il.store(1, operand, il.not_expr(1, il.load(1, operand)), flags="nzvc"),
    "coma": lambda il, operand, mode: il.set_reg(1, "a", il.not_expr(1, il.reg(1, "a")), flags="nzvc"),
    "comb": lambda il, operand, mode: il.set_reg(1, "b", il.not_expr(1, il.reg(1, "b")), flags="nzvc"),
    "cpx": lambda il, operand, mode: il.sub(2, il.reg(2, "x"), load_or_immediate(2, il, mode, operand), flags="nzvc"),
    "daa": lambda il, operand, mode: il.set_reg(1, "a", il.intrinsic([], "bcd_adjust", [il.reg(1, "a")]), flags="nzc"),
    "dec": lambda il, operand, mode: il.store(1, operand, il.sub(1, il.load(1, operand), il.const(1, 1)), flags="nzv"),
    "deca": lambda il, operand, mode: il.set_reg(1, "a", il.sub(1, il.reg(1, "a"), il.const(1, 1)), flags="nzv"),
    "decb": lambda il, operand, mode: il.set_reg(1, "b", il.sub(1, il.reg(1, "b"), il.const(1, 1)), flags="nzv"),
    "des": lambda il, operand, mode: il.set_reg(2, "s", il.sub(2, il.reg(2, "s"), il.const(1, 1))),
    "dex": lambda il, operand, mode: il.set_reg(2, "x", il.sub(2, il.reg(2, "x"), il.const(1, 1)), flags="z"),
    "eora": lambda il, operand, mode: il.set_reg(1, "a", il.xor_expr(1, il.reg(1, "a"), load_or_immediate(1, il, mode, operand)), flags="nzv"),
    "eorb": lambda il, operand, mode: il.set_reg(1, "b", il.xor_expr(1, il.reg(1, "b"), load_or_immediate(1, il, mode, operand)), flags="nzv"),
    "inc": lambda il, operand, mode: il.store(1, operand, il.add(1, il.load(1, operand), il.const(1, 1)), flags="nzv"),
    "inca": lambda il, operand, mode: il.set_reg(1, "a", il.add(1, il.reg(1, "a"), il.const(1, 1)), flags="nzv"),
    "incb": lambda il, operand, mode: il.set_reg(1, "b", il.add(1, il.reg(1, "b"), il.const(1, 1)), flags="nzv"),
    "ins": lambda il, operand, mode: il.set_reg(2, "s", il.add(2, il.reg(2, "s"), il.const(1, 1))),
    "inx": lambda il, operand, mode: il.set_reg(2, "x", il.add(2, il.reg(2, "x"), il.const(1, 1), flags="z")),
    "jmp": lambda il, operand, mode: jump(il, operand),
    "jsr": lambda il, operand, mode: il.call(operand),
    "ldaa": lambda il, operand, mode: il.set_reg(1, "a", load_or_immediate(1, il, mode, operand), flags="nzv"),
    "ldab": lambda il, operand, mode: il.set_reg(1, "b", load_or_immediate(1, il, mode, operand), flags="nzv"),
    "ldd": lambda il, operand, mode: il.set_reg(2, "d", load_or_immediate(2, il, mode, operand), flags="nzv"),
    "lds": lambda il, operand, mode: il.set_reg(2, "s", load_or_immediate(2, il, mode, operand), flags="nzv"),
    "ldx": lambda il, operand, mode: il.set_reg(2, "x", load_or_immediate(2, il, mode, operand), flags="nzv"),
    "lsr": lambda il, operand, mode: il.store(1, operand, il.logical_shift_right(1, il.load(1, operand), il.const(1, 1), flags="nzvc")),
    "lsra": lambda il, operand, mode: il.set_reg(1, "a", il.logical_shift_right(1, il.reg(1, "a"), il.const(1, 1), flags="nzvc")),
    "lsrb": lambda il, operand, mode: il.set_reg(1, "b", il.logical_shift_right(1, il.reg(1, "b"), il.const(1, 1), flags="nzvc")),
    "lsrd": lambda il, operand, mode: il.set_reg(2, "d", il.logical_shift_right(2, il.reg(2, "d"), il.const(1, 1), flags="nzvc")),
    "mul": lambda il, operand, mode: il.set_reg(2, "d", il.mult(2, il.reg(1, "a"), il.reg(1, "b")), flags="c"),
    "neg": lambda il, operand, mode: il.store(1, operand, il.neg_expr(1, il.load(1, operand)), flags="nzvc"),
    "nega": lambda il, operand, mode: il.set_reg(1, "a", il.neg_expr(1, il.reg(1, "a")), flags="nzvc"),
    "negb": lambda il, operand, mode: il.set_reg(1, "b", il.neg_expr(1, il.reg(1, "b")), flags="nzvc"),
    "nop": lambda il, operand, mode: il.nop(),
    "oraa": lambda il, operand, mode: il.set_reg(1, "a", il.or_expr(1, il.reg(1, "a"), load_or_immediate(1, il, mode, operand), flags="nzv")),
    "orab": lambda il, operand, mode: il.set_reg(1, "b", il.or_expr(1, il.reg(1, "b"), load_or_immediate(1, il, mode, operand), flags="nzv")),
    "psha": lambda il, operand, mode: il.push(1, il.reg(1, "a")),
    "pshb": lambda il, operand, mode: il.push(1, il.reg(1, "b")),
    "pshx": lambda il, operand, mode: il.push(2, il.reg(2, "x")),
    "pula": lambda il, operand, mode: il.set_reg(1, "a", il.pop(1)),
    "pulb": lambda il, operand, mode: il.set_reg(1, "b", il.pop(1)),
    "pulx": lambda il, operand, mode: il.set_reg(2, "x", il.pop(2)),
    "rol": lambda il, operand, mode: il.store(1, operand, il.rotate_left_carry(1, il.load(1, operand), il.const(1, 1), il.flag("c")), flags="nzvc"),
    "rola": lambda il, operand, mode: il.set_reg(1, "a", il.rotate_left_carry(1, il.reg(1, "a"), il.const(1, 1), il.flag("c")), flags="nzvc"),
    "rolb": lambda il, operand, mode: il.set_reg(1, "b", il.rotate_left_carry(1, il.reg(1, "b"), il.const(1, 1), il.flag("c")), flags="nzvc"),
    "ror": lambda il, operand, mode: il.store(1, operand, il.rotate_right_carry(1, il.load(1, operand), il.const(1, 1), il.flag("c")), flags="nzvc"),
    "rora": lambda il, operand, mode: il.set_reg(1, "a", il.rotate_right_carry(1, il.reg(1, "a"), il.const(1, 1), il.flag("c")), flags="nzvc"),
    "rorb": lambda il, operand, mode: il.set_reg(1, "b", il.rotate_right_carry(1, il.reg(1, "b"), il.const(1, 1), il.flag("c")), flags="nzvc"),
    "rti": rti, # What flags do we need to fix.
    "rts": lambda il, operand, mode: il.ret(il.add(2, il.pop(2), il.const(2, 1))),
    "sba": lambda il, operand, mode: il.set_reg(1, "a", il.sub(1, il.reg(1, "a"), il.reg(1, "b")), flags="nzvc"),
    "sbca": lambda il, operand, mode: il.set_reg(1, "a", il.sub_borrow(1, il.reg(1, "a"), load_or_immediate(1, il, mode, operand), il.flag("c")), flags="nzvc"),
    "sbcb": lambda il, operand, mode: il.set_reg(1, "a", il.sub_borrow(1, il.reg(1, "a"), load_or_immediate(1, il, mode, operand), il.flag("c")), flags="nzvc"),
    "sec": lambda il, operand, mode: il.set_flag("c", il.const(0, 1)),
    "sei": lambda il, operand, mode: il.set_flag("i", il.const(0, 1)),
    "sev": lambda il, operand, mode: il.set_flag("v", il.const(0, 1)),
    "slp": lambda il, operand, mode: il.intrinsic([], "sleep", []),
    "staa": lambda il, operand, mode: il.store(1, operand, il.reg(1, "a"), flags="nzv"),
    "stab": lambda il, operand, mode: il.store(1, operand, il.reg(1, "b"), flags="nzv"),
    "std": lambda il, operand, mode: il.store(2, operand, il.reg(2, "d"), flags="nzv"),
    "sts": lambda il, operand, mode: il.store(2, operand, il.reg(2, "s"), flags="nzv"),
    "stx": lambda il, operand, mode: il.store(2, operand, il.reg(2, "x"), flags="nzv"),
    "suba": lambda il, operand, mode: il.set_reg(1, "a", il.sub(1, il.reg(1, "a"), load_or_immediate(1, il, mode, operand)), "nzvc"),
    "subb": lambda il, operand, mode: il.set_reg(1, "b", il.sub(1, il.reg(1, "b"), load_or_immediate(1, il, mode, operand)), "nzvc"),
    "subd": lambda il, operand, mode: il.set_reg(2, "d", il.sub(2, il.reg(2, "d"), load_or_immediate(1, il, mode, operand)), "nzvc"),
    "swi": software_interrupt,
    "tab": lambda il, operand, mode: il.set_reg(1, "b", il.reg(1, "a"), flags="nzv"),
    "tap": lambda il, operand, mode: il.set_reg(2, "ccr", il.reg(2, "d"), flags="*"),
    "tba": lambda il, operand, mode: il.set_reg(1, "a", il.and_expr(1, il.reg(1, "b"), il.const(1, 0b11000000)), flags="nzv"),
    "tpa": lambda il, operand, mode: il.set_reg(1, "a", il.reg(1, "ccr")),
    "tst": lambda il, operand, mode: il.sub(1, operand, il.const(1, 0), flags="nzvc"),
    "tsta": lambda il, operand, mode: il.sub(1, il.reg(1, "a"), il.const(1, 0), flags="nzvc"),
    "tstb": lambda il, operand, mode: il.sub(1, il.reg(1, "b"), il.const(1, 0), flags="nzvc"),
    "tsx": lambda il, operand, mode: il.set_reg(2, "x", il.add(2, il.reg(2, "s"), il.const(2, 1))),
    "txs": lambda il, operand, mode: il.set_reg(2, "s", il.sub(2, il.reg(2, "x"), il.const(2, 1))),
    "wai": wait_for_interrupt,

    "aim": lambda il, operands, mode: il.store(1, operands[1], il.and_expr(1, operands[0], operands[1]), flags="nzv"),
    "oim": lambda il, operands, mode: il.store(1, operands[1], il.or_expr(1, operands[0], operands[1]), flags="nzv"),
    "eim": lambda il, operands, mode: il.store(1, operands[1], il.xor_expr(1, operands[0], operands[1]), flags="nzv"),
    "tim": lambda il, operands, mode: il.and_expr(1, operands[0], operands[1], flags="nzv"),
    "xgdx": lambda il, operand, mode: [
        il.set_reg(2, LLIL_TEMP(0), il.reg(2, "d")),
        il.set_reg(2, "d", il.reg(2, "x")),
        il.set_reg(2, "x", il.reg(2, LLIL_TEMP(0))),
    ]
}


def get_il_instruction(instruction: str) -> ILInstructionGenerator:
    return il_instructions.get(instruction, None)


instructions = {
    0x00: {},
    0x01: {"mnemonic": "nop", "mode": AddressingMode.INHERENT},
    0x02: {},
    0x03: {},
    0x04: {"mnemonic": "lsrd", "mode": AddressingMode.INHERENT},
    0x05: {"mnemonic": "asld", "mode": AddressingMode.INHERENT},
    0x06: {"mnemonic": "tap", "mode": AddressingMode.INHERENT},
    0x07: {"mnemonic": "tpa", "mode": AddressingMode.INHERENT},
    0x08: {"mnemonic": "inx", "mode": AddressingMode.INHERENT},
    0x09: {"mnemonic": "dex", "mode": AddressingMode.INHERENT},
    0x0a: {"mnemonic": "clv", "mode": AddressingMode.INHERENT},
    0x0b: {"mnemonic": "sev", "mode": AddressingMode.INHERENT},
    0x0c: {"mnemonic": "clc", "mode": AddressingMode.INHERENT},
    0x0d: {"mnemonic": "sec", "mode": AddressingMode.INHERENT},
    0x0e: {"mnemonic": "cli", "mode": AddressingMode.INHERENT},
    0x0f: {"mnemonic": "sei", "mode": AddressingMode.INHERENT},
    0x10: {"mnemonic": "sba", "mode": AddressingMode.INHERENT},
    0x11: {"mnemonic": "cba", "mode": AddressingMode.INHERENT},
    0x12: {},
    0x13: {},
    0x14: {},
    0x15: {},
    0x16: {"mnemonic": "tab", "mode": AddressingMode.INHERENT},
    0x17: {"mnemonic": "tba", "mode": AddressingMode.INHERENT},
    0x18: {"mnemonic": "xgdx", "mode": AddressingMode.INHERENT},  # HD8303
    0x19: {"mnemonic": "daa", "mode": AddressingMode.INHERENT},
    0x1a: {"mnemonic": "slp", "mode": AddressingMode.INHERENT},  # HD8303
    0x1b: {"mnemonic": "aba", "mode": AddressingMode.INHERENT},
    0x1c: {},
    0x1d: {},
    0x1e: {},
    0x1f: {},
    0x20: {"mnemonic": "bra", "mode": AddressingMode.RELATIVE},
    0x21: {"mnemonic": "brn", "mode": AddressingMode.RELATIVE},
    0x22: {"mnemonic": "bhi", "mode": AddressingMode.RELATIVE},
    0x23: {"mnemonic": "bls", "mode": AddressingMode.RELATIVE},
    0x24: {"mnemonic": "bcc", "mode": AddressingMode.RELATIVE},
    0x25: {"mnemonic": "bcs", "mode": AddressingMode.RELATIVE},
    0x26: {"mnemonic": "bne", "mode": AddressingMode.RELATIVE},
    0x27: {"mnemonic": "beq", "mode": AddressingMode.RELATIVE},
    0x28: {"mnemonic": "bvc", "mode": AddressingMode.RELATIVE},
    0x29: {"mnemonic": "bvs", "mode": AddressingMode.RELATIVE},
    0x2a: {"mnemonic": "bpl", "mode": AddressingMode.RELATIVE},
    0x2b: {"mnemonic": "bmi", "mode": AddressingMode.RELATIVE},
    0x2c: {"mnemonic": "bge", "mode": AddressingMode.RELATIVE},
    0x2d: {"mnemonic": "blt", "mode": AddressingMode.RELATIVE},
    0x2e: {"mnemonic": "bgt", "mode": AddressingMode.RELATIVE},
    0x2f: {"mnemonic": "ble", "mode": AddressingMode.RELATIVE},
    0x30: {"mnemonic": "tsx", "mode": AddressingMode.INHERENT},
    0x31: {"mnemonic": "ins", "mode": AddressingMode.INHERENT},
    0x32: {"mnemonic": "pula", "mode": AddressingMode.INHERENT},
    0x33: {"mnemonic": "pulb", "mode": AddressingMode.INHERENT},
    0x34: {"mnemonic": "des", "mode": AddressingMode.INHERENT},
    0x35: {"mnemonic": "txs", "mode": AddressingMode.INHERENT},
    0x36: {"mnemonic": "psha", "mode": AddressingMode.INHERENT},
    0x37: {"mnemonic": "pshb", "mode": AddressingMode.INHERENT},
    0x38: {"mnemonic": "pulx", "mode": AddressingMode.INHERENT},
    0x39: {"mnemonic": "rts", "mode": AddressingMode.INHERENT},
    0x3a: {"mnemonic": "abx", "mode": AddressingMode.INHERENT},
    0x3b: {"mnemonic": "rti", "mode": AddressingMode.INHERENT},
    0x3c: {"mnemonic": "pshx", "mode": AddressingMode.INHERENT},
    0x3d: {"mnemonic": "mul", "mode": AddressingMode.INHERENT},
    0x3e: {"mnemonic": "wai", "mode": AddressingMode.INHERENT},
    0x3f: {"mnemonic": "swi", "mode": AddressingMode.INHERENT},
    0x40: {"mnemonic": "nega", "mode": AddressingMode.INHERENT},
    0x41: {},
    0x42: {},
    0x43: {"mnemonic": "coma", "mode": AddressingMode.INHERENT},
    0x44: {"mnemonic": "lsra", "mode": AddressingMode.INHERENT},
    0x45: {},
    0x46: {"mnemonic": "rora", "mode": AddressingMode.INHERENT},
    0x47: {"mnemonic": "asra", "mode": AddressingMode.INHERENT},
    0x48: {"mnemonic": "asla", "mode": AddressingMode.INHERENT},
    0x49: {"mnemonic": "rola", "mode": AddressingMode.INHERENT},
    0x4a: {"mnemonic": "deca", "mode": AddressingMode.INHERENT},
    0x4b: {},
    0x4c: {"mnemonic": "inca", "mode": AddressingMode.INHERENT},
    0x4d: {"mnemonic": "tsta", "mode": AddressingMode.INHERENT},
    0x4e: {},
    0x4f: {"mnemonic": "clra", "mode": AddressingMode.INHERENT},
    0x50: {"mnemonic": "negb", "mode": AddressingMode.INHERENT},
    0x51: {},
    0x52: {},
    0x53: {"mnemonic": "comb", "mode": AddressingMode.INHERENT},
    0x54: {"mnemonic": "lsrb", "mode": AddressingMode.INHERENT},
    0x55: {},
    0x56: {"mnemonic": "rorb", "mode": AddressingMode.INHERENT},
    0x57: {"mnemonic": "asrb", "mode": AddressingMode.INHERENT},
    0x58: {"mnemonic": "aslb", "mode": AddressingMode.INHERENT},
    0x59: {"mnemonic": "rolb", "mode": AddressingMode.INHERENT},
    0x5a: {"mnemonic": "decb", "mode": AddressingMode.INHERENT},
    0x5b: {},
    0x5c: {"mnemonic": "incb", "mode": AddressingMode.INHERENT},
    0x5d: {"mnemonic": "tstb", "mode": AddressingMode.INHERENT},
    0x5e: {},
    0x5f: {"mnemonic": "clrb", "mode": AddressingMode.INHERENT},
    0x60: {"mnemonic": "neg", "mode": AddressingMode.INDEXED},
    0x61: {"mnemonic": "aim", "mode": AddressingMode.INDEXED_IMMEDIATE},  # HD8303
    0x62: {"mnemonic": "oim", "mode": AddressingMode.INDEXED_IMMEDIATE},  # HD8303
    0x63: {"mnemonic": "com", "mode": AddressingMode.INDEXED},
    0x64: {"mnemonic": "lsr", "mode": AddressingMode.INDEXED},
    0x65: {"mnemonic": "eim", "mode": AddressingMode.INDEXED_IMMEDIATE},  # HD8303
    0x66: {"mnemonic": "ror", "mode": AddressingMode.INDEXED},
    0x67: {"mnemonic": "asr", "mode": AddressingMode.INDEXED},
    0x68: {"mnemonic": "asl", "mode": AddressingMode.INDEXED},
    0x69: {"mnemonic": "rol", "mode": AddressingMode.INDEXED},
    0x6a: {"mnemonic": "dec", "mode": AddressingMode.INDEXED},
    0x6b: {"mnemonic": "tim", "mode": AddressingMode.INDEXED_IMMEDIATE},  # HD8303
    0x6c: {"mnemonic": "inc", "mode": AddressingMode.INDEXED},
    0x6d: {"mnemonic": "tst", "mode": AddressingMode.INDEXED},
    0x6e: {"mnemonic": "jmp", "mode": AddressingMode.INDEXED},  # FIXME in IL
    0x6f: {"mnemonic": "clr", "mode": AddressingMode.INDEXED},
    0x70: {"mnemonic": "neg", "mode": AddressingMode.EXTENDED},
    0x71: {"mnemonic": "aim", "mode": AddressingMode.DIRECT_IMMEDIATE},  # HD8303
    0x72: {"mnemonic": "oim", "mode": AddressingMode.DIRECT_IMMEDIATE},  # HD8303
    0x73: {"mnemonic": "com", "mode": AddressingMode.EXTENDED},
    0x74: {"mnemonic": "lsr", "mode": AddressingMode.EXTENDED},
    0x75: {"mnemonic": "eim", "mode": AddressingMode.DIRECT_IMMEDIATE},  # HD8303
    0x76: {"mnemonic": "ror", "mode": AddressingMode.EXTENDED},
    0x77: {"mnemonic": "asr", "mode": AddressingMode.EXTENDED},
    0x78: {"mnemonic": "asl", "mode": AddressingMode.EXTENDED},
    0x79: {"mnemonic": "rol", "mode": AddressingMode.EXTENDED},
    0x7a: {"mnemonic": "dec", "mode": AddressingMode.EXTENDED},
    0x7b: {"mnemonic": "tim", "mode": AddressingMode.DIRECT_IMMEDIATE},  # HD8303
    0x7c: {"mnemonic": "inc", "mode": AddressingMode.EXTENDED},
    0x7d: {"mnemonic": "tst", "mode": AddressingMode.EXTENDED},
    0x7e: {"mnemonic": "jmp", "mode": AddressingMode.EXTENDED},
    0x7f: {"mnemonic": "clr", "mode": AddressingMode.EXTENDED},
    0x80: {"mnemonic": "suba", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x81: {"mnemonic": "cmpa", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x82: {"mnemonic": "sbca", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x83: {"mnemonic": "subd", "mode": AddressingMode.IMMEDIATE_WORD},
    0x84: {"mnemonic": "anda", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x85: {"mnemonic": "bita", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x86: {"mnemonic": "ldaa", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x87: {},
    0x88: {"mnemonic": "eora", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x89: {"mnemonic": "adca", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x8a: {"mnemonic": "oraa", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x8b: {"mnemonic": "adda", "mode": AddressingMode.IMMEDIATE_BYTE},
    0x8c: {"mnemonic": "cpx", "mode": AddressingMode.IMMEDIATE_WORD},
    0x8d: {"mnemonic": "bsr", "mode": AddressingMode.RELATIVE},
    0x8e: {"mnemonic": "lds", "mode": AddressingMode.IMMEDIATE_WORD},
    0x8f: {},
    0x90: {"mnemonic": "suba", "mode": AddressingMode.DIRECT},
    0x91: {"mnemonic": "cmpa", "mode": AddressingMode.DIRECT},
    0x92: {"mnemonic": "sbca", "mode": AddressingMode.DIRECT},
    0x93: {"mnemonic": "subd", "mode": AddressingMode.DIRECT},
    0x94: {"mnemonic": "anda", "mode": AddressingMode.DIRECT},
    0x95: {"mnemonic": "bita", "mode": AddressingMode.DIRECT},
    0x96: {"mnemonic": "ldaa", "mode": AddressingMode.DIRECT},
    0x97: {"mnemonic": "staa", "mode": AddressingMode.DIRECT},
    0x98: {"mnemonic": "eora", "mode": AddressingMode.DIRECT},
    0x99: {"mnemonic": "adca", "mode": AddressingMode.DIRECT},
    0x9a: {"mnemonic": "oraa", "mode": AddressingMode.DIRECT},
    0x9b: {"mnemonic": "adda", "mode": AddressingMode.DIRECT},
    0x9c: {"mnemonic": "cpx", "mode": AddressingMode.DIRECT},
    0x9d: {"mnemonic": "jsr", "mode": AddressingMode.DIRECT},
    0x9e: {"mnemonic": "lds", "mode": AddressingMode.DIRECT},
    0x9f: {"mnemonic": "sts", "mode": AddressingMode.DIRECT},
    0xa0: {"mnemonic": "suba", "mode": AddressingMode.INDEXED},
    0xa1: {"mnemonic": "cmpa", "mode": AddressingMode.INDEXED},
    0xa2: {"mnemonic": "sbca", "mode": AddressingMode.INDEXED},
    0xa3: {"mnemonic": "subd", "mode": AddressingMode.INDEXED},
    0xa4: {"mnemonic": "anda", "mode": AddressingMode.INDEXED},
    0xa5: {"mnemonic": "bita", "mode": AddressingMode.INDEXED},
    0xa6: {"mnemonic": "ldaa", "mode": AddressingMode.INDEXED},
    0xa7: {"mnemonic": "staa", "mode": AddressingMode.INDEXED},
    0xa8: {"mnemonic": "eora", "mode": AddressingMode.INDEXED},
    0xa9: {"mnemonic": "adca", "mode": AddressingMode.INDEXED},
    0xaa: {"mnemonic": "oraa", "mode": AddressingMode.INDEXED},
    0xab: {"mnemonic": "adda", "mode": AddressingMode.INDEXED},
    0xac: {"mnemonic": "cpx", "mode": AddressingMode.INDEXED},
    0xad: {"mnemonic": "jsr", "mode": AddressingMode.INDEXED},  # FIXME in IL
    0xae: {"mnemonic": "lds", "mode": AddressingMode.INDEXED},
    0xaf: {"mnemonic": "sts", "mode": AddressingMode.INDEXED},
    0xb0: {"mnemonic": "suba", "mode": AddressingMode.EXTENDED},
    0xb1: {"mnemonic": "cmpa", "mode": AddressingMode.EXTENDED},
    0xb2: {"mnemonic": "sbca", "mode": AddressingMode.EXTENDED},
    0xb3: {"mnemonic": "subd", "mode": AddressingMode.EXTENDED},
    0xb4: {"mnemonic": "anda", "mode": AddressingMode.EXTENDED},
    0xb5: {"mnemonic": "bita", "mode": AddressingMode.EXTENDED},
    0xb6: {"mnemonic": "ldaa", "mode": AddressingMode.EXTENDED},
    0xb7: {"mnemonic": "staa", "mode": AddressingMode.EXTENDED},
    0xb8: {"mnemonic": "eora", "mode": AddressingMode.EXTENDED},
    0xb9: {"mnemonic": "adca", "mode": AddressingMode.EXTENDED},
    0xba: {"mnemonic": "oraa", "mode": AddressingMode.EXTENDED},
    0xbb: {"mnemonic": "adda", "mode": AddressingMode.EXTENDED},
    0xbc: {"mnemonic": "cpx", "mode": AddressingMode.EXTENDED},
    0xbd: {"mnemonic": "jsr", "mode": AddressingMode.EXTENDED},
    0xbe: {"mnemonic": "lds", "mode": AddressingMode.EXTENDED},
    0xbf: {"mnemonic": "sts", "mode": AddressingMode.EXTENDED},
    0xc0: {"mnemonic": "subb", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xc1: {"mnemonic": "cmpb", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xc2: {"mnemonic": "sbcb", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xc3: {"mnemonic": "addd", "mode": AddressingMode.IMMEDIATE_WORD},
    0xc4: {"mnemonic": "andb", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xc5: {"mnemonic": "bitb", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xc6: {"mnemonic": "ldab", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xc7: {},
    0xc8: {"mnemonic": "eorb", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xc9: {"mnemonic": "adcb", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xca: {"mnemonic": "orab", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xcb: {"mnemonic": "addb", "mode": AddressingMode.IMMEDIATE_BYTE},
    0xcc: {"mnemonic": "ldd", "mode": AddressingMode.IMMEDIATE_WORD},
    0xcd: {},
    0xce: {"mnemonic": "ldx", "mode": AddressingMode.IMMEDIATE_WORD},
    0xcf: {},
    0xd0: {"mnemonic": "subb", "mode": AddressingMode.DIRECT},
    0xd1: {"mnemonic": "cmpb", "mode": AddressingMode.DIRECT},
    0xd2: {"mnemonic": "sbcb", "mode": AddressingMode.DIRECT},
    0xd3: {"mnemonic": "addd", "mode": AddressingMode.DIRECT},
    0xd4: {"mnemonic": "andb", "mode": AddressingMode.DIRECT},
    0xd5: {"mnemonic": "bitb", "mode": AddressingMode.DIRECT},
    0xd6: {"mnemonic": "ldab", "mode": AddressingMode.DIRECT},
    0xd7: {"mnemonic": "stab", "mode": AddressingMode.DIRECT},
    0xd8: {"mnemonic": "eorb", "mode": AddressingMode.DIRECT},
    0xd9: {"mnemonic": "adcb", "mode": AddressingMode.DIRECT},
    0xda: {"mnemonic": "orab", "mode": AddressingMode.DIRECT},
    0xdb: {"mnemonic": "addb", "mode": AddressingMode.DIRECT},
    0xdc: {"mnemonic": "ldd", "mode": AddressingMode.DIRECT},
    0xdd: {"mnemonic": "std", "mode": AddressingMode.DIRECT},
    0xde: {"mnemonic": "ldx", "mode": AddressingMode.DIRECT},
    0xdf: {"mnemonic": "stx", "mode": AddressingMode.DIRECT},
    0xe0: {"mnemonic": "subb", "mode": AddressingMode.INDEXED},
    0xe1: {"mnemonic": "cmpb", "mode": AddressingMode.INDEXED},
    0xe2: {"mnemonic": "sbcb", "mode": AddressingMode.INDEXED},
    0xe3: {"mnemonic": "addd", "mode": AddressingMode.INDEXED},
    0xe4: {"mnemonic": "andb", "mode": AddressingMode.INDEXED},
    0xe5: {"mnemonic": "bitb", "mode": AddressingMode.INDEXED},
    0xe6: {"mnemonic": "ldab", "mode": AddressingMode.INDEXED},
    0xe7: {"mnemonic": "stab", "mode": AddressingMode.INDEXED},
    0xe8: {"mnemonic": "eorb", "mode": AddressingMode.INDEXED},
    0xe9: {"mnemonic": "adcb", "mode": AddressingMode.INDEXED},
    0xea: {"mnemonic": "orab", "mode": AddressingMode.INDEXED},
    0xeb: {"mnemonic": "addb", "mode": AddressingMode.INDEXED},
    0xec: {"mnemonic": "ldd", "mode": AddressingMode.INDEXED},
    0xed: {"mnemonic": "std", "mode": AddressingMode.INDEXED},
    0xee: {"mnemonic": "ldx", "mode": AddressingMode.INDEXED},
    0xef: {"mnemonic": "stx", "mode": AddressingMode.INDEXED},
    0xf0: {"mnemonic": "subb", "mode": AddressingMode.EXTENDED},
    0xf1: {"mnemonic": "cmpb", "mode": AddressingMode.EXTENDED},
    0xf2: {"mnemonic": "sbcb", "mode": AddressingMode.EXTENDED},
    0xf3: {"mnemonic": "addd", "mode": AddressingMode.EXTENDED},
    0xf4: {"mnemonic": "andb", "mode": AddressingMode.EXTENDED},
    0xf5: {"mnemonic": "bitb", "mode": AddressingMode.EXTENDED},
    0xf6: {"mnemonic": "ldab", "mode": AddressingMode.EXTENDED},
    0xf7: {"mnemonic": "stab", "mode": AddressingMode.EXTENDED},
    0xf8: {"mnemonic": "eorb", "mode": AddressingMode.EXTENDED},
    0xf9: {"mnemonic": "adcb", "mode": AddressingMode.EXTENDED},
    0xfa: {"mnemonic": "orab", "mode": AddressingMode.EXTENDED},
    0xfb: {"mnemonic": "addb", "mode": AddressingMode.EXTENDED},
    0xfc: {"mnemonic": "ldd", "mode": AddressingMode.EXTENDED},
    0xfd: {"mnemonic": "std", "mode": AddressingMode.EXTENDED},
    0xfe: {"mnemonic": "ldx", "mode": AddressingMode.EXTENDED},
    0xff: {"mnemonic": "stx", "mode": AddressingMode.EXTENDED},
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

    label = instruction["mnemonic"]
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


def get_destination_from_relative_operation(address, data):
    offset = struct.unpack("b", data[1:2])[0]
    destination = (address + offset + 2) & 0xffff
    return destination


class HD6303(Architecture):
    name = ARCHITECTURE_STRING
    address_size = 2
    default_int_size = 1
    instr_alignment = 1
    max_instr_length = 3
    endianness = Endianness.BigEndian

    intrinsics = {
        'bcd_adjust': IntrinsicInfo([Type.int(1)], [Type.int(1)]),
        'sleep': IntrinsicInfo([], [])
    }

    regs = {
        # Stack Pointer
        's': RegisterInfo('s', 2),

        # program counter
        'p': RegisterInfo('p', 2),
        'pch': RegisterInfo('p', 1, 0),
        'pcl': RegisterInfo('p', 1, 1),

        # Index register
        "x": RegisterInfo("x", 2),
        "xh": RegisterInfo("x", 1, 0),
        "xl": RegisterInfo("x", 1, 1),

        # Accumulator
        'd': RegisterInfo('d', 2),
        'a': RegisterInfo('d', 1, 0),
        'b': RegisterInfo('d', 1, 1),

        'ccr': RegisterInfo('ccr', 1)
    }

    stack_pointer = 's'

    flags = ["h", "i", "n", "z", "v", "c"]
    flag_roles = {
        "h": FlagRole.HalfCarryFlagRole,
        "i": FlagRole.SpecialFlagRole,  # Interrupt
        "n": FlagRole.NegativeSignFlagRole,
        "z": FlagRole.ZeroFlagRole,
        "v": FlagRole.OverflowFlagRole,
        "c": FlagRole.CarryFlagRole,
    }

    flag_write_types = ["*", "nzvc", "z", "nzv", "nzc", "hnzvc", "c", "i", "v"]

    flags_written_by_flag_write_type = {
        "*": ["h", "i", "n", "z", "v", "c"],
        "nzvc": ["n", "z", "v", "c"],
        "nzc": ["n", "z", "c"],
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
            destination = get_destination_from_relative_operation(address, data)

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

    def get_instruction_low_level_il(self, data, address, il: LowLevelILFunction):
        label, operand_length, operand_value, tokenizer, mode = parse_instruction(data)
        log_debug("%.4x    %s" % (address, label))

        length = operand_length + 1

        il_operand_fn = get_il_operand(mode)
        if il_operand_fn is None:
            log_debug("Operand: '%s' not implemented" % mode)
            return length

        if label in branching_instructions:  # Always Relative Addressing Mode
            operand_destination = get_destination_from_relative_operation(address, data)
            il_operand = il_operand_fn(il, operand_destination)
        else:
            il_operand = il_operand_fn(il, operand_value)

        il_instruction_fn = get_il_instruction(label)
        if il_instruction_fn is None:
            log_debug("Instr: '%s' not implemented" % label)
            il.append(il.nop())
            return length

        il_instruction = il_instruction_fn(il, il_operand, mode)

        if isinstance(il_instruction, list):
            for i in il_instruction:
                il.append(i)
        elif il_instruction is not None:
            il.append(il_instruction)

        return length

    # def get_instruction_low_level_il(self, data, address, il: LowLevelILFunction):
    #     label, operand_length, operand_value, tokenizer, mode = parse_instruction(data)
    #     log_debug("%.4x    %s" % (address, label))
    #
    #     length = operand_length + 1
    #
    #
    #     return length

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
