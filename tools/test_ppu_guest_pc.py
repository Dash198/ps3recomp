#!/usr/bin/env python3
"""Unit vectors for the G5 guest-PC probe: the lifter's half of it.

The runtime half (PS3_GUEST_PC, ppu_guest_pc_enter, the per-thread frame ring)
only ever runs if the lifter does two things, and both are silent if they break:
it must declare the contract in the source preamble, and it must emit PPU_SET_PC
as the FIRST statement of every lifted function.

"First" is the whole point. Emitted after the prologue instead, or only in some
functions, ctx->cia would name the wrong function for exactly the faults the
probe exists to attribute -- and nothing would look broken. Same for the
declaration: drop it and the lift still writes, the build still succeeds, and the
probe quietly stops working on the next re-lift.

So these vectors pin the spelling, the position, the 8-digit padding, the guard
(OFF by default, one predictable branch), and that the contract is in the SOURCE
preamble and not the header -- the header is included by C translation units that
have no `extern "C"`.

Run: python tools/test_ppu_guest_pc.py
"""

import os
import sys

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS)

import ppu_disasm                                          # noqa: E402
from ppu_lifter import (HEADER_PREAMBLE, PPULifter,        # noqa: E402
                        SOURCE_PREAMBLE)

TEXT = 0x10000

FAILS = []


def ok(name):
    print(f"ok   {name}")


def bad(name, detail):
    print(f"FAIL {name}: {detail}")
    FAILS.append(name)


def check(name, got, want):
    if got == want:
        ok(name)
    else:
        bad(name, f"got {got!r}, want {want!r}")


def w_std_r3_r1():
    """`std r3, 0x0(r1)` -- a memory write, so the body starts with an access and
    the position of PPU_SET_PC relative to it is observable."""
    return (62 << 26) | (3 << 21) | (1 << 16) | 0          # std r3, 0(r1)


def w_blr():
    return (19 << 26) | (20 << 21) | (16 << 1)


def emit(addr, words):
    """Lift one function and return its emitted definition lines."""
    lifter = PPULifter()
    ins = [ppu_disasm.decode(w, addr + 4 * i) for i, w in enumerate(words)]
    func = lifter.lift_function(ins, addr, addr + 4 * len(words))
    return lifter._function_def_lines(func, {}, [], {})


def test_preamble_declares_the_contract():
    for want in ("g_ppu_guest_pc", "ppu_guest_pc_enter", "#define PPU_SET_PC"):
        if want not in SOURCE_PREAMBLE:
            bad("preamble declares the contract", f"{want!r} is missing")
            return
    ok("preamble declares the contract")


def test_the_contract_is_not_in_the_header():
    """The header is included by C translation units (the smoke title), and the
    source preamble spells the declaration `extern "C"` unguarded. The contract
    belongs in the source preamble, which is C++."""
    check("no PPU_SET_PC in HEADER_PREAMBLE",
          "PPU_SET_PC" in HEADER_PREAMBLE, False)
    check("no g_ppu_guest_pc in HEADER_PREAMBLE",
          "g_ppu_guest_pc" in HEADER_PREAMBLE, False)
    check("no ppu_guest_pc_enter in HEADER_PREAMBLE",
          "ppu_guest_pc_enter" in HEADER_PREAMBLE, False)


def test_it_is_the_first_statement():
    lines = emit(TEXT, [w_std_r3_r1(), w_blr()])
    check("first emitted line opens the body",
          lines[0], "void func_00010000(ppu_context* ctx) {")
    check("PPU_SET_PC is the very first statement",
          lines[1], "    PPU_SET_PC(ctx, 0x00010000);")
    # ...and not merely somewhere before the end: the memory write follows it.
    body = "\n".join(lines)
    pc, wr = body.find("PPU_SET_PC"), body.find("vm_write")
    if pc < 0 or wr < 0 or pc > wr:
        bad("PPU_SET_PC precedes the first memory access",
            f"PPU_SET_PC at {pc}, first memory access at {wr}:\n{body}")
    else:
        ok("PPU_SET_PC precedes the first memory access")


def test_address_is_zero_padded_to_eight_digits():
    """`0x{addr:08X}` -- a short form would still compile and still be wrong for
    the low addresses this image actually uses."""
    lines = emit(0x10200, [w_blr()])
    check("low address is 8 hex digits",
          lines[1], "    PPU_SET_PC(ctx, 0x00010200);")


def test_the_emitted_call_is_guarded():
    """OFF by default: the macro tests the global rather than always calling, so
    the fast path is one load and one predictable branch."""
    macro = SOURCE_PREAMBLE.split("#define PPU_SET_PC", 1)[1]
    macro = macro.split("\n", 1)[0] + "\n" + macro.split("\n", 2)[1]
    if "g_ppu_guest_pc" not in macro or "if" not in macro:
        bad("emitted call is guarded", f"macro body is {macro!r}")
    else:
        ok("emitted call is guarded, not unconditional")


def test_every_function_gets_one():
    """No shape-specific exemptions: the probe is only trustworthy if a fault can
    be attributed in ANY lifted function."""
    for addr, words, label in (
        (TEXT, [w_blr()], "leaf"),
        (TEXT, [w_std_r3_r1(), w_blr()], "store"),
        (0x0101ACE8, [w_blr()], "high address / import-stub range"),
    ):
        lines = emit(addr, words)
        want = f"    PPU_SET_PC(ctx, 0x{addr:08X});"
        if want not in lines[1]:
            bad(f"emits for {label}", f"got {lines[1]!r}, want {want!r}")
            return
        if sum("PPU_SET_PC" in ln for ln in lines) != 1:
            bad(f"emits for {label}", f"expected exactly one, got {lines}")
            return
    ok("every function shape gets exactly one PPU_SET_PC")


def main() -> int:
    test_preamble_declares_the_contract()
    test_the_contract_is_not_in_the_header()
    test_it_is_the_first_statement()
    test_address_is_zero_padded_to_eight_digits()
    test_the_emitted_call_is_guarded()
    test_every_function_gets_one()
    if FAILS:
        print(f"FAILED: {', '.join(FAILS)}")
        return 1
    print("all guest-PC emission vectors passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
