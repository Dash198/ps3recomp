#!/usr/bin/env python3
"""Unit vectors for discover_setjmp_helpers: which functions are the guest
setjmp / longjmp context helpers.

No SDK, no ELF: the PowerPC words are the exact ones the GT6 image carries (and
what ppu_disasm prints for them), round-tripped through ppu_disasm.decode first
so an encoding mistake here reports as ENCODING and never as a false lifter
failure.

The shape being pinned is one idiom with two tails:

    addi   r3, r3, 15          ; block = (block + 15) & ~15
    rldicr r3, r3, 0, 59
    std    r1, 0x0(r3)         ; __savegprlr_14 : setjmp
  / ld     r1, 0x0(r3)         ; __restgprlr_14 : longjmp (ends blr to reloaded LR)

The lifter turns the save half's call sites into a host setjmp landing pad
(PPU_SETJMP_GUARD) and the restore half's body into ppu_lj_do. Getting the
classification wrong either way is silent and corrupts guest stacks, so the
vectors cover the two helpers, the align-only near miss that must not match, the
r1-offset requirement, the immediate, the function-entry filter, and the two
emissions (guard at the call site, hook at the blr).

Run: python tools/test_ppu_setjmp_helpers.py
"""

import os
import sys

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS)

import ppu_disasm                                      # noqa: E402
from ppu_lifter import PPULifter, discover_setjmp_helpers   # noqa: E402

TEXT = 0x10000

# Words lifted verbatim out of EMAIN.elf (func_00BDCF2C / func_00BDD050).
W_ALIGN15 = 0x3863000F     # addi   r3, r3, 15
W_ALIGN7 = 0x38630007      # addi   r3, r3, 7    (wrong immediate)
W_RLDICR = 0x786306E4      # rldicr r3, r3, 0, 59
W_STD_R1 = 0xF8230000      # std    r1, 0x0(r3)  -> save helper
W_LD_R1 = 0xE8230000       # ld     r1, 0x0(r3)  -> restore helper
W_STD_R2 = 0xF8430008      # std    r2, 0x8(r3)  (does not touch the sp slot)


def dec(words, base=TEXT):
    return [ppu_disasm.decode(w, base + 4 * i) for i, w in enumerate(words)]


def w_bl(from_addr, to_addr):
    """`bl to_addr` placed at from_addr (I-form, LK=1)."""
    return (18 << 26) | ((to_addr - from_addr) & 0x03FFFFFC) | 1


def w_blr():
    return (19 << 26) | (20 << 21) | (16 << 1)


FAILS = []


def check(name, got, want):
    if got == want:
        print(f"ok   {name}")
    else:
        show = lambda s: "{}".format(sorted(f"0x{a:08X}" for a in s))
        print(f"FAIL {name}: got {show(got)}, want {show(want)}")
        FAILS.append(name)


def test_encodings():
    ins = dec([W_ALIGN15, W_RLDICR, W_STD_R1, W_LD_R1, W_STD_R2])
    got = [(i.mnemonic, i.operands) for i in ins]
    want = [("addi", "r3, r3, 15"),
            ("rldicr", "r3, r3, 0, 59"),
            ("std", "r1, 0x0(r3)"),
            ("ld", "r1, 0x0(r3)"),
            ("std", "r2, 0x8(r3)")]
    if got != want:
        print(f"ENCODING mismatch:\n  got  {got}\n  want {want}")
        sys.exit(2)
    print("ok   encodings decode as the vectors assume")


def test_save_helper():
    """align ; align ; std r1,0x0 -> the save half (setjmp return-0 path)."""
    ins = dec([W_ALIGN15, W_RLDICR, W_STD_R1])
    savers, restorers = discover_setjmp_helpers(ins, {TEXT})
    check("save helper recognised", savers, {TEXT})
    check("save helper is not a restore helper", restorers, set())


def test_restore_helper():
    """align ; align ; ld r1,0x0 -> the restore half (ends blr to reloaded LR)."""
    ins = dec([W_ALIGN15, W_RLDICR, W_LD_R1])
    savers, restorers = discover_setjmp_helpers(ins, {TEXT})
    check("restore helper recognised", restorers, {TEXT})
    check("restore helper is not a save helper", savers, set())


def test_align_alone_is_not_a_helper():
    """The align idiom without the r1 store/load is an unrelated block align.

    The same two instructions occur inline at ~20 sites in GT6 that merely align
    a block; they must not be classified as helpers.
    """
    ins = dec([W_ALIGN15, W_RLDICR, W_STD_R2])
    savers, restorers = discover_setjmp_helpers(ins, {TEXT})
    check("align + unrelated store is neither helper", savers | restorers, set())


def test_wrong_align_immediate():
    """A `+7` align is not the idiom even with the same tail."""
    ins = dec([W_ALIGN7, W_RLDICR, W_STD_R1])
    savers, restorers = discover_setjmp_helpers(ins, {TEXT})
    check("wrong align immediate is neither helper", savers | restorers, set())


def test_needs_a_function_entry():
    """A match that is NOT a function start is dropped when entries are known."""
    ins = dec([W_ALIGN15, W_RLDICR, W_STD_R1])
    savers, _ = discover_setjmp_helpers(ins, {TEXT + 4})
    check("idiom off a function entry is dropped", savers, set())
    savers, _ = discover_setjmp_helpers(ins, None)
    check("without entries the idiom still matches", savers, {TEXT})


def test_both_helpers_in_one_image():
    """Save and restore helpers coexist, as they do in GT6's statically linked libgcc."""
    ins = dec([W_ALIGN15, W_RLDICR, W_LD_R1])          # restore at TEXT
    ins += dec([W_ALIGN15, W_RLDICR, W_STD_R1], base=TEXT + 0x20)
    savers, restorers = discover_setjmp_helpers(ins, {TEXT, TEXT + 0x20})
    check("save and restore classified independently", (savers, restorers),
          ({TEXT + 0x20}, {TEXT}))


def test_save_call_site_emits_the_guard():
    """A `bl` to the save helper becomes the guarded call, not a plain call.

    The pad is armed at the CALL SITE: this frame is the one still live when the
    matching longjmp fires (the helper itself has already returned).
    """
    lifter = PPULifter()
    lifter.setjmp_savers = {TEXT + 4}
    ins = dec([w_bl(TEXT, TEXT + 4), w_blr()])
    func = lifter.lift_function(ins, TEXT, TEXT + 8)
    body = "\n".join(func.body_lines)
    assert "PPU_SETJMP_GUARD(ctx, func_00010004);" in body, body
    assert "func_00010004(ctx);" not in body, body
    print("ok   save call site emits PPU_SETJMP_GUARD, not a plain call")


def test_restore_helper_body_emits_the_longjmp_hook():
    """The restore helper captures block/sp at entry and jumps at its blr."""
    lifter = PPULifter()
    lifter.setjmp_restorers = {TEXT}
    ins = dec([W_ALIGN15, W_RLDICR, W_LD_R1, w_blr()])
    func = lifter.lift_function(ins, TEXT, TEXT + 16)
    body = "\n".join(func.body_lines)
    assert "uint64_t _sj_blk = PPU_SJ_ALIGN(ctx->gpr[3]);" in body, body
    assert "uint64_t _sj_sp  = ctx->gpr[1];" in body, body
    assert "ppu_lj_do(ctx, _sj_blk, _sj_sp);" in body, body
    # the jump belongs at the blr -- before the body's first return
    assert body.index("ppu_lj_do") < body.index("return;"), body
    print("ok   restore helper body captures blk/sp and emits ppu_lj_do at the blr")


def main() -> int:
    test_encodings()
    test_save_helper()
    test_restore_helper()
    test_align_alone_is_not_a_helper()
    test_wrong_align_immediate()
    test_needs_a_function_entry()
    test_both_helpers_in_one_image()
    test_save_call_site_emits_the_guard()
    test_restore_helper_body_emits_the_longjmp_hook()
    if FAILS:
        print(f"FAILED: {', '.join(FAILS)}")
        return 1
    print("all setjmp-helper vectors passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
