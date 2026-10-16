#!/usr/bin/env python3
"""Unit vectors for spbalance.py: stack balance + the frame-moving census.

No ELF, no SDK: each vector is a hand-written fragment of the lifted C the
lifter emits, in a throwaway tree on disk, parsed by the same code path the real
tree uses.

Why this test exists: spbalance.py reported zero imbalances on GT6's 70,027
lifted functions, and a checker that reports zero is indistinguishable from a
checker that is broken -- this tool was in fact broken that way for a while
(51,482 phantom imbalances) after the lifter changed its epilogue emission. So
every class the tool claims to find has a vector here that makes it fire:

  - a body that allocates and returns without restoring  -> IMBALANCED
  - a body with a goto label                             -> unverifiable
  - a continuation body (no prologue)                     -> unverifiable
  - a dynamic frame (stdux / mr r1,rN)                    -> unverifiable + move
  - a setjmp context restore (whole reg file off one base) -> CONTEXT RESTORE
  - ... without the ppu_lj_do hook the lifter emits        -> UNHANDLED (the
                                                              Module 3 bug class)
  - a direct caller of a context restore                  -> call site counted

Run: python tools/test_spbalance.py
"""

import os
import shutil
import subprocess
import sys
import tempfile

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS)

import spbalance as S                                   # noqa: E402

SPB = os.path.join(TOOLS, "spbalance.py")
TMP = tempfile.mkdtemp(prefix="spbalance-test-", dir="/tmp/opencode")

FAILS = []


def check(name, got, want):
    if got == want:
        print(f"ok   {name}")
    else:
        print(f"FAIL {name}: got {got!r}, want {want!r}")
        FAILS.append(name)


# --- the lifted-C fragments -------------------------------------------------
# Each is what ppu_lifter.py emits for the PowerPC shape named in the comment.

BALANCED = """\
void func_00001000(ppu_context* ctx) {
        vm_write64(ctx->gpr[1] + -0x70, ctx->gpr[1]); ctx->gpr[1] += -0x70;
        ctx->gpr[0] = ctx->lr;
        ctx->gpr[3] = ctx->gpr[3] | ((uint64_t)0x154 << 16);
        ctx->gpr[0] = vm_read64(ctx->gpr[1] + 0x80);
        ctx->lr = ctx->gpr[0];
        ctx->gpr[1] = ctx->gpr[1] + (int64_t)(0x70);
        return;
}
"""

# allocates 0x70, returns restoring 0 -> leaks 0x70 into its caller
UNBALANCED = """\
void func_00002000(ppu_context* ctx) {
        vm_write64(ctx->gpr[1] + -0x70, ctx->gpr[1]); ctx->gpr[1] += -0x70;
        ctx->gpr[0] = ctx->lr;
        return;
}
"""

# an early-exit inline return, then the main epilogue; both restore the frame,
# and the conditional one must not make the rest of the body unreachable
CONDITIONAL_EXIT = """\
void func_00003000(ppu_context* ctx) {
        vm_write64(ctx->gpr[1] + -0x70, ctx->gpr[1]); ctx->gpr[1] += -0x70;
        ctx->gpr[0] = ctx->lr;
        if (((ctx->cr >> 0) & 2)) { ctx->gpr[1] = ctx->gpr[1] + (int64_t)(0x70); return; }
        ctx->gpr[3] = ctx->gpr[3] | ((uint64_t)0x154 << 16);
        ctx->gpr[1] = ctx->gpr[1] + (int64_t)(0x70);
        return;
}
"""

# a goto label: control can re-enter after an earlier return, so the allocation
# on the path to a return is not derivable from the text
HAS_LABEL = """\
void func_00004000(ppu_context* ctx) {
        vm_write64(ctx->gpr[1] + -0x70, ctx->gpr[1]); ctx->gpr[1] += -0x70;
        if (((ctx->cr >> 0) & 2)) goto loc_00004020;
        ctx->gpr[3] = ctx->gpr[3] | 0x1;
loc_00004020:
        ctx->gpr[1] = ctx->gpr[1] + (int64_t)(0x70);
        return;
}
"""

# a continuation: no prologue of its own, it restores a frame allocated by a
# previous chunk (the lifter splits one function across bodies this way)
CONTINUATION = """\
void func_00005000(ppu_context* ctx) {
        ctx->gpr[0] = vm_read64(ctx->gpr[1] + 0x80);
        ctx->lr = ctx->gpr[0];
        ctx->gpr[1] = ctx->gpr[1] + (int64_t)(0x70);
        return;
}
"""

# stdux: the frame is sized at run time, so the restore is not a constant and a
# constant-bracket check cannot say anything about it
DYNAMIC_FRAME = """\
void func_00006000(ppu_context* ctx) {
        vm_write64(ctx->gpr[1] + -0x70, ctx->gpr[1]); ctx->gpr[1] += -0x70;
        ctx->gpr[28] = ctx->gpr[1] | ctx->gpr[1];
        { uint64_t ea = ctx->gpr[1] + ctx->gpr[9]; vm_write64(ea, ctx->gpr[0]); ctx->gpr[1] = ea; }
        ctx->gpr[1] = ctx->gpr[28] | ctx->gpr[28];
        return;
}
"""

# libgcc __restgprlr_14: r1 AND a broad slice of the non-volatile file reloaded
# from one base that is not the frame pointer (r3 is the caller's jmp_buf)
CONTEXT_RESTORE_HEAD = """\
void func_00BDD050(ppu_context* ctx) {
        ctx->gpr[14] = vm_read64(ctx->gpr[3] + 0x18);
        ctx->gpr[15] = vm_read64(ctx->gpr[3] + 0x20);
        ctx->gpr[16] = vm_read64(ctx->gpr[3] + 0x28);
        ctx->gpr[17] = vm_read64(ctx->gpr[3] + 0x30);
        ctx->gpr[18] = vm_read64(ctx->gpr[3] + 0x38);
        ctx->gpr[19] = vm_read64(ctx->gpr[3] + 0x40);
        ctx->gpr[20] = vm_read64(ctx->gpr[3] + 0x48);
        ctx->gpr[21] = vm_read64(ctx->gpr[3] + 0x50);
        ctx->gpr[22] = vm_read64(ctx->gpr[3] + 0x58);
        ctx->gpr[23] = vm_read64(ctx->gpr[3] + 0x60);
        ctx->gpr[24] = vm_read64(ctx->gpr[3] + 0x68);
        ctx->gpr[25] = vm_read64(ctx->gpr[3] + 0x70);
        ctx->gpr[26] = vm_read64(ctx->gpr[3] + 0x78);
        ctx->gpr[27] = vm_read64(ctx->gpr[3] + 0x80);
        ctx->gpr[28] = vm_read64(ctx->gpr[3] + 0x88);
        ctx->gpr[29] = vm_read64(ctx->gpr[3] + 0x90);
        ctx->gpr[30] = vm_read64(ctx->gpr[3] + 0x98);
        ctx->gpr[31] = vm_read64(ctx->gpr[3] + 0xA0);
        ctx->gpr[0] = vm_read64(ctx->gpr[3] + 0x8);
        ctx->gpr[1] = vm_read64(ctx->gpr[3] + 0x0);
        ctx->lr = ctx->gpr[0];
"""

# Module 4 handles it: the lifter injects the block/sp captures and ppu_lj_do
CONTEXT_RESTORE_HOOK = """\
        uint64_t _sj_blk = PPU_SJ_ALIGN(ctx->gpr[3]);
        uint64_t _sj_sp  = ctx->gpr[1];
        ppu_lj_do(ctx, _sj_blk, _sj_sp);
        return;
}
"""

CONTEXT_RESTORE_UNHANDLED = CONTEXT_RESTORE_HEAD + "        return;\n}\n"
CONTEXT_RESTORE_HANDLED = CONTEXT_RESTORE_HEAD + CONTEXT_RESTORE_HOOK

# a caller: the call is a direct bl, so the tool can name the site
CALLER = """\
void func_00007000(ppu_context* ctx) {
        vm_write64(ctx->gpr[1] + -0x80, ctx->gpr[1]); ctx->gpr[1] += -0x80;
        ctx->gpr[0] = ctx->lr;
        ctx->lr = 0x00007030; func_00BDD050(ctx); DRAIN_TRAMPOLINE(ctx);
        ctx->gpr[0] = vm_read64(ctx->gpr[1] + 0x90);
        ctx->lr = ctx->gpr[0];
        ctx->gpr[1] = ctx->gpr[1] + (int64_t)(0x80);
        return;
}
"""

GUARD = """\
void func_00008000(ppu_context* ctx) {
        vm_write64(ctx->gpr[1] + -0x70, ctx->gpr[1]); ctx->gpr[1] += -0x70;
        ctx->gpr[0] = ctx->lr;
        ctx->lr = 0x00008020; PPU_SETJMP_GUARD(ctx, func_00BDCF2C);
        ctx->gpr[0] = vm_read64(ctx->gpr[1] + 0x80);
        ctx->lr = ctx->gpr[0];
        ctx->gpr[1] = ctx->gpr[1] + (int64_t)(0x70);
        return;
}
"""


def write_tree(name, text):
    root = os.path.join(TMP, name)
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "ppu_recomp_000.cpp"), "w", encoding="utf-8") as f:
        f.write(text)
    return root


def run_cli(args):
    p = subprocess.run([sys.executable, SPB] + args,
                       capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


# --- vectors ---------------------------------------------------------------

def test_balanced_body_is_checkable_and_clean():
    root = write_tree("balanced", BALANCED)
    funcs = S.parse(root)
    assert S._pattern_sanity(funcs)
    bad, cov = S.balance(funcs)
    check("balanced body has no imbalance", bad, [])
    check("balanced body is checkable", cov["checkable"], 1)


def test_unbalanced_body_fires():
    root = write_tree("unbalanced", UNBALANCED)
    funcs = S.parse(root)
    bad, cov = S.balance(funcs)
    check("unbalanced body is found", [(n, alloc) for n, _, alloc in bad],
          [("func_00002000", 0x70)])
    check("unbalanced body's restore is 0", [r for _, rs, _ in bad for r in rs], [0])


def test_conditional_return_keeps_later_returns_reachable():
    root = write_tree("cond", CONDITIONAL_EXIT)
    funcs = S.parse(root)
    # both the earlier conditional return and the final one are recorded
    check("conditional exit does not hide the later return",
          len(funcs["func_00003000"]["returns"]), 2)
    bad, cov = S.balance(funcs)
    check("conditional-exit body is checkable", cov["checkable"], 1)
    check("conditional-exit body is clean", bad, [])


def test_label_body_is_unverifiable():
    root = write_tree("label", HAS_LABEL)
    funcs = S.parse(root)
    check("goto label is the reason",
          S._unverifiable_reason(funcs["func_00004000"]),
          "goto labels (needs reachability)")
    bad, _ = S.balance(funcs)
    check("label body is not reported as an imbalance", bad, [])


def test_continuation_body_is_unverifiable():
    root = write_tree("continuation", CONTINUATION)
    funcs = S.parse(root)
    check("continuation is the reason",
          S._unverifiable_reason(funcs["func_00005000"]),
          "no prologue (continuation body)")


def test_dynamic_frame_is_unverifiable_and_counted_as_a_move():
    root = write_tree("dynframe", DYNAMIC_FRAME)
    funcs = S.parse(root)
    check("stdux is seen as a move", funcs["func_00006000"]["moves"], ["ea", "mr"])
    check("dynamic frame is unverifiable",
          S._unverifiable_reason(funcs["func_00006000"]),
          "r1 moved by a non-constant amount (dynamic frame)")
    bad, _ = S.balance(funcs)
    check("dynamic frame is not an imbalance", bad, [])


def test_context_restore_detection():
    root = write_tree("ctxrestore", CONTEXT_RESTORE_UNHANDLED + CALLER + GUARD)
    funcs = S.parse(root)
    c = S.census(funcs)
    check("exactly one context restore", c["ctx_restores"], ["func_00BDD050"])
    check("unhooked context restore is UNHANDLED",
          c["ctx_restores_unhandled"], ["func_00BDD050"])   # the Module 3 class
    check("its direct caller is counted",
          c["ctx_restore_callers"], {"func_00BDD050": [("func_00007000", 1)]})
    check("the setjmp guard site is counted", len(c["guards"]), 1)
    check("no longjmp hook in this tree", c["longjmp_hooks"], [])
    d = S.baseline_dict(funcs, *S.balance(funcs), c)
    check("baseline reports the unhandled count", d["context_restores_unhandled"], 1)
    check("baseline reports the call site count",
          d["context_restore_call_sites"], 1)


def test_context_restore_with_the_module4_hook_is_handled():
    root = write_tree("ctxhandled", CONTEXT_RESTORE_HANDLED + CALLER)
    funcs = S.parse(root)
    c = S.census(funcs)
    check("with the hook the restore is handled", c["ctx_restores_unhandled"], [])
    check("the hook is counted", c["longjmp_hooks"], ["func_00BDD050"])
    # the restore reloads r1 from the block, so it is a move by definition --
    # and it is the *only* one here
    check("the context restore is the only move", c["move_functions"], ["func_00BDD050"])


def test_stale_patterns_are_refused():
    """ALLOC matching while BRACKET does not is the exact stale state this tool
    shipped in; it must refuse rather than report phantoms."""
    stale = "".join(
        f"""\
void func_{0x100000 + i * 4:08X}(ppu_context* ctx) {{
        vm_write64(ctx->gpr[1] + -0x70, ctx->gpr[1]); ctx->gpr[1] += -0x70;
        return;
}}
""" for i in range(101))
    root = write_tree("stale", stale)
    funcs = S.parse(root)
    check("stale emission is detected", S._pattern_sanity(funcs), False)


def test_baseline_roundtrip_and_diff():
    root = write_tree("baseline", BALANCED + UNBALANCED)
    funcs = S.parse(root)
    imbalances, cov = S.balance(funcs)
    c = S.census(funcs)
    cur = S.baseline_dict(funcs, imbalances, cov, c)
    path = os.path.join(TMP, "baseline", "spbalance_baseline.txt")
    S.write_baseline(path, cur)
    check("baseline round-trips", S.read_baseline(path), cur)

    lines, fail = S.diff_against_baseline(cur, cur)
    check("identical census passes", fail, False)

    grown = dict(cur, imbalanced_bodies=cur["imbalanced_bodies"] + 1)
    lines, fail = S.diff_against_baseline(grown, cur)
    check("an increased count fails", fail, True)
    check("and says so", any("INCREASE" in l for l in lines), True)

    shrunk = dict(cur, checkable_bodies=cur["checkable_bodies"] - 1)
    lines, fail = S.diff_against_baseline(shrunk, cur)
    check("shrinking coverage fails", fail, True)
    check("and says why", any("coverage must not shrink" in l for l in lines), True)

    smaller = dict(cur, r1_move_functions=0)
    lines, fail = S.diff_against_baseline(smaller, cur)
    check("a non-coverage decrease is fine", fail, False)

    lines, fail = S.diff_against_baseline(dict(cur, brand_new_key=3),
                                          {k: v for k, v in cur.items() if k != "longjmp_hooks"})
    check("a new nonzero key fails", fail, True)


def test_cli_exit_codes():
    root = write_tree("cli", BALANCED + UNBALANCED + CONTEXT_RESTORE_HANDLED)
    base = os.path.join(TMP, "cli", "baseline.txt")

    rc, out = run_cli([root, "--baseline", base, "--update-baseline"])
    check("--update-baseline exits 0", rc, 0)
    check("--update-baseline writes the file", os.path.exists(base), True)

    rc, out = run_cli([root, "--baseline", base])
    check("stable tree exits 0", rc, 0)
    check("stable tree reports PASS", "PASS" in out, True)

    with open(base, "w", encoding="utf-8") as f:
        f.write("imbalanced_bodies\t0\n")
    rc, out = run_cli([root, "--baseline", base])
    check("regression exits 1", rc, 1)
    check("regression reports FAIL", "FAIL" in out, True)

    rc, out = run_cli([os.path.join(TMP, "stale"), "--baseline",
                       os.path.join(TMP, "stale", "b.txt")])
    check("stale patterns exit 2", rc, 2)
    check("stale patterns say so", "patterns are stale" in out, True)

    rc, out = run_cli([os.path.join(TMP, "does-not-exist")])
    check("missing directory exits 2", rc, 2)


def main() -> int:
    try:
        test_balanced_body_is_checkable_and_clean()
        test_unbalanced_body_fires()
        test_conditional_return_keeps_later_returns_reachable()
        test_label_body_is_unverifiable()
        test_continuation_body_is_unverifiable()
        test_dynamic_frame_is_unverifiable_and_counted_as_a_move()
        test_context_restore_detection()
        test_context_restore_with_the_module4_hook_is_handled()
        test_stale_patterns_are_refused()
        test_baseline_roundtrip_and_diff()
        test_cli_exit_codes()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    if FAILS:
        print(f"FAILED: {', '.join(FAILS)}")
        return 1
    print("all spbalance vectors passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
