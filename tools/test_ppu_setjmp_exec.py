#!/usr/bin/env python3
"""Executed guest setjmp/longjmp vectors (the G1 regression, run for real).

`test_ppu_setjmp_helpers.py` pins the *shape* of the classification and the
*text* of the two emissions. It never runs them, so it cannot tell a landing pad
that works from one that compiles and does nothing. This is the executed
companion: it lifts the save helper, the restore helper and two callers with the
REAL PPULifter, compiles the emitted C together with the REAL runtime machinery
(`runtime/ppu/ppu_setjmp.inc` -- the exact text `ppu_loader.cpp` compiles), and
lets a real `longjmp` run. Then it checks what the resume actually did.

Why the .inc and not a copy: a hand-written stand-in for ppu_sj_slot / ppu_lj_do
would test the copy, not the runtime, and drift the first time either side
changed. Only the two things `ppu_loader.cpp` owns and the harness cannot link
are stubbed here -- the guest memory read (`vm_read64`) and the vcall /
trampoline bookkeeping that `ppu_lj_do` restores and clears.

What is executed (all words are GT6's, per test_ppu_setjmp_helpers.py):

    call site     bl <save helper>       -> PPU_SETJMP_GUARD (arms a pad HERE)
    save helper   align; align; std r1   -> writes the setjmp-time sp into block[0]
    restore       align; align; ld r1    -> ppu_lj_do(blk, entry sp) at the blr
    callback      (host) calls the restore helper -- the guest's longjmp

Vectors:
  1  one round trip   the jump lands after the guard in the caller's frame, sp
                      is the setjmp sp, the vcall state is unwound, a pending
                      trampoline is cleared, and -- the proof it JUMPED -- the
                      statement after the guard runs a second time.
  2  many round trips the slot table and the restored state stay sane.
  3  misaligned block a block handed over misaligned still resolves: the arm
                      site and the jump site apply the same PPU_SJ_ALIGN.
  4  dead target      the setjmp frame is DEEPER than the jump (saved sp <
                      current sp): refused rather than jumped into, caller runs on.
  5  never armed      a block that was never armed is refused, no jump.

Usage:
    python tools/test_ppu_setjmp_exec.py          # lift + compile + run
    python tools/test_ppu_setjmp_exec.py --emit   # just write the C file
"""

import argparse
import os
import shutil
import subprocess
import sys

TOOLS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TOOLS)
sys.path.insert(0, TOOLS)

import ppu_disasm                                                   # noqa: E402
from ppu_lifter import (PPULifter, FENCE_PREAMBLE,                  # noqa: E402
                        discover_setjmp_helpers)

# Guest addresses of the synthetic image. The helpers keep their real bodies;
# the callers are the minimum that exercises the mechanism.
SAV = 0x1000        # align; align; std r1,0x0(r3); blr
RES = 0x2000        # align; align; ld  r1,0x0(r3); blr
CB = 0x3000         # the host callback (not lifted): calls the restore helper
CALLER1 = 0x4000    # bl SAV; bl CB; blr                (sp constant)
CALLER4 = 0x4100    # bl SAV; addi r1,r1,0x100; bl CB; blr   (deeper than the pad)

BLK1, BLK2 = 0x1000, 0x2000     # guest context blocks inside the 64 KB stub
SP0 = 0x7FFF0000                # guest r1 at the setjmp call
VCSP_ARM, VCDEPTH_ARM = 7, 3    # vcall state when the pad was armed
ROUNDTRIPS = 8

# Words lifted verbatim out of EMAIN.elf (func_00BDCF2C / func_00BDD050).
W_ALIGN15 = 0x3863000F     # addi   r3, r3, 15
W_RLDICR = 0x786306E4      # rldicr r3, r3, 0, 59
W_STD_R1 = 0xF8230000      # std    r1, 0x0(r3)  -> save helper
W_LD_R1 = 0xE8230000       # ld     r1, 0x0(r3)  -> restore helper
W_BLR = (19 << 26) | (20 << 21) | (16 << 1)


def w_bl(from_addr, to_addr):
    """`bl to_addr` placed at from_addr (I-form, LK=1)."""
    return (18 << 26) | ((to_addr - from_addr) & 0x03FFFFFC) | 1


def w_addi(rt, ra, si):
    return (14 << 26) | (rt << 21) | (ra << 16) | (si & 0xFFFF)


def dec(words, base):
    return [ppu_disasm.decode(w, base + 4 * i) for i, w in enumerate(words)]


def build_lift():
    """Decode the words and lift them with the real lifter. Returns
    (lifter, funcs, all_insns) or exits with an ENCODING/classification error."""
    sav_w = [W_ALIGN15, W_RLDICR, W_STD_R1, W_BLR]
    res_w = [W_ALIGN15, W_RLDICR, W_LD_R1, W_BLR]
    c1_w = [w_bl(CALLER1, SAV), w_bl(CALLER1 + 4, CB), W_BLR]
    c4_w = [w_bl(CALLER4, SAV), w_addi(1, 1, 0x100), w_bl(CALLER4 + 8, CB), W_BLR]

    all_insns = (dec(sav_w, SAV) + dec(res_w, RES)
                 + dec(c1_w, CALLER1) + dec(c4_w, CALLER4))
    # Round-trip the encodings: a wrong word here must report as ENCODING, never
    # as a false lifter/runtime failure.
    want = ["addi", "rldicr", "std", "blr",
            "addi", "rldicr", "ld", "blr",
            "bl", "bl", "blr",
            "bl", "addi", "bl", "blr"]
    got = [i.mnemonic for i in all_insns]
    if got != want:
        print(f"ENCODING mismatch:\n  got  {got}\n  want {want}")
        sys.exit(2)

    lifter = PPULifter()
    # Wire the executed vector to the REAL classifier rather than hardcoding the
    # helper addresses: if discovery ever stops seeing the idiom, this is red.
    savers, restorers = discover_setjmp_helpers(all_insns, {SAV, RES})
    if savers != {SAV} or restorers != {RES}:
        print(f"CLASSIFY mismatch: savers={savers!r} restorers={restorers!r}")
        sys.exit(2)
    lifter.setjmp_savers = savers
    lifter.setjmp_restorers = restorers

    funcs = {
        SAV: lifter.lift_function(all_insns, SAV, SAV + 16),
        RES: lifter.lift_function(all_insns, RES, RES + 16),
        CALLER1: lifter.lift_function(all_insns, CALLER1, CALLER1 + 12),
        CALLER4: lifter.lift_function(all_insns, CALLER4, CALLER4 + 16),
    }

    # The emissions this test exists to execute. Same assertions as the static
    # sibling, but here a missing one would also make the run meaningless.
    c1 = "\n".join(funcs[CALLER1].body_lines)
    c4 = "\n".join(funcs[CALLER4].body_lines)
    res = "\n".join(funcs[RES].body_lines)
    for what, ok in (
        ("caller1 arms the pad", f"PPU_SETJMP_GUARD(ctx, func_{SAV:08X});" in c1),
        ("caller4 arms the pad", f"PPU_SETJMP_GUARD(ctx, func_{SAV:08X});" in c4),
        ("callers call the callback", f"func_{CB:08X}(ctx)" in c1 and f"func_{CB:08X}(ctx)" in c4),
        ("restore body jumps", "ppu_lj_do(ctx, _sj_blk, _sj_sp);" in res),
        ("restore captures the entry sp", "uint64_t _sj_sp  = ctx->gpr[1];" in res),
    ):
        if not ok:
            print(f"EMISSION mismatch: {what} is absent\n--- caller1\n{c1}"
                  f"\n--- caller4\n{c4}\n--- restore\n{res}")
            sys.exit(2)
    return lifter, funcs


DRIVER_HEAD = r'''
/* ---- the two things ppu_loader.cpp owns that this harness cannot link ------ */
#include <stdlib.h>

static int g_pass = 0, g_fail = 0;
static void sj_check(const char* name, unsigned long long got, unsigned long long want) {
    if (got != want) { printf("FAIL %s: got 0x%llX want 0x%llX\n", name, got, want); g_fail++; }
    else g_pass++;
}

/* 64 KB big-endian scratch page, the same VM stub the instruction conformance
 * driver uses; the guest context block lives in it. */
static uint8_t g_vm_stub[65536];
extern "C" uint64_t vm_read64(uint64_t a) {
    uint64_t v; memcpy(&v, g_vm_stub + ((uint32_t)a & 0xFFFFu), 8);
    return __builtin_bswap64(v);
}
extern "C" void vm_write64(uint64_t a, uint64_t v) {
    v = __builtin_bswap64(v); memcpy(g_vm_stub + ((uint32_t)a & 0xFFFFu), &v, 8);
}

/* vcall bookkeeping + the trampoline pointer. ppu_loader.cpp defines these
 * above the include point; ppu_lj_do unwinds/clears them on a jump. */
static PPU_THREAD_LOCAL int g_vcall_sp = 0;
static PPU_THREAD_LOCAL int g_vcall_depth = 0;
extern "C" PPU_THREAD_LOCAL void (*g_trampoline_fn)(void*) = nullptr;
static void sj_dummy_tramp(void*) {}
extern "C" int g_ppu_guest_pc = 0;
extern "C" void ppu_guest_pc_enter(ppu_context*, uint32_t) {}

/* ---- the REAL machinery: the exact text ppu_loader.cpp compiles ------------- */
#include "ppu_setjmp.inc"
'''


def emit(path, funcs):
    lifter = PPULifter()
    pre = lifter._preamble_lines()
    # Same substitution the instruction conformance driver makes: the generated
    # per-game header is replaced by the bare context header this driver needs.
    pre[0] = pre[0].replace('#include "ppu_recomp.h"',
                            '#include "ppu_context.h"\n#include <stdint.h>\n'
                            + FENCE_PREAMBLE)

    out = ["/* Auto-generated by tools/test_ppu_setjmp_exec.py -- DO NOT EDIT. */",
           "#define _CRT_SECURE_NO_WARNINGS"]
    out.extend(pre)
    out.append(DRIVER_HEAD)

    out.append("/* ---- lifted functions (emitted by PPULifter, verbatim) ---- */")
    out.append(f"void func_{CB:08X}(ppu_context* ctx);   /* host callback, defined below */")
    for addr in (SAV, RES, CALLER1, CALLER4):
        out.append(f"void func_{addr:08X}(ppu_context* ctx);")
    for addr in (SAV, RES, CALLER1, CALLER4):
        out.append(f"void func_{addr:08X}(ppu_context* ctx) {{")
        # Same shape as _function_def_lines: G5 names the running guest function.
        out.append(f"    PPU_SET_PC(ctx, 0x{addr:08X});")
        out.extend(funcs[addr].body_lines)
        out.append("}")

    # The callback is the guest's `longjmp` caller: a host function that drives
    # the restore helper. It runs TWICE per successful round trip -- once from
    # the guarded call, once from the resume point after the jump -- which is
    # exactly how the test tells a jump from a plain return.
    out.append(f'''
/* ---- the callback + scenario state ---------------------------------------- */
static unsigned long long g_cb_runs = 0;
static unsigned long long g_sp_at_resume = 0;
static uint64_t g_cb_block_override = 0;

void func_{CB:08X}(ppu_context* ctx) {{
    g_cb_runs++;
    if (g_cb_runs == 1) {{
        if (g_cb_block_override) ctx->gpr[3] = g_cb_block_override;
        g_vcall_sp = {VCSP_ARM + 92}; g_vcall_depth = {VCDEPTH_ARM + 85};   /* frames the jump unwinds past */
        g_trampoline_fn = sj_dummy_tramp;              /* must be cleared on the jump */
        func_{RES:08X}(ctx);                           /* the guest's longjmp */
    }} else {{
        g_sp_at_resume = ctx->gpr[1];                  /* only reached if it JUMPED */
    }}
}}

static ppu_context g_ctx;

static void sj_reset(uint64_t blk, uint64_t sp) {{
    memset(&g_ctx, 0, sizeof(g_ctx));
    memset(g_vm_stub, 0, sizeof(g_vm_stub));
    g_ctx.gpr[1] = sp;
    g_ctx.gpr[3] = blk;
    g_cb_runs = 0; g_sp_at_resume = 0; g_cb_block_override = 0;
    g_vcall_sp = {VCSP_ARM}; g_vcall_depth = {VCDEPTH_ARM};
    g_trampoline_fn = nullptr;
}}

int main(void) {{
    ppu_context* ctx = &g_ctx;

    /* 1. one round trip: the jump resumes AFTER the guard, in the caller. */
    sj_reset(0x{BLK1:X}, 0x{SP0:X});
    func_{CALLER1:08X}(ctx);
    sj_check("V1 callback ran twice (the longjmp resumed after the guard)", g_cb_runs, 2);
    sj_check("V1 r1 at the resume is the setjmp-time sp", g_sp_at_resume, 0x{SP0:X}ULL);
    sj_check("V1 r1 after the round trip is the setjmp-time sp", (unsigned long long)ctx->gpr[1], 0x{SP0:X}ULL);
    sj_check("V1 g_vcall_sp unwound to the arm-time value", (unsigned long long)(unsigned)g_vcall_sp, {VCSP_ARM});
    sj_check("V1 g_vcall_depth unwound to the arm-time value", (unsigned long long)(unsigned)g_vcall_depth, {VCDEPTH_ARM});
    sj_check("V1 the pending trampoline was cleared by the jump", g_trampoline_fn == nullptr, 1);

    /* 2. many round trips: the slot table + restored state stay sane. */
    for (int i = 0; i < {ROUNDTRIPS}; i++) {{
        sj_reset(0x{BLK1:X}, 0x{SP0:X});
        func_{CALLER1:08X}(ctx);
        sj_check("V2 round trip: the jump resumed", g_cb_runs, 2);
        sj_check("V2 round trip: r1 is the setjmp-time sp", (unsigned long long)ctx->gpr[1], 0x{SP0:X}ULL);
        sj_check("V2 round trip: vcall sp restored", (unsigned long long)(unsigned)g_vcall_sp, {VCSP_ARM});
    }}

    /* 3. a misaligned block: the arm site and the jump site must align alike. */
    sj_reset(0x{BLK1:X} + 3, 0x{SP0:X});
    g_cb_block_override = 0x{BLK1:X} + 3;
    func_{CALLER1:08X}(ctx);
    sj_check("V3 misaligned block still resolves (both sites align)", g_cb_runs, 2);

    /* 4. the pad is DEEPER than the jump: refuse, do not jump into a dead frame. */
    sj_reset(0x{BLK1:X}, 0x{SP0:X});
    func_{CALLER4:08X}(ctx);              /* pops r1 by 0x100 before the callback */
    sj_check("V4 non-ancestor jump refused (no resume)", g_cb_runs, 1);
    sj_check("V4 the helper body still reloaded r1 from the block", (unsigned long long)ctx->gpr[1], 0x{SP0:X}ULL);

    /* 5. a block that was never armed: refuse, no jump. */
    sj_reset(0x{BLK1:X}, 0x{SP0:X});
    g_cb_block_override = 0x{BLK2:X};
    func_{CALLER1:08X}(ctx);
    sj_check("V5 unarmed block refused (no resume)", g_cb_runs, 1);

    printf("[ppu-setjmp-exec] %d checks, %d failures\\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}}
''')
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {path} ({len(out)} lines)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--emit", action="store_true", help="only write the C file")
    args = ap.parse_args()

    lifter, funcs = build_lift()

    os.makedirs(os.path.join(ROOT, "scratch"), exist_ok=True)
    cpath = os.path.join(ROOT, "scratch", "ppu_setjmp_exec.cpp")
    epath = os.path.join(ROOT, "scratch",
                         "ppu_setjmp_exec.exe" if os.name == "nt" else "ppu_setjmp_exec")
    log = os.path.join(ROOT, "scratch", "ppu_setjmp_exec.log")
    emit(cpath, funcs)
    if args.emit:
        return 0

    # Compiled AND run: the emissions and the runtime only meet in a running
    # longjmp, and for a long time a missing compiler silently reduced a suite
    # like this to "the C generates". Windows self-launches vcvars, as
    # test_ppu_lift.py does; everywhere else use the system compiler.
    if os.name == "nt":
        from msvc_env import find_vcvars
        vcvars = find_vcvars() or ""
        bat = os.path.join(ROOT, "scratch", "ppu_setjmp_exec_run.bat")
        with open(bat, "w") as f:
            f.write("@echo off\n")
            f.write(f'call "{vcvars}" >nul 2>nul\n')
            f.write(f'cd /d "{ROOT}"\n')
            f.write(f'cl /nologo /O1 /W3 /I runtime\\ppu /Fe:"{epath}" "{cpath}" > "{log}" 2>&1\n')
            f.write("if errorlevel 1 exit /b 2\n")
            f.write(f'"{epath}" >> "{log}" 2>&1\n')
        rc = subprocess.run(["cmd", "/c", bat], cwd=ROOT).returncode
    else:
        cxx = (os.environ.get("CXX") or shutil.which("c++")
               or shutil.which("clang++") or shutil.which("g++"))
        if not cxx:
            rc = 2
            with open(log, "w") as f:
                f.write("no C++ compiler found (set CXX)\n")
        else:
            with open(log, "w") as f:
                cp = subprocess.run([cxx, "-std=c++17", "-O1", "-w",
                                     "-I", os.path.join("runtime", "ppu"),
                                     "-o", epath, cpath],
                                    cwd=ROOT, stdout=f, stderr=subprocess.STDOUT)
            if cp.returncode != 0:
                rc = 2
            else:
                with open(log, "a") as f:
                    rc = subprocess.run([epath], cwd=ROOT, stdout=f,
                                        stderr=subprocess.STDOUT).returncode

    tail = open(log).read() if os.path.exists(log) else ""
    for ln in tail.splitlines():
        if ln.startswith("FAIL") or "[ppu-setjmp-exec]" in ln or "error" in ln.lower()[:6]:
            print(ln)
    if rc == 2:
        no_compiler = ("is not recognized as an internal or external command" in tail
                       or "no C++ compiler found" in tail)
        if no_compiler:
            print("SKIPPED: no C++ compiler available -- the generated setjmp "
                  "driver was NOT compiled or run, so the executed vectors did "
                  "not run.")
            # A CI skip here is a false green: this suite IS the execution.
            if os.environ.get("CI"):
                print("...and this is CI, where skipping the only executed "
                      "setjmp test is a failure, not a pass.")
                return 1
            return 0
        print(f"COMPILE FAILED -- see {log}")
        return 1
    if rc != 0:
        print(f"RUN FAILED (rc={rc}) -- see {log}")
        return 1
    summary = next((ln for ln in tail.splitlines() if "[ppu-setjmp-exec]" in ln), "")
    print(summary or "ran, but printed no summary")
    return 0


if __name__ == "__main__":
    sys.exit(main())
