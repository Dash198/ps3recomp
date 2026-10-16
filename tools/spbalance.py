#!/usr/bin/env python3
"""spbalance.py - stack-balance and frame-moving census over lifted PPU output.

Two questions, both about `r1`.

1. STACK BALANCE. A lifted function allocates its frame with
   `gpr[1] += -N` and returns it with `gpr[1] = gpr[1] + (int64_t)(N)` before a
   real `return`. A body whose return restores something other than what its
   prologue allocated corrupts sp for its caller.

   That check is only sound on bodies this tool can read without reachability
   analysis: exactly one prologue, no `goto` labels, no trampoline handoff, and
   no return before the prologue. A body with a `loc_` label can be entered by a
   backward `goto` that ran before an earlier return, and the lifter's chunking
   also glues fragments of neighbouring functions into one emitted body, so for
   those the cumulative allocation on the path to a return is not derivable from
   the text. Rather than guess -- which is what an earlier revision of this tool
   did, reporting 51,482 phantom imbalances -- those bodies are counted as
   UNVERIFIABLE and the check runs on the sound subset only. The coverage count
   is part of the baseline and must not decrease.

2. FRAME-MOVING CALLEES. The balance check above only sees a function's own
   `addi r1, r1, N` brackets. A callee that rewrites `r1` out from under its
   caller is invisible to it, and that was exactly the `setjmp`/`longjmp`
   blocker (RECOMP_STATUS Module 3): libgcc's `__restgprlr_14` (`func_00BDD050`
   in GT6) reloads the WHOLE non-volatile register file -- `r1` and the `lr`
   included -- from the caller's jmp_buf, then ends in `blr` to the reloaded
   `lr`. Lifted as an ordinary returning call, the caller resumed with the
   jmp_buf's old sp and leaked 0x390 per round trip, until sp walked off the end
   of the VM arena.

   So this tool also classifies every non-bracket write to `r1`:

     - `gpr[1] = ea`              `stdux`   -- dynamic-size frame update
     - `gpr[1] = gpr[N]|gpr[N]`   `mr r1,rN` -- sp restored from a saved register
     - `gpr[1] = vm_read64(...)`            -- sp reloaded from memory; the base
                                               decides whether it is this
                                               function's own frame
                                               (`ld r1, off(r31)`) or a foreign
                                               context block (`ld r1, 0(r3)`)

   A CONTEXT RESTORE is the last form where the same base also feeds a broad
   register-file reload (>= 8 distinct registers): that base is a setjmp block,
   not a frame. Those are the callees whose callers cannot assume `r1` survives.
   Since Module 4 the lifter marks them with a `ppu_lj_do` hook (the runtime
   longjmps instead of returning), so a context restore WITHOUT that hook is the
   regression this tool exists to catch. Measured on GT6: 105 frame-moving
   functions (98 dynamic-frame, 104 sp-from-register, 9 sp-from-memory), of
   which exactly one -- `func_00BDD050` -- is a context restore, and it is
   hooked.

Usage:
    python spbalance.py <dir-with-ppu_recomp_*.cpp> [--focus func_XXXXXXXX]
                        [--baseline scratch/spbalance_baseline.txt]
                        [--update-baseline]

Exit status: 0 no new finding vs baseline (or --update-baseline), 1 a finding
increased or the checked coverage decreased, 2 the file patterns no longer match
the lifter's emission or no input was found.
"""
import argparse
import collections
import glob
import os
import re
import sys

# --- what the lifter emits today -------------------------------------------
# Pinned by tools/test_ppu_setjmp_helpers.py and by the generated output in
# recomp/. ALLOC and BRACKET are the fragile pair: if the epilogue emission
# changes and BRACKET stops matching, every prologue looks un-restored.
SIG      = re.compile(r'^void (func_[0-9A-Fa-f]{8})\(ppu_context\* ctx\) \{')
LABEL    = re.compile(r'^loc_[0-9A-Fa-f]+:')
ALLOC    = re.compile(r'ctx->gpr\[1\] \+= -(0x[0-9A-Fa-f]+);')
BRACKET  = re.compile(r'ctx->gpr\[1\] = ctx->gpr\[1\] \+ \(int64_t\)\((-?)0x([0-9A-Fa-f]+)\);')
R1_EA    = re.compile(r'ctx->gpr\[1\] = ea;')
R1_MR    = re.compile(r'ctx->gpr\[1\] = ctx->gpr\[(\d+)\] \| ctx->gpr\[\d+\];')
R1_LDMEM = re.compile(r'ctx->gpr\[1\] = vm_read64\(ctx->gpr\[(\d+)\] \+ 0x[0-9A-Fa-f]+\);')
LD64     = re.compile(r'ctx->gpr\[(\d+)\] = vm_read64\(ctx->gpr\[(\d+)\] \+ 0x[0-9A-Fa-f]+\);')
TRAMP    = re.compile(r'g_trampoline_fn = \(void\(\*\)\(void\*\)\)(func_[0-9A-Fa-f]{8})')
CALL     = re.compile(r'(func_[0-9A-Fa-f]{8})\(ctx\);')
GUARD    = re.compile(r'PPU_SETJMP_GUARD\(ctx, (func_[0-9A-Fa-f]{8})\)')
LJHOOK   = re.compile(r'\bppu_lj_do\(ctx, ')

# A jmp_buf reload touches the whole non-volatile file; the frame reloads the
# lifter emits for alloca-style sp switches touch 2-5. 8 separates them with a
# wide margin (measured on GT6: 5 vs 22).
CTX_RESTORE_MIN_REGS = 8

DEFAULT_BASELINE = os.path.join("scratch", "spbalance_baseline.txt")


def parse(d):
    """name -> record. One pass per chunk, flushing at each definition."""
    funcs = {}

    def flush(name, body):
        text = ''.join(body)

        # Linear walk: `returns` is (restore_at_return, came_before_prologue),
        # one entry per real return. Control-flow exits are tracked so that a
        # fragment glued after one is not attributed to this body's prologue.
        returns = []
        last_rest = 0
        seen_prologue = False
        reachable = True
        n_prologues = 0
        labels = 0
        n_tramps = 0
        for ln in body:
            if LABEL.match(ln):
                labels += 1
                reachable = True
            if ALLOC.search(ln):
                n_prologues += len(ALLOC.findall(ln))
                if reachable:
                    seen_prologue = True
            m = BRACKET.search(ln)
            if m and reachable:
                last_rest = (-1 if m.group(1) else 1) * int(m.group(2), 16)
            stripped = ln.strip()
            # An exit ends reachability only when it is UNCONDITIONAL: the
            # lifter writes those as a bare `return;` or a `{ g_trampoline_fn
            # ... }` block. A conditional return is inlined as `if (...) { ...;
            # return; }`, so control continues and later returns are still
            # reachable -- dropping them would silently shrink the check.
            if 'g_trampoline_fn' in ln:
                n_tramps += len(TRAMP.findall(ln))
                if stripped.startswith('{'):
                    last_rest = 0
                    reachable = False
            elif re.search(r'\breturn;', ln):
                if reachable:
                    returns.append((last_rest, not seen_prologue))
                if stripped == 'return;':
                    last_rest = 0
                    reachable = False

        alloc = sum(int(x, 16) for x in ALLOC.findall(text))

        moves = []
        if R1_EA.search(text):
            moves.append("ea")
        if any(r != "1" for r in R1_MR.findall(text)):
            moves.append("mr")
        r1_bases = R1_LDMEM.findall(text)
        if r1_bases:
            moves.append("ldmem")

        # Context restore: r1 reloaded from a base that is not the frame
        # pointer, and that same base feeds a broad register-file reload.
        by_base = collections.defaultdict(set)
        for rd, ra in LD64.findall(text):
            by_base[ra].add(rd)
        ctx_restore = any(b != "1" and len(by_base[b]) >= CTX_RESTORE_MIN_REGS
                          for b in r1_bases)

        funcs[name] = dict(
            alloc=alloc, n_prologues=n_prologues, brackets=len(BRACKET.findall(text)),
            returns=returns, labels=labels, n_tramps=n_tramps,
            calls=CALL.findall(text),      # list: duplicate sites are counted
            moves=moves, ctx_restore=ctx_restore,
            guards=GUARD.findall(text), longjmp_hook=bool(LJHOOK.search(text)),
        )

    for path in sorted(glob.glob(os.path.join(d, 'ppu_recomp_*.cpp'))):
        cur = None
        body = []
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                m = SIG.match(line)
                if m:
                    if cur:
                        flush(cur, body)
                    cur = m.group(1)
                    body = []
                elif cur is not None:
                    if line.startswith('}'):
                        flush(cur, body)
                        cur = None
                        body = []
                    else:
                        body.append(line)
        if cur:
            flush(cur, body)
    return funcs


def _pattern_sanity(funcs):
    """Refuse to report if the r1 bracket patterns stopped matching.

    ALLOC surviving while BRACKET does not is exactly how this tool went stale
    once: the epilogue emission changed from `(int64_t)(int32_t)(r1 + N)` to
    `r1 + (int64_t)(N)`, BRACKET matched nothing, every prologue looked like an
    un-restored leak, and the tool printed 51,482 phantom imbalances. A tool
    that cries wolf is worse than no tool, so this is a hard error.
    """
    alloc_fns = sum(1 for f in funcs.values() if f['alloc'] > 0)
    bracket_fns = sum(1 for f in funcs.values() if f['brackets'] > 0)
    if alloc_fns >= 100 and bracket_fns == 0:
        print("ERROR: prologue allocations found but no epilogue brackets -- the "
              "r1 emission patterns are stale (see BRACKET in this file). "
              "Refusing to report.", file=sys.stderr)
        return False
    return True


def _unverifiable_reason(f):
    """Why a body is outside the sound subset (None == it is checkable)."""
    if f['moves']:
        # r1 is rewritten by something other than a constant bracket, so there
        # is no constant to compare a return's restore against: alloca-style
        # dynamic frames (stdux / `mr r1, rN`), and the setjmp context restores.
        return "r1 moved by a non-constant amount (dynamic frame)"
    if f['n_prologues'] == 0:
        return "no prologue (continuation body)"
    if f['n_prologues'] > 1:
        return "more than one prologue (glued fragments)"
    if not f['returns']:
        return "no real return (tail-only body)"
    if any(pre for _, pre in f['returns']):
        return "leading continuation fragment before the prologue"
    if f['labels']:
        return "goto labels (needs reachability)"
    if f['n_tramps']:
        return "trampoline handoff (needs reachability)"
    return None


def balance(funcs, focus=None):
    """(imbalances, coverage) over the bodies that are sound to check.

    imbalance entry: (name, restores_seen, allocated).
    """
    imbalances = []
    coverage = collections.Counter()
    for n, f in sorted(funcs.items()):
        if focus and n != focus:
            continue
        reason = _unverifiable_reason(f)
        if reason:
            coverage[reason] += 1
            continue
        coverage["checkable"] += 1
        bad = [r for r, _ in f['returns'] if r != f['alloc']]
        if bad:
            imbalances.append((n, sorted(set(bad)), f['alloc']))
    return imbalances, coverage


def census(funcs):
    """The frame-moving class: every count the baseline ratchets on."""
    ctx = [n for n, f in funcs.items() if f['ctx_restore']]
    unhandled = [n for n in ctx if not funcs[n]['longjmp_hook']]
    # a context restore reached by a direct call: the caller cannot assume r1
    # survives it (it longjmps now, so the fall-through is unreachable -- but a
    # *new* such caller means new code is relying on the old broken behaviour).
    callers = collections.OrderedDict()
    for callee in ctx:
        sites = [(n, f['calls'].count(callee)) for n, f in sorted(funcs.items())
                 if callee in f['calls']]
        if sites:
            callers[callee] = sites
    return dict(
        move_functions=[n for n, f in funcs.items() if f['moves']],
        ctx_restores=ctx,
        ctx_restores_unhandled=unhandled,
        ctx_restore_callers=callers,
        ctx_restore_call_sites=sum(k for sites in callers.values() for _, k in sites),
        guards=[(n, g) for n, f in funcs.items() for g in f['guards']],
        longjmp_hooks=[n for n, f in funcs.items() if f['longjmp_hook']],
    )


def build_report(funcs, imbalances, coverage, c):
    lines = []
    prologues = sum(1 for f in funcs.values() if f['n_prologues'])
    brackets = sum(1 for f in funcs.values() if f['brackets'] > 0)
    lines.append(f"parsed {len(funcs)} functions; {prologues} with a prologue; "
                 f"{brackets} with a bracket epilogue")
    lines.append("")

    lines.append("=== 1. stack balance (bodies checkable without reachability) ===")
    lines.append(f"checkable bodies: {coverage['checkable']}")
    unver = sum(v for k, v in coverage.items() if k != "checkable")
    lines.append(f"unverifiable bodies: {unver}")
    for reason, cnt in sorted(coverage.items(), key=lambda kv: -kv[1]):
        if reason != "checkable":
            lines.append(f"  {cnt:6d}  {reason}")
    lines.append(f"IMBALANCED bodies: {len(imbalances)}")
    for i, (n, bad, alloc) in enumerate(imbalances):
        if i >= 40:
            lines.append(f"  ... {len(imbalances) - 40} more")
            break
        lines.append(f"  {n}: alloc=0x{alloc:X} but returns restoring "
                     f"{', '.join(f'0x{b & 0xFFFFFFFFFFFFFFFF:X}' for b in bad)}")
    lines.append("")

    lines.append("=== 2. functions that move r1 by a non-constant amount ===")
    lines.append(f"frame-moving functions: {len(c['move_functions'])}")
    kinds = collections.Counter()
    for n in c['move_functions']:
        for k in funcs[n]['moves']:
            kinds[k] += 1
    lines.append(f"  dynamic-frame update stores (stdux) : {kinds['ea']}")
    lines.append(f"  r1 from a saved register (mr r1,rN): {kinds['mr']}")
    lines.append(f"  r1 reloaded from memory             : {kinds['ldmem']}")
    lines.append(f"CONTEXT RESTORES (full register file from one non-frame base): "
                 f"{len(c['ctx_restores'])}")
    for n in c['ctx_restores']:
        handled = "handled by ppu_lj_do" if funcs[n]['longjmp_hook'] else "NO HOOK (unhandled!)"
        lines.append(f"  {n}: {handled}")
    if c['ctx_restores_unhandled']:
        lines.append(f"  !! unhandled context restores (guest stack corruption on "
                     f"every call): {len(c['ctx_restores_unhandled'])}")
    lines.append("")

    lines.append("=== 3. call sites that cannot assume r1 survives ===")
    lines.append(f"setjmp guard sites (PPU_SETJMP_GUARD): {len(c['guards'])}")
    shown = collections.Counter(n for n, _ in c['guards'])
    for n, cnt in list(shown.items())[:12]:
        lines.append(f"  {n}: {cnt}")
    if len(shown) > 12:
        lines.append(f"  ... {len(shown) - 12} more callers")
    lines.append(f"longjmp hooks (ppu_lj_do): {len(c['longjmp_hooks'])}")
    for n in c['longjmp_hooks']:
        lines.append(f"  {n}")
    lines.append(f"context restores reached by a direct call: "
                 f"{c['ctx_restore_call_sites']} site(s)")
    for callee, sites in c['ctx_restore_callers'].items():
        total = sum(k for _, k in sites)
        lines.append(f"  -> {callee}: {total} site(s) from {len(sites)} caller(s), "
                     f"first {sites[0][0]}  (r1 rewinds here; the callee "
                     f"longjmps, so the fall-through is unreachable)")
    lines.append("")
    return "\n".join(lines)


# Coverage must not go DOWN: a shrinking checkable set means the tool quietly
# stopped verifying something, which is how it went stale before.
MUST_NOT_DECREASE = ("checkable_bodies",)


def baseline_dict(funcs, imbalances, coverage, c):
    """Flat key->count dict, the same shape as tools/lift_audit.py's baseline."""
    return {
        "imbalanced_bodies": len(imbalances),
        "checkable_bodies": coverage["checkable"],
        "r1_move_functions": len(c['move_functions']),
        "context_restores": len(c['ctx_restores']),
        "context_restores_unhandled": len(c['ctx_restores_unhandled']),
        "setjmp_guard_sites": len(c['guards']),
        "longjmp_hooks": len(c['longjmp_hooks']),
        "context_restore_call_sites": c['ctx_restore_call_sites'],
    }


def write_baseline(path, d):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("# spbalance.py baseline -- generated file, do not hand-edit.\n")
        f.write("# key<TAB>count, one per line, sorted by key.\n")
        f.write("# checkable_bodies must not decrease (coverage ratchet).\n")
        for k in sorted(d):
            f.write(f"{k}\t{d[k]}\n")


def read_baseline(path):
    if not os.path.exists(path):
        return None
    d = {}
    with open(path, "r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line or line.startswith("#"):
                continue
            k, _, v = line.partition("\t")
            if v.strip():
                d[k] = int(v.strip())
    return d


def diff_against_baseline(current, baseline):
    """A NEW anomaly is a key whose count increased, or a nonzero key absent
    from the baseline. A MUST_NOT_DECREASE key that shrank is also an anomaly.
    Other decreases are fine (same reading as tools/lift_audit.py)."""
    lines, fail = [], False
    any_diff = False
    for k in sorted(set(current) | set(baseline)):
        cur = current.get(k, 0)
        base = baseline.get(k, 0)
        if cur == base:
            continue
        any_diff = True
        if k not in baseline and cur > 0:
            lines.append(f"  NEW key {k}: {cur} (not in baseline) -- FAIL")
            fail = True
        elif cur > base:
            lines.append(f"  INCREASE {k}: {base} -> {cur} (+{cur - base}) -- FAIL")
            fail = True
        elif k in MUST_NOT_DECREASE:
            lines.append(f"  DECREASE {k}: {base} -> {cur} ({cur - base}) -- FAIL "
                         f"(coverage must not shrink)")
            fail = True
        else:
            lines.append(f"  decrease {k}: {base} -> {cur} ({cur - base}) -- ok")
    if not any_diff:
        lines.append("  (no diff vs baseline)")
    return lines, fail


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir", nargs="?", default=".",
                    help="directory holding ppu_recomp_*.cpp (default: .)")
    ap.add_argument("--focus", help="only check one body")
    ap.add_argument("--baseline", default=DEFAULT_BASELINE,
                    help=f"baseline file (default: {DEFAULT_BASELINE})")
    ap.add_argument("--update-baseline", action="store_true",
                    help="write the current census as the new baseline and exit 0")
    args = ap.parse_args()

    if not glob.glob(os.path.join(args.dir, "ppu_recomp_*.cpp")):
        print(f"ERROR: no ppu_recomp_*.cpp in {args.dir} -- has this tree ever "
              f"been lifted?", file=sys.stderr)
        return 2

    funcs = parse(args.dir)
    if not _pattern_sanity(funcs):
        return 2

    imbalances, coverage = balance(funcs, args.focus)
    c = census(funcs)
    print(build_report(funcs, imbalances, coverage, c))

    current = baseline_dict(funcs, imbalances, coverage, c)
    if args.update_baseline:
        write_baseline(args.baseline, current)
        print(f"=== Baseline written: {args.baseline} ({len(current)} keys) ===")
        return 0

    baseline = read_baseline(args.baseline)
    if baseline is None:
        print(f"=== No baseline at {args.baseline} -- run with --update-baseline "
              f"to seed one. Skipping diff. ===")
        return 0

    print(f"=== Diff vs baseline ({args.baseline}) ===")
    diff_lines, fail = diff_against_baseline(current, baseline)
    for ln in diff_lines:
        print(ln)
    if fail:
        print("=== FAIL: new stack-balance / frame-moving finding vs baseline ===")
        return 1
    print("=== PASS: no new finding vs baseline ===")
    return 0


if __name__ == '__main__':
    sys.exit(main())
