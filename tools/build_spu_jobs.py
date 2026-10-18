#!/usr/bin/env python3
"""build_spu_jobs.py -- lift a title's RAW SPU job binaries and register them.

A SPURS jobchain job is not an SPU ELF and not a policy module. The SDK's
`job_elf-to-bin` turns the linked job ELF into a flat image; the title loads
those bytes from its own data files and hands them to cellSpursRunJobChain. The
runtime never sees an ELF header, so:

  * tools/extract_spu_images.py cannot find them (they are not in the EBOOT),
  * and tools/build_spu_workloads.py cannot size or fingerprint them.

The only place the bytes exist is spu_workload_dispatch_job()'s MISS path,
which (with SPU_DUMP_MISS=<dir>) writes one file per unknown image:

    <dir>/spujob_<FNV1a64 of the image>_<size in bytes>.bin

This tool lifts those dumps and emits a registration TU that keys each lifted
image by the SAME FNV-1a-64 fingerprint the runtime computes, so the next
dispatch of the same bytes is a HIT.

Image layout (shared by every SDT/WWS job binary seen so far -- e.g. Sony's
"SDT Sound GP" soce* modules and CRI's jobelf):

    0x00  16 bytes   four `ila $r2, imm`  -- a content SIGNATURE, not code
    0x10  8 bytes    `xori $r80,$r80,4 ; br +4`.
    0x18  8 bytes    `xori $r80,$r80,4 ; br <ENTRY>`  <- the ENTRY is this `br`
    0x20  16 bytes   reserved (`stop 0` x4)
    0x30  ...        code; the module's real CRT/main lives further in

The double `xori` cancels and nothing before 0x30 is data the entry consumes, so
entering at the trampoline target is equivalent to executing the header first.
Reading ENTRY from the `br` at 0x1C (rather than assuming 0x30) keeps this
correct for modules whose CRT is not the first function -- e.g. CRI's reads
`br 0x71D0`.

The job is staged at local-store address 0 by the runtime (spurs_job.c) and the
module is position-independent, so every image lifts at base 0.

Output: <lifted>/<img>/spu_recomp.{c,h}, <lifted>/spu_jobs_manifest.json, and
the registration TU (--out).

Usage:
  python tools/build_spu_jobs.py \
      --jobs <port>/spu/misses --lifted <port>/spu \
      --out <port>/spu/spu_jobs.c \
      --register-fn gt6_spu_jobs_register_all --title gt6 --constructor
"""
import argparse
import glob
import json
import os
import re
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wrap_spu_elf import wrap                      # noqa: E402
from spu_disasm import spu_decode                  # noqa: E402

# PIC seeding helpers, shared with the WWS jobmodule lifter: a SPURS job is
# position-independent, so computed branches (`a $r0,$r0,$base ; bi $r0` and
# `switch` tables) are materialised at run time and no branch names them.
# lift_jobmods seeds them from the module bytes; the same idioms are emitted by
# the same SDK for these modules, so reuse the exact scans.
from lift_jobmods import manual_link_targets, switch_table_targets  # noqa: E402

# Image ids for fingerprinted job images. Clear of the ids the runtime hard-codes
# (0..6, and 22/23 = the CRI task runner / resolver-only image) and of the WWS
# jobmodule overlays (>=200).
JOB_IMAGE_BASE = 40

BASE = 0x0                 # jobs are staged at LS 0 by spurs_job.c
TRAMPOLINE_BR = 0x1C       # the header `br` that names the entry
DEFAULT_ENTRY = 0x30       # fallback if the trampoline is not a plain `br`

# Two ways these modules carry their own name. Both are strictly cosmetic (the
# directory/prefix label); the fingerprint of the bytes is the real key.
#   * an SDT/Sound-GP style info block with a `name = <x>` line (14 of 16 here),
#   * Sony's 16-byte NUL-padded `spu_name` field, used when there is no text
#     block (e.g. `socisynth`, `socdac3`).
_NAME_TEXT_RE = re.compile(rb"name[ \t]*=[ \t]*([ -~]{1,40}?)[\r\n]")
_NAME_FIELD_RE = re.compile(rb"[A-Za-z][A-Za-z0-9_]{3,15}\x00")


def fnv1a64(b: bytes) -> int:
    """Byte-identical to spu_workload_fingerprint() in runtime/spu/spu_workload.c."""
    h = 1469598103934665603
    for x in b:
        h = ((h ^ x) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


def sanitize(name: str) -> str:
    s = re.sub(r"[^0-9A-Za-z_]", "_", name).strip("_")
    if not s or s[0].isdigit():
        s = "m_" + s
    return s


def module_name(raw: bytes) -> str:
    """The name this job module carries for itself, or `unk`.

    Purely cosmetic: it names the lifted directory and the registry comment.
    The 16-byte name field lives in the module-info section the linker drops
    among rodata; nothing after it decodes as an identifier, so the last
    16-byte-aligned candidate is it. A wrong label is harmless (the fingerprint
    is what dispatches), which is why this stays a sniff and never fails."""
    m = _NAME_TEXT_RE.search(raw)
    if m:
        return sanitize(m.group(1).decode("ascii", "replace"))
    cands = [mm for mm in _NAME_FIELD_RE.finditer(raw) if mm.start() % 16 == 0]
    if cands:
        return sanitize(cands[-1].group()[:-1].decode("ascii", "replace"))
    return "unk"


def entry_from_trampoline(raw: bytes, override: int):
    """The `br` target at 0x1C, or `override` if the caller forced one.

    Returns (entry, how) so the manifest records whether it was read or forced.
    """
    if override is not None:
        return override, "forced"
    if len(raw) >= TRAMPOLINE_BR + 4:
        ins = spu_decode(struct.unpack_from(">I", raw, TRAMPOLINE_BR)[0],
                         TRAMPOLINE_BR)
        if ins.mnemonic in ("br", "bra"):
            t = ins.operands.split(",")[-1].strip()
            if t.startswith("0x"):
                v = int(t, 16) & 0xFFFFF
                if BASE <= v < BASE + len(raw):
                    return v, "trampoline"
    return DEFAULT_ENTRY, "default"


def debase_includes(path: str):
    """Rewrite the depth-sensitive relative includes the lifter emits so the
    lifted tree is location-independent (resolved via the build -I path)."""
    try:
        txt = open(path, encoding="utf-8", errors="ignore").read()
    except OSError:
        return
    new = re.sub(r'#include\s+"(?:\.\./)+runtime/spu/([A-Za-z0-9_]+\.h)"',
                 r'#include "\1"', txt)
    if new != txt:
        open(path, "w", encoding="utf-8", newline="\n").write(new)


def parse_dump_name(path: str):
    """spujob_<FP16>_<size>.bin -> (fp, size). None if it does not match."""
    m = re.fullmatch(r"spujob_([0-9A-Fa-f]{16})_(\d+)\.bin", os.path.basename(path))
    if not m:
        return None
    return int(m.group(1), 16), int(m.group(2))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--jobs", required=True,
                    help="Directory of spujob_<fp>_<size>.bin dumps "
                         "(SPU_DUMP_MISS output).")
    ap.add_argument("--lifted", required=True,
                    help="Directory to lift into: <lifted>/<img>/spu_recomp.{c,h}.")
    ap.add_argument("--out", required=True,
                    help="Registration TU to write (e.g. <port>/spu/spu_jobs.c).")
    ap.add_argument("--register-fn", default="spu_jobs_register_all",
                    help="Name of the emitted registration function.")
    ap.add_argument("--title", default="port", help="Label used in comments.")
    ap.add_argument("--entry", default=None, metavar="ADDR",
                    help="Force the entry LS address for every image "
                         "(default: read the trampoline `br` at 0x1C).")
    ap.add_argument("--lifter", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "spu_lifter.py"))
    ap.add_argument("--constructor", action="store_true",
                    help="Also emit an __attribute__((constructor)) that "
                         "registers at startup.")
    ap.add_argument("--relift", action="store_true",
                    help="Re-lift even if a prior lift exists.")
    ap.add_argument("--skip-lift", action="store_true",
                    help="Do not run the lifter; assume --lifted is populated "
                         "(still fixes includes + emits the registry).")
    args = ap.parse_args()

    override = int(args.entry, 0) if args.entry is not None else None

    dumps = sorted(glob.glob(os.path.join(args.jobs, "*.bin")))
    if not dumps:
        sys.exit(f"[build_spu_jobs] no *.bin in {args.jobs}")

    imgs = []   # dict(name,img,prefix,fp,size,entry,how,funcs,unsupported,switch)
    tmp_elf = os.path.join(args.lifted, "_job_tmp.elf")
    os.makedirs(args.lifted, exist_ok=True)

    for path in dumps:
        raw = open(path, "rb").read()
        meta = parse_dump_name(path)
        if meta is None:
            print(f"[build_spu_jobs] skip (not a spujob_ dump): {path}")
            continue
        want_fp, want_size = meta
        got_fp = fnv1a64(raw)
        # A mismatch means the dump does not correspond to the fingerprint the
        # runtime computes over these very bytes -- registering it would look
        # right and never HIT, so refuse loudly instead.
        if got_fp != want_fp or len(raw) != want_size:
            sys.exit(f"[build_spu_jobs] {os.path.basename(path)}: fingerprint/size "
                     f"mismatch -- got fp=0x{got_fp:016X} size={len(raw)}, filename "
                     f"says fp=0x{want_fp:016X} size={want_size}. Re-dump.")
        entry, how = entry_from_trampoline(raw, override)
        name = module_name(raw)
        img = f"job_{name}_{got_fp & 0xFFFFFFFF:08X}"
        prefix = img + "_"
        outsub = os.path.join(args.lifted, img)
        srcc = os.path.join(outsub, "spu_recomp.c")

        switch = switch_table_targets(raw, base=BASE)
        manual = manual_link_targets(raw, base=BASE)
        # Only seed addresses that land inside this image (the scans are exact,
        # but a malformed module must not sprout out-of-range entries).
        extra = sorted({BASE + entry_g for entry_g in (entry,)}
                       | {a for a in switch if BASE <= a < BASE + len(raw)}
                       | {a for a in manual if BASE <= a < BASE + len(raw)})

        funcs = unsup = 0
        if not args.skip_lift and (args.relift or not os.path.exists(srcc)):
            os.makedirs(outsub, exist_ok=True)
            with open(tmp_elf, "wb") as f:
                f.write(wrap(raw, base=BASE, entry=entry))
            cmd = [sys.executable, args.lifter, "--auto-functions", tmp_elf,
                   "--base", hex(BASE), "--symbol-prefix", prefix, "-o", outsub,
                   "--source-name", "spu_recomp.c", "--header-name", "spu_recomp.h"]
            if extra:
                cmd += ["--extra-funcs", ",".join(hex(a) for a in extra)]
            print(f"[build_spu_jobs] LIFT {img}  entry=0x{entry:X} ({how}) "
                  f"size={len(raw)} seeds={len(extra)}")
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                sys.exit(f"[build_spu_jobs] lift FAILED for {img}\n{r.stderr}")
            for line in r.stdout.splitlines():
                s = line.strip()
                if s.endswith("function(s) lifted"):
                    funcs = int(s.split()[0])
                if "unsupported instruction(s)" in s:
                    unsup = int(s.split()[0])
        else:
            print(f"[build_spu_jobs] reuse lift {img}")

        debase_includes(os.path.join(outsub, "spu_recomp.h"))
        debase_includes(srcc)

        # The entry symbol must exist, or the registry names a function the
        # linker cannot resolve.
        hdr = os.path.join(outsub, "spu_recomp.h")
        sym = f"{prefix}spu_func_{entry:08X}"
        if os.path.exists(hdr) and f"{sym}(" not in open(hdr, encoding="utf-8",
                                                        errors="ignore").read():
            sys.exit(f"[build_spu_jobs] {img}: entry symbol {sym}({entry:#x}) not in "
                     f"the lifted header -- the entry guess is wrong")

        imgs.append(dict(name=name, img=img, prefix=prefix, fp=got_fp,
                         size=len(raw), entry=entry, how=how, funcs=funcs,
                         unsupported=unsup, switch_targets=len(switch)))

    if os.path.exists(tmp_elf):
        os.remove(tmp_elf)
    if not imgs:
        sys.exit("[build_spu_jobs] nothing lifted")

    with open(os.path.join(args.lifted, "spu_jobs_manifest.json"), "w") as f:
        json.dump(imgs, f, indent=2)

    emit_register(args, imgs)
    tot = sum(m["unsupported"] for m in imgs)
    print(f"[build_spu_jobs] {len(imgs)} job image(s), {tot} unsupported "
          f"instruction(s), image ids {JOB_IMAGE_BASE}..{JOB_IMAGE_BASE + len(imgs) - 1}")
    for m in imgs:
        print(f"    {m['img']:36} entry=0x{m['entry']:05X} ({m['how']:10}) "
              f"funcs={m['funcs']:3} unsup={m['unsupported']}")


def emit_register(args, imgs):
    L = []
    L.append(f"/* {os.path.basename(args.out)} -- GENERATED by tools/build_spu_jobs.py.")
    L.append(f" * Registers the {len(imgs)} lifted RAW SPU job binaries of \"{args.title}\"")
    L.append(" * with the workload dispatch registry, keyed by the FNV-1a-64 fingerprint of")
    L.append(" * the exact bytes the title hands to cellSpursRunJobChain(). spurs_job.c stages")
    L.append(" * the image at local store 0 and enters at the image's own crt trampoline")
    L.append(" * target, so every image lifts at base 0 and is registered under its own id. */")
    L.append('#include "spu_workload.h"')
    L.append("")
    L.append("extern void spu_begin_image(int image_id);")
    L.append("")
    for m in imgs:
        L.append(f"extern void {m['prefix']}spu_func_{m['entry']:08X}(spu_context*);")
        L.append(f"extern void {m['prefix']}spu_recomp_register(void);")
    L.append("")
    L.append(f"void {args.register_fn}(void)")
    L.append("{")
    for i, m in enumerate(imgs):
        img_id = JOB_IMAGE_BASE + i
        L.append(f"    /* {m['name']} -- src {m['size']} bytes, entry 0x{m['entry']:05X} "
                 f"({m['how']}) */")
        L.append(f"    spu_begin_image({img_id}); {m['prefix']}spu_recomp_register();")
        L.append(f"    spu_workload_register_img(0x{m['fp']:016X}ULL, "
                 f"{m['prefix']}spu_func_{m['entry']:08X}, {img_id}, \"{m['img']}\");")
    L.append("    spu_begin_image(0);")
    L.append("}")
    if args.constructor:
        L.append("")
        L.append("/* Auto-register at startup, before the game builds any job chain. */")
        L.append(f"__attribute__((constructor)) static void {args.register_fn}_ctor(void)")
        L.append("{")
        L.append(f"    {args.register_fn}();")
        L.append("}")
    L.append("")
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    open(args.out, "w", encoding="utf-8", newline="\n").write("\n".join(L))
    print(f"[build_spu_jobs] wrote {args.out}")


if __name__ == "__main__":
    main()
