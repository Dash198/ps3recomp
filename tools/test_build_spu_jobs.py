"""Self-check for the Module-13 raw-job-bin lifter -- tools/build_spu_jobs.py.

GT6's Sound GP audio jobs reach cellSpursRunJobChain as flat binaries, not SPU
ELFs, so nothing in the workload pipeline could see them: every dispatch MISSed
and the job chain's guard timed out. build_spu_jobs.py lifts them and keys each
one by the FNV-1a-64 fingerprint of the exact bytes the title hands over. Three
things can drift without any compile or run complaint:

  * the fingerprint VALUE. runtime/spu/spu_workload.c hashes with a NON-STANDARD
    basis -- 1469598103934665603, one digit short of the canonical
    14695981039346656037. A tool that "fixes" it computes a signature that can
    never match: dispatch still MISSes, the chain still gives up, and the only
    witness is a log line. So pin both constants against the runtime source and
    check the tool reproduces each dump's own fingerprint from its bytes.
  * the ENTRY. Every one of these images opens with a 16-byte `ila $r2` content
    signature and a fixed trampoline whose `br` at 0x1C names the entry (0x30 in
    all 16 GT6 modules; CRI's jobelf says 0x71D0). Entering at 0, 0x10 or 0x18
    runs the header instead, and entering at 0x20 executes `stop` -- a job that
    silently does nothing, or halts. The `br` is the only place the entry is
    written down, so read it, and do not let a default take over.
  * the emitted REGISTRY -- one registration per dump, ids unique and clear of
    the ids the runtime hard-codes, and every symbol it names actually declared
    by the lift it points at. A wrong id or a symbol from another image links
    fine and dispatches into the wrong local store.

The names are cosmetic but hard-coded here anyway: a sniff that regresses to
`unk` for all 16 is a living directory tree that can no longer be read, and it
would go unnoticed.

Run: python tools/test_build_spu_jobs.py
"""
import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PORT = os.path.join(os.path.dirname(ROOT), "gt6")
sys.path.insert(0, HERE)
import build_spu_jobs as B                       # noqa: E402

CHECKS = 0


def check(cond, why):
    global CHECKS
    assert cond, why
    CHECKS += 1


def read(path):
    with open(path, encoding="latin1") as f:
        return f.read()


# font-family: (fingerprint from the dump's filename) -> the name the module
# carries for itself. Every one is a Sony "SDT Sound GP" / sgx audio module.
NAMES = {
    0x1A132583581116A6: "socepdideq",
    0x1B6BDAC375C5438D: "soceamp",
    0x48AF2BC79A72CB50: "socelverbx",
    0x49C1D6C47E80AF43: "socelverb",
    0x5DA195169669A5FF: "socedly",
    0x80435D36E623FAA0: "socefilter",
    0x82D0BE145EC28AEE: "socecomp",
    0x9804ABA84566F431: "soceumix",
    0x9A06064F16BA5A14: "socepdirta",
    0xABD49FC58F53F368: "socethru",
    0xC475F3E739C0945D: "socepdicomp",
    0xCB9BD0241BB0DE67: "socisynth",
    0xF523F26F69764538: "socdac3",
    0xFCAFDAA04564D5C1: "socepdidist",
    0xFDFFAAC1BCD5352E: "socedmix",
    0xFE031AF67ED048DE: "socetverb",
}

# The runtime's hard-coded image ids (spu_channels.c): 0..6 and 22/23. The job
# registry must not collide with any of them.
RESERVED_IDS = {0, 1, 2, 3, 4, 5, 6, 22, 23}


def main() -> int:
    # --- 1. the fingerprint is the runtime's, not the canonical FNV-1a-64 -----
    rt = read(os.path.join(ROOT, "runtime", "spu", "spu_workload.c"))
    check("1469598103934665603" in rt,
          "spu_workload.c no longer uses the non-standard FNV basis the "
          "registry and this tool must agree on")
    check("1099511628211" in rt, "spu_workload.c's FNV prime changed")
    check("14695981039346656037" not in rt,
          "the CANONICAL basis appeared in spu_workload.c -- if the runtime "
          "switched to it, the tool must switch too (and every golden re-record)")
    check(B.fnv1a64(b"") == 1469598103934665603,
          "fnv1a64('') must be the bare basis")
    # The name in the file is the fingerprint of the file. If this ever fails,
    # the registry is keyed to bytes the guest never supplies.
    check(B.fnv1a64(b"\x00\x01\x02\x03") == 0x28B196A081BFF727,
          "fnv1a64 disagrees with the reference implementation")

    # --- 2. every dump: fingerprint, size, entry, name ------------------------
    dumps = sorted(glob.glob(os.path.join(PORT, "spu", "misses", "spujob_*.bin")))
    check(len(dumps) == 16,
          "expected the 16 SDT Sound GP job dumps, found %d" % len(dumps))
    seen_fp = {}
    for path in dumps:
        raw = open(path, "rb").read()
        meta = B.parse_dump_name(path)
        check(meta is not None, "%s does not match spujob_<fp>_<size>.bin"
              % os.path.basename(path))
        fp, size = meta
        check(B.fnv1a64(raw) == fp,
              "%s: content does not hash to its own filename fingerprint "
              "(got 0x%016X)" % (os.path.basename(path), B.fnv1a64(raw)))
        check(len(raw) == size, "%s: file size != name" % os.path.basename(path))
        check(fp not in seen_fp, "fingerprint 0x%016X appears twice" % fp)
        seen_fp[fp] = path

        entry, how = B.entry_from_trampoline(raw, None)
        check(how == "trampoline",
              "%s: entry must be read from the 0x1C `br`, got %r"
              % (os.path.basename(path), how))
        check(entry == 0x30,
              "%s: entry is 0x%X, not the trampoline target 0x30"
              % (os.path.basename(path), entry))
        check(B.module_name(raw) == NAMES[fp],
              "%s: name sniff gave %r, expected %r"
              % (os.path.basename(path), B.module_name(raw), NAMES[fp]))

    check(set(seen_fp) == set(NAMES),
          "the dump set and the name table disagree")

    # --- 3. the emitted registry --------------------------------------------
    reg_path = os.path.join(PORT, "spu", "spu_jobs.c")
    check(os.path.exists(reg_path), "gt6/spu/spu_jobs.c is missing")
    reg = read(reg_path)
    regs = re.findall(
        r"spu_workload_register_img\(0x([0-9A-F]{16})ULL,\s*"
        r"(\w+),\s*(\d+),\s*\"([^\"]+)\"\);", reg)
    check(len(regs) == 16, "registry must register 16 images, has %d" % len(regs))

    ids, registered = [], {}
    for fp_hex, sym, img_id, label in regs:
        fp = int(fp_hex, 16)
        iid = int(img_id)
        ids.append(iid)
        check(iid not in RESERVED_IDS,
              "image id %d collides with a runtime hard-coded id" % iid)
        check(fp in NAMES,
              "registry registers 0x%016X, which is not one of the dumps" % fp)
        registered[fp] = (sym, iid, label) if fp in NAMES else None
        check(sym.endswith("_spu_func_00000030"),
              "%s: the registered symbol must be the entry the trampoline names "
              "(0x30), got %s" % (label, sym))
        check(label.startswith("job_%s_" % NAMES[fp]),
              "%s: label does not start with the module's own name" % label)
        # The lift it points at must actually declare that symbol.
        hdr = os.path.join(PORT, "spu", label, "spu_recomp.h")
        check(os.path.exists(hdr), "%s: no lifted header at %s" % (label, hdr))
        if os.path.exists(hdr):
            check(re.search(re.escape(sym) + r"\s*\(", read(hdr)) is not None,
                  "%s: header does not declare %s" % (label, sym))
            srcc = os.path.join(PORT, "spu", label, "spu_recomp.c")
            check(os.path.exists(srcc),
                  "%s: no lifted source (the build globs */spu_recomp.c)" % label)
    check(sorted(ids) == list(range(min(ids), min(ids) + 16)),
          "image ids must be one contiguous block, got %s" % sorted(ids))
    check(len(set(ids)) == 16, "image ids must be unique")
    check(ids[0] == B.JOB_IMAGE_BASE,
          "the registry's first id (%d) must be the tool's JOB_IMAGE_BASE (%d) "
          "-- a stale registry means the images were never re-registered"
          % (ids[0], B.JOB_IMAGE_BASE))
    check(B.JOB_IMAGE_BASE not in RESERVED_IDS,
          "the tool's JOB_IMAGE_BASE (%d) collides with a runtime hard-coded id"
          % B.JOB_IMAGE_BASE)
    check(set(registered) == set(NAMES),
          "registry does not cover the same images as the dumps")

    check(reg.rindex("spu_workload_register_img") < reg.index("spu_begin_image(0);"),
          "the registry must leave the image cursor at 0 after the last image")
    check(re.search(r"__attribute__\(\(constructor\)\)", reg) is not None,
          "the registry must self-register from a constructor (the runtime "
          "dispatches before main()'s first frame in some titles)")

    # --- 4. the entry reader is not a constant in disguise -------------------
    blob = open(dumps[0], "rb").read()
    check(B.entry_from_trampoline(blob, 0x1234) == (0x1234, "forced"),
          "an explicit --entry must win over the trampoline")
    check(B.entry_from_trampoline(blob, None)[0] == 0x30,
          "the trampoline read must give 0x30 for a real dump")
    # The fallback is what runs when an image carries no trampoline `br` at all.
    # Pin the number, not the constant: comparing against B.DEFAULT_ENTRY would
    # let a changed default through.
    check(B.DEFAULT_ENTRY == 0x30,
          "the fallback entry must stay 0x30 (the trampoline target every "
          "SDT/WWS job binary seen names)")
    check(B.entry_from_trampoline(b"\x00" * 0x40, None) == (0x30, "default"),
          "an image with no `br` at 0x1C must fall back to 0x30, not read "
          "garbage")

    # --- 5. the build actually compiles the registry -------------------------
    cm = read(os.path.join(PORT, "CMakeLists.txt"))
    check(re.search(r"ITEMS[^)]*\bspu_jobs\.c\b", cm) is not None,
          "gt6/CMakeLists.txt does not list spu_jobs.c among the generated "
          "SPU TUs, so the registry would not be compiled")
    check("file(GLOB SPU_LIFTED" in cm and "*/spu_recomp.c" in cm,
          "the SPU source glob changed; lifted job dirs may no longer build")

    # --- 6. small pure helpers ----------------------------------------------
    check(B.sanitize("soce filter") == "soce_filter", "sanitize must fold junk")
    check(B.sanitize("2ch").startswith("m_"), "sanitize must not emit a "
          "leading digit into a C identifier")
    check(B.parse_dump_name("/x/spujob_ABD49FC58F53F368_9488.bin")
          == (0xABD49FC58F53F368, 9488), "parse_dump_name must read fp and size")
    check(B.parse_dump_name("spujob_ABD49FC58F53F36_9488.bin") is None,
          "a 15-hex fingerprint must be rejected -- the runtime writes 16")
    check(B.parse_dump_name("spujob_abc.bin") is None,
          "parse_dump_name must reject names that carry no fingerprint")

    print("ok: %d checks (fingerprint basis, entry, names, registry wiring)"
          % CHECKS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
