"""Self-check for the Module-12 HLE answers -- the five imports the title reaches
and the port used to answer with a silent zero.

Why this is a source/wiring test and not a unit test: the handlers live in
libs/ (C, compiled into ps3recomp_runtime) and most of them are four lines long.
What they must get right is not control flow but *numbers* -- the guest-visible
offsets, the error codes, and above all the NID each one is registered under. A
NID is SHA-1(name + suffix)[:4], so a renamed handler, or a registration the
generator silently drops, makes the guest's import fall back to the unresolved
path and answer CELL_OK with untouched out-params -- precisely the failure this
module exists to remove, and one that "it compiled" cannot catch. So:

  * each of the five guest NIDs, taken from GT6's import table, hashes to the
    handler name we define for it -- including the trap pair
    `cellFiberPpuInitialize` vs `_cellFiberPpuInitialize`, which are different
    NIDs (only the underscore one is imported by any title);
  * `gen_hle_nids.py --all` really registers all five, with those NIDs, and does
    not register one twice (the wiring, end to end);
  * the offsets and error codes are the reference's, and the handler bodies
    actually use them (a constant that no longer reaches the code is not a fix);
  * the unresolved path now prints the guest caller and the arguments, so a miss
    stays traceable.

The reference numbers are from RPCS3 (cellSpurs.h/cellSpurs.cpp, cellVideoOut.h,
cellAvconfExt.cpp); the offsets are also the SDK's, which is why the port's
pre-existing SPURS constants already agreed with them.

Run: python tools/test_hle_answers.py
"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from nid_database import compute_nid             # noqa: E402

CHECKS = 0


def check(cond, why):
    global CHECKS
    assert cond, why
    CHECKS += 1


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="latin1") as f:
        return f.read()


def c_body(src, name):
    """The body of the C function `name` (definition, not a declaration)."""
    m = re.search(r"^[A-Za-z_][\w \t\*]*?\b" + re.escape(name) +
                  r"\s*\([^;]*?\)\s*\{", src, re.M)
    if not m:
        return None
    i = src.index("{", m.end() - 1)
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i:j + 1]
    return None


def c_define(text, macro):
    m = re.search(r"#define\s+" + re.escape(macro) + r"\s+(.+)$", text, re.M)
    return m.group(1).strip() if m else None


def c_enum_value(src, name):
    """The value of an enumerator, e.g. SPURS_WKL_FLAG = 0x60."""
    m = re.search(re.escape(name) + r"\s*=\s*(0[xX][0-9A-Fa-f]+|\d+)", src)
    return int(m.group(1), 0) if m else None


# ---------------------------------------------------------------------------
# The five, as GT6 imports them (analysis/EMAIN.imports.json), by library.
# ---------------------------------------------------------------------------
ANSWERS = {
    0x55870804: ("cellFiber", "_cellFiberPpuInitialize"),
    0xFAA275A4: ("cellSysutilAvconfExt", "cellVideoOutGetScreenSize"),
    0x2DDBCC0A: ("cellSpurs", "_cellSpursWorkloadFlagReceiver2"),
    0xC765B995: ("cellSpurs", "cellSpursGetWorkloadFlag"),
    0x30AA96C4: ("cellSpurs", "cellSpursInitializeWithAttribute2"),
}


def main() -> int:
    # --- 1. NID identity ----------------------------------------------------
    for nid, (lib, name) in ANSWERS.items():
        check(compute_nid(name) == nid,
              "%s: 0x%08X is not the hash of %s (got 0x%08X)"
              % (lib, nid, name, compute_nid(name)))

    # The trap: the SDK exports the initialiser under an underscore and
    # cellFiberPpuInitialize is the header's wrapper. They are different NIDs, and
    # no firmware PRX exports the non-underscore name -- so a handler named
    # without it answers a NID that does not exist while the imported one falls
    # through. Pin both facts.
    check(compute_nid("_cellFiberPpuInitialize") == 0x55870804,
          "the underscore name must be the imported NID")
    check(compute_nid("cellFiberPpuInitialize") == 0x5BF7D922,
          "cellFiberPpuInitialize is a different NID (0x5BF7D922), so it cannot "
          "stand in for 0x55870804")
    check(0x5BF7D922 != 0x55870804, "the two cellFiber init NIDs must differ")

    # --- 2. the generator registers all five --------------------------------
    tmp = tempfile.mkdtemp(prefix="hle_answers_")
    out = os.path.join(tmp, "ppu_hle_nids.cpp")
    r = subprocess.run([sys.executable, os.path.join(HERE, "gen_hle_nids.py"),
                        "--out", out, "--all"],
                       cwd=ROOT, capture_output=True, text=True)
    check(r.returncode == 0, "gen_hle_nids.py --all failed: %s" % r.stderr[-400:])
    table = open(out, encoding="latin1").read()
    regs = re.findall(r'ps3_hle_register\(0x([0-9A-F]{8})u,\s*"([^"]+)"', table)
    bynid = {}
    for nid_hex, name in regs:
        bynid.setdefault(int(nid_hex, 16), []).append(name)
    for nid, (lib, name) in ANSWERS.items():
        check(name in bynid.get(nid, []),
              "the table does not register %s at 0x%08X (entry: %r)"
              % (name, nid, bynid.get(nid)))
    check(all(len(v) == 1 for v in bynid.values()),
          "a NID is registered twice: %r"
          % sorted((nid, v) for nid, v in bynid.items() if len(v) > 1))

    # --- 3. the constants are the reference's -------------------------------
    spurs_c = read("libs/spurs/cellSpurs.c")
    spurs_h = read("libs/spurs/cellSpurs.h")
    vout_h = read("libs/video/cellVideoOut.h")

    # CellSpurs guest layout (reference cellSpurs.h; the port already agreed).
    for name, want in [("SPURS_WKL_FLAG", 0x60), ("SPURS_FLAGS1", 0x74),
                       ("SPURS_NSPUS", 0x76), ("SPURS_WKL_RECEIVER", 0x77),
                       ("SPURS_WKL_ENABLED", 0xB0),
                       ("SPURS_INST_SIZE", 0x1000), ("SPURS_INST_SIZE2", 0x2000)]:
        got = c_enum_value(spurs_c, name)
        check(got == want, "%s: got %s, reference says 0x%X"
              % (name, hex(got) if got is not None else None, want))

    check(c_define(spurs_h, "CELL_SPURS_MAX_WORKLOAD") == "16", "MAX_WORKLOAD")
    check(c_define(spurs_h, "CELL_SPURS_MAX_WORKLOAD2") == "32", "MAX_WORKLOAD2")

    # Policy-module errors -- a separate base (0x80410800), cannot be derived
    # from CELL_ERROR_BASE_SPURS with |.
    for macro, want in [("CELL_SPURS_POLICY_MODULE_ERROR_AGAIN", 0x80410801),
                        ("CELL_SPURS_POLICY_MODULE_ERROR_INVAL", 0x80410802),
                        ("CELL_SPURS_POLICY_MODULE_ERROR_SRCH", 0x80410805),
                        ("CELL_SPURS_POLICY_MODULE_ERROR_PERM", 0x80410809),
                        ("CELL_SPURS_POLICY_MODULE_ERROR_BUSY", 0x8041080A),
                        ("CELL_SPURS_POLICY_MODULE_ERROR_STAT", 0x8041080F),
                        ("CELL_SPURS_POLICY_MODULE_ERROR_ALIGN", 0x80410810),
                        ("CELL_SPURS_POLICY_MODULE_ERROR_NULL_POINTER",
                         0x80410811)]:
        d = c_define(spurs_h, macro)
        got = int(re.search(r"0x([0-9A-Fa-f]{8})", d).group(1), 16) if d else None
        check(got == want, "%s: got %s, reference says 0x%08X"
              % (macro, d, want))

    # cellVideoOut errors: 0x8002b220..0x8002b228. The whole block used to be
    # derived from CELL_ERROR_BASE_VIDEO (0x8002b100) and was off by 0x120.
    for macro, want in [("CELL_VIDEO_OUT_ERROR_NOT_IMPLEMENTED", 0x8002B220),
                        ("CELL_VIDEO_OUT_ERROR_ILLEGAL_PARAMETER", 0x8002B222),
                        ("CELL_VIDEO_OUT_ERROR_UNSUPPORTED_VIDEO_OUT",
                         0x8002B225),
                        ("CELL_VIDEO_OUT_ERROR_VALUE_IS_NOT_SET", 0x8002B228)]:
        d = c_define(vout_h, macro)
        got = int(re.search(r"0x([0-9A-Fa-f]+)", d).group(1), 16) if d else None
        check(got == want, "%s: got %s, reference says 0x%08X"
              % (macro, hex(got) if got is not None else None, want))
    check(not re.search(r"#define\s+CELL_VIDEO_OUT_ERROR_\w+\s+.*CELL_ERROR_BASE_VIDEO",
                        vout_h),
          "the video-out errors must not be derived from the wrong base again")

    # --- 4. the bodies use those constants ----------------------------------
    b = c_body(spurs_c, "cellSpursGetWorkloadFlag")
    check(b is not None, "cellSpursGetWorkloadFlag is not defined in cellSpurs.c")
    # The *store* must be the wklFlag address (spurs+0x60). Matching the whole
    # body would also be satisfied by the printf that reports it, which is why
    # this pins the assignment itself.
    check(re.search(r"vm_write32\([^;]*SPURS_WKL_FLAG\s*\)", b),
          "GetWorkloadFlag must store the wklFlag address (spurs+0x60): %r" % b)
    check("SPURS_POLICY_MODULE_ERROR_NULL_POINTER" in b,
          "GetWorkloadFlag must refuse a NULL argument: %r" % b)

    b = c_body(spurs_c, "_cellSpursWorkloadFlagReceiver2")
    check(b is not None, "_cellSpursWorkloadFlagReceiver2 is not defined")
    for need, why in [("SPURS_WKL_RECEIVER", "reads/writes the receiver byte"),
                      ("0xFF", "0xff is the free slot"),
                      ("CELL_SPURS_POLICY_MODULE_ERROR_BUSY",
                       "claiming a taken slot is BUSY"),
                      ("CELL_SPURS_POLICY_MODULE_ERROR_PERM",
                       "releasing someone else's slot is PERM"),
                      ("CELL_SPURS_POLICY_MODULE_ERROR_SRCH",
                       "an unenabled workload is SRCH"),
                      ("SPURS_WKL_ENABLED", "the enabled mask gates the claim")]:
        check(need in b, "%s: %s (%r)" % ("_cellSpursWorkloadFlagReceiver2", why, b))

    b = c_body(spurs_c, "cellSpursInitializeWithAttribute2")
    check(b is not None, "cellSpursInitializeWithAttribute2 is not defined")
    check("SPURS_INST_SIZE2" in b,
          "the SPURS2 instance must be the 8 KB one: %r" % b)

    avconf_c = read("libs/misc/cellAvconfExt.c")
    b = c_body(avconf_c, "cellVideoOutGetScreenSize")
    check(b is not None, "cellVideoOutGetScreenSize is not defined")
    check("CELL_VIDEO_OUT_ERROR_VALUE_IS_NOT_SET" in b,
          "a 2D boot returns VALUE_IS_NOT_SET (as the reference does): %r" % b)
    check("CELL_VIDEO_OUT_PRIMARY" in b, "videoOut must be validated: %r" % b)

    fiber_c = read("libs/spurs/cellFiber.c")
    b = c_body(fiber_c, "_cellFiberPpuInitialize")
    check(b is not None, "_cellFiberPpuInitialize is not defined in cellFiber.c")
    check(re.search(r"return\s+CELL_OK\s*;", b),
          "the reference's _cellFiberPpuInitialize returns CELL_OK: %r" % b)
    check("cellFiberPpuInitialize(" not in b,
          "_cellFiberPpuInitialize must not forward to the scheduler install "
          "(the reference does not, and a second call would then return STAT)")

    # --- 5. the unresolved path stays attributable --------------------------
    hle = read("runtime/ppu/ppu_hle.cpp")
    check('"hle:unresolved:0x%08X"' in hle,
          "the unresolved milestone key must stay (the gate keys on it)")
    i = hle.find('"[hle] unresolved NID')
    check(i >= 0, "the unresolved diagnostic line is gone")
    if i >= 0:
        # The format is split across concatenated string literals, so scan the
        # whole statement (up to the call's closing paren).
        blk = hle[i:hle.index(");", i)]
        check("lr=0x%08X" in blk and "cia=0x%08X" in blk,
              "an unresolved NID must name the guest caller: %r" % blk)
        check("r3..r10" in blk and blk.count("%08X") >= 11,
              "an unresolved NID must record all eight argument registers: %r"
              % blk)

    print("ok: %d checks (NID identity, registration, reference constants, "
          "bodies, attribution)" % CHECKS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
