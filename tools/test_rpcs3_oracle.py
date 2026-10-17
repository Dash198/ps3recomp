"""Self-check for tools/rpcs3_oracle.py (the emulator-loader-log behaviour oracle).

The tool's value is that it says *what the emulator knows* about a port's boot, so the
checks are about the three places that could make it lie:

  * it must only ever agree with a name the hash rule verifies -- a placeholder the
    loader printed, or a plausible-looking name whose hash is off, must not make a
    port's name look "agreed";
  * the ordered import stream must keep the loader's order, because "first divergence"
    is an order statement;
  * the alignment must put each milestone key in exactly one bucket, and only the
    unresolved ones become divergences.

No log is needed: fixture lines go to a temp file, so this runs anywhere.  The last
block pins the two facts this module is about -- the five GT6 imports the port answers
with a silent zero, and the first of them.

Run: python tools/test_rpcs3_oracle.py
"""
import contextlib
import io
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import rpcs3_oracle as ro                        # noqa: E402
from nid_database import compute_nid             # noqa: E402

CHECKS = 0


def check(cond, why):
    global CHECKS
    assert cond, why
    CHECKS += 1


def write(path, text):
    with open(path, "w") as f:
        f.write(text)
    return path


def imp(lib, name, nid, addr, stamp="0:00:03.995054"):
    return ("\u00b7! %s ppu_loader: **** %s import: [%s] (0x%08x) -> 0x%x\n"
            % (stamp, lib, name, nid, addr))


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rpcs3_oracle_")

    fiber_nid = compute_nid("_cellFiberPpuInitialize")
    net_nid = compute_nid("sys_net_initialize_network_ex")

    log = write(os.path.join(tmp, "a.log"),
                imp("cellFiber", "_cellFiberPpuInitialize", fiber_nid, 0x3C030,
                    "0:00:03.995079")
                + imp("sys_net", "sys_net_initialize_network_ex", net_nid, 0x3B7E0)
                # a placeholder: the loader had no name, so it printed the NID
                + imp("sys_fs", "0x0d5b4a14", 0x0D5B4A14, 0x3B850)
                + ("\u00b7! 0:00:05.044637 {SPRX Worker 3} ppu_loader: **** cellFiber "
                   "export: (0x%08x) at 0x00d0788 [at:0x00bea30, rtoc:0x000d8ab0]:  "
                   "_cellFiberPpuInitialize\n" % fiber_nid)
                + "ppu_loader: Loading library: liblv2.sprx\n"
                + "ppu_loader: ** Imported module 'cellFiber'\n"
                + ("\u00b7U 0:00:12.000000 {PPU[0x1000000] Thread (main)} cellSpurs "
                   "TODO: cellSpursFoo is not implemented\n"))

    # --- the ordered stream, and what may enter by_name -------------------------
    o = ro.Oracle([log])
    check([i.name for i in o.imports] ==
          ["_cellFiberPpuInitialize", "sys_net_initialize_network_ex", "0x0d5b4a14"],
          "import order changed: %r" % ([i.name for i in o.imports],))
    check(o.imports[0].addr == 0x3C030 and o.imports[0].stamp == "0:00:03.995079",
          "addr/stamp mis-parsed: %r" % ((o.imports[0].addr, o.imports[0].stamp),))
    check(o.imports[2].placeholder is True and o.imports[0].placeholder is False,
          "placeholder detection wrong")
    check(o.by_nid[fiber_nid].name == "_cellFiberPpuInitialize",
          "by_nid should map the NID to its first import")
    check(o.name_of(0x0D5B4A14)[0] is None,
          "a placeholder NID must not resolve to a name: %r" % (o.name_of(0x0D5B4A14),))
    check("_cellFiberPpuInitialize" in o.by_name and
          "sys_net_initialize_network_ex" in o.by_name,
          "verified names missing from by_name: %r" % (sorted(o.by_name),))
    check("0x0d5b4a14" not in o.by_name, "placeholder leaked into by_name")
    check(o.libs == ["liblv2.sprx", "cellFiber"], "load stream wrong: %r" % (o.libs,))
    check(o.todos and o.todos[0][0] == "cellSpurs" and
          "cellSpursFoo" in o.todos[0][1], "TODO line mis-parsed: %r" % (o.todos,))
    check(o.todo_for("cellSpursFoo") and not o.todo_for("cellSpursBar"),
          "todo_for did not match by needle")

    # --- a name is believed only when it hashes back ----------------------------
    # A real name stitched to the wrong NID must not become an agreement.
    bad = write(os.path.join(tmp, "bad.log"),
                imp("cellFiber", "_cellFiberPpuInitialize", 0x12345678, 0x3C030))
    ob = ro.Oracle([bad])
    check(ob.name_of(0x12345678) == (None, []),
          "a mismatched name must not resolve: %r" % (ob.name_of(0x12345678),))
    check("_cellFiberPpuInitialize" not in ob.by_name,
          "mismatched name leaked into by_name")

    # --- milestone parsing, and the buckets -------------------------------------
    ms = write(os.path.join(tmp, "port.milestone"),
               "# ps3recomp milestone log v1\n"
               "1\thle:_cellFiberPpuInitialize\n"
               "2\thle:unresolved:0x%08X\n"
               "3\tsys:330\n"
               "4\thle:noSuchFunction\n"
               "# counts\n"
               "count\thle:_cellFiberPpuInitialize\t1\n" % net_nid)
    keys = ro.parse_milestones(ms)
    check(keys == [(1, "hle:_cellFiberPpuInitialize"),
                   (2, "hle:unresolved:0x%08X" % net_nid),
                   (3, "sys:330"), (4, "hle:noSuchFunction")],
          "milestone parse wrong: %r" % (keys,))
    a = ro.analyse(o, keys)
    check(a["agreed"] == [(1, "hle:_cellFiberPpuInitialize")],
          "agreed bucket wrong: %r" % (a["agreed"],))
    check(a["unknown"] == [(4, "hle:noSuchFunction")],
          "unknown bucket wrong: %r" % (a["unknown"],))
    check(a["sys_keys"] == [(3, "330")], "sys bucket wrong: %r" % (a["sys_keys"],))
    check(len(a["unresolved"]) == 1, "unresolved bucket wrong: %r" % (a["unresolved"],))
    idx, nid, name, libs, addr, stamp = a["unresolved"][0]
    check((idx, nid, name, libs, addr) ==
          (2, net_nid, "sys_net_initialize_network_ex", ["sys_net"], 0x3B7E0),
          "the unresolved key was not named from the oracle: %r"
          % (a["unresolved"][0],))

    # --- the report, and its exit status ----------------------------------------
    buf = io.StringIO()
    rc = ro.report(o, keys, out=buf)
    text = buf.getvalue()
    check(rc == 1, "a name disagreement should exit 1, got %d" % rc)
    check("FIRST DIVERGENCE" in text and "sys_net_initialize_network_ex" in text,
          "report did not name the first divergence:\n%s" % text)
    clean = ro.analyse(o, [(1, "hle:_cellFiberPpuInitialize")])
    check(not clean["unresolved"] and not clean["unknown"],
          "clean stream should have no divergence: %r" % (clean,))
    check(ro.report(o, [(1, "hle:_cellFiberPpuInitialize")], out=io.StringIO()) == 0,
          "a stream with nothing to flag should exit 0")

    # --- CLI --------------------------------------------------------------------
    with contextlib.redirect_stdout(io.StringIO()):
        check(ro.main([log, "--lookup", "0x%08X" % fiber_nid]) == 0,
              "--lookup of a named NID should exit 0")
        check(ro.main([log, "--lookup", "0xDEADBEEF"]) == 1,
              "--lookup of an unknown NID should exit 1")
        check(ro.main([log, "--lookup", "sys_net_initialize_network_ex"]) == 0,
              "--lookup by name should exit 0")
        check(ro.main([log, "--lookup", "no_such_name"]) == 1,
              "--lookup of an unknown name should exit 1")
        check(ro.main([log, "--align", ms]) == 1,
              "--align with a disagreement should exit 1")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            check(ro.main([log, "--breakpoints",
                           "_cellFiberPpuInitialize,sys_net_initialize_network_ex"]) == 0,
                  "--breakpoints should exit 0 when every name is placed")
        rec = json.loads(buf.getvalue())
        check([r["addr"] for r in rec] == ["0x0003C030", "0x0003B7E0"],
              "breakpoints wrong: %r" % (rec,))
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            check(ro.main([log, "--breakpoints", "no_such_name"]) == 1,
                  "--breakpoints should exit 1 when a name has no address")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            check(ro.main([log, "--dump-imports"]) == 0, "--dump-imports should exit 0")
        check(len(buf.getvalue().strip().splitlines()) == 3,
              "--dump-imports should print one line per import")
        with contextlib.redirect_stderr(io.StringIO()), \
                contextlib.redirect_stdout(io.StringIO()):
            check(ro.main([os.path.join(tmp, "nope.log"), "--lookup", "0x0"]) == 2,
                  "a missing log should exit 2")

    # --- the two facts this module is about -------------------------------------
    # GT6 calls five imports the port has no handler for; the oracle names them, and
    # the first one in boot order is the first divergence.
    unresolved = {0x55870804: "_cellFiberPpuInitialize",
                  0xFAA275A4: "cellVideoOutGetScreenSize",
                  0x2DDBCC0A: "_cellSpursWorkloadFlagReceiver2",
                  0xC765B995: "cellSpursGetWorkloadFlag",
                  0x30AA96C4: "cellSpursInitializeWithAttribute2"}
    for nid, want in unresolved.items():
        check(compute_nid(want) == nid,
              "0x%08X is not the hash of %s" % (nid, want))

    print("ok: %d checks (order, refusals, milestones, buckets, report, CLI, "
          "GT6 pins)" % CHECKS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
