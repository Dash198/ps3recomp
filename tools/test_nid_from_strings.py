"""Self-check for tools/nid_from_strings.py (the string-table name gazetteer).

Covers the properties that make a match *definitive* rather than lucky:
  * only firmware-shaped identifiers are harvested, and only whole ones;
  * a name that straddles a read-chunk boundary is still seen;
  * one NID -> exactly one name is required; two names hashing to the same NID is
    refused, not resolved to the first;
  * --imports skips what nid_database.py already knows, emits a JSON that loads back
    into the database, and reports what it could not name.

No binary is needed: the fixture strings are written to a temp file, so this runs
anywhere. The last block pins the five NIDs GT6 imports and the gate records as
hle:unresolved, which is what the tool was written for.

Run: python tools/test_nid_from_strings.py
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import nid_from_strings as nfs                      # noqa: E402
from nid_database import NIDDatabase, compute_nid   # noqa: E402

CHECKS = 0


def check(cond, why):
    global CHECKS
    assert cond, why
    CHECKS += 1


def write(path, blob):
    with open(path, "wb") as f:
        f.write(blob)
    return path


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="nid_from_strings_")

    # --- harvesting: whole firmware-shaped identifiers only --------------------
    names = ["cellFooBar", "sys_baz_qux", "_cellPrivate", "cellVideoOutGetScreenSize"]
    junk = ["FooBarBaz", "cell/path/with/slashes", "x_cellNotAPrefix"]
    blob = b"\x00".join(n.encode() for n in names + junk) + b"\x00"
    b1 = write(os.path.join(tmp, "one.bin"), blob)
    got = sorted(nfs.iter_names(b1))
    check(got == sorted(names), "harvested %r, wanted %r" % (got, names))

    # --- a name split across a read chunk is still seen ------------------------
    # 16-byte chunks, name starting at byte 30 so it straddles two boundaries.
    # NUL-padded, as a real string table is; the tail overlap must rejoin it.
    padded = b"\x00" * 30 + b"cellChunkBoundary" + b"\x00" * 20
    b2 = write(os.path.join(tmp, "two.bin"), padded)
    check(list(nfs.iter_names(b2, chunk=16)) == ["cellChunkBoundary"],
          "chunk-boundary name lost")

    # --- one NID -> one name, else refuse -------------------------------------
    gaz = nfs.build_gazetteer([b1, b2])
    nid = compute_nid("cellFooBar")
    check(nfs.resolve(gaz, nid) == ("cellFooBar", None), "unique resolution failed")
    check(nfs.resolve(gaz, 0xDEADBEEF) == (None, []), "unknown NID not reported")

    collided = {0x1234: {"cellOne": {"f"}, "cellTwo": {"f"}}}
    check(nfs.resolve(collided, 0x1234) == (None, ["cellOne", "cellTwo"]),
          "ambiguous NID should be refused, not picked")

    # --- --lookup exit codes ---------------------------------------------------
    import io
    import contextlib
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc_ok = nfs.main([b1, "--lookup", "0x%08X" % nid])
    check(rc_ok == 0 and "cellFooBar" in out.getvalue(), "--lookup known failed")
    with contextlib.redirect_stdout(io.StringIO()):
        rc_bad = nfs.main([b1, "--lookup", "0xDEADBEEF", "--minlen", "4"])
    check(rc_bad == 1, "--lookup unknown should exit 1")

    # --- --imports: skip known, emit loadable JSON ----------------------------
    known_name, known_nid = "cellFsOpen", compute_nid("cellFsOpen")   # in the builtins
    new_name, new_nid = "cellFooBar", compute_nid("cellFooBar")
    imports = [{"library": "cellFs", "nid": "0x%08X" % known_nid, "stub": "0x0"},
               {"library": "cellFoo", "nid": "0x%08X" % new_nid, "stub": "0x0"}]
    imp_path = os.path.join(tmp, "imports.json")
    with open(imp_path, "w") as f:
        json.dump(imports, f)
    out_json = os.path.join(tmp, "named.json")
    with contextlib.redirect_stdout(io.StringIO()):
        rc = nfs.main([b1, "--imports", imp_path, "--only-unknown", "--out", out_json])
    check(rc == 0, "--imports exited %d" % rc)
    emitted = json.load(open(out_json))
    check(emitted == {"cellFoo": {"cellFooBar": "0x%08X" % new_nid}},
          "emitted JSON wrong: %r" % emitted)

    ndb = NIDDatabase()
    ndb.load_builtins()
    ndb.load_json(out_json)                       # the file must load back
    res = ndb.lookup_nid(new_nid)
    check(res and res[1] == new_name, "emitted JSON does not resolve: %r" % (res,))

    # --- ambiguity is refused by --imports too --------------------------------
    real_compute = nfs.compute_nid
    nfs.compute_nid = lambda name: 0x1234 if name in ("cellOne", "cellTwo") \
        else real_compute(name)
    try:
        b3 = write(os.path.join(tmp, "three.bin"), b"cellOne\x00cellTwo\x00")
        amb_imports = os.path.join(tmp, "amb.json")
        with open(amb_imports, "w") as f:
            json.dump([{"library": "cellAmb", "nid": "0x00001234", "stub": "0x0"}], f)
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            rc = nfs.main([b3, "--imports", amb_imports])
        check(rc == 1, "ambiguous import should exit 1")
    finally:
        nfs.compute_nid = real_compute

    # --- the five GT6 NIDs this was written for -------------------------------
    # Each name must hash to the NID GT6 imports; the library is GT6's own import
    # table's, and the gate records these as hle:unresolved (see gt6/ROADMAP.md G6).
    pin = [(0x2DDBCC0A, "_cellSpursWorkloadFlagReceiver2"),
           (0xFAA275A4, "cellVideoOutGetScreenSize"),
           (0xCA9A60BF, "sys_mempool_create"),
           (0x1F71ECBE, "cellKbGetConfiguration"),
           (0x5C832BD7, "cellUsbdSetThreadPriority2")]
    for want_nid, want_name in pin:
        check(compute_nid(want_name) == want_nid,
              "%s does not hash to 0x%08X" % (want_name, want_nid))
        check(ndb.lookup_nid(want_nid) is not None,
              "0x%08X not in the database" % want_nid)

    print("ok: %d checks (harvest, ambiguity refusal, CLI, JSON reload, GT6 pins)"
          % CHECKS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
