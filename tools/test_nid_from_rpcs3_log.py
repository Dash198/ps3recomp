"""Self-check for tools/nid_from_rpcs3_log.py (the emulator-loader-log name source).

The tool rests on one rule -- a name is believed only when compute_nid(name) is the
NID printed beside it -- so these checks are mostly about what it *refuses*:

  * the two placeholders an emulator prints for a name it does not know (the bare NID,
    and <library>_<NID>) are counted, never resolved;
  * a plausible-looking identifier whose hash is wrong is rejected;
  * a NID that two names both claim is refused, not resolved to one of them;
  * --imports names only what it can verify, and writes a JSON that loads back.

No log is needed: the fixture lines are written to a temp file, so this runs anywhere.
The last block pins the committed nid_from_rpcs3.json -- every entry must satisfy the
hash invariant, agree with nid_from_protos.json where the two overlap, and name the
five GT6 imports Module 8 was about.

Run: python tools/test_nid_from_rpcs3_log.py
"""
import contextlib
import io
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import nid_from_rpcs3_log as nfrl                  # noqa: E402
from nid_database import NIDDatabase, compute_nid   # noqa: E402

CHECKS = 0


def check(cond, why):
    global CHECKS
    assert cond, why
    CHECKS += 1


def write(path, text):
    with open(path, "w") as f:
        f.write(text)
    return path


def imp(lib, name, nid):
    return ("\u00b7! 0:00:03.995054 ppu_loader: **** %s import: [%s] (0x%08x) -> 0x3b850\n"
            % (lib, name, nid))


def exp(lib, name, nid):
    return ("\u00b7! 0:00:05.044637 {SPRX Worker 3} ppu_loader: **** %s export: "
            "(0x%08x) at 0x00d0788 [at:0x00bea30, rtoc:0x000d8ab0]:  %s\n"
            % (lib, nid, name))


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="nid_from_rpcs3_log_")

    # --- the two shapes of line, and where the name is on each ------------------
    good = compute_nid("cellLogToolAlpha")
    log = write(os.path.join(tmp, "a.log"),
                imp("cellLibOne", "cellLogToolAlpha", good)
                + exp("cellLibTwo", "cellLogToolBeta", compute_nid("cellLogToolBeta")))
    got = list(nfrl.iter_entries([log]))
    check(got[0] == ("cellLibOne", "cellLogToolAlpha", good, "import"),
          "import line mis-parsed: %r" % (got[0],))
    check(got[1] == ("cellLibTwo", "cellLogToolBeta", compute_nid("cellLogToolBeta"),
                     "export"),
          "export line mis-parsed (name must come after the rtoc bracket): %r"
          % (got[1],))

    # --- what it refuses --------------------------------------------------------
    # Both placeholder shapes, plus a real-looking name whose hash is off by one.
    junk = write(os.path.join(tmp, "junk.log"),
                 imp("sys_fs", "0x0d5b4a14", 0x0D5B4A14)
                 + imp("sceNpBasicLimited", "sceNpBasicLimited_0xEB42E2E6", 0xEB42E2E6)
                 + imp("sysPs2Disc", "sysPs2Disc_A84FD3C3", 0xA84FD3C3)
                 + imp("cellLibOne", "cellLogToolAlpha", good ^ 1))
    gaz, stats = nfrl.build_gazetteer([junk])
    check(gaz == {}, "refused lines leaked into the gazetteer: %r" % (gaz,))
    check(stats["placeholder"] == 3, "placeholder count %d, wanted 3" % stats["placeholder"])
    check(stats["unverified"] == 1, "unverified count %d, wanted 1" % stats["unverified"])
    check(stats["verified"] == 0, "verified count %d, wanted 0" % stats["verified"])

    # --- what it accepts, and the JSON it writes --------------------------------
    gaz, stats = nfrl.build_gazetteer([log])
    check(stats["verified"] == 2 and len(gaz) == 2,
          "two verified names expected, got %r / %r" % (stats, gaz))
    name, libs = nfrl.resolve(gaz, compute_nid("cellLogToolAlpha"))
    check((name, libs) == ("cellLogToolAlpha", ["cellLibOne"]),
          "resolve returned %r" % ((name, libs),))
    check(nfrl.resolve(gaz, 0xDEADBEEF) == (None, []),
          "unknown NID should resolve to (None, [])")
    out = nfrl.gazetteer_json(gaz)
    check(out == {"cellLibOne": {"cellLogToolAlpha": "0x%08X" % good},
                  "cellLibTwo": {"cellLogToolBeta": "0x%08X" % compute_nid("cellLogToolBeta")}},
          "gazetteer_json wrong: %r" % (out,))

    # --- a NID two names claim is refused, not guessed --------------------------
    real_compute = nfrl.compute_nid
    nfrl.compute_nid = lambda n: 0x1234 if n in ("cellOne", "cellTwo") else real_compute(n)
    try:
        amb = write(os.path.join(tmp, "amb.log"),
                    imp("cellAmb", "cellOne", 0x1234) + imp("cellAmb", "cellTwo", 0x1234))
        gaz, _ = nfrl.build_gazetteer([amb])
        name, names = nfrl.resolve(gaz, 0x1234)
        check(name is None and names == ["cellOne", "cellTwo"],
              "ambiguous NID should be refused: %r" % ((name, names),))
        check(nfrl.gazetteer_json(gaz) == {},
              "ambiguous NID must not be emitted: %r" % (nfrl.gazetteer_json(gaz),))
        amb_imports = write(os.path.join(tmp, "amb.json"),
                            json.dumps([{"library": "cellAmb", "nid": "0x00001234",
                                         "stub": "0x0"}]))
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            rc = nfrl.main([amb, "--imports", amb_imports])
        check(rc == 1, "ambiguous import should exit 1, got %d" % rc)
    finally:
        nfrl.compute_nid = real_compute

    # --- CLI: --lookup verdict, and --imports writing a loadable file ------------
    with contextlib.redirect_stdout(io.StringIO()):
        rc = nfrl.main([log, "--lookup", "0x%08X" % good])
        check(rc == 0, "--lookup of a known NID should exit 0, got %d" % rc)
        rc = nfrl.main([log, "--lookup", "0xDEADBEEF"])
        check(rc == 1, "--lookup of an unknown NID should exit 1, got %d" % rc)

    imports = write(os.path.join(tmp, "imports.json"), json.dumps([
        {"library": "cellLibOne", "nid": "0x%08X" % good, "stub": "0x1011cc0"},
        {"library": "cellLibNine", "nid": "0xDEADBEEF", "stub": "0x1011cf8"},
    ]))
    named_json = os.path.join(tmp, "named.json")
    with contextlib.redirect_stdout(io.StringIO()):
        rc = nfrl.main([log, "--imports", imports, "--out", named_json])
        check(rc == 0, "--imports with nothing ambiguous should exit 0, got %d" % rc)
    ndb = NIDDatabase()
    ndb.load_json(named_json)                     # the file must load back
    check(ndb.lookup_nid(good) is not None, "emitted JSON does not resolve 0x%08X" % good)
    check(ndb.lookup_nid(0xDEADBEEF) is None, "unnameable NID must not be emitted")

    # --- the committed gazetteer -------------------------------------------------
    path = os.path.join(HERE, "nid_from_rpcs3.json")
    committed = json.load(open(path))
    total = sum(len(v) for v in committed.values())
    check(total >= 2500, "committed gazetteer shrank to %d names" % total)
    bad = [(n, name) for funcs in committed.values() for name, n in funcs.items()
           if compute_nid(name) != int(n, 0)]
    check(not bad, "entries fail the hash invariant: %r" % (bad[:5],))
    protos = json.load(open(os.path.join(HERE, "nid_from_protos.json")))
    other = {int(n, 0): name for funcs in protos.values() for name, n in funcs.items()}
    clash = [(nid, other[nid], name) for funcs in committed.values()
             for name, n in funcs.items() for nid in (int(n, 0),)
             if nid in other and other[nid] != name]
    check(not clash, "disagrees with nid_from_protos.json: %r" % (clash[:5],))

    # The five GT6 imports this source settled (and the six it cannot: cellGameStorage
    # and sceNpBasicLimited are private to the game, so no emulator names them).
    ndb = NIDDatabase()
    ndb.load_builtins()
    for nid, want in [(0x2DDBCC0A, "_cellSpursWorkloadFlagReceiver2"),
                      (0xFAA275A4, "cellVideoOutGetScreenSize"),
                      (0xCA9A60BF, "sys_mempool_create"),
                      (0x1F71ECBE, "cellKbGetConfiguration"),
                      (0x5C832BD7, "cellUsbdSetThreadPriority2")]:
        res = ndb.lookup_nid(nid)
        check(res is not None and res[1] == want,
              "0x%08X resolves to %r, wanted %s" % (nid, res, want))
    for nid in (0x23EC78CE, 0x50771F25, 0x8DBD9594, 0xA9201831, 0xD7724C0A, 0xEB42E2E6):
        check(ndb.lookup_nid(nid) is None,
              "0x%08X should stay unnamed (no public name exists)" % nid)

    print("ok: %d checks (line parse, refusals, ambiguity, CLI, JSON reload, "
          "committed gazetteer, GT6 pins)" % CHECKS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
