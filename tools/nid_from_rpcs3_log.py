"""nid_from_rpcs3_log.py - name NIDs from an emulator's module-loader log.

A NID is SHA-1(name + suffix)[:4], so it cannot be inverted: an unresolved import can
only be named by hashing a *candidate* name and finding it hashes back to that NID.
nid_harvest.py takes candidates from a debug build's .symtab and nid_from_strings.py
from a binary's plain string table; both then verify the same way.  An emulator's
loader log is a third source, and the strongest of the three, because it prints the
name *and* the NID side by side for every import and export of every module it loads:

    ppu_loader: **** sys_fs import: [cellFsReadWithOffset] (0x0d5b4a14) -> 0x3b850
    ppu_loader: **** sysPrxForUser export: (0x04e83d2c) at 0x00d0708 [..]:  _sys_strncmp

When the emulator has no name for a NID it prints a placeholder instead: either the
bare NID (`0x0d5b4a14`) or `<library>_<NID>` (`sceNpBasicLimited_0xEB42E2E6`).  A
placeholder is self-rejecting, because it is not the function's name and so never
hashes to the NID.  That leaves one rule, the same one every name source here uses --
accept a name only when compute_nid(name) == nid -- plus refusing a NID that two
different names both claim.

This is the source that confirmed the five GT6 imports Module 8 had named (e.g.
_cellSpursWorkloadFlagReceiver2) and then named 220 more; see G7 in gt6/ROADMAP.md.

    # what does 0x1F71ECBE resolve to, given this log?
    python nid_from_rpcs3_log.py RPCS3.log --lookup 0x1F71ECBE

    # name every import in a port's import table, writing the unknown ones as a JSON
    # file nid_database.py can load
    python nid_from_rpcs3_log.py RPCS3.log --imports EMAIN.imports.json \\
           --only-unknown --out nid_from_rpcs3.json

Exit status is 0 unless something it was asked about was unresolved or ambiguous, so
it is usable as a check.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nid_database import NIDDatabase, compute_nid   # noqa: E402
from nid_from_strings import load_imports           # noqa: E402

# The two loader lines that carry a (library, name, NID) triple.  RPCS3 prints the
# export name last, after the OPD/rtoc bracket, so the export pattern anchors on the
# end of line to keep the bracket's contents out of the name.
IMPORT_RE = re.compile(
    r"ppu_loader:\s+\*\*\*\*\s+(\S+)\s+import:\s+\[(.+?)\]\s+\((0x[0-9a-fA-F]+)\)")
EXPORT_RE = re.compile(
    r"ppu_loader:\s+\*\*\*\*\s+(\S+)\s+export:\s+\((0x[0-9a-fA-F]+)\)"
    r".*?:\s+(\S+)\s*$")

# A name we are willing to hash.  Refusing anything else means a mangled parse can
# never contribute a candidate.
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# What the emulator prints when it does not know a name: the NID itself, or the
# library with the NID appended.  Reported separately from a plain hash mismatch,
# because "the oracle does not know this either" is a useful fact about a NID.
PLACEHOLDER_RE = re.compile(r"^(?:0x[0-9a-fA-F]+|[A-Za-z0-9_]+_(?:0x)?[0-9A-F]{8})$")


def iter_entries(paths):
    """Yield (library, name, nid, kind) for every named import/export line in *paths*.

    Reads as text with replacement, so a log truncated mid-line or carrying stray
    bytes does not abort the scan.
    """
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = IMPORT_RE.search(line)
                if m:
                    yield m.group(1), m.group(2), int(m.group(3), 16), "import"
                    continue
                m = EXPORT_RE.search(line)
                if m:
                    yield m.group(1), m.group(3), int(m.group(2), 16), "export"


def build_gazetteer(paths):
    """Scan the logs into (NID -> {name: {libraries}}) of verified names, plus counts.

    An entry is kept only if the name is a plausible identifier *and* hashes back to
    the NID on its own line.  Two lines naming the same NID differently are both kept,
    so resolve() can refuse instead of picking one.
    """
    gaz: dict[int, dict[str, set[str]]] = {}
    stats: collections.Counter = collections.Counter()
    for lib, name, nid, kind in iter_entries(paths):
        stats[kind] += 1
        if PLACEHOLDER_RE.match(name):
            stats["placeholder"] += 1
            continue
        if not IDENT_RE.match(name) or compute_nid(name) != nid:
            stats["unverified"] += 1
            continue
        stats["verified"] += 1
        gaz.setdefault(nid, {}).setdefault(name, set()).add(lib)
    return gaz, stats


def resolve(gaz, nid: int):
    """(name, libraries) when exactly one name hashes to *nid*, else (None, names)."""
    names = sorted(gaz.get(nid, {}))
    if len(names) == 1:
        return names[0], sorted(gaz[nid][names[0]])
    if not names:
        return None, []
    return None, names                      # ambiguous: refuse, do not pick one


def gazetteer_json(gaz) -> dict:
    """{library: {name: "0xNID"}} for every resolved NID, sorted and deduplicated.

    Shaped for nid_database.NIDDatabase.load_json, and matching save_json()'s use of
    upper-case hex so the file diffs cleanly against the other sources.
    """
    out: dict[str, dict[str, str]] = {}
    for nid in sorted(gaz):
        name, libs = resolve(gaz, nid)
        if not name:
            continue                        # ambiguous: emit nothing rather than guess
        out.setdefault(libs[0], {})[name] = "0x%08X" % nid
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", nargs="+", help="emulator log file(s) to scan")
    ap.add_argument("--lookup", action="append", default=[], metavar="0xNID",
                    help="resolve this NID (repeatable)")
    ap.add_argument("--imports", metavar="FILE",
                    help="name every NID in a port import table (JSON list)")
    ap.add_argument("--only-unknown", action="store_true",
                    help="with --imports, skip NIDs nid_database.py already resolves")
    ap.add_argument("--out", metavar="FILE",
                    help="write a {library: {name: 0xNID}} JSON (with --imports: "
                         "only the NIDs in that table)")
    args = ap.parse_args(argv)

    for p in args.log:
        if not os.path.exists(p):
            print("nid_from_rpcs3_log: no such file: %s" % p, file=sys.stderr)
            return 2

    gaz, stats = build_gazetteer(args.log)
    ambiguous = sum(1 for nid in gaz if len(gaz[nid]) > 1)
    print("gazetteer: %d distinct NIDs, %d unambiguous (%d verified names, "
          "%d placeholders, %d unverified) from %d log(s)"
          % (len(gaz), len(gaz) - ambiguous, stats["verified"], stats["placeholder"],
             stats["unverified"], len(args.log)))

    rc = 0
    if args.lookup:
        for spec in args.lookup:
            nid = int(spec, 0)
            name, libs = resolve(gaz, nid)
            if name:
                print("  0x%08X  %s  [%s]" % (nid, name, ",".join(libs)))
            elif libs:
                print("  0x%08X  AMBIGUOUS: %s" % (nid, ", ".join(libs)))
                rc = 1
            else:
                print("  0x%08X  (no name in the log)" % nid)
                rc = 1

    if args.imports:
        imports = load_imports(args.imports)
        db = NIDDatabase()
        db.load_builtins()
        out: dict[str, dict[str, str]] = {}
        n_known = n_named = n_amb = n_none = 0
        seen: set[int] = set()
        for lib, nid in imports:
            if nid in seen:
                continue
            seen.add(nid)
            if args.only_unknown and db.lookup_nid(nid):
                n_known += 1
                continue
            name, libs = resolve(gaz, nid)
            if name:
                out.setdefault(lib, {})[name] = "0x%08X" % nid
                n_named += 1
            elif libs:
                n_amb += 1
                print("  AMBIGUOUS 0x%08X (%s): %s" % (nid, lib, ", ".join(libs)),
                      file=sys.stderr)
                rc = 1
            else:
                n_none += 1
        print("imports: %d distinct NIDs; %d named, %d already known, %d ambiguous, "
              "%d unnamed" % (len(seen), n_named, n_known, n_amb, n_none))
        for lib in sorted(out):
            print("  %-22s %d named" % (lib, len(out[lib])))
        if args.out:
            with open(args.out, "w") as f:
                json.dump(out, f, indent=1, sort_keys=True)
                f.write("\n")
            print("wrote %s (%d names)" % (args.out, sum(len(v) for v in out.values())))
        return rc

    if args.out:
        out = gazetteer_json(gaz)
        with open(args.out, "w") as f:
            json.dump(out, f, indent=1, sort_keys=True)
            f.write("\n")
        print("wrote %s (%d names in %d libraries)"
              % (args.out, sum(len(v) for v in out.values()), len(out)))

    return rc


if __name__ == "__main__":
    sys.exit(main())
