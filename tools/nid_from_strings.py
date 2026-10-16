"""nid_from_strings.py - name unresolved NIDs from a binary's plain string table.

A NID is SHA-1(name + suffix)[:4].  It cannot be inverted, so an imported NID is only
resolvable if you can produce a candidate *name* to hash.  nid_harvest.py gets names from
a debug build's .symtab; this tool gets them from the plain ASCII strings of any binary
that mentions Sony's API names -- an emulator, an SDK-linked tool, a debug build.  The
match is still verified the same way, compute_nid(name) == the imported NID, so a hit is
definitive rather than a guess, and a NID whose candidate names disagree is refused
rather than resolved to one of them.  (Firmware PRXs cannot do this: a PS3 export table
carries the library name and the NIDs, never the per-export names.  See G6 in
gt6/ROADMAP.md.)

    # what does 0x1F71ECBE resolve to, given this binary's strings?
    python nid_from_strings.py <binary> --lookup 0x1F71ECBE

    # name every import in a port's import table, and write the unknown ones as a
    # JSON file nid_database.py can load
    python nid_from_strings.py <binary> --imports EMAIN.imports.json --only-unknown \\
           --out nid_from_strings.json

Exit status is 0 unless --lookup/--imports found nothing for something it was asked
about, so it is usable as a check.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nid_database import NIDDatabase, compute_nid   # noqa: E402
from nid_harvest import FW_PREFIXES                 # noqa: E402

# A firmware function name: ASCII identifier, no decoration, firmware-shaped prefix.
NAME_RE = re.compile(rb"[ -~]{4,}")
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def iter_names(path: str, minlen: int = 4, chunk: int = 1 << 22):
    """Yield distinct firmware-shaped identifiers found in *path*'s string data.

    An identifier only counts when it is a *whole* printable run, which is how a
    string table stores one (NUL- or whitespace-delimited). Text that merely
    contains a name, like `"cellFs is a module"` or `"cell/fs/path"`, is not
    harvested, so a prose string cannot inject a plausible-looking candidate.

    Reads in chunks and keeps a small overlap so an identifier that straddles a
    chunk boundary is still seen.  No external `strings` dependency, so this runs
    the same on Linux and Windows.
    """
    tail = b""
    seen: set[str] = set()
    with open(path, "rb") as f:
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            data = tail + buf
            for m in NAME_RE.finditer(data):
                s = m.group(0).decode("ascii", "ignore")
                if len(s) < minlen or not s.startswith(FW_PREFIXES):
                    continue
                if not IDENT_RE.match(s) or s in seen:
                    continue
                seen.add(s)
                yield s
            tail = data[-64:]
    # Identifiers can also appear split by a NUL in the tail; nothing more to do.


def build_gazetteer(paths, minlen: int = 4) -> dict[int, dict[str, set[str]]]:
    """NID -> {name -> {files that mention it}} over every input binary."""
    gaz: dict[int, dict[str, set[str]]] = {}
    for p in paths:
        for name in iter_names(p, minlen):
            gaz.setdefault(compute_nid(name), {}).setdefault(name, set()).add(p)
    return gaz


def resolve(gaz, nid: int):
    """(name, None) when exactly one name hashes to *nid*, else (None, names)."""
    names = sorted(gaz.get(nid, {}))
    if len(names) == 1:
        return names[0], None
    if not names:
        return None, []
    return None, names                      # ambiguous: refuse, do not pick one


def load_imports(path: str):
    """Read a port import table: a list of {library, nid, stub} (see gen_imports.py)."""
    with open(path) as f:
        data = json.load(f)
    out = []
    for e in data:
        out.append((e.get("library", "(unknown)"), int(str(e["nid"]), 0)))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", nargs="+", help="file(s) whose strings to search")
    ap.add_argument("--lookup", action="append", default=[], metavar="0xNID",
                    help="resolve this NID (repeatable)")
    ap.add_argument("--imports", metavar="FILE",
                    help="name every NID in a port import table (JSON list)")
    ap.add_argument("--only-unknown", action="store_true",
                    help="with --imports, skip NIDs nid_database.py already resolves")
    ap.add_argument("--out", metavar="FILE",
                    help="with --imports, write a {library: {name: 0xNID}} JSON")
    ap.add_argument("--minlen", type=int, default=4, help="minimum name length (4)")
    args = ap.parse_args(argv)

    for p in args.binary:
        if not os.path.exists(p):
            print("nid_from_strings: no such file: %s" % p, file=sys.stderr)
            return 2

    gaz = build_gazetteer(args.binary, args.minlen)
    named = sum(1 for nid in gaz if len(gaz[nid]) == 1)
    print("gazetteer: %d distinct NIDs, %d unambiguous, from %d file(s)"
          % (len(gaz), named, len(args.binary)))

    rc = 0
    if args.lookup:
        for spec in args.lookup:
            nid = int(spec, 0)
            name, ambiguous = resolve(gaz, nid)
            if name:
                src = ",".join(sorted(gaz[nid][name]))
                print("  0x%08X  %s  [%s]" % (nid, name, os.path.basename(src)))
            elif ambiguous:
                print("  0x%08X  AMBIGUOUS: %s" % (nid, ", ".join(ambiguous)))
                rc = 1
            else:
                print("  0x%08X  (no name string found)" % nid)
                rc = 1

    if args.imports:
        imports = load_imports(args.imports)
        db = NIDDatabase()
        db.load_builtins()
        out: dict[str, dict[str, str]] = {}
        n_known = n_named = n_amb = n_none = 0
        per_lib: dict[str, list[int]] = {}
        for lib, nid in imports:
            per_lib.setdefault(lib, []).append(nid)
        seen: set[int] = set()
        for lib, nid in imports:
            if nid in seen:
                continue
            seen.add(nid)
            if args.only_unknown and db.lookup_nid(nid):
                n_known += 1
                continue
            name, ambiguous = resolve(gaz, nid)
            if name:
                out.setdefault(lib, {})[name] = "0x%08X" % nid
                n_named += 1
            elif ambiguous:
                n_amb += 1
                print("  AMBIGUOUS 0x%08X (%s): %s" % (nid, lib, ", ".join(ambiguous)),
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
            print("wrote %s" % args.out)

    return rc


if __name__ == "__main__":
    sys.exit(main())
