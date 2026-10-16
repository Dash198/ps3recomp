"""import_dashboard.py - what a port imports, and how well each import is covered.

Answers, for one title's import table, the question that otherwise needs a crash log:
for every NID the guest links against, is it NAMED (nid_database.py), is it
IMPLEMENTED (does the runtime actually register a handler), how does its module rate in
docs/MODULE_STATUS.md, and was it CALLED -- and did it come back unresolved? -- in a
milestone log.

The classes the roadmap cares about:

  implemented  a handler exists and its module rates Complete
  partial      a handler exists and its module rates Partial
  unrated      a handler exists but no MODULE_STATUS.md row covers the module
  missing      no handler at all -- the path that silently fakes CELL_OK today
  unnamed      (orthogonal) nid_database.py cannot put a name to the NID

The row worth reading is a NID that is `missing` *and* was CALLED: that is the runtime's
`hle:unresolved` line, turned from an anecdote into a list.

Where "implemented" comes from, all three sources a real build has:

  1. the generated table -- gen_hle_nids.py's own scanner over every PRX module --all
     would register (so this column cannot drift from ppu_hle_nids.cpp);
  2. explicit ps3_hle_register / ps3_hle_register_ctx calls with a literal or
     ps3_compute_nid("name") NID, anywhere in the toolkit (ppu_sysprx.cpp's GCM init,
     ppu_fs.cpp's cellFs surface, sysNet.c's socket table, ...);
  3. the same calls inside a *table loop* (sysNet.c registers {"name", fn} rows),
     resolved by reading the table in the same file.

A port registers handlers of its own, so pass its sources too -- otherwise its stubs
show up as missing:

    python import_dashboard.py --imports EMAIN.imports.json \\
           --extra-src ../gt6/stubs.cpp --log run.txt --check

--check exits 1 when an import is unnamed, or when a log proves a NID ran unresolved
while the static view claims it has a handler (a real contradiction, not a note).
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from nid_database import NIDDatabase, compute_nid   # noqa: E402
import gen_hle_nids                                 # noqa: E402

SRC_GLOBS = ("runtime/**/*.c", "runtime/**/*.cpp",
             "libs/**/*.c", "libs/**/*.cpp")

# ps3_hle_register(0xNID, "name", ...) and
# ps3_hle_register_ctx(ps3_compute_nid("name"), "name", ...)
REG_LITERAL = re.compile(
    r"ps3_hle_register(?:_ctx)?\(\s*(0x[0-9A-Fa-f]+)u?\s*,\s*\"([^\"]+)\"")
REG_COMPUTED = re.compile(
    r"ps3_hle_register(?:_ctx)?\(\s*ps3_compute_nid\(\s*\"([^\"]+)\"\s*\)\s*,"
    r"\s*\"([^\"]+)\"")
# ps3_hle_register_ctx(ps3_compute_nid(tab[i].name), tab[i].name, tab[i].fn)
REG_TABLE = re.compile(
    r"ps3_hle_register(?:_ctx)?\(\s*ps3_compute_nid\(\s*(\w+)\s*\[\s*i\s*\]"
    r"\s*\.\s*name\s*\)")


# ---------------------------------------------------------------------------
# inputs
# ---------------------------------------------------------------------------

def load_imports(path: str):
    """[(library, nid)] deduplicated, library order preserved."""
    with open(path) as f:
        data = json.load(f)
    out, seen = [], set()
    for e in data:
        nid = int(str(e["nid"]), 0)
        if nid in seen:
            continue
        seen.add(nid)
        out.append((e.get("library", "(unknown)"), nid))
    return out


def is_test_file(path: str) -> bool:
    """True for the toolkit's unit-test sources (registering mock handlers).

    A game links neither, so counting them would credit the port with a handler
    that will not exist at run time.
    """
    parts = os.path.normpath(path).split(os.sep)
    return ("tests" in parts or "test" in parts
            or os.path.basename(path).startswith("test_"))


def parse_registrations(txt: str, path: str, warn):
    """(nid, name) for every registration this source file makes, all three forms."""
    out = []
    for m in REG_LITERAL.finditer(txt):
        out.append((int(m.group(1), 16), m.group(2)))
    for m in REG_COMPUTED.finditer(txt):
        out.append((compute_nid(m.group(1)), m.group(2)))
    for m in REG_TABLE.finditer(txt):
        var = m.group(1)
        decl = re.search(re.escape(var) + r"\s*\[\s*\]\s*=\s*\{(.*?)\n\s*\};",
                         txt, re.S)
        if not decl:
            warn("%s: registration loop over %s[] but no initializer found -- "
                 "its rows are counted as missing" % (os.path.basename(path), var))
            continue
        for nm in re.findall(r"\"([^\"]+)\"", decl.group(1)):
            out.append((compute_nid(nm), nm))
    return out


def load_handlers(extra_src=(), warn=print):
    """{nid: (module, name)} for every handler a build of this tree registers.

    module is the source file's basename, which is what a MODULE_STATUS.md row is
    usually keyed by (sysNet.c -> sys_net is handled by the normalized join).
    """
    handlers: dict[int, tuple[str, str]] = {}

    def add(nid, name, module):
        handlers.setdefault(nid, (module, name))

    # 1. the generated table: exactly gen_hle_nids.py --all's scanner.
    for mod in gen_hle_nids.discover_all():
        for path in glob.glob(os.path.join(ROOT, "libs", "**", mod + ".c"),
                              recursive=True):
            for nid, name in gen_hle_nids.scan(path):
                add(nid, name, mod)
    for path in glob.glob(os.path.join(ROOT, "runtime", "**", "*.c"), recursive=True):
        mod = os.path.splitext(os.path.basename(path))[0]
        for nid, name in gen_hle_nids.scan(path):
            add(nid, name, mod)

    # 2/3. explicit registrations anywhere in the tree, plus the port's own sources.
    for pattern in SRC_GLOBS:
        for path in glob.glob(os.path.join(ROOT, pattern), recursive=True):
            if is_test_file(path):
                continue
            try:
                txt = open(path, encoding="latin1").read()
            except OSError:
                continue
            mod = os.path.splitext(os.path.basename(path))[0]
            for nid, name in parse_registrations(txt, path, warn):
                add(nid, name, mod)
    for path in extra_src:
        txt = open(path, encoding="latin1").read()
        mod = os.path.splitext(os.path.basename(path))[0]
        for nid, name in parse_registrations(txt, path, warn):
            add(nid, name, mod)
    return handlers


def norm(name: str) -> str:
    return name.lower().replace("_", "")


def load_module_status(path: str):
    """{module: (status, note)} plus a normalized alias map for the join."""
    rows = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.startswith("|"):
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) < 4 or set(cells[2]) <= set("- "):
                continue
            name = cells[0].strip("* ")
            if name.lower() in ("", "module", "total"):
                continue
            status = cells[2].replace("*", "").strip()
            if not status or status.lower() in ("status", "total"):
                continue
            rows[cells[0].strip("* ")] = (status, cells[3])
    alias = {norm(k): v for k, v in rows.items()}
    return rows, alias


def status_for(rows, alias, module, library):
    """The row for a handler: by source module, then by import library, both
    case/underscore-insensitively (sysNet.c and library sys_net both -> sys_net)."""
    for key in (module, library):
        if not key:
            continue
        if key in rows:
            return rows[key]
        hit = alias.get(norm(key))
        if hit:
            return hit
    return None


def load_log(path: str):
    """(called_names, unresolved_nids) from a PS3_MILESTONE_OUT log.

    `hle:<name>` is emitted only when a handler was found; `hle:unresolved:0xNID`
    instead when none was.  Keys appear both in the # counts block and in the
    first-occurrence stream, so every field of every line is scanned.
    """
    called, unresolved = set(), set()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            for key in line.rstrip("\n").split("\t"):
                if not key.startswith("hle:"):
                    continue
                body = key[len("hle:"):]
                if body.startswith("unresolved:"):
                    try:
                        unresolved.add(int(body.split(":", 1)[1], 0))
                    except ValueError:
                        pass
                else:
                    called.add(body)
    return called, unresolved


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------

ORDER = ["missing", "unnamed", "partial", "unrated", "implemented"]


def classify(handler, status_row):
    if handler is None:
        return "missing"
    if status_row is None:
        return "unrated"
    status = status_row[0].lower()
    if status.startswith("complete"):
        return "implemented"
    if status.startswith("partial"):
        return "partial"
    return status.replace(" ", "")


PLACEHOLDER = re.compile(r"^(?:cell|sce|sys)\w*_[0-9A-Fa-f]{8}$")


def build(imports, handlers, rows, alias, called_names, unresolved):
    db = NIDDatabase()
    db.load_builtins()
    called_nids = {compute_nid(n) for n in called_names}
    out = []
    for library, nid in imports:
        handler = handlers.get(nid)
        named = db.lookup_nid(nid)
        module = handler[0] if handler else None
        hname = handler[1] if handler else None
        status_row = status_for(rows, alias, module, library)
        # The port sometimes registers a NID it cannot name as <lib>_<nid>; that is
        # a placeholder, not a name, so it is shown as one and does not count as named.
        stub_name = bool(hname) and bool(PLACEHOLDER.match(hname))
        display = named[1] if named else \
            ("(stub: %s)" % hname if stub_name else (hname or None))
        out.append({
            "library": library,
            "nid": nid,
            "name": display,
            "named": named is not None,
            "handler": bool(handler),
            "handler_name": hname,
            "placeholder_name": stub_name,
            "module": module,
            "status": classify(handler, status_row),
            "module_status": status_row[0] if status_row else None,
            "note": status_row[1] if status_row else None,
            "called": nid in called_nids or nid in unresolved,
            "unresolved": nid in unresolved,
        })
    return out


# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------

def row_rank(r):
    """Order rows by how much attention they deserve: proved unresolved first, then
    called, then any missing handler, then anything unnamed."""
    return (0 if r["unresolved"] else 1 if r["called"] else 2
            if r["status"] == "missing" else 3 if not r["named"] else 4,
            r["library"], -r["nid"])


def print_report(rows, log_given, limit, notes):
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    unnamed = [r for r in rows if not r["named"]]
    called = [r for r in rows if r["called"]]
    called_unnamed = [r for r in called if not r["named"]]
    called_missing = [r for r in called if r["status"] == "missing"]

    print("%d imported NIDs; %d named, %d unnamed"
          % (len(rows), len(rows) - len(unnamed), len(unnamed)))
    print("coverage: " + ", ".join("%s %d" % (k, counts[k])
                                   for k in ORDER if k in counts)
          + "".join(", %s %d" % (k, v) for k, v in sorted(counts.items())
                    if k not in ORDER))
    if log_given:
        print("called during the run: %d (missing: %d, unnamed: %d)"
              % (len(called), len(called_missing), len(called_unnamed)))

    if notes:
        print("\nmodules behind the NIDs that were called:")
        seen = set()
        for r in sorted(called, key=lambda r: (r["library"], -r["nid"])):
            if not r["note"] or r["note"] in seen:
                continue
            seen.add(r["note"])
            print("  %-16s %-9s %s" % (r["module"] or r["library"],
                                       r["module_status"] or "?",
                                       r["note"][:96]))

    # Order by how much a row deserves attention (see row_rank): proved unresolved,
    # called, missing, unnamed.
    interesting = [r for r in rows if r["status"] != "implemented" or not r["named"]
                   or r["unresolved"] or (r["called"] and r["status"] == "partial")]
    interesting.sort(key=row_rank)
    shown = interesting if limit <= 0 else interesting[:limit]
    if shown:
        libw = min(22, max(7, max(len(r["library"]) for r in shown)))
        namew = min(41, max(4, max(len(r["name"] or "(unknown)") for r in shown)))
        print("\n%-*s %-10s %-*s %-11s %s"
              % (libw, "library", "nid", namew, "name", "status", "seen"))
        for r in shown:
            nm = r["name"] or "(unknown)"
            print("%-*s 0x%08X %-*s %-11s %s"
                  % (libw, r["library"][:libw], r["nid"], namew, nm[:namew],
                     r["status"],
                     "UNRESOLVED" if r["unresolved"] else
                     "called" if r["called"] else ""))
        rest = len(interesting) - len(shown)
        if rest > 0:
            print("... %d more (--limit 0 for all, --json for data)" % rest)
    return counts, unnamed, called_unnamed, called_missing


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--imports", required=True,
                    help="port import table (JSON list of {library, nid, stub})")
    ap.add_argument("--log", help="milestone log (PS3_MILESTONE_OUT) for the runtime view")
    ap.add_argument("--extra-src", action="append", default=[], metavar="FILE",
                    help="port source that registers handlers (e.g. stubs.cpp)")
    ap.add_argument("--module-status",
                    default=os.path.join(ROOT, "docs", "MODULE_STATUS.md"),
                    help="module status table (default docs/MODULE_STATUS.md)")
    ap.add_argument("--json", metavar="FILE", help="write the full table as JSON")
    ap.add_argument("--limit", type=int, default=40,
                    help="rows in the detail table, 0 for all (40)")
    ap.add_argument("--notes", action="store_true",
                    help="also print the module note for each called import")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 on an unnamed import or a static/runtime contradiction")
    args = ap.parse_args(argv)

    for p, what in ((args.imports, "imports"), (args.module_status, "module status")):
        if not os.path.exists(p):
            print("import_dashboard: no %s file at %s" % (what, p), file=sys.stderr)
            return 2
    for p in [args.log] + args.extra_src:
        if p and not os.path.exists(p):
            print("import_dashboard: no such file: %s" % p, file=sys.stderr)
            return 2

    def warn(msg):
        print("import_dashboard: %s" % msg, file=sys.stderr)

    imports = load_imports(args.imports)
    handlers = load_handlers(args.extra_src, warn)
    rows, alias = load_module_status(args.module_status)
    called_names, unresolved = load_log(args.log) if args.log else (set(), set())

    table = build(imports, handlers, rows, alias, called_names, unresolved)
    counts, unnamed, called_unnamed, called_missing = print_report(
        table, bool(args.log), args.limit, args.notes)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(table, f, indent=1, sort_keys=True)
            f.write("\n")
        print("\nwrote %s" % args.json)

    rc = 0
    if args.check:
        # An import nobody calls does not have to be named yet (that is the work
        # queue the summary counts); one the guest DOES call and we cannot name is
        # a defect now.  Also fail on a static/runtime contradiction, which would
        # mean this tool is lying rather than incomplete.
        if called_unnamed:
            print("\ncheck: %d called import(s) unnamed: %s"
                  % (len(called_unnamed),
                     ", ".join("0x%08X" % r["nid"] for r in called_unnamed)),
                  file=sys.stderr)
            rc = 1
        contradicted = [r for r in table if r["unresolved"] and r["handler"]]
        if contradicted:
            print("check: %d NID(s) have a handler yet ran unresolved: %s"
                  % (len(contradicted),
                     ", ".join("0x%08X" % r["nid"] for r in contradicted)),
                  file=sys.stderr)
            rc = 1
        if rc == 0:
            print("\ncheck: every called import named; no static/runtime contradiction")
    return rc


if __name__ == "__main__":
    sys.exit(main())
