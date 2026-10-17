"""rpcs3_oracle.py - read an emulator's boot log as an oracle for a port's boot.

`nid_from_rpcs3_log.py` mines an RPCS3 loader log for *names*.  This tool uses the
same log as an *oracle for behaviour*: it turns the log into an ordered stream and
diffs that stream against a recompiled port's milestone log (`include/ps3emu/
milestone.h`), so "what did the title actually ask for" can be compared with "what
did our build actually do".

Why this is the log and not something better: RPCS3 does not log HLE or lv2 calls
(they are logged at level `notice` only inside a handful of module handlers; raising
`Log:` to `Trace` adds PPU/SPU recompiler chatter, not call sites -- measured, see
gt6/ROADMAP.md G7).  What the loader log *does* print, for every module it maps, is
the import/export table in order, with the library, the name, the NID and the address
the call will land on:

    ppu_loader: **** cellFiber import: [_cellFiberPpuInitialize] (0x55870804) -> 0x3c030
    ppu_loader: **** cellSpurs export: (0x2ddbcc0a) at 0x013353c [..]:  _cellSpursWorkloadFlagReceiver2

That is enough for the two questions a milestone log raises:

  * the port wrote `hle:unresolved:0x55870804` -- the title called an import we have
    no handler for, and the runtime answers it by returning 0, i.e. silently doing
    nothing.  The oracle says which function that is (`_cellFiberPpuInitialize`, from
    `cellFiber`) and when the title first reached it.  That is the first divergence.
  * the port wrote `hle:some_name` -- the oracle should show `some_name` in *some*
    import table; if it never does, our name for that NID is wrong.

A NID is believed only when it hashes back (the rule every name source here uses), so
the oracle's names are as trustworthy here as in `nid_from_rpcs3_log.py`.

    # what does our boot silently no-op, and where does it first diverge?
    python rpcs3_oracle.py RPCS3.log --align port.milestone

    # one NID
    python rpcs3_oracle.py RPCS3.log --lookup 0x30AA96C4

    # turn import names into GDB-stub breakpoints for tools/rpcs3_probe/probe.py
    python rpcs3_oracle.py RPCS3.log --breakpoints _cellFiberPpuInitialize,cellSpursGetWorkloadFlag

Exit status is 0 when the report was produced and every `hle:` name the port used is a
name the oracle knows; it is 1 when the port used a name the oracle never saw, because
that means the port and the emulator disagree about what it called.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nid_from_rpcs3_log import build_gazetteer, resolve   # noqa: E402

# An import line, with the address the loader patched the call to.  RPCS3 prints the
# address as "-> 0xNNN" for imports (exports instead carry "at 0xNNN"), which is what
# distinguishes the two even before the "import:"/"export:" word.
IMPORT_RE = re.compile(
    r"ppu_loader:\s+\*\*\*\*\s+(\S+)\s+import:\s+\[(.+?)\]\s+\((0x[0-9a-fA-F]+)\)"
    r"\s*->\s*(0x[0-9a-fA-F]+)")

# "Loading library: liblv2.sprx" / "Importing module 'sys_fs'" -- the load stream, in
# order.  RPCS3 prints a library once per distinct PRX it maps.
LOAD_LIB_RE = re.compile(r"ppu_loader:\s+Loading library:\s*(\S+)")
LOAD_MOD_RE = re.compile(r"ppu_loader:\s+\*\*\s+Imported module '([^']+)'")

# A level-`todo` line: "·U <stamp> {<thread>} <channel> TODO: <text>".  RPCS3 uses this
# for what *it* has not implemented, which is worth knowing when our port also misses
# a function -- "the emulator stubs it too" is a different problem from "we missed it".
TODO_RE = re.compile(
    r"^\u00b7U\s+\S+(?:\s+\{([^}]*)\})?\s+([A-Za-z_][A-Za-z0-9_ ]*?)\s+TODO:\s*(.*)$")

STAMP_RE = re.compile(r"(\d+:\d\d:\d\d\.\d+)")

# A milestone stream line: "<n>\t<key>".  count/comment lines are not keys.
MS_KEY_RE = re.compile(r"^(\d+)\t(.+)$")


class Import:
    __slots__ = ("order", "lib", "name", "nid", "addr", "stamp", "line")

    def __init__(self, order, lib, name, nid, addr, stamp, line):
        self.order, self.lib, self.name = order, lib, name
        self.nid, self.addr, self.stamp, self.line = nid, addr, stamp, line

    @property
    def placeholder(self):
        """True when the loader had no name and printed the NID (or <lib>_NID)."""
        return self.name.lower() == "0x%08x" % self.nid


class Oracle:
    """The ordered stream a loader log implies, plus the name gazetteer."""

    def __init__(self, paths):
        self.paths = list(paths)
        self.imports = []                 # ordered Import
        self.by_nid = {}                  # nid -> first Import
        self.by_name = {}                 # name -> first Import (verified names only)
        self.libs = []                    # ordered library/module load events
        self.todos = []                   # (channel, text, stamp)
        self.lines = 0
        for path in self.paths:
            self._read(path)
        # The gazetteer is built after the read, so that by_name can be filled from
        # imports whose printed name the hash rule verifies.
        self.gaz, self.stats = build_gazetteer(self.paths)
        for imp in self.imports:
            if not imp.placeholder and self.name_of(imp.nid)[0] == imp.name:
                self.by_name.setdefault(imp.name, imp)

    def _read(self, path):
        with open(path, encoding="utf-8", errors="replace") as f:
            for n, line in enumerate(f, 1):
                self.lines += 1
                m = IMPORT_RE.search(line)
                if m:
                    stamp = STAMP_RE.search(line)
                    imp = Import(len(self.imports), m.group(1), m.group(2),
                                 int(m.group(3), 16), int(m.group(4), 16),
                                 stamp.group(1) if stamp else "", n)
                    self.imports.append(imp)
                    self.by_nid.setdefault(imp.nid, imp)
                    continue
                m = LOAD_LIB_RE.search(line) or LOAD_MOD_RE.search(line)
                if m:
                    self.libs.append(m.group(1))
                    continue
                m = TODO_RE.match(line)
                if m:
                    stamp = STAMP_RE.search(line)
                    self.todos.append((m.group(2), m.group(3).strip(),
                                       stamp.group(1) if stamp else ""))

    def name_of(self, nid):
        """(name, libraries) for *nid* per the hash-verified gazetteer."""
        return resolve(self.gaz, nid)

    def todo_for(self, needle):
        """TODO texts that mention *needle* (a function name)."""
        return [t for t in self.todos if needle and needle in t[1]]


def parse_milestones(path):
    """Ordered [(index, key)] from a milestone stream written by runtime/milestone.c."""
    keys = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = MS_KEY_RE.match(line.rstrip("\n"))
            if m:
                keys.append((int(m.group(1)), m.group(2)))
    return keys


UNRESOLVED_RE = re.compile(r"^hle:unresolved:(0x[0-9a-fA-F]{8})$")


def analyse(oracle, keys):
    """Bucket a port's milestone keys into what the oracle can explain.

    Returns a dict with:
      unresolved : [(index, nid, name, libs, addr, stamp)] in boot order -- imports the
                   port answered with a silent 0.  The first is the first divergence.
      unknown    : [(index, key)] hle: names the oracle never saw as an import, i.e.
                   the port and the emulator disagree about what was called.
      agreed     : [(index, key)] hle: names the oracle knows.
      sys_keys   : [(index, n)] lv2 syscall numbers (the oracle does not number these).
    """
    unresolved, unknown, agreed, sys_keys = [], [], [], []
    for idx, key in keys:
        m = UNRESOLVED_RE.match(key)
        if m:
            nid = int(m.group(1), 16)
            name, libs = oracle.name_of(nid)
            imp = oracle.by_nid.get(nid)
            unresolved.append((idx, nid, name, libs,
                               imp.addr if imp else None,
                               imp.stamp if imp else ""))
            continue
        if key.startswith("hle:"):
            short = key[4:]
            if short in oracle.by_name:
                agreed.append((idx, key))
            else:
                unknown.append((idx, key))
            continue
        if key.startswith("sys:"):
            sys_keys.append((idx, key[4:]))
    return {"unresolved": unresolved, "unknown": unknown,
            "agreed": agreed, "sys_keys": sys_keys}


def report(oracle, keys, out=sys.stdout, top=None):
    a = analyse(oracle, keys)
    n_imports = len(oracle.imports)
    print("oracle: %d log line(s), %d import line(s), %d library load(s), %d TODO(s), "
          "%d distinct NIDs named" %
          (oracle.lines, n_imports, len(oracle.libs), len(oracle.todos),
           sum(1 for _ in oracle.gaz)), file=out)
    print("port:   %d milestone key(s): %d hle, %d syscall" %
          (len(keys), sum(1 for _, k in keys if k.startswith("hle:")),
           len(a["sys_keys"])), file=out)

    print("\nFIRST DIVERGENCE", file=out)
    if a["unresolved"]:
        idx, nid, name, libs, addr, stamp = a["unresolved"][0]
        print("  milestone #%d  %s" % (idx, name or "hle:unresolved:0x%08X" % nid), file=out)
        print("    the title called this import; our port has no handler, so it "
              "returned 0", file=out)
        print("    oracle: %s %s (0x%08X) -> %s @ %s" %
              (libs[0] if libs else "?", name or "(unnamed)", nid,
               "0x%08X" % addr if addr is not None else "?", stamp or "?"), file=out)
        todo = oracle.todo_for(name)
        if todo:
            print("    note: the emulator stubs it too (%s)" % todo[0][1], file=out)
    else:
        print("  none -- every hle: call the port made is an import the oracle knows "
              "and the port had a handler for it", file=out)

    if a["unresolved"]:
        print("\nsilent no-ops (%d of %d hle keys)" %
              (len(a["unresolved"]),
               len(a["unresolved"]) + len(a["agreed"]) + len(a["unknown"])), file=out)
        for row in (a["unresolved"][:top] if top else a["unresolved"]):
            idx, nid, name, libs, addr, stamp = row
            print("  #%-5d 0x%08X  %-24s %-22s %s" %
                  (idx, nid, name or "(unnamed by the oracle)",
                   libs[0] if libs else "?", stamp), file=out)

    if a["unknown"]:
        print("\nNAME DISAGREEMENTS (%d) -- the port used a name no import table has"
              % len(a["unknown"]), file=out)
        for idx, key in (a["unknown"][:top] if top else a["unknown"]):
            print("  #%-5d %s" % (idx, key), file=out)
    else:
        print("\nname disagreements: none (%d hle names all appear as imports)"
              % len(a["agreed"]), file=out)

    print("\nnot a divergence: %d import(s) the oracle resolved that the port never "
          "called (an unused import is normal)" % n_imports, file=out)
    return 1 if a["unknown"] else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", nargs="+", help="emulator loader log file(s)")
    ap.add_argument("--align", metavar="MILESTONE",
                    help="diff a port's PS3_MILESTONE_OUT stream against the log")
    ap.add_argument("--lookup", action="append", default=[], metavar="NID|NAME",
                    help="name a NID, or locate a name's import(s) (repeatable)")
    ap.add_argument("--breakpoints", metavar="NAME[,NAME...]",
                    help="print probe.py-style breakpoints for the named imports")
    ap.add_argument("--dump-imports", action="store_true",
                    help="print the ordered import stream")
    ap.add_argument("--top", type=int, default=None,
                    help="with --align, list only the first N of each bucket")
    ap.add_argument("--out", metavar="FILE", help="write the report here too")
    args = ap.parse_args(argv)

    for p in args.log:
        if not os.path.exists(p):
            print("rpcs3_oracle: no such file: %s" % p, file=sys.stderr)
            return 2

    oracle = Oracle(args.log)

    if args.dump_imports:
        for imp in oracle.imports:
            print("%6d  %-22s %-40s 0x%08X -> 0x%08X  %s" %
                  (imp.order, imp.lib, imp.name, imp.nid, imp.addr, imp.stamp))
        return 0

    if args.lookup:
        rc = 0
        for spec in args.lookup:
            if spec.lower().startswith("0x"):
                nid = int(spec, 16)
                name, libs = oracle.name_of(nid)
                imp = oracle.by_nid.get(nid)
                if not name:
                    print("  0x%08X  (no verified name in the log)" % nid)
                    rc = 1
                    continue
                print("  0x%08X  %s  [%s]%s" %
                      (nid, name, ",".join(libs),
                       "  -> 0x%08X @ %s" % (imp.addr, imp.stamp) if imp else ""))
            else:
                imp = oracle.by_name.get(spec)
                if not imp:
                    print("  %s  (not imported anywhere in the log)" % spec)
                    rc = 1
                    continue
                print("  %s  0x%08X  [%s]  import #%d -> 0x%08X @ %s" %
                      (spec, imp.nid, imp.lib, imp.order, imp.addr, imp.stamp))
        return rc

    if args.breakpoints:
        want = [w.strip() for w in args.breakpoints.split(",") if w.strip()]
        recipes, missing = [], []
        for name in want:
            imp = oracle.by_name.get(name)
            if imp is None and name.lower().startswith("0x"):
                imp = oracle.by_nid.get(int(name, 16))
            if imp is None:
                missing.append(name)
                continue
            recipes.append({"op": "breakpoint", "addr": "0x%08X" % imp.addr,
                            "label": imp.name, "continue_first": True, "max_hits": 1})
        print(json.dumps(recipes, indent=2))
        for name in missing:
            print("rpcs3_oracle: no address for %s" % name, file=sys.stderr)
        return 1 if missing else 0

    if args.align:
        keys = parse_milestones(args.align)
        out = sys.stdout
        fh = None
        if args.out:
            fh = open(args.out, "w")
            out = fh
        rc = report(oracle, keys, out=out, top=args.top)
        if fh:
            fh.close()
            with open(args.out) as f:
                sys.stdout.write(f.read())
        return rc

    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
