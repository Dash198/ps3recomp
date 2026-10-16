"""Self-check for tools/import_dashboard.py.

The dashboard is a join over four sources that all have to be right for its verdict
to mean anything: a port's import table, the handler set the runtime actually
registers, docs/MODULE_STATUS.md, and a milestone log. This pins each source's
parser against a fixture, then pins the joins (module -> status row by normalized
name, then by import library) and the three answers that matter -- named, missing,
and "the runtime proved this one unresolved".

Fixtures are synthetic, so this runs anywhere; the handler set it joins against is
the real one (gen_hle_nids.py's scanner plus every registration in the tree), which
is exactly what a build produces.

Run: python tools/test_import_dashboard.py
"""
import contextlib
import io
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import import_dashboard as dash                 # noqa: E402
from nid_database import compute_nid            # noqa: E402

CHECKS = 0


def check(cond, why):
    global CHECKS
    assert cond, why
    CHECKS += 1


def write(path, text):
    with open(path, "w") as f:
        f.write(text)
    return path


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = dash.main(argv)
    return rc, out.getvalue(), err.getvalue()


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="import_dashboard_")

    # ---- registrations: literal, ps3_compute_nid("..."), and a table loop -----
    reg_src = write(os.path.join(tmp, "reg.c"), """
    extern "C" void ps3_hle_register(unsigned int nid, const char* name, void* fn);
    static void h_ok(ppu_context* c) { (void)c; }
    void ppu_reg_register(void) {
        ps3_hle_register(0x5EED0001, "cellLiteral", reinterpret_cast<void*>(h_ok));
        ps3_hle_register_ctx(ps3_compute_nid("cellComputed"), "cellComputed", h_ok);
        static const struct { const char* name; void* fn; } tab[] = {
            { "cellRowA", h_ok }, { "cellRowB", h_ok },
        };
        for (size_t i = 0; i < 2; i++)
            ps3_hle_register_ctx(ps3_compute_nid(tab[i].name), tab[i].name, tab[i].fn);
    }
    """)
    regs = dash.parse_registrations(open(reg_src).read(), reg_src, lambda m: None)
    got = dict(regs)
    check(got.get(0x5EED0001) == "cellLiteral", "literal registration not parsed")
    check(got.get(compute_nid("cellComputed")) == "cellComputed",
          "ps3_compute_nid registration not parsed")
    check(got.get(compute_nid("cellRowA")) == "cellRowA"
          and got.get(compute_nid("cellRowB")) == "cellRowB",
          "table-loop rows not resolved: %r" % (sorted(got.values()),))

    # a table loop whose initializer is not in the file must warn, not invent rows
    w = []
    check(dash.parse_registrations(
        "ps3_hle_register_ctx(ps3_compute_nid(tab[i].name), tab[i].name, tab[i].fn);",
        "x.c", w.append) == [], "unresolvable table loop invented rows")
    check(w and "tab" in w[0], "unresolvable table loop did not warn: %r" % (w,))

    handlers = dash.load_handlers([reg_src], lambda m: None)
    check(handlers.get(0x5EED0001) == ("reg", "cellLiteral"),
          "extra source not folded into the handler set")
    # unit-test mocks are not handlers a game will ever have: test_hle.cpp registers
    # 0x12345678 and nothing else in the tree does.
    check(not dash.is_test_file(os.path.join(dash.ROOT, "runtime", "ppu", "ppu_sysprx.cpp"))
          and dash.is_test_file(os.path.join(dash.ROOT, "runtime", "ppu", "tests",
                                           "test_hle.cpp")),
          "is_test_file misjudges toolkit sources")
    check(0x12345678 not in handlers,
          "a unit-test-only registration was counted as a handler")

    # the real table loop in sysNet.c must resolve (this is the one in the tree)
    net = os.path.join(dash.ROOT, "libs", "network", "sysNet.c")
    net_regs = dash.parse_registrations(open(net, encoding="latin1").read(), net,
                                        lambda m: None)
    check(len(net_regs) > 15 and "recvfrom" in {n for _, n in net_regs},
          "sysNet.c socket table did not resolve: %d rows" % len(net_regs))

    # ---- module status table --------------------------------------------------
    status_src = write(os.path.join(tmp, "status.md"), """
| Module | Category | Status | Notes |
|--------|----------|--------|-------|
| cellFs | File | **Complete** | real file I/O |
| cellBar | Bar | Partial | no real bar |
| sys_net | Net | **Complete** | sockets |
| **Total** | 3 | | |
""")
    rows, alias = dash.load_module_status(status_src)
    check(rows.get("cellFs") == ("Complete", "real file I/O"), "status row parsed wrong")
    check("Module" not in rows and "**Total**" not in rows, "header/footer leaked into rows")
    check(dash.status_for(rows, alias, "cellFs", "whatever") == rows["cellFs"],
          "exact module join failed")
    # sysNet.c -> sys_net: the source basename only joins normalization
    check(dash.status_for(rows, alias, "sysNet", "nope") == ("Complete", "sockets"),
          "normalized module join failed")
    # a port's own source file (stubs.c) has no row, so the import library decides
    check(dash.status_for(rows, alias, "port_stubs", "cellBar") == rows["cellBar"],
          "library fallback join failed")
    check(dash.status_for(rows, alias, "nope", "nope2") is None, "unknown module joined")

    # ---- the four cases, end to end -------------------------------------------
    port_src = write(os.path.join(tmp, "port_stubs.c"), """
    void ps3_hle_register(unsigned int nid, const char* name, void* fn);
    static void h_stub(void) {}
    void port_register(void) {
        ps3_hle_register(0x0BADF00D, "cellBar_0BADF00D", (void*)h_stub);
    }
    """)
    named_impl = compute_nid("cellFsOpen")                    # handler, in the DB
    named_missing = compute_nid("_cellSpursWorkloadFlagReceiver2")   # DB name, no handler
    unnamed_stub = 0x0BADF00D                                 # handler, placeholder name
    unnamed_missing = 0x01010101                              # no handler, no name
    imports = [
        {"library": "cellFs", "nid": "0x%08X" % named_impl, "stub": "0x0"},
        {"library": "cellSpurs", "nid": "0x%08X" % named_missing, "stub": "0x0"},
        {"library": "cellBar", "nid": "0x%08X" % unnamed_stub, "stub": "0x0"},
        {"library": "cellBar", "nid": "0x%08X" % unnamed_missing, "stub": "0x0"},
    ]
    imports_path = os.path.join(tmp, "imports.json")
    with open(imports_path, "w") as f:
        json.dump(imports, f)
    log_path = write(os.path.join(tmp, "run.txt"),
                     "# counts\ncount\thle:cellFsOpen\t7\n"
                     "count\thle:unresolved:0x%08X\t1\n"
                     "1\thle:cellFsOpen\n2\thle:unresolved:0x%08X\n"
                     % (named_missing, named_missing))

    argv = ["--imports", imports_path, "--log", log_path, "--extra-src", port_src,
            "--module-status", status_src, "--json", os.path.join(tmp, "out.json")]
    rc, out, err = run(argv + ["--check"])
    check("4 imported NIDs; 2 named, 2 unnamed" in out,
          "summary wrong:\n%s" % out.splitlines()[0])
    check("called during the run: 2 (missing: 1, unnamed: 0)" in out,
          "runtime summary wrong: %s" % [l for l in out.splitlines()
                                         if l.startswith("called")])
    check(rc == 0 and "no static/runtime contradiction" in out,
          "check should pass: rc=%d\n%s%s" % (rc, out, err))
    # the reached-but-unhandled row comes first, ahead of the unevaluated ones
    lines = out.splitlines()
    hdr = next(i for i, l in enumerate(lines) if l.startswith("library"))
    check("UNRESOLVED" in lines[hdr + 1] and "0x%08X" % named_missing in lines[hdr + 1],
          "proved-unresolved row not first: %r" % (lines[hdr + 1],))
    check("(stub: cellBar_0BADF00D)" in out,
          "port placeholder shown as a real name:\n%s" % out)

    table = {r["nid"]: r for r in json.load(open(os.path.join(tmp, "out.json")))}
    check(table[named_impl]["status"] == "implemented" and table[named_impl]["called"],
          "implemented/called misclassified")
    check(table[named_missing]["status"] == "missing" and table[named_missing]["named"]
          and table[named_missing]["called"] and table[named_missing]["unresolved"],
          "named-and-reached-but-unhandled misclassified: %r" % (table[named_missing],))
    check(table[unnamed_stub]["status"] == "partial"      # library cellBar -> Partial
          and not table[unnamed_stub]["named"]
          and table[unnamed_stub]["placeholder_name"],
          "port stub misclassified: %r" % (table[unnamed_stub],))
    # never reached, so it stays the work queue rather than a --check failure
    check(table[unnamed_missing]["status"] == "missing"
          and not table[unnamed_missing]["called"]
          and not table[unnamed_missing]["unresolved"]
          and not table[unnamed_missing]["named"],
          "unreached unknown misclassified: %r" % (table[unnamed_missing],))

    # ---- check fails on the two things that are actually defects ---------------
    called_unknown = write(os.path.join(tmp, "unknown.txt"), "1\thle:MadeUpCallName\n")
    imports2 = os.path.join(tmp, "imports2.json")
    with open(imports2, "w") as f:
        json.dump(imports + [{"library": "cellBar",
                              "nid": "0x%08X" % compute_nid("MadeUpCallName"),
                              "stub": "0x0"}], f)
    rc, out, err = run(["--imports", imports2, "--log", called_unknown,
                        "--extra-src", port_src, "--module-status", status_src,
                        "--check"])
    check(rc == 1 and "called import(s) unnamed" in err,
          "a called-but-unnamed import should fail the check: rc=%d %s" % (rc, err))

    contradiction = write(os.path.join(tmp, "bad.txt"),
                          "1\thle:unresolved:0x%08X\n" % named_impl)
    rc, out, err = run(["--imports", imports_path, "--log", contradiction,
                        "--extra-src", port_src, "--module-status", status_src,
                        "--check"])
    check(rc == 1 and "have a handler yet ran unresolved" in err,
          "static/runtime contradiction should fail the check: rc=%d %s" % (rc, err))

    # ---- missing inputs are an error, not a silent empty report ---------------
    rc, out, err = run(["--imports", os.path.join(tmp, "nope.json")])
    check(rc == 2 and "no imports file" in err, "missing input should exit 2")

    print("ok: %d checks (registration forms, status joins, four coverage classes, "
          "check exits)" % CHECKS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
