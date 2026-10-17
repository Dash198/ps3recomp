"""Self-check for tools/rpcs3_probe/boot.py (the reproducible headless boot).

The rig exists to make a boot repeatable without destroying the previous log or the
user's config, so the checks are about that promise:

  * the log path is always under ``--cache-root`` and never the default
    ``~/.cache/rpcs3/RPCS3.log`` (RPCS3 truncates that file at startup);
  * ``Log:`` overrides are written into the config for the run and restored
    afterwards, whatever the emulator does;
  * ``--dry-run`` creates nothing and runs nothing.

No emulator is needed: the "rpcs3" here is a two-line script.

Run: python tools/test_rpcs3_boot.py
"""
import contextlib
import io
import os
import stat
import sys
import tempfile
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "rpcs3_probe"))
import boot as B                                  # noqa: E402

CHECKS = 0


def check(cond, why):
    global CHECKS
    assert cond, why
    CHECKS += 1


def write(path, text, exec_bit=False):
    with open(path, "w") as f:
        f.write(text)
    if exec_bit:
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return path


CONFIG = textwrap.dedent("""\
    Core:
      PPU Decoder: Recompiler
    Log:
      {}
    Miscellaneous:
      Automatically start games after boot: true
    """)


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rpcs3_boot_")

    # --- log-level overrides ----------------------------------------------------
    check(B.parse_overrides(None) is None, "empty --log should mean no change")
    check(B.parse_overrides("") is None, "blank --log should mean no change")
    check(B.parse_overrides("PPU:Trace, cellSpurs: Notice") ==
          {"PPU": "Trace", "cellSpurs": "Notice"},
          "override parse wrong: %r" % (B.parse_overrides("PPU:Trace,cellSpurs: Notice"),))
    try:
        B.parse_overrides("PPU")
        check(False, "a --log item without a colon should raise")
    except ValueError:
        check(True, "")
    try:
        B.rewrite_log_node("Core:\n  x: 1\n", {"PPU": "Trace"})
        check(False, "a config with no Log: node should raise")
    except ValueError:
        check(True, "")
    check(B.rewrite_log_node(CONFIG, None) == CONFIG,
          "None overrides must leave the config byte-identical")
    got = B.rewrite_log_node(CONFIG, {"PPU": "Trace"})
    check("Log:\n  PPU: Trace\n" in got and "  {}\n" not in got,
          "Log: node not rewritten: %r" % got)
    check(got.count("Log:") == 1 and "Automatically start games" in got,
          "rewrite touched the wrong part of the config: %r" % got)
    check("  {}\n" in B.rewrite_log_node(CONFIG, {}),
          "an explicit empty override should restore the '{}' node")

    # --- the plan never touches the default log ---------------------------------
    p = B.plan("/tmp/nope/rpcs3", "/tmp/nope/EBOOT.BIN", os.path.join(tmp, "iso"), 120)
    check(p["argv"][1] == "--headless", "the boot must be headless: %r" % (p["argv"],))
    check(p["env"]["XDG_CACHE_HOME"] == p["cache_dir"],
          "XDG_CACHE_HOME must be the isolated cache")
    check(p["log"].startswith(p["cache_root"]) and p["log"].endswith("RPCS3.log"),
          "log escaped the cache root: %r" % p["log"])
    check(os.path.join(os.path.expanduser("~"), ".cache", "rpcs3", "RPCS3.log")
          != p["log"], "the plan must not target the default log")

    # --- prepare() in dry mode changes nothing ----------------------------------
    iso = os.path.join(tmp, "iso2")
    home = os.path.join(tmp, "homecache")
    os.makedirs(os.path.join(home, "cache"))
    p2 = B.plan("x", "y", iso, 5)
    links = B.prepare(p2, home_cache=home, dry=True)
    check(not os.path.exists(iso), "dry prepare created the cache root")
    check(links == [(os.path.join(p2["rpcs3_home"], "cache"),
                     os.path.join(home, "cache"))],
          "dry prepare should report the cache link it would make: %r" % (links,))
    B.prepare(p2, home_cache=home)
    check(os.path.islink(os.path.join(p2["rpcs3_home"], "cache")),
          "a real prepare should symlink the emulator cache in")

    # --- --dry-run runs nothing -------------------------------------------------
    fake = write(os.path.join(tmp, "rpcs3"), "#!/bin/sh\nexit 0\n", exec_bit=True)
    title = write(os.path.join(tmp, "EBOOT.BIN"), "not really an elf\n")
    cfg = write(os.path.join(tmp, "config.yml"), CONFIG)
    iso3 = os.path.join(tmp, "iso3")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = B.main(["--rpcs3", fake, "--title", title, "--cache-root", iso3,
                     "--config", cfg, "--log", "PPU:Trace", "--dry-run"])
    check(rc == 0, "--dry-run should exit 0, got %d" % rc)
    check(not os.path.exists(iso3), "--dry-run created the cache root")
    check("PPU: Trace" in buf.getvalue() and "XDG_CACHE_HOME" in buf.getvalue(),
          "--dry-run did not show the plan:\n%s" % buf.getvalue())
    check(open(cfg).read() == CONFIG, "--dry-run edited the config")

    # --- a real (scripted) boot, and the config it must restore -----------------
    cfg2 = write(os.path.join(tmp, "config2.yml"), CONFIG)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = B.main(["--rpcs3", fake, "--title", title,
                     "--cache-root", os.path.join(tmp, "iso4"),
                     "--config", cfg2, "--log", "PPU:Trace", "--seconds", "5"])
    check(rc == 0, "a boot of an exiting script should exit 0, got %d" % rc)
    check(open(cfg2).read() == CONFIG,
          "the config was not restored after the boot:\n%s" % open(cfg2).read())

    # --- a boot that has to be killed is still restored -------------------------
    sleeper = write(os.path.join(tmp, "sleeper"), "#!/bin/sh\nsleep 30\n", exec_bit=True)
    cfg3 = write(os.path.join(tmp, "config3.yml"), CONFIG)
    with contextlib.redirect_stdout(io.StringIO()):
        rc = B.main(["--rpcs3", sleeper, "--title", title,
                     "--cache-root", os.path.join(tmp, "iso5"), "--config", cfg3,
                     "--log", "PPU:Trace", "--seconds", "0.4"])
    check(rc == 0, "a killed boot should still report rc 0, got %d" % rc)
    check(open(cfg3).read() == CONFIG,
          "a killed boot did not restore the config:\n%s" % open(cfg3).read())

    # --- a missing emulator is refused ------------------------------------------
    with contextlib.redirect_stderr(io.StringIO()):
        check(B.main(["--rpcs3", os.path.join(tmp, "gone"), "--title", title,
                      "--dry-run"]) == 2, "a missing rpcs3 should exit 2")

    print("ok: %d checks (overrides, isolation, dry-run, config restore, kill)" % CHECKS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
