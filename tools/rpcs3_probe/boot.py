"""boot.py - run a title headlessly and keep the emulator's log, reproducibly.

The loader log is the oracle `tools/rpcs3_oracle.py` reads (see its docstring for why
that is the log and not a call trace), so producing one on demand is the other half of
the rig.  Two things make that safe to do repeatedly:

  * the log is **never** written to the default ``~/.cache/rpcs3/RPCS3.log``.  RPCS3
    truncates that file at startup, so a boot would silently destroy the previous one.
    We point ``XDG_CACHE_HOME`` at ``--cache-root`` instead; the emulator's caches are
    symlinked back in so a warm boot stays warm.
  * the config that carries the log levels is ``~/.config/rpcs3/config.yml`` and RPCS3
    rewrites it, so ``--log`` edits it under a backup and restores it afterwards.

The log-level schema is per-channel under ``Log:`` and it does work for a CLI boot
(measured: ``PPU: Trace`` produced 12.6M trace lines)::

    Log:
      PPU: Trace
      cellSpurs: Trace

What it does *not* buy is a call stream -- RPCS3 logs import tables, not HLE calls --
so leave it alone unless you are chasing a recompiler question.  The load stream is
already in the default log.

    # plan only: print the command, the log path and the config change, run nothing
    python boot.py --rpcs3 <rpscs3> --title <EBOOT.BIN> --dry-run

    # a real 2-minute boot, logging nothing but the defaults
    python boot.py --rpcs3 <rpcs3> --title <EBOOT.BIN> --seconds 120 --out boot.log

    # ... then align it with a port's milestone stream
    python ../rpcs3_oracle.py boot.log --align port.milestone
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

# The cache subdirectories RPCS3 keeps under XDG_CACHE_HOME/rpcs3.  Symlinking the
# real ones in means an isolated log costs nothing in recompilation.
CACHE_SUBDIRS = ("cache", "shaderlog", "spu_progs", "ppu_progs")

# "Log:\n  {}\n" or "Log:\n  <channel>: <level>\n"* -- the whole node, to be replaced.
LOG_NODE_RE = re.compile(r"^Log:\n(?:  .*\n)*", re.M)


def rewrite_log_node(text, overrides):
    """Return *text* with its ``Log:`` node replaced by *overrides* (channel->level).

    ``overrides`` of ``None`` means "leave the file as it was" -- the common case,
    because the default log already carries the load stream.
    """
    if overrides is None:
        return text
    node = "Log:\n"
    if overrides:
        node += "".join("  %s: %s\n" % (k, v) for k, v in overrides.items())
    else:
        node += "  {}\n"
    if not LOG_NODE_RE.search(text):
        raise ValueError("no 'Log:' node to replace in the config")
    return LOG_NODE_RE.sub(node, text, count=1)


def parse_overrides(spec):
    """``"PPU:Trace,cellSpurs:Notice"`` -> ``{"PPU": "Trace", ...}``; ``None`` if empty."""
    if not spec:
        return None
    out = {}
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        if ":" not in item:
            raise ValueError("--log wants channel:level, got %r" % item)
        ch, level = item.split(":", 1)
        out[ch.strip()] = level.strip()
    return out


def plan(rpcs3, title, cache_root, seconds):
    """Everything that decides a boot, as data, so --dry-run can print it."""
    cache = os.path.join(cache_root, "cache")
    rpcs3_cache = os.path.join(cache, "rpcs3")
    argv = [rpcs3, "--headless", title]
    return {
        "argv": argv,
        "env": {"XDG_CACHE_HOME": cache},
        "cache_root": cache_root,
        "cache_dir": cache,
        "rpcs3_home": rpcs3_cache,
        "log": os.path.join(rpcs3_cache, "RPCS3.log"),
        "seconds": seconds,
    }


def prepare(p, home_cache=None, dry=False):
    """Create the isolated cache dir and link the real caches into it.

    Returns the list of (name, target) links that were made; makes no change when
    *dry* is set.
    """
    home_cache = home_cache or os.path.join(os.path.expanduser("~"), ".cache", "rpcs3")
    made = []
    if dry:
        return [(os.path.join(p["rpcs3_home"], d), os.path.join(home_cache, d))
                for d in CACHE_SUBDIRS if os.path.isdir(os.path.join(home_cache, d))]
    os.makedirs(p["rpcs3_home"], exist_ok=True)
    for d in CACHE_SUBDIRS:
        src = os.path.join(home_cache, d)
        dst = os.path.join(p["rpcs3_home"], d)
        if os.path.isdir(src) and not os.path.exists(dst):
            os.symlink(src, dst)
            made.append((dst, src))
    return made


def boot(p, config=None, overrides=None):
    """Run the boot for *p['seconds']*, return (rc, log_path).

    The config is restored no matter how the run ends, including on SIGKILL of the
    emulator, because the restore is in a finally block of this function.
    """
    config = config or os.path.join(os.path.expanduser("~"), ".config", "rpcs3",
                                    "config.yml")
    backup = None
    try:
        if overrides is not None and os.path.exists(config):
            with open(config) as f:
                original = f.read()
            with open(config, "w") as f:
                f.write(rewrite_log_node(original, overrides))
            backup = original
        env = dict(os.environ, **p["env"])
        proc = subprocess.Popen(p["argv"], env=env,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                start_new_session=(os.name == "posix"))
        try:
            rc = proc.wait(timeout=p["seconds"])
        except subprocess.TimeoutExpired:
            # RPCS3 never exits on its own; the timeout *is* the end of the capture.
            if os.name == "posix":
                os.killpg(os.getpgid(proc.pid), 9)
            else:
                proc.kill()
            proc.wait()
            rc = -9
        return rc, p["log"]
    finally:
        if backup is not None:
            with open(config, "w") as f:
                f.write(backup)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rpcs3", required=True,
                    help="the rpcs3 executable (an extracted AppImage's usr/bin/rpcs3)")
    ap.add_argument("--title", required=True, help="the (S)ELF to boot, e.g. EBOOT.BIN")
    ap.add_argument("--cache-root", default="/tmp/opencode/rpcs3_boot",
                    help="isolated XDG_CACHE_HOME (default: %(default)s)")
    ap.add_argument("--out", metavar="FILE", help="copy the log here when done")
    ap.add_argument("--seconds", type=float, default=120.0,
                    help="how long to let it run before killing it (default: %(default)s)")
    ap.add_argument("--log", metavar="CH:LEVEL,...",
                    help="pin per-channel log levels for this boot only")
    ap.add_argument("--config", help="the config.yml to patch (default: the user's)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan; create nothing, run nothing")
    args = ap.parse_args(argv)

    if not os.path.exists(args.rpcs3):
        print("boot: no such rpcs3: %s" % args.rpcs3, file=sys.stderr)
        return 2
    if not args.dry_run and not os.path.exists(args.title):
        print("boot: no such title: %s" % args.title, file=sys.stderr)
        return 2
    overrides = parse_overrides(args.log)
    p = plan(args.rpcs3, args.title, args.cache_root, args.seconds)
    links = prepare(p, dry=args.dry_run)

    config = args.config or os.path.join(os.path.expanduser("~"), ".config", "rpcs3",
                                         "config.yml")
    if overrides:
        with open(config) as f:
            after = rewrite_log_node(f.read(), overrides)
        shown = after.split("Log:", 1)[1].split("\n\n", 1)[0][:200]
    else:
        shown = "  (unchanged: the default log already carries the load stream)"

    if args.dry_run:
        print("would run:   %s" % " ".join(p["argv"][:2] + ["<title>"]))
        print("title:       %s" % args.title)
        print("for:         %.0fs, then SIGKILL" % args.seconds)
        print("XDG_CACHE_HOME=%s" % p["env"]["XDG_CACHE_HOME"])
        print("log written: %s  (never ~/.cache/rpcs3/RPCS3.log)" % p["log"])
        print("would link:  %s" % (", ".join(d for d, _ in links) or "(nothing to link)"))
        print("config:      %s" % config)
        print("config Log: node for this run")
        print(shown)
        return 0

    os.makedirs(p["cache_root"], exist_ok=True)
    prepare(p)
    t0 = time.time()
    rc, log = boot(p, config=config, overrides=overrides)
    dt = time.time() - t0
    nlines = 0
    if os.path.exists(log):
        nlines = sum(1 for _ in open(log, encoding="utf-8", errors="replace"))
    print("boot: %s  rc=%d  %.0fs  %s  (%d lines)" %
          (os.path.basename(args.title), rc, dt, log, nlines))
    if args.out and os.path.exists(log):
        shutil.copyfile(log, args.out)
        print("boot: log copied to %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
