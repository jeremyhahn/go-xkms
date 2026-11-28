"""code-review-v5125-tests.py -- the regression tests for code-review.yml
v5.12.5 (Tenant Agent ruling 1012: Codex reviews failed after a fixed 600 s
wait for the host's review lock).

The code under test is read out of the workflow file and run under bash.
Nothing reaches the network.

  B. THE BUDGET IS THE JOB'S. lib.sh's JOB_BUDGET equals the review job's
     timeout-minutes in seconds.
  W. EVERY LOCK WAIT IS THE BUDGET'S. Both flock calls on the review lock
     wait "$wait_s" from lock_wait, and no fixed -w number is left; the
     review's wait is computed before workflow commands stop.
  L. lock_wait prints the budget left less the time asked for, and dies with
     the reason (recorded in $WORK/error) when nothing is left or the start
     time is not a number.

Run: python3 -I software/templates/github-actions/testdata/code-review-v5125-tests.py [workflow]
"""
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
WF = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parent / "code-review.yml"
src = WF.read_text()
fails = []


def check(name, ok, why=""):
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else ": " + why))
    if not ok:
        fails.append(name)


def one(pat, text, what):
    m = re.findall(pat, text, re.S)
    if len(m) != 1:
        print("FATAL: %s found %d times" % (what, len(m)))
        sys.exit(9)
    return m[0]


review = one(r"\n  review:\n(.*?)\n  review-opencode:\n", src, "the review job")
minutes = int(one(r"\n    timeout-minutes: (\d+)\n", review, "the review job's timeout-minutes"))
lib = one(r"cat > \"\$WORK/lib.sh\" <<'LIB'\n(.*?)\n\s*LIB\n", review, "the review job's lib.sh")
budget = one(r"JOB_BUDGET=\$\(\( (\d+ \* 60) \)\)", lib, "JOB_BUDGET")
check("B1 JOB_BUDGET is the review job's timeout-minutes", eval(budget) == minutes * 60,
      "%s != %d * 60" % (budget, minutes))

flocks = re.findall(r"flock -w (\S+) -E 75 \"\$CODEX_MASTER/\.review\.lock\"", src)
check("W1 two flocks on the review lock", len(flocks) == 2, str(flocks))
check("W2 each waits $wait_s", all(f == '"$wait_s"' for f in flocks), str(flocks))
check("W3 no fixed wait is left", not re.search(r"flock -w \d", src))
check("W4 each wait is from lock_wait", len(re.findall(r"wait_s=\$\(lock_wait \$\(\( ", src)) == 2)
codex = one(r"- name: Review the head with codex as uid 1000\n(.*?)\n      - name: ", src, "the codex step")
check("W5 the review's wait comes before stop-commands",
      0 <= codex.find("wait_s=$(lock_wait") < codex.find('echo "::stop-commands::'))
check("W6 the timeout message names the wait", codex.count('timed out after $wait_s s waiting') == 1)

lw = one(r"(lock_wait\(\) \{\n.*?\n\s*\})(?:\n|$)", lib, "lock_wait")
die = one(r"(die\(\) \{.*?\})\n", lib, "die")


def run(start, need):
    with tempfile.TemporaryDirectory() as w:
        if start is not None:
            pathlib.Path(w, "job-start").write_text(str(start) + "\n")
        script = "set -euo pipefail\nshopt -s inherit_errexit\nCODEX_MASTER=/root/.codex\n%s\nJOB_BUDGET=$(( %s ))\n%s\nx=$(lock_wait %s)\necho \"$x\"\n" % (die, budget, lw, need)
        p = subprocess.run(["bash", "-c", script], env={"WORK": w, "PATH": os.environ["PATH"]},
                           capture_output=True, text=True)
        err = pathlib.Path(w, "error")
        return p.returncode, p.stdout.strip(), err.read_text() if err.exists() else ""


now = int(time.time())
rc, out, err = run(now - 100, 2000)
check("L1 the wait is the budget left less the need", rc == 0 and out.isdigit() and abs(int(out) - (minutes * 60 - 100 - 2000)) <= 2, (rc, out, err))
rc, out, err = run(now - 100, minutes * 60)
check("L2 no time left dies with the reason", rc != 0 and "no time is left" in err, (rc, out, err))
rc, out, err = run("x1", 10)
check("L3 a bad start time dies", rc != 0 and "not a number" in err, (rc, out, err))
rc, out, err = run(None, 10)
check("L4 a missing start time dies", rc != 0 and "cannot read" in err, (rc, out, err))
check("L5 the guard writes the start time", src.count('date +%s > "$WORK/job-start"') == 1)

print("ALL PASS" if not fails else "FAILED: " + " ".join(fails))
sys.exit(1 if fails else 0)
