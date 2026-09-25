#!/usr/bin/env bash
#
# Tests for scripts/release-assets.sh against a local stub of the two Gitea
# endpoints it uses: the release-by-tag lookup and the asset download URL,
# plus the asset POST and DELETE that `upload` performs. The stub records
# every mutating request, so each decision of the upload table -- skip,
# replace, add -- is asserted by what reached the server, not by what the
# script printed. Nothing here touches a real release.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/scripts/release-assets.sh"
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { [ "$2" = "$3" ] && ok "$1" || no "$1" "$2" "$3"; }
true_() { local name=$1; shift; "$@" && ok "$name" || no "$name" "true" "false"; }
false_() { local name=$1; shift; "$@" && no "$name" "false" "true" || ok "$name"; }
section() { printf '\n%s\n' "$1"; }

# --- stub Gitea -------------------------------------------------------------
STUB=$(mktemp -d)
ASSETS="$STUB/assets"   # one file per asset; the file name is the asset name
LOG="$STUB/requests.log"
mkdir -p "$ASSETS"; : > "$LOG"
cat > "$STUB/server.py" <<'PY'
import json, os, sys, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
ASSETS, LOG, TAG = sys.argv[1], sys.argv[2], sys.argv[3]
def asset_id(name):
    names = sorted(os.listdir(ASSETS)); return 100 + names.index(name)
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body=b"", ctype="application/json"):
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def _auth(self):
        return self.headers.get("Authorization") == "token stub-token"
    def do_GET(self):
        if not self._auth(): return self._send(401, b'{"message":"no"}')
        u = urllib.parse.urlparse(self.path)
        if u.path == f"/api/v1/repos/o/r/releases/tags/{TAG}":
            base = f"http://{self.headers['Host']}"
            assets = [{"id": asset_id(n), "name": n, "size": os.path.getsize(os.path.join(ASSETS, n)),
                       "browser_download_url": f"{base}/dl/{n}"} for n in sorted(os.listdir(ASSETS))]
            return self._send(200, json.dumps({"id": 1, "tag_name": TAG, "assets": assets}).encode())
        if u.path.startswith("/dl/"):
            p = os.path.join(ASSETS, u.path[4:])
            if os.path.exists(p): return self._send(200, open(p, "rb").read(), "application/octet-stream")
        return self._send(404, b'{"message":"not found"}')
    def do_POST(self):
        if not self._auth(): return self._send(401, b'{"message":"no"}')
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
        if u.path == "/api/v1/repos/o/r/releases/1/assets" and "name" in q:
            name = q["name"][0]; n = int(self.headers.get("Content-Length", "0")); self.rfile.read(n)
            open(os.path.join(ASSETS, name), "wb").write(b"uploaded")
            open(LOG, "a").write(f"POST {name}\n")
            return self._send(201, json.dumps({"id": asset_id(name), "name": name}).encode())
        return self._send(404, b'{}')
    def do_DELETE(self):
        if not self._auth(): return self._send(401, b'{"message":"no"}')
        u = urllib.parse.urlparse(self.path)
        prefix = "/api/v1/repos/o/r/releases/1/assets/"
        if u.path.startswith(prefix):
            aid = int(u.path[len(prefix):])
            for n in sorted(os.listdir(ASSETS)):
                if asset_id(n) == aid:
                    os.remove(os.path.join(ASSETS, n)); open(LOG, "a").write(f"DELETE {aid} {n}\n")
                    return self._send(204)
        return self._send(404, b'{}')
srv = HTTPServer(("127.0.0.1", 0), H)
print(srv.server_address[1], flush=True)
srv.serve_forever()
PY
python3 "$STUB/server.py" "$ASSETS" "$LOG" v9.9.9-alpha > "$STUB/port" 2> "$STUB/server.err" &
SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$STUB"' EXIT
# The stub prints its port once bound. Python start-up on a loaded CI runner
# has been measured past the 5 s this wait used to allow, and an empty PORT
# silently became port 80, failing every assertion below with "Failed to
# connect to 127.0.0.1 port 80". The wait is now generous, and a server that
# never comes up fails the suite by name with its own stderr.
for _ in $(seq 1 600); do [ -s "$STUB/port" ] && break; sleep 0.1; done
PORT=$(cat "$STUB/port")
if [ -z "$PORT" ]; then
    echo "release-assets.test.sh: stub API server did not publish a port within 60s" >&2
    cat "$STUB/server.err" >&2
    exit 1
fi
export RELEASE_API="http://127.0.0.1:${PORT}/api/v1" RELEASE_REPO="o/r" RELEASE_TAG="v9.9.9-alpha" RELEASE_TOKEN="stub-token"
V=9.9.9-alpha

# --- expected: the matrix ---------------------------------------------------
section "expected"
eq "the matrix is 20 assets (2 arch x (2 binaries x 2 variants + xkey) x file+sha256)" "20" "$("$SCRIPT" expected "$V" | wc -l | tr -d ' ')"
true_ "a FIPS xkmsd for arm64 is expected" grep -qx "xkmsd-$V-linux-arm64-fips.sha256" <<<"$("$SCRIPT" expected "$V")"
false_ "xkey has no FIPS variant" grep -q "xkey-$V-linux-amd64-fips" <<<"$("$SCRIPT" expected "$V")"

# --- verify: names what is missing, and only that ----------------------------
section "verify"
OUT=$("$SCRIPT" verify "$V" 2>&1); RC=$?
eq "an empty release fails verify" "1" "$RC"
eq "every expected asset is named missing" "20" "$(grep -c '^missing: ' <<<"$OUT")"
while read -r n; do printf 'sha256 of %s\n' "$n" > "$ASSETS/$n"; done < <("$SCRIPT" expected "$V")
rm -f "$ASSETS/xkmsd-$V-linux-arm64-fips" "$ASSETS/xkey-$V-linux-amd64.sha256"
OUT=$("$SCRIPT" verify "$V" 2>&1); RC=$?
eq "two missing assets fail verify" "1" "$RC"
eq "exactly the two are named" "missing: xkey-$V-linux-amd64.sha256
missing: xkmsd-$V-linux-arm64-fips" "$(grep '^missing: ' <<<"$OUT" | sort)"
printf 'x\n' > "$ASSETS/xkmsd-$V-linux-arm64-fips"; printf 'x\n' > "$ASSETS/xkey-$V-linux-amd64.sha256"
OUT=$("$SCRIPT" verify "$V" 2>&1); RC=$?
eq "a complete release passes verify" "0" "$RC"
eq "list sees all 20" "20" "$("$SCRIPT" list | wc -l | tr -d ' ')"

# --- verify-complete: the final-gate form, matrix + checksums.txt, no extras --
# (go-xkms#1026). Picks up right where "verify" left off: all 20 matrix
# assets present, no checksums.txt yet -- exactly the state create-checksums
# is in right before it decides whether to build checksums.txt.
section "verify-complete"
OUT=$("$SCRIPT" verify-complete "$V" 2>&1); RC=$?
eq "the matrix alone is NOT complete -- checksums.txt is still missing" "1" "$RC"
eq "names exactly checksums.txt as missing" "missing: checksums.txt" "$(grep '^missing: ' <<<"$OUT")"
printf 'master\n' > "$ASSETS/checksums.txt"
OUT=$("$SCRIPT" verify-complete "$V" 2>&1); RC=$?
eq "matrix + checksums.txt passes verify-complete" "0" "$RC"
eq "states the exact count" "1" "$(grep -c '21 asset' <<<"$OUT")"
printf 'stray\n' > "$ASSETS/xkmsd-$V-linux-mips.sha256"
OUT=$("$SCRIPT" verify-complete "$V" 2>&1); RC=$?
eq "an asset outside the matrix fails verify-complete" "1" "$RC"
eq "names it as unexpected, not missing" "unexpected: xkmsd-$V-linux-mips.sha256" "$(grep '^unexpected: ' <<<"$OUT")"
rm -f "$ASSETS/xkmsd-$V-linux-mips.sha256" "$ASSETS/checksums.txt"
eq "state restored to the 20-asset matrix for the sections below" "20" "$("$SCRIPT" list | wc -l | tr -d ' ')"

# --- download: honours the glob and the token ---------------------------------
section "download"
D="$STUB/dl"
"$SCRIPT" download "$D" '*.sha256' >/dev/null
eq "the glob selects the ten checksum files" "10" "$(ls "$D" | wc -l | tr -d ' ')"
eq "a downloaded file is byte-identical to the asset" "$(cat "$ASSETS/xkmsctl-$V-linux-amd64.sha256")" "$(cat "$D/xkmsctl-$V-linux-amd64.sha256")"
false_ "a wrong token is refused" env RELEASE_TOKEN=wrong "$SCRIPT" list

# --- upload: skip / replace / add, by what reached the server -----------------
section "upload"
W="$STUB/work"; mkdir -p "$W"
cp "$ASSETS/xkmsctl-$V-linux-amd64" "$W/xkmsctl-$V-linux-amd64"                 # identical -> skip
printf 'rebuilt\n' > "$W/xkmsd-$V-linux-amd64"                                      # differs   -> replace
printf 'master\n' > "$W/checksums.txt"                                              # absent    -> add
REPLACED_ID=$(python3 -c "import os;n=sorted(os.listdir('$ASSETS'));print(100+n.index('xkmsd-$V-linux-amd64'))")
: > "$LOG"
OUT=$(DRY_RUN=1 "$SCRIPT" upload "$W/xkmsctl-$V-linux-amd64" "$W/xkmsd-$V-linux-amd64" "$W/checksums.txt" 2>&1); RC=$?
eq "dry run succeeds" "0" "$RC"
eq "dry run changes nothing on the server" "" "$(cat "$LOG")"
true_ "dry run reports the skip" grep -q "xkmsctl-$V-linux-amd64: already present" <<<"$OUT"
true_ "dry run reports the replace with the asset id" grep -q "replacing asset $REPLACED_ID" <<<"$OUT"
true_ "dry run reports the add" grep -q "checksums.txt: absent, uploading" <<<"$OUT"
: > "$LOG"
OUT=$("$SCRIPT" upload "$W/xkmsctl-$V-linux-amd64" "$W/xkmsd-$V-linux-amd64" "$W/checksums.txt" 2>&1); RC=$?
eq "upload succeeds" "0" "$RC"
eq "identical asset: no request; differing: DELETE then POST; absent: POST" \
	"DELETE $REPLACED_ID xkmsd-$V-linux-amd64
POST xkmsd-$V-linux-amd64
POST checksums.txt" "$(cat "$LOG")"
eq "the release now carries 21 assets" "21" "$("$SCRIPT" list | wc -l | tr -d ' ')"
: > "$LOG"
"$SCRIPT" upload "$W/checksums.txt" >/dev/null 2>&1
# The stub stores every POST body as the bytes "uploaded", so the second
# pass sees a differing digest and must replace rather than add: this is the
# re-run path, and it must not fail on an asset that already exists.
eq "a re-run replaces an existing asset instead of failing on it" "1" "$(grep -c '^POST checksums.txt$' "$LOG")"
false_ "a missing local file is refused" "$SCRIPT" upload "$W/does-not-exist"
false_ "an unset RELEASE_TOKEN is refused before any request" env -u RELEASE_TOKEN "$SCRIPT" list

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
