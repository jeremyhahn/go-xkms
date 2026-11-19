package buildgates

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A pool build fetches its Alpine packages through the LAN apk mirror
// (DEVCACHE_APK_MIRROR, ruling 886), so the index sum that keys the
// integration image must read the indexes through that mirror too (Codex P1
// on go-qrdb #1631): a sum of the public indexes would let a stale mirror's packages
// be cached under the current public sum and kept once the mirror caught up.
// apk names each index file after its repository URL, so the sum hashes the
// index contents alone: a current mirror gives the hosted runner's sum, a
// stale one another.

// apkMirrorProbeDocker runs the probe it is given instead of starting a
// container. The probe's /etc/apk/repositories and /var/cache/apk are
// $STUB_DIR/repos and $STUB_DIR/cache, and its /tmp/apk-mirror is
// $STUB_DIR/tmp/apk-mirror, which it writes from its stdin, the script
// apk-index-sum.sh streams to it (v3); any -v is refused, as a pool's daemon,
// which does not share the job's filesystem, would not find it. Each -e is
// exported. The stub apk answers `update` by writing one index per
// repository line, named after the line's checksum as apk names it after the
// URL, whose content is $INDEX_CDN for dl-cdn and $INDEX_MIRROR for any other
// host.
const apkMirrorProbeDocker = `#!/bin/sh
set -eu
[ "$1" = run ] || { echo "stub docker: unexpected $*" >&2; exit 99; }
shift
mkdir -p "$STUB_DIR/bin" "$STUB_DIR/cache"
printf '%s\n' 'https://dl-cdn.alpinelinux.org/alpine/v3.22/main' 'https://dl-cdn.alpinelinux.org/alpine/v3.22/community' > "$STUB_DIR/repos"
cat > "$STUB_DIR/bin/apk" <<'APK'
#!/bin/sh
[ "$1" = update ] || exit 0
while read -r url; do
	case $url in
	https://dl-cdn.alpinelinux.org/*) content="$INDEX_CDN ${url##*/}" ;;
	*) content="$INDEX_MIRROR ${url##*/}" ;;
	esac
	name=$(printf '%s' "$url" | cksum | cut -d' ' -f1)
	printf '%s\n' "$content" > "$STUB_DIR/cache/APKINDEX.$name.tar.gz"
done < "$APK_REPOSITORIES"
APK
chmod +x "$STUB_DIR/bin/apk"
probe=
while [ $# -gt 0 ]; do
	case $1 in
	-e) export "$2"; shift 2 ;;
	-v) echo "stub docker: -v $2 names a path on the runner, which the pool's daemon does not share" >&2; exit 98 ;;
	-c) probe=$2; shift 2 ;;
	*) shift ;;
	esac
done
probe=$(printf '%s' "$probe" | sed "s#/etc/apk/repositories#$STUB_DIR/repos#g; s#/var/cache/apk#$STUB_DIR/cache#g; s#/tmp/apk-mirror#$STUB_DIR/tmp/apk-mirror#g")
mkdir -p "$STUB_DIR/tmp"
APK_REPOSITORIES="$STUB_DIR/repos" PATH="$STUB_DIR/bin:$PATH" sh -c "$probe"
`

// runMirrorProbe runs `make -s apk-index-sum` with the stub docker, the
// given DEVCACHE_APK_MIRROR and the index contents the CDN and the mirror
// serve, and returns the sum and stderr.
func runMirrorProbe(t *testing.T, mirror, cdnIndex, mirrorIndex string) (string, string) {
	t.Helper()
	stub := t.TempDir()
	if err := os.WriteFile(filepath.Join(stub, "docker"), []byte(apkMirrorProbeDocker), 0o700); err != nil { // #nosec G306 -- the stub must be executable
		t.Fatalf("write stub docker: %v", err)
	}
	script, err := filepath.Abs(filepath.Join(cachesRoot, "scripts", "apk-index-sum.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script) // #nosec G204 -- the repository's own script
	cmd.Dir = cachesRoot
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "APK_BASE_IMAGES=") && !strings.HasPrefix(kv, "PATH=") && !strings.HasPrefix(kv, "DEVCACHE_APK_MIRROR=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "PATH="+stub+string(os.PathListSeparator)+os.Getenv("PATH"), "STUB_DIR="+stub,
		"APK_BASE_IMAGES=alpine:3.22", "DEVCACHE_APK_MIRROR="+mirror, "INDEX_CDN="+cdnIndex, "INDEX_MIRROR="+mirrorIndex)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("scripts/apk-index-sum.sh: %v\n%s", err, errOut.String())
	}
	return strings.TrimSpace(out.String()), errOut.String()
}

func TestApkIndexSum_ReadsTheMirrorTheBuildReads(t *testing.T) {
	const mirror = "http://192.168.77.7:3143/alpine"
	hosted, _ := runMirrorProbe(t, "", "index-v2", "unused")
	if len(hosted) != 64 || strings.Trim(hosted, "0123456789abcdef") != "" {
		t.Fatalf("the hosted sum is %q; want a sha256", hosted)
	}
	current, stderr := runMirrorProbe(t, mirror, "index-v2", "index-v2")
	if current != hosted {
		t.Errorf("a current mirror sums %s, the public indexes %s: the same indexes must give one sum whatever their URL", current, hosted)
	}
	stale, _ := runMirrorProbe(t, mirror, "index-v2", "index-v1")
	if stale == hosted {
		t.Errorf("a stale mirror sums the same as the public indexes (%s): the image would keep the stale packages once the mirror caught up", stale)
	}
	if again, _ := runMirrorProbe(t, mirror, "index-v2", "index-v1"); again != stale {
		t.Errorf("the same stale mirror sums %s, then %s", stale, again)
	}
	if strings.Contains(stderr, "192.168.") {
		t.Errorf("the probe prints the mirror's address:\n%s", stderr)
	}
	if !strings.Contains(stderr, "2 index file(s)") {
		t.Errorf("the probe does not report the two index files it read:\n%s", stderr)
	}
}
