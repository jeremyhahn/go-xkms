package buildgates

import (
	"regexp"
	"strings"
	"testing"
)

// xkmsVersionFlag is the linker flag that sets the library version
// pkg/xkms.Version reports (#2309, Codex round 3 on #2322): under -trimpath
// the package cannot find VERSION through its source path.
const (
	xkmsVersionTarget = "github.com/jeremyhahn/go-xkms/pkg/xkms.buildVersion"
	xkmsVersionFlag   = "-X " + xkmsVersionTarget + "=$(VERSION)"
)

// TestMakefileLDFLAGSSetXkmsVersion: the global LDFLAGS every build target
// passes carries the pkg/xkms version flag beside the pkg/cli one.
func TestMakefileLDFLAGSSetXkmsVersion(t *testing.T) {
	mk := strings.ReplaceAll(readMakefile(t), "\\\n", " ")
	m := regexp.MustCompile(`(?m)^LDFLAGS\s*:?=(.*)$`).FindStringSubmatch(mk)
	if m == nil {
		t.Fatal("Makefile has no global LDFLAGS assignment")
	}
	if !strings.Contains(m[1], xkmsVersionFlag) {
		t.Fatalf("Makefile LDFLAGS lacks %q: pkg/xkms reports \"unknown\" under -trimpath: %q", xkmsVersionFlag, m[0])
	}
}
