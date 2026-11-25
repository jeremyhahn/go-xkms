package confidentialvm

import (
	"os"
	"testing"
)

func TestNewAttester_RefusesAnEntryWithNoProviderAndRemovesIt(t *testing.T) {
	root := t.TempDir()
	useRoot(t, root)
	_, err := NewAttester()
	wantStep(t, err, "provider")
	left, rerr := os.ReadDir(root)
	if rerr != nil || len(left) != 0 {
		t.Fatalf("entries left under the root: %v, %v", left, rerr)
	}
}
