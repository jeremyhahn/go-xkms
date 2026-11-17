package xkms

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-xkms/internal/loginca"

	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
)

// loginCAKeyCN is the reserved name prefix of tenant login CA keys
// (loginca.KeyCN).
const loginCAKeyCN = loginca.KeyCN

// errReservedKey refuses a user-addressable operation on a key the node
// keeps for internal use. No role or key policy lifts it: keys:sign, held by
// User and Operator, would otherwise let them mint login certificates.
var errReservedKey = errors.New("keystore: key is reserved for internal use")

// refuseReservedKey refuses ref when it names a reserved key, in any of the
// forms a request may use: the bare name, a version of it, a tenant-prefixed
// name, or the keyname part of backend:type:algo:keyname.
func refuseReservedKey(ref string) error {
	name := ref
	if i := strings.LastIndexAny(name, ":/"); i >= 0 {
		name = name[i+1:]
	}
	name = strings.TrimSpace(name)
	if base, _, ok := keyversion.Parse(name); ok {
		name = base
	}
	if name == loginCAKeyCN || strings.HasPrefix(name, loginCAKeyCN+"-") {
		return fmt.Errorf("%w: %q", errReservedKey, ref)
	}
	return nil
}
