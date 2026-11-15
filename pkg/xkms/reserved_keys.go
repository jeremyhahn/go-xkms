package xkms

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
)

// LoginCAKeyCN names a tenant's login CA key: the key go-qrdb signs the
// tenant's login certificates with (Key B). The node provisions it on the
// backend directly, under this name followed by "-" and the tenant; no caller
// reaches it, or any name with that prefix, through the service.
const LoginCAKeyCN = "qrdb-login-ca"

// ErrReservedKey refuses a user-addressable operation on a key the node
// keeps for internal use. No role or key policy lifts it: keys:sign, held by
// User and Operator, would otherwise let them mint login certificates.
var ErrReservedKey = errors.New("keystore: key is reserved for internal use")

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
	if name == LoginCAKeyCN || strings.HasPrefix(name, LoginCAKeyCN+"-") {
		return fmt.Errorf("%w: %q", ErrReservedKey, ref)
	}
	return nil
}
