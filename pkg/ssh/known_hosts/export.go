// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package known_hosts

import (
	"bufio"
	"context"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// PinFromPublicKey builds a Pin from a host public key, filling the Fingerprint
// (OpenSSH SHA256), Algorithm, and the wire-format PublicKey so the pin can be
// emitted as a known_hosts line. The caller still persists it via Store.Add.
func PinFromPublicKey(host string, sc scope.Scope, owner string, pub ssh.PublicKey, source string) *Pin {
	if source == "" {
		source = SourceManual
	}
	return &Pin{
		Host:        host,
		Fingerprint: ssh.FingerprintSHA256(pub),
		Algorithm:   pub.Type(),
		Scope:       sc,
		Owner:       owner,
		AddedAt:     time.Now().UTC(),
		Source:      source,
		PublicKey:   pub.Marshal(),
	}
}

// Emit renders a pin as a single OpenSSH known_hosts line:
//
//	<host> <algorithm> <base64-key>
//
// It returns *NoPublicKeyError when the pin carries no PublicKey (legacy pins
// recorded as fingerprint-only cannot be emitted — only verified in-process).
func Emit(pin *Pin) (string, error) {
	if pin == nil {
		return "", &NilInputError{Field: "pin"}
	}
	if len(pin.PublicKey) == 0 {
		return "", &NoPublicKeyError{Host: pin.Host}
	}
	pub, err := ssh.ParsePublicKey(pin.PublicKey)
	if err != nil {
		return "", &SerializationError{Op: "parse pin public key", Err: err}
	}
	line := strings.TrimRight(string(ssh.MarshalAuthorizedKey(pub)), "\n")
	return pin.Host + " " + line, nil
}

// EmitAll renders every pin under (sc, owner) that carries a PublicKey into a
// single OpenSSH known_hosts file body. Pins without a PublicKey are skipped
// (they remain usable for in-process Verify). The returned bytes are suitable
// for writing to a temp UserKnownHostsFile.
func EmitAll(ctx context.Context, store Store, sc scope.Scope, owner string) ([]byte, error) {
	pins, err := store.List(ctx, sc, owner)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	for _, pin := range pins {
		line, lerr := Emit(pin)
		if lerr != nil {
			continue // skip fingerprint-only pins
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// ImportKnownHostsFile parses an OpenSSH known_hosts file and pins every host
// key not already pinned under (sc, owner). It is used to sync host keys the
// system ssh client accepted (first-contact) back into the store. Returns the
// number of newly-added pins. Existing pins are left untouched (no rotation).
func ImportKnownHostsFile(ctx context.Context, store Store, sc scope.Scope, owner, path, source string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, &StorageError{Op: "open known_hosts", Err: err}
	}
	defer func() { _ = f.Close() }() // read-only: a close error changes nothing

	if source == "" {
		source = SourceImport
	}
	added := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, hosts, pub, _, _, perr := ssh.ParseKnownHosts([]byte(line))
		if perr != nil {
			continue
		}
		for _, h := range hosts {
			host := normalizeKnownHost(h)
			if host == "" {
				continue
			}
			if _, gerr := store.Get(ctx, sc, owner, host); gerr == nil {
				continue // already pinned
			}
			pin := PinFromPublicKey(host, sc, owner, pub, source)
			if aerr := store.Add(ctx, pin); aerr == nil {
				added++
			}
		}
	}
	if serr := scanner.Err(); serr != nil {
		return added, &StorageError{Op: "scan known_hosts", Err: serr}
	}
	return added, nil
}

// normalizeKnownHost strips the optional "[host]:port" decoration OpenSSH adds
// for non-default ports, returning the bare host usable as a storage path
// component. Hashed entries (leading '|') are skipped (returns "").
func normalizeKnownHost(h string) string {
	if strings.HasPrefix(h, "|") {
		return "" // hashed host — not addressable for our pin store
	}
	if strings.HasPrefix(h, "[") {
		if end := strings.Index(h, "]"); end > 1 {
			return h[1:end]
		}
	}
	return h
}
