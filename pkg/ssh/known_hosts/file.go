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
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// AppendMissing appends the OpenSSH known_hosts lines in srcData that are
// not already present in the known_hosts file at dstPath, deduplicating by
// host + fingerprint. It is used to mirror newly-accepted host keys (e.g.
// ones a TOFU confirmer just pinned, or ones the system `ssh` client
// accepted) into an external known_hosts file such as ~/.ssh/known_hosts.
//
// A missing dstPath is treated as an empty file — every line in srcData is
// appended, creating dstPath with 0600 permissions. Hashed (leading '|')
// and unparseable lines are skipped for both dedup comparison and
// appending, the same as everywhere else this package parses known_hosts
// blobs (see ImportKnownHostsFile).
func AppendMissing(srcData []byte, dstPath string) (err error) {
	existing := make(map[string]bool)
	if dstData, derr := os.ReadFile(dstPath); derr == nil {
		forEachKnownHost(dstData, func(host string, pub ssh.PublicKey) {
			existing[host+"|"+ssh.FingerprintSHA256(pub)] = true
		})
	}

	var toAppend []string
	forEachKnownHost(srcData, func(host string, pub ssh.PublicKey) {
		k := host + "|" + ssh.FingerprintSHA256(pub)
		if !existing[k] {
			existing[k] = true
			toAppend = append(toAppend, host+" "+strings.TrimRight(string(ssh.MarshalAuthorizedKey(pub)), "\n"))
		}
	})
	if len(toAppend) == 0 {
		return nil
	}

	f, err := os.OpenFile(dstPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return &StorageError{Op: "open known_hosts for append", Err: err}
	}
	// This is a write path: a failed Close can mean the appended lines never
	// reached the disk, so it is reported rather than discarded. An error from
	// the writes below wins, since it is the more specific failure.
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = &StorageError{Op: "close known_hosts after append", Err: cerr}
		}
	}()
	for _, line := range toAppend {
		if _, werr := f.WriteString(line + "\n"); werr != nil {
			return &StorageError{Op: "append known_hosts", Err: werr}
		}
	}
	return nil
}

// LookupFile searches the OpenSSH known_hosts file at path for host,
// returning its public key when present. host is matched both against the
// bare hostname on a known_hosts line and against the host portion of the
// OpenSSH "[host]:port" decoration used for non-default ports (see
// normalizeKnownHost); hashed entries cannot be matched against a plaintext
// host and are skipped, the same as everywhere else this package parses
// known_hosts blobs.
//
// A missing file is not an error: LookupFile returns (nil, false, nil), the
// same result as a present-but-non-matching file.
func LookupFile(path, host string) (ssh.PublicKey, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, &StorageError{Op: "read known_hosts", Err: err}
	}

	var found ssh.PublicKey
	forEachKnownHost(data, func(h string, pub ssh.PublicKey) {
		if found != nil {
			return
		}
		if h == host || normalizeKnownHost(h) == host {
			found = pub
		}
	})
	if found == nil {
		return nil, false, nil
	}
	return found, true, nil
}

// forEachKnownHost parses a known_hosts blob line-by-line, invoking fn for
// each (host, key) pair. Blank, comment ('#'), hashed (leading '|'), and
// unparseable lines are skipped.
func forEachKnownHost(data []byte, fn func(host string, pub ssh.PublicKey)) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
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
			if !strings.HasPrefix(h, "|") {
				fn(h, pub)
			}
		}
	}
}
