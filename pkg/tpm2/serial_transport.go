// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package tpm2

import (
	"sync"

	"github.com/google/go-tpm/tpm2/transport"
)

// serialTransport sends one TPM command at a time. A TPM transport is a
// command write followed by a response read on one stream (simulator,
// character device, socket); two goroutines sending at once interleave
// those bytes and each reads the other's response.
type serialTransport struct {
	mu   sync.Mutex
	next transport.TPM
}

// serialise wraps t so its commands never overlap. A nil or already
// serialised transport is returned as is.
func serialise(t transport.TPM) transport.TPM {
	if t == nil {
		return nil
	}
	if _, ok := t.(*serialTransport); ok {
		return t
	}
	return &serialTransport{next: t}
}

// Send implements transport.TPM.
func (s *serialTransport) Send(input []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.next.Send(input)
}
