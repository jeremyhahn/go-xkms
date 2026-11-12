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

package types

import (
	"bytes"
	"context"
	"testing"
)

// securityEventStub is the smallest SecurityEventProvider: a KeyProvider
// with the one added method.
type securityEventStub struct {
	KeyProvider
	record []byte
}

func (s securityEventStub) AttestSecurityEvents(_ context.Context, _ []byte) ([]byte, error) {
	return s.record, nil
}

// The capability embeds KeyProvider, so a provider that has it is also a
// KeyProvider.
var (
	_ SecurityEventProvider = securityEventStub{}
	_ KeyProvider           = SecurityEventProvider(nil)
)

func TestSecurityEventProviderIsOptional(t *testing.T) {
	var kp KeyProvider = securityEventStub{record: []byte{0xa0}}
	sep, ok := kp.(SecurityEventProvider)
	if !ok {
		t.Fatal("a KeyProvider with AttestSecurityEvents is not a SecurityEventProvider")
	}
	got, err := sep.AttestSecurityEvents(context.Background(), []byte("nonce"))
	if err != nil || !bytes.Equal(got, []byte{0xa0}) {
		t.Fatalf("AttestSecurityEvents = %x, %v", got, err)
	}
	var plain KeyProvider = struct{ KeyProvider }{}
	if _, ok := plain.(SecurityEventProvider); ok {
		t.Fatal("a KeyProvider without the method satisfies SecurityEventProvider")
	}
}
