// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package pairingproto_test

import (
	"bytes"
	"testing"

	pkgproto "github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
)

func TestReexport_Constants(t *testing.T) {
	ints := []struct {
		name      string
		got, want int64
	}{
		{"AttestChannelBindingSize", pairingproto.AttestChannelBindingSize, pkgproto.AttestChannelBindingSize},
		{"AttestProtocolV1", pairingproto.AttestProtocolV1, pkgproto.AttestProtocolV1},
		{"AttestStaticKeySize", pairingproto.AttestStaticKeySize, pkgproto.AttestStaticKeySize},
		{"FragmentHeaderSize", pairingproto.FragmentHeaderSize, pkgproto.FragmentHeaderSize},
		{"FlagFirstFragment", pairingproto.FlagFirstFragment, pkgproto.FlagFirstFragment},
		{"FlagLastFragment", pairingproto.FlagLastFragment, pkgproto.FlagLastFragment},
		{"ErrorCodeUserCancelled", pairingproto.ErrorCodeUserCancelled, pkgproto.ErrorCodeUserCancelled},
	}
	for _, c := range ints {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
	if pairingproto.PIVSlotAuthentication != pkgproto.PIVSlotAuthentication {
		t.Errorf("PIVSlotAuthentication = %q, want %q", pairingproto.PIVSlotAuthentication, pkgproto.PIVSlotAuthentication)
	}
}

func TestReexport_Errors(t *testing.T) {
	errs := []struct {
		name      string
		got, want error
	}{
		{"ErrAttestGenesisChallenge", pairingproto.ErrAttestGenesisChallenge, pkgproto.ErrAttestGenesisChallenge},
		{"ErrAttestSignatureInvalid", pairingproto.ErrAttestSignatureInvalid, pkgproto.ErrAttestSignatureInvalid},
		{"ErrAttestSignatureMissing", pairingproto.ErrAttestSignatureMissing, pkgproto.ErrAttestSignatureMissing},
	}
	for _, c := range errs {
		if c.got != c.want {
			t.Errorf("%s is not the pkg/pairingproto sentinel", c.name)
		}
	}
}

func TestReexport_RemoteListBackupsParams(t *testing.T) {
	takesPkg := func(pkgproto.RemoteListBackupsParams) {}
	takesPkg(pairingproto.RemoteListBackupsParams{})
}

func TestReexport_IsLocalMethod(t *testing.T) {
	for _, m := range []string{pairingproto.MethodLocalSyncStatus, pairingproto.MethodRemoteSign, "bogus"} {
		if got, want := pairingproto.IsLocalMethod(m), pkgproto.IsLocalMethod(m); got != want {
			t.Errorf("IsLocalMethod(%q) = %v, want %v", m, got, want)
		}
	}
}

func TestReexport_ComputeAttestChannelBinding(t *testing.T) {
	initiator := bytes.Repeat([]byte{0x01}, pkgproto.AttestStaticKeySize)
	responder := bytes.Repeat([]byte{0x02}, pkgproto.AttestStaticKeySize)
	prologue := []byte("prologue")

	got, err := pairingproto.ComputeAttestChannelBinding(initiator, responder, prologue)
	if err != nil {
		t.Fatalf("ComputeAttestChannelBinding() error = %v", err)
	}
	want, err := pkgproto.ComputeAttestChannelBinding(initiator, responder, prologue)
	if err != nil {
		t.Fatalf("pkg ComputeAttestChannelBinding() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("ComputeAttestChannelBinding() = %x, want %x", got, want)
	}
}
