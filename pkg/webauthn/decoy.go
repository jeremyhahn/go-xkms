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

package webauthn

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"

	"github.com/go-webauthn/webauthn/protocol"
)

// Decoy login ceremonies (go-xkms#1296).
//
// A user-identified login for an email that names no account, or names an
// account with no credentials, must not be distinguishable from a real one.
// It is answered with a real go-webauthn ceremony run against a decoy
// account whose allowCredentials are derived from HKDF-SHA256 keyed by a
// per-process secret over the requested email (or handle). The derivation is
// deterministic, so repeated probes for one email see the same credential
// descriptors — exactly as they would for a real account — while nobody
// without the key can tell them from real ones.
//
// The key is drawn at startup and held only in memory: the webauthn
// configuration carries no server secret, and persisting one would make this
// package a key custodian. The consequence is that decoys change when the
// process restarts, and differ between the nodes of a cluster, whereas a real
// account's descriptors do not. Distinguishing on that requires probing the
// same email across a restart or across nodes.

const (
	// decoyKeySize is the length of the per-process decoy key.
	decoyKeySize = 32

	// decoyInfo is the HKDF info label; the requested subject follows it.
	decoyInfo = "go-xkms webauthn login decoy v1"

	// decoyKindEmail and decoyKindHandle separate the two subject spaces,
	// so an email and a handle with the same bytes derive different decoys.
	decoyKindEmail  byte = 'e'
	decoyKindHandle byte = 'h'

	// decoyMaxCredentials bounds how many credentials a decoy account
	// holds; a real account commonly holds one or two passkeys.
	decoyMaxCredentials = 2

	// decoyMaxCredentialIDLen is the longest decoy credential ID.
	decoyMaxCredentialIDLen = 64

	// decoyHandleLen matches the 8-byte handles every store issues.
	decoyHandleLen = 8

	// decoyHeaderLen is the handle, the credential count byte, and one
	// (length, transports) selector byte pair per credential.
	decoyHeaderLen = decoyHandleLen + 1 + 2*decoyMaxCredentials

	// decoyMaterialLen is the HKDF output length one decoy consumes.
	decoyMaterialLen = decoyHeaderLen + decoyMaxCredentials*decoyMaxCredentialIDLen
)

// decoyCredentialIDLens are the credential ID lengths a decoy chooses from:
// the lengths real platform and roaming authenticators commonly issue.
var decoyCredentialIDLens = []int{16, 32, 48, decoyMaxCredentialIDLen}

// decoyTransports are the transport hint sets a decoy chooses from: the sets
// real authenticators commonly report at registration.
var decoyTransports = [][]protocol.AuthenticatorTransport{
	{protocol.USB},
	{protocol.USB, protocol.NFC},
	{protocol.Internal},
	{protocol.Internal, protocol.Hybrid},
	{protocol.Hybrid, protocol.Internal},
}

// newDecoyKey draws the per-process decoy key.
func newDecoyKey() ([]byte, error) {
	key := make([]byte, decoyKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, WrapError("generate decoy key", err)
	}
	return key, nil
}

// decoySubject tags subject with its kind, forming the HKDF input that
// identifies one requested account.
func decoySubject(kind byte, subject []byte) []byte {
	out := make([]byte, 0, len(subject)+1)
	out = append(out, kind)
	return append(out, subject...)
}

// decoyUser derives the decoy account for subject: an 8-byte handle and one
// or two credentials with realistic ID lengths and transport hints.
func (s *Service) decoyUser(subject []byte) (*DefaultUser, error) {
	material, err := hkdf.Key(sha256.New, s.decoyKey, nil, decoyInfo+string(subject), decoyMaterialLen)
	if err != nil {
		return nil, err
	}

	handle := material[:decoyHandleLen]
	count := 1 + int(material[decoyHandleLen])%decoyMaxCredentials

	creds := make([]*Credential, count)
	for i := range creds {
		selectors := material[decoyHandleLen+1+2*i:]
		idLen := decoyCredentialIDLens[int(selectors[0])%len(decoyCredentialIDLens)]
		idStart := decoyHeaderLen + i*decoyMaxCredentialIDLen
		creds[i] = &Credential{
			ID:        material[idStart : idStart+idLen],
			UserID:    handle,
			Transport: decoyTransports[int(selectors[1])%len(decoyTransports)],
		}
	}

	user := NewDefaultUser(handle, "", "")
	user.SetCredentials(creds)
	return user, nil
}
