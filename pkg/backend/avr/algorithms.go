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

package avr

import (
	aggeneric "github.com/jeremyhahn/arduino-generic/sdk/go"
)

// Algorithm names one signature algorithm an AVR crypto provider may be able
// to perform. The strings are the wire protocol's own names for them.
type Algorithm string

const (
	// AlgorithmECDSAP256SHA256 is ECDSA over P-256 with SHA-256. This is what
	// a secure element performs, and what the DeviceID keypair is.
	AlgorithmECDSAP256SHA256 Algorithm = "ecdsa-p256-sha256"

	// AlgorithmEd25519 is Ed25519.
	//
	// Present in the vocabulary because the wire defines a bit for it, NOT
	// because the usual part performs it: the ATECC608A has no hardware
	// Ed25519 and never reports this bit. It is reported only when the device
	// itself sets it.
	AlgorithmEd25519 Algorithm = "ed25519"

	// AlgorithmHMACSHA256 is the symmetric identity of TCG's DICE Symmetric
	// profile — the path that specification defines for parts too small for
	// asymmetric crypto. A verifier holding the key can forge the response,
	// so it admits a device to a local trust domain behind an attested
	// gateway and never to a public one.
	AlgorithmHMACSHA256 Algorithm = "hmac-sha256"
)

// algorithmBits pairs each named algorithm with the CAPS bit that reports it.
// Ordered, so Named returns a stable list, and it is the ONLY route from a
// capability bit to a name: nothing else in this package may conclude that a
// device can perform an algorithm.
var algorithmBits = []struct {
	bit  aggeneric.AlgorithmSet
	name Algorithm
}{
	{aggeneric.AlgECDSAP256SHA256, AlgorithmECDSAP256SHA256},
	{aggeneric.AlgEd25519, AlgorithmEd25519},
	{aggeneric.AlgHMACSHA256, AlgorithmHMACSHA256},
}

// algorithmSets is the reverse lookup, built once from the same table so the
// two cannot disagree.
var algorithmSets = func() map[Algorithm]aggeneric.AlgorithmSet {
	m := make(map[Algorithm]aggeneric.AlgorithmSet, len(algorithmBits))
	for _, a := range algorithmBits {
		m[a.name] = a.bit
	}
	return m
}()

// knownAlgorithms is every bit this host has a name for.
var knownAlgorithms = func() aggeneric.AlgorithmSet {
	var s aggeneric.AlgorithmSet
	for _, a := range algorithmBits {
		s |= a.bit
	}
	return s
}()

// Algorithms is what a device's CAPS reply says its crypto provider can
// actually perform.
//
// It is built from the device's bitmap and from nothing else. The failure this
// exists to prevent is a host advertising an algorithm on a backend's behalf
// because the backend holds keys at all, and then negotiating a peer down onto
// an algorithm the device fails to perform at the moment it matters most. The
// device is the only authority on what it can do, and the bitmap is how it
// says so.
type Algorithms struct {
	set aggeneric.AlgorithmSet
}

// Can reports whether the device can perform alg.
//
// An algorithm this host has no name for can never be performed as far as a
// caller here is concerned: Can returns false for it, which negotiates down
// rather than up.
func (a Algorithms) Can(alg Algorithm) bool {
	bit, ok := algorithmSets[alg]
	if !ok {
		return false
	}
	return a.set.Can(bit)
}

// Named returns the algorithms the device offers that this host has a name
// for, in a stable order.
func (a Algorithms) Named() []Algorithm {
	out := make([]Algorithm, 0, len(algorithmBits))
	for _, entry := range algorithmBits {
		if a.set.Can(entry.bit) {
			out = append(out, entry.name)
		}
	}
	return out
}

// Unnamed returns the bits the device set that this host has no name for.
//
// Reported rather than dropped. A device offering something newer than the
// host is the ordinary state of a fleet mid-upgrade, and a capability report
// that silently showed fewer algorithms than were offered would hide it.
func (a Algorithms) Unnamed() aggeneric.AlgorithmSet {
	return a.set &^ knownAlgorithms
}

// Empty reports whether the device claimed no algorithm at all.
//
// True for firmware built before the bitmap was appended to CAPS, which is not
// an error: the reply is complete by the contract that firmware was built
// against, and the empty set is the honest reading of it. It is also the
// direction a negotiation may safely fail in.
func (a Algorithms) Empty() bool { return a.set == 0 }

// Set returns the raw bitmap, for a caller that needs to record exactly what
// the device reported.
func (a Algorithms) Set() aggeneric.AlgorithmSet { return a.set }

// String renders the set the way the SDK renders it, including the hex form of
// any bit this host cannot name.
func (a Algorithms) String() string { return a.set.String() }
