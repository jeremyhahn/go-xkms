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

package piv

import (
	"crypto/x509/pkix"
	"math/big"
	"strconv"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/factor/internal/decoy"
)

// decoyLabel versions the PIV decoy derivation. Anything that changes what a
// given (seed, userID, like) derives needs a new label.
const decoyLabel = "xkms/piv-decoy/v1"

// decoySerialSize is the byte length of the serials buildSelfSignedCert
// draws: uniform below 2^128.
const decoySerialSize = 16

// decoyShapes maps each algorithm the software PIV generator supports to the
// shape of a key of that algorithm.
var decoyShapes = map[string]decoy.KeyShape{
	"rsa2048":   {Algorithm: decoy.AlgorithmRSA, Bits: 2048},
	"rsa4096":   {Algorithm: decoy.AlgorithmRSA, Bits: 4096},
	"ecdsap256": {Algorithm: decoy.AlgorithmECDSA, Curve: "P-256"},
	"ecdsap384": {Algorithm: decoy.AlgorithmECDSA, Curve: "P-384"},
	"ed25519":   {Algorithm: decoy.AlgorithmEd25519},
}

// DecoyEnrollment returns the stand-in enrollment go-qrdb challenges userID
// with when userID holds no PIV enrollment, so the challenge cannot be told
// from a real holder's (go-qrdb authfactors.DecoyEnroller).
//
// The result is a function of (seed, userID, like). Its algorithm, slot and
// ttl are the values predominant in like's metadata, and its certificate is
// issued exactly as Enroll issues one, over a derived key of that algorithm,
// with a derived serial and a validity start derived within the span of
// like's certificates. An empty like yields the form New(cfg).Enroll records
// with no MethodParams. The private key is discarded once the certificate is
// signed, so Verify fails against the decoy for any response.
func (f *Factor) DecoyEnrollment(seed []byte, userID string, like []*qrdbsdk.AuthFactorEnrollment) (*qrdbsdk.AuthFactorEnrollment, error) {
	d, err := decoy.New(decoyLabel, seed, userID)
	if err != nil {
		return nil, err
	}

	algorithm := f.cfg.DefaultAlgorithm
	if _, ok := decoyShapes[algorithm]; !ok {
		algorithm = defaultAlgorithm
	}
	var algorithms []string
	for _, a := range decoy.MetadataValues(like, "algorithm") {
		if _, ok := decoyShapes[a]; ok {
			algorithms = append(algorithms, a)
		}
	}
	algorithm = decoy.Predominant(algorithms, algorithm)
	slot := decoy.Predominant(decoy.NonEmpty(decoy.MetadataValues(like, "slot")), string(f.cfg.DefaultSlot))
	cn := "PIV " + slot

	key, err := d.Key("key", decoyShapes[algorithm])
	if err != nil {
		return nil, err
	}
	serialBytes, err := d.Bytes("serial", decoySerialSize)
	if err != nil {
		return nil, err
	}
	from, to := decoy.NotBeforeSpan(decoy.Certificates(like))
	notBefore, err := d.Time("not-before", from, to)
	if err != nil {
		return nil, err
	}
	certPEM, err := issueSelfSignedCert(decoy.Signer(key), pkix.Name{CommonName: cn}, new(big.Int).SetBytes(serialBytes), notBefore, defaultValidityDays)
	if err != nil {
		return nil, &decoy.DerivationError{Purpose: "certificate"}
	}

	metadata := map[string]string{
		"slot":      slot,
		"algorithm": algorithm,
		"cn":        cn,
		"ttl":       decoy.Predominant(decoy.NonEmpty(decoy.MetadataValues(like, "ttl")), strconv.Itoa(f.cfg.ChallengeTTLSeconds)),
	}
	return d.Enrollment(FactorName, like, certPEM, metadata)
}
