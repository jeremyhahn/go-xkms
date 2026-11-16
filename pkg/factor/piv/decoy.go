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
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strconv"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
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
	// The OU and the validity mirror one roster certificate, picked from the
	// seed: the decoys carry the roster's mix (a roster with legacy OU-less
	// holders yields OU-less decoys in the same share), and each decoy's
	// NotBefore falls within its exemplar's cohort (the roster certificates
	// with the same OU), so no decoy pairs an OU with a date only the other
	// cohort has. Roster enrollments rebuilt by the ceremony carry no
	// TenantID, so the certificates are the source.
	subject := pkix.Name{CommonName: cn}
	var tenant string
	certs := decoy.Certificates(like)
	cohort := certs
	if len(certs) > 0 {
		pickBytes, err := d.Bytes("tenant-ou", 8)
		if err != nil {
			return nil, err
		}
		pick := new(big.Int).Mod(new(big.Int).SetBytes(pickBytes), big.NewInt(int64(len(certs)))).Int64()
		tenant = certOU(certs[pick])
		cohort = make([]*x509.Certificate, 0, len(certs))
		for _, c := range certs {
			if certOU(c) == tenant {
				cohort = append(cohort, c)
			}
		}
	} else {
		tenants := make([]string, 0, len(like))
		for _, e := range like {
			if e != nil {
				tenants = append(tenants, e.TenantID)
			}
		}
		tenant = decoy.Predominant(decoy.NonEmpty(tenants), "")
	}
	from, to := decoy.NotBeforeSpan(cohort)
	notBefore, err := d.Time("not-before", from, to)
	if err != nil {
		return nil, err
	}
	if tenant != "" {
		if subject, _, err = ca.StampTenant(tenant, subject, nil); err != nil {
			return nil, &decoy.DerivationError{Purpose: "certificate"}
		}
	}
	certPEM, err := issueSelfSignedCert(decoy.Signer(key), subject, new(big.Int).SetBytes(serialBytes), notBefore, defaultValidityDays)
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

// certOU returns a certificate's tenant OU (Subject OU[0]), or "" when the
// certificate carries none.
func certOU(c *x509.Certificate) string {
	if ou := c.Subject.OrganizationalUnit; len(ou) > 0 {
		return ou[0]
	}
	return ""
}
