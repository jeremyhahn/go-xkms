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
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sort"
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

// deriveDecoyKey derives one decoy key; a variable so a test can record the
// derivation work a decoy does.
var deriveDecoyKey = func(d *decoy.Deriver, purpose string, s decoy.KeyShape) (crypto.Signer, error) {
	return d.Key(purpose, s)
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
	ttl := decoy.Predominant(decoy.NonEmpty(decoy.MetadataValues(like, "ttl")), strconv.Itoa(f.cfg.ChallengeTTLSeconds))

	// Every observable shape field mirrors one roster holder, picked from the
	// seed: its tenant OU, key algorithm, slot and TTL together, so the
	// decoys carry the roster's mix (legacy OU-less holders yield OU-less
	// decoys in the same share) and never a combination no holder has. The
	// NotBefore falls within the exemplar's cohort (the holders of the same
	// shape), so no decoy pairs a shape with a date only another cohort has.
	// Roster enrollments rebuilt by the ceremony carry no TenantID, so the
	// certificates are the source of the OU.
	var tenant string
	var cohort []*x509.Certificate
	holders := rosterHolders(like, algorithm, slot, ttl)
	// The derivation and signing work covers every algorithm in the roster,
	// whichever exemplar is picked: go-qrdb derives the decoy before it looks
	// the holder up, so work that followed the exemplar's algorithm would let
	// latency tell a holder from a stranger with the same certificate shape.
	workAlgorithms := map[string]bool{algorithm: true}
	for _, h := range holders {
		workAlgorithms[h.shape.algorithm] = true
	}
	if len(holders) > 0 {
		pickBytes, err := d.Bytes("tenant-ou", 8)
		if err != nil {
			return nil, err
		}
		pick := new(big.Int).Mod(new(big.Int).SetBytes(pickBytes), big.NewInt(int64(len(holders)))).Int64()
		exemplar := holders[pick].shape
		tenant, algorithm, slot, ttl = exemplar.tenant, exemplar.algorithm, exemplar.slot, exemplar.ttl
		for _, h := range holders {
			if h.shape == exemplar {
				cohort = append(cohort, h.cert)
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
	cn := "PIV " + slot

	serialBytes, err := d.Bytes("serial", decoySerialSize)
	if err != nil {
		return nil, err
	}
	from, to := decoy.NotBeforeSpan(cohort)
	notBefore, err := d.Time("not-before", from, to)
	if err != nil {
		return nil, err
	}
	subject := pkix.Name{CommonName: cn}
	if tenant != "" {
		if subject, _, err = ca.StampTenant(tenant, subject, nil); err != nil {
			return nil, &decoy.DerivationError{Purpose: "certificate"}
		}
	}
	names := make([]string, 0, len(workAlgorithms))
	for a := range workAlgorithms {
		names = append(names, a)
	}
	sort.Strings(names)
	var certPEM []byte
	for _, a := range names {
		key, err := deriveDecoyKey(d, "key", decoyShapes[a])
		if err != nil {
			return nil, err
		}
		pemBytes, err := issueSelfSignedCert(decoy.Signer(key), subject, new(big.Int).SetBytes(serialBytes), notBefore, defaultValidityDays)
		if err != nil {
			return nil, &decoy.DerivationError{Purpose: "certificate"}
		}
		if a == algorithm {
			certPEM = pemBytes
		}
	}

	metadata := map[string]string{
		"slot":      slot,
		"algorithm": algorithm,
		"cn":        cn,
		"ttl":       ttl,
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

// holderShape is the observable shape of one roster holder: the fields a
// challenge exposes beside the certificate's key and dates.
type holderShape struct {
	tenant, algorithm, slot, ttl string
}

// rosterHolder is one roster enrollment holding a certificate, with its shape.
type rosterHolder struct {
	cert  *x509.Certificate
	shape holderShape
}

// rosterHolders returns like's enrollments that hold a certificate of a
// shape a decoy can derive. A field the enrollment lacks takes the given
// roster-wide value, as the decoy would.
func rosterHolders(like []*qrdbsdk.AuthFactorEnrollment, algorithm, slot, ttl string) []rosterHolder {
	holders := make([]rosterHolder, 0, len(like))
	for _, e := range like {
		if e == nil {
			continue
		}
		certs := decoy.Certificates([]*qrdbsdk.AuthFactorEnrollment{e})
		if len(certs) == 0 {
			continue
		}
		s := holderShape{tenant: certOU(certs[0]), algorithm: algorithm, slot: slot, ttl: ttl}
		if a := e.Metadata["algorithm"]; a != "" {
			if _, ok := decoyShapes[a]; !ok {
				continue
			}
			s.algorithm = a
		}
		if v := e.Metadata["slot"]; v != "" {
			s.slot = v
		}
		if v := e.Metadata["ttl"]; v != "" {
			s.ttl = v
		}
		holders = append(holders, rosterHolder{cert: certs[0], shape: s})
	}
	return holders
}
