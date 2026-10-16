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

// Package refvalue verifies signed reference values: a CoRIM (Concise
// Reference Integrity Manifest, draft-ietf-rats-corim) wrapped in a
// COSE_Sign1 message (RFC 9052). It is an RFC 9334 evidence-level primitive:
// it proves who signed a set of reference values and returns them, and it
// makes no appraisal decision. Comparing evidence against the returned values
// is the Verifier's job, which lives above this library.
//
// Only the reference-value triples of each CoMID are extracted. Endorsed
// values, attester-verification keys and device-identity keys are
// deliberately out of scope for this primitive; a CoRIM that carries them
// still verifies, and they are ignored.
//
// A uint measurement key names a PCR. A reference value whose environment
// class carries no index states final PCR values (PCRDigests); one whose class
// carries an index states the digest of one event a component image extends
// into that PCR, the index being the event's position (ComponentDigests).
//
// Decoding, CoRIM validation and the COSE signature check are delegated to
// the Veraison reference implementation (github.com/veraison/corim and
// github.com/veraison/go-cose); this package adds the trust decision (a
// pinned key or a certificate chain from the x5chain header), the validity
// windows, and a flat, library-neutral result type.
package refvalue

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"strconv"
	"time"

	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	cose "github.com/veraison/go-cose"
	"github.com/veraison/swid"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// VerifyOptions selects the signer trust source and the verification time.
// Exactly one of PublicKey and Roots must be set.
type VerifyOptions struct {
	// PublicKey pins the signer: the COSE signature must verify under it.
	PublicKey crypto.PublicKey

	// Roots trusts any signer whose certificate, carried in the COSE x5chain
	// header (label 33, leaf first), chains to one of these anchors.
	Roots *x509.CertPool

	// Intermediates supplements the intermediates carried in x5chain.
	Intermediates *x509.CertPool

	// Now is the verification time. The zero value means time.Now().
	Now time.Time
}

// Manifest is a verified CoRIM's identity and reference values.
type Manifest struct {
	// ID is the CoRIM identifier (corim-id), rendered as a string.
	ID string
	// Profile is the first profile the CoRIM declares, or "" when none.
	Profile string
	// Signer is the signer name from corim-meta.
	Signer string
	// NotBefore and NotAfter bound the signature validity from corim-meta;
	// zero when the CoRIM does not state them.
	NotBefore, NotAfter time.Time
	// ReferenceValues lists every reference-value triple of every CoMID.
	ReferenceValues []ReferenceValue
}

// ReferenceValue is one reference-value triple: an environment and the
// measurements it is expected to produce.
type ReferenceValue struct {
	Environment  Environment
	Measurements []Measurement
}

// Environment identifies the target environment of a reference value. Empty
// fields were not present in the CoRIM.
type Environment struct {
	// ClassID is the class identifier in its string form.
	ClassID string
	// ClassIDType names ClassID's type ("uuid", "oid", "psa.impl-id", ...).
	ClassIDType string
	Vendor      string
	Model       string
	// Layer and Index are nil when absent.
	Layer *uint64
	Index *uint64
	// Instance is the instance identifier in its string form.
	Instance string
	// InstanceType names Instance's type ("ueid", "uuid", "bytes", ...).
	InstanceType string
	// InstanceBytes is the instance identifier's raw bytes.
	InstanceBytes []byte
}

// Measurement is one expected measurement.
type Measurement struct {
	Key     MeasurementKey
	Digests []Digest
	// SVN is the exact security version number, nil when absent or when the
	// CoRIM states a minimum rather than an exact value (MinSVN).
	SVN *uint64
	// MinSVN is the minimum security version number, nil when absent.
	MinSVN *uint64
	// RawValue is the expected raw value, nil when absent.
	RawValue []byte
}

// Measurement key kinds, as Veraison names them.
const (
	KeyKindNone                = ""
	KeyKindUint                = comid.UintType
	KeyKindOID                 = comid.OIDType
	KeyKindUUID                = comid.UUIDType
	KeyKindPSARefValID         = "psa.refval-id"
	KeyKindCCAPlatformConfigID = "cca.platform-config-id"
)

// MeasurementKey is a measurement's key (mkey). Kind is KeyKindNone when the
// measurement has no key. Uint is set only for KeyKindUint; String is the
// key's string form for every kind.
type MeasurementKey struct {
	Kind   string
	Uint   uint64
	String string
}

// Digest is one expected digest. Algorithm is an IANA Named Information Hash
// Algorithm Registry identifier (1 = sha-256, 7 = sha-384, 8 = sha-512).
type Digest struct {
	Algorithm uint64
	Value     []byte
}

// hashByAlgorithm maps the IANA named-information identifiers this package
// can select to Go hashes.
var hashByAlgorithm = map[uint64]crypto.Hash{
	swid.Sha256: crypto.SHA256,
	swid.Sha384: crypto.SHA384,
	swid.Sha512: crypto.SHA512,
}

// Hash maps the digest's algorithm to a Go hash. It reports false for any
// algorithm other than SHA-256, SHA-384 and SHA-512.
func (d Digest) Hash() (crypto.Hash, bool) {
	h, ok := hashByAlgorithm[d.Algorithm]
	return h, ok
}

// maxPCRIndex is the highest PCR index a TPM 2.0 PC Client platform defines.
const maxPCRIndex = 23

// maxComponentOrdinal bounds a component's event position; no event log
// holds more events than this (evidence.MaxEvents is far lower).
const maxComponentOrdinal = 1 << 20

// PCRDigests collects, for every measurement keyed by a uint (the PCR index
// convention of TPM CoRIM profiles), each digest computed with hash. The
// result maps a PCR index to every acceptable value for it. Measurements with
// another key kind, and components (see Component), are skipped.
func (m *Manifest) PCRDigests(hash crypto.Hash) (map[int][][]byte, error) {
	if !selectableHash(hash) {
		return nil, &errs.Detail{Err: ErrUnsupportedHash, Detail: hash.String()}
	}
	out := make(map[int][][]byte)
	for _, rv := range m.ReferenceValues {
		if rv.Environment.Index != nil {
			continue // a component's digests; see ComponentDigests
		}
		for _, meas := range rv.Measurements {
			if meas.Key.Kind != KeyKindUint {
				continue
			}
			idx, err := pcrIndex(meas.Key)
			if err != nil {
				return nil, err
			}
			for _, d := range meas.Digests {
				if h, ok := d.Hash(); !ok || h != hash {
					continue
				}
				if len(d.Value) != hash.Size() {
					return nil, &errs.Detail{Err: ErrDigestLength, Detail: "PCR " + meas.Key.String}
				}
				out[idx] = append(out[idx], bytes.Clone(d.Value))
			}
		}
	}
	return out, nil
}

// Component is the expected digest of one event a component image extends
// into a PCR, rather than a PCR's final value. A reference value is a
// component when its environment's class carries an index: each of its
// uint-keyed measurements names the PCR, the class index is the event's
// position among the events extended into that PCR (counting from 0, as
// evidence.Substitution counts), and the measurement's digest is the event
// digest the new image produces.
type Component struct {
	PCR     int
	Ordinal int
	Digest  []byte
}

// ComponentDigests returns every component measurement of the manifest with
// its digest computed with hash. A component measurement must carry exactly
// one digest of that hash; none, or more than one, is refused with
// ErrComponentDigest, because the event it replaces could not be predicted.
func (m *Manifest) ComponentDigests(hash crypto.Hash) ([]Component, error) {
	if !selectableHash(hash) {
		return nil, &errs.Detail{Err: ErrUnsupportedHash, Detail: hash.String()}
	}
	var out []Component
	for _, rv := range m.ReferenceValues {
		if rv.Environment.Index == nil {
			continue
		}
		if *rv.Environment.Index > maxComponentOrdinal {
			return nil, &errs.Detail{Err: ErrComponentOrdinal, Detail: strconv.FormatUint(*rv.Environment.Index, 10)}
		}
		ordinal := int(*rv.Environment.Index)
		for _, meas := range rv.Measurements {
			if meas.Key.Kind != KeyKindUint {
				continue
			}
			idx, err := pcrIndex(meas.Key)
			if err != nil {
				return nil, err
			}
			var digest []byte
			for _, d := range meas.Digests {
				if h, ok := d.Hash(); !ok || h != hash {
					continue
				}
				if digest != nil {
					return nil, &errs.Detail{Err: ErrComponentDigest, Detail: "PCR " + meas.Key.String + ": more than one " + hash.String() + " digest"}
				}
				if len(d.Value) != hash.Size() {
					return nil, &errs.Detail{Err: ErrDigestLength, Detail: "PCR " + meas.Key.String}
				}
				digest = bytes.Clone(d.Value)
			}
			if digest == nil {
				return nil, &errs.Detail{Err: ErrComponentDigest, Detail: "PCR " + meas.Key.String + ": no " + hash.String() + " digest"}
			}
			out = append(out, Component{PCR: idx, Ordinal: ordinal, Digest: digest})
		}
	}
	return out, nil
}

// selectableHash reports whether PCRDigests and ComponentDigests can select
// digests of hash.
func selectableHash(hash crypto.Hash) bool {
	return hash == crypto.SHA256 || hash == crypto.SHA384 || hash == crypto.SHA512
}

// pcrIndex returns a uint measurement key as a PCR index, refusing one past
// the highest PCR.
func pcrIndex(key MeasurementKey) (int, error) {
	if key.Uint > maxPCRIndex {
		return 0, &errs.Detail{Err: ErrPCRIndex, Detail: key.String}
	}
	return int(key.Uint), nil
}

// VerifySigned verifies a COSE_Sign1 signed CoRIM and returns its reference
// values. The signature must verify under the trusted signer key, the CoRIM
// must be valid, and both the corim-meta signature validity and the RIM
// validity, when present, must contain the verification time.
func VerifySigned(data []byte, opts VerifyOptions) (*Manifest, error) {
	if (opts.PublicKey == nil) == (opts.Roots == nil) {
		return nil, ErrTrustSource
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	var signed corim.SignedCorim
	if err := signed.FromCOSE(data); err != nil {
		return nil, &errs.Joined{Lead: ErrMalformed, Cause: err}
	}

	key := opts.PublicKey
	if opts.Roots != nil {
		leaf, err := verifySignerChain(data, opts.Roots, opts.Intermediates, now)
		if err != nil {
			return nil, err
		}
		key = leaf
	}
	if err := signed.Verify(key); err != nil {
		return nil, &errs.Joined{Lead: ErrSignature, Cause: err}
	}

	if v := signed.Meta.Validity; v != nil {
		if err := checkWindow(v.NotBefore, v.NotAfter, now, "signature validity"); err != nil {
			return nil, err
		}
	}
	if v := signed.UnsignedCorim.RimValidity; v != nil {
		if err := checkWindow(v.NotBefore, v.NotAfter, now, "rim validity"); err != nil {
			return nil, err
		}
	}

	return buildManifest(&signed)
}

// checkWindow enforces a CoRIM validity window.
func checkWindow(notBefore *time.Time, notAfter, now time.Time, what string) error {
	if notBefore != nil && now.Before(*notBefore) {
		return &errs.Detail{Err: ErrNotYetValid, Detail: what + " starts " + notBefore.UTC().Format(time.RFC3339)}
	}
	if now.After(notAfter) {
		return &errs.Detail{Err: ErrExpired, Detail: what + " ended " + notAfter.UTC().Format(time.RFC3339)}
	}
	return nil
}

// verifySignerChain extracts the x5chain header from the COSE message and
// verifies it to roots, returning the leaf's public key. The protected
// header is preferred; RFC 9360 permits either bucket, and the signature
// check that follows binds the message to the leaf key in both cases.
func verifySignerChain(data []byte, roots, extra *x509.CertPool, now time.Time) (crypto.PublicKey, error) {
	msg := cose.NewSign1Message()
	if err := msg.UnmarshalCBOR(data); err != nil {
		return nil, &errs.Joined{Lead: ErrMalformed, Cause: err}
	}
	raw, ok := msg.Headers.Protected[cose.HeaderLabelX5Chain]
	if !ok {
		raw, ok = msg.Headers.Unprotected[cose.HeaderLabelX5Chain]
	}
	if !ok {
		return nil, &errs.Detail{Err: ErrSignerChain, Detail: "no x5chain header"}
	}
	certs, err := parseX5Chain(raw)
	if err != nil {
		return nil, err
	}

	intermediates := x509.NewCertPool()
	if extra != nil {
		intermediates = extra.Clone()
	}
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, &errs.Joined{Lead: ErrSignerChain, Cause: err}
	}
	return certs[0].PublicKey, nil
}

// parseX5Chain decodes an x5chain value: one DER certificate as a byte
// string, or an array of them, leaf first (RFC 9360 §2).
func parseX5Chain(raw any) ([]*x509.Certificate, error) {
	var ders [][]byte
	switch v := raw.(type) {
	case []byte:
		ders = [][]byte{v}
	case []any:
		for _, item := range v {
			der, ok := item.([]byte)
			if !ok {
				return nil, &errs.Detail{Err: ErrSignerChain, Detail: "x5chain element is not a byte string"}
			}
			ders = append(ders, der)
		}
	default:
		return nil, &errs.Detail{Err: ErrSignerChain, Detail: "x5chain is neither a byte string nor an array"}
	}
	if len(ders) == 0 {
		return nil, &errs.Detail{Err: ErrSignerChain, Detail: "x5chain is empty"}
	}
	certs := make([]*x509.Certificate, 0, len(ders))
	for _, der := range ders {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, &errs.Joined{Lead: ErrSignerChain, Cause: err}
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// buildManifest flattens a verified signed CoRIM into a Manifest.
func buildManifest(signed *corim.SignedCorim) (*Manifest, error) {
	m := &Manifest{
		ID:     signed.UnsignedCorim.GetID(),
		Signer: signed.Meta.Signer.Name,
	}
	if p := signed.UnsignedCorim.Profiles; p != nil && len(*p) > 0 {
		if s, err := (*p)[0].Get(); err == nil {
			m.Profile = s
		}
	}
	if v := signed.Meta.Validity; v != nil {
		m.NotAfter = v.NotAfter
		if v.NotBefore != nil {
			m.NotBefore = *v.NotBefore
		}
	}

	for _, tag := range signed.UnsignedCorim.Tags {
		body, ok := bytes.CutPrefix(tag, corim.ComidTag)
		if !ok {
			continue // a CoSWID or CoTS tag carries no reference-value triples
		}
		var c comid.Comid
		if err := c.FromCBOR(body); err != nil {
			return nil, &errs.Joined{Lead: ErrMalformed, Cause: err}
		}
		if c.Triples.ReferenceValues == nil {
			continue
		}
		for _, rv := range *c.Triples.ReferenceValues {
			m.ReferenceValues = append(m.ReferenceValues, convertReferenceValue(rv))
		}
	}
	return m, nil
}

// convertReferenceValue maps one Veraison reference-value triple.
func convertReferenceValue(rv comid.ReferenceValue) ReferenceValue {
	out := ReferenceValue{Environment: convertEnvironment(rv.Environment)}
	for _, meas := range rv.Measurements {
		out.Measurements = append(out.Measurements, convertMeasurement(meas))
	}
	return out
}

// convertEnvironment maps a Veraison environment.
func convertEnvironment(env comid.Environment) Environment {
	var out Environment
	if c := env.Class; c != nil {
		if c.ClassID != nil && c.ClassID.IsSet() {
			out.ClassID = c.ClassID.String()
			out.ClassIDType = c.ClassID.Type()
		}
		if c.Vendor != nil {
			out.Vendor = *c.Vendor
		}
		if c.Model != nil {
			out.Model = *c.Model
		}
		out.Layer = cloneUint(c.Layer)
		out.Index = cloneUint(c.Index)
	}
	if inst := env.Instance; inst != nil && inst.Value != nil {
		out.Instance = inst.String()
		out.InstanceType = inst.Type()
		out.InstanceBytes = bytes.Clone(inst.Bytes())
	}
	return out
}

// convertMeasurement maps a Veraison measurement.
func convertMeasurement(meas comid.Measurement) Measurement {
	var out Measurement
	if k := meas.Key; k != nil && k.IsSet() {
		out.Key = MeasurementKey{Kind: k.Type(), String: k.Value.String()}
		if u, err := k.GetKeyUint(); err == nil {
			out.Key.Uint = u
		}
	}
	if d := meas.Val.Digests; d != nil {
		for _, h := range *d {
			out.Digests = append(out.Digests, Digest{Algorithm: h.HashAlgID, Value: bytes.Clone(h.HashValue)})
		}
	}
	if s := meas.Val.SVN; s != nil && s.Value != nil {
		switch v := s.Value.(type) {
		case comid.TaggedSVN:
			n := uint64(v)
			out.SVN = &n
		case *comid.TaggedSVN:
			n := uint64(*v)
			out.SVN = &n
		case comid.TaggedMinSVN:
			n := uint64(v)
			out.MinSVN = &n
		case *comid.TaggedMinSVN:
			n := uint64(*v)
			out.MinSVN = &n
		}
	}
	if r := meas.Val.RawValue; r != nil {
		if b, err := r.GetBytes(); err == nil {
			out.RawValue = bytes.Clone(b)
		}
	}
	return out
}

// cloneUint copies an optional uint so the result does not alias the
// decoded CoRIM.
func cloneUint(p *uint64) *uint64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
