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

// Package ca implements replicated CRL artifact persistence (go-xkms#275).
//
// Revocation STATE (serial, reason, revokedAt) already replicates through
// ca.revocationStore -- see recordRevocation / listRevocationBlobs in
// ca_extensions.go. This file persists the signed CRL BYTES derived from
// that state as a sibling artifact in the same store, so any instance in a
// qrdb/Raft cluster can serve a CRL without holding the CA signing key: only
// the instance that revoked or that first observes a stale artifact signs a
// new one, and the DER it produces replicates to every other instance like
// any other row.
//
// There is deliberately no leader election and no background scheduler
// here (owner ruling, go-xkms#275, option A): CRL refresh happens (1) right
// after a successful revocation, best-effort, and (2) lazily on read when
// the persisted artifact is missing or its NextUpdate has passed. Both are
// correct on a single node and require no cluster awareness the CA layer
// does not already have.
package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// crlKeyPrefix is the storage key prefix for persisted CRL artifacts, a
// sibling of revocationKeyPrefix in the same store: revocation STATE lives
// under "revocations/<serial>.json", the signed CRL BYTES derived from that
// state live under "crl/<issuer-ski-hex>". Both go through ca.revocationStore,
// so the artifact replicates the same way the state that produced it does.
const crlKeyPrefix = "crl/"

// crlKey returns the storage key for the CRL published by the issuing
// certificate identified by ski (its SubjectKeyId). Keying by SKI rather
// than subject CN survives a CA renaming its subject, and disambiguates a
// root CRL from an intermediate CRL when a CA instance has both.
//
// Every CA certificate has a SubjectKeyId: crypto/x509.CreateCertificate
// populates it automatically for a CA template, and CreateRevocationList
// requires the issuer to have one set.
func crlKey(ski []byte) string {
	return crlKeyPrefix + hex.EncodeToString(ski)
}

// persistedCRL is the on-disk form of a published CRL artifact.
type persistedCRL struct {
	DER        []byte    `json:"der"`
	Number     string    `json:"number"`
	ThisUpdate time.Time `json:"this_update"`
	NextUpdate time.Time `json:"next_update"`
}

// Clock reports the current time. It is the seam that lets a test control
// CRL staleness detection (regenerate-on-read past NextUpdate) instead of
// waiting out a real validity window.
type Clock func() time.Time

// now returns ca.clock() when a clock has been injected (tests), or
// time.Now() in production.
func (ca *CA) now() time.Time {
	if ca.clock != nil {
		return ca.clock()
	}
	return time.Now()
}

// putCRLBlob persists a signed CRL artifact to the datastore-backed
// revocation store, the sole persistence medium for the CRL artifact.
func (ca *CA) putCRLBlob(ctx context.Context, ski []byte, rec *persistedCRL) error {
	buf, err := json.Marshal(rec)
	if err != nil {
		return &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("marshal crl: %v", err)}
	}
	if err := ca.revocationStore.Put(ctx, crlKey(ski), buf); err != nil {
		return &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("persist crl: %v", err)}
	}
	return nil
}

// getCRLBlob reads the persisted CRL artifact for the issuer identified by
// ski from the datastore-backed revocation store. Returns ErrCRLNotFound
// when no artifact has been published yet for that issuer.
func (ca *CA) getCRLBlob(ctx context.Context, ski []byte) (*persistedCRL, error) {
	data, err := ca.revocationStore.Get(ctx, crlKey(ski))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrCRLNotFound
		}
		return nil, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("get crl: %v", err)}
	}

	var rec persistedCRL
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("unmarshal crl: %v", err)}
	}
	return &rec, nil
}

// nextCRLNumber returns the next monotonically increasing CRL number for
// the issuer identified by ski, per RFC 5280 Section 5.2.3. It is derived
// from the previously persisted artifact's Number rather than wall-clock
// time, so it strictly increases even when refresh-on-revoke regenerates a
// CRL more than once inside the same clock tick (or under an injected test
// clock that does not advance between calls).
func (ca *CA) nextCRLNumber(ctx context.Context, ski []byte) *big.Int {
	prev, err := ca.getCRLBlob(ctx, ski)
	if err != nil || prev.Number == "" {
		return big.NewInt(1)
	}
	n, ok := new(big.Int).SetString(prev.Number, 10)
	if !ok {
		return big.NewInt(1)
	}
	return n.Add(n, big.NewInt(1))
}

// generateAndPersistCRL builds a fresh CRL from the current revocation set,
// signs it, persists the DER as the replicated artifact, warms certStore's
// in-memory cache, and returns the DER. It is the shared implementation
// behind GenerateCRL (the explicit, always-regenerate force-refresh verb),
// CRL (regenerates only when the persisted artifact is missing or stale),
// and the refresh-on-revoke hook in recordRevocation.
//
// Callers are responsible for the ErrNotInitialized guard; this method
// assumes the CA is initialized and an issuing certificate is available.
func (ca *CA) generateAndPersistCRL(ctx context.Context) ([]byte, error) {
	ca.mu.RLock()
	issuingCert := ca.getIssuingCertificate()
	ca.mu.RUnlock()

	if issuingCert == nil {
		return nil, ErrCRLGenerationFailed
	}

	signer, err := ca.getSigner(ctx)
	if err != nil {
		return nil, &errs.Detail{Err: ErrCRLGenerationFailed, Detail: fmt.Sprintf("%v", err)}
	}

	// Build revoked certificates list.
	ca.revocationsMutex.RLock()
	revokedEntries := make([]x509.RevocationListEntry, 0, len(ca.revocations))
	for _, info := range ca.revocations {
		revokedEntries = append(revokedEntries, x509.RevocationListEntry{
			SerialNumber:   info.SerialNumber,
			RevocationTime: info.RevocationTime,
			ReasonCode:     info.Reason,
		})
	}
	ca.revocationsMutex.RUnlock()

	// Determine CRL validity from issuing identity.
	crlValidityDays := DefaultCRLValidityDays
	if issuingIdentity := ca.config.IssuingIdentity(); issuingIdentity != nil {
		crlValidityDays = issuingIdentity.GetCRLValidityDays()
	}

	number := ca.nextCRLNumber(ctx, issuingCert.SubjectKeyId)
	generatedAt := ca.now()
	template := &x509.RevocationList{
		Number:                    number,
		ThisUpdate:                generatedAt,
		NextUpdate:                generatedAt.AddDate(0, 0, crlValidityDays),
		RevokedCertificateEntries: revokedEntries,
		SignatureAlgorithm:        determineSignatureAlgorithm(signer.Public()),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, issuingCert, signer)
	if err != nil {
		return nil, &errs.Detail{Err: ErrCRLGenerationFailed, Detail: fmt.Sprintf("%v", err)}
	}

	rec := &persistedCRL{
		DER:        crlDER,
		Number:     number.String(),
		ThisUpdate: template.ThisUpdate,
		NextUpdate: template.NextUpdate,
	}
	if err := ca.putCRLBlob(ctx, issuingCert.SubjectKeyId, rec); err != nil {
		return nil, err
	}

	// Warm the in-memory cache so subsequent reads on this instance are
	// fast; best-effort, since the artifact persisted above is
	// authoritative and a warm-cache failure does not affect correctness.
	if crl, parseErr := x509.ParseRevocationList(crlDER); parseErr == nil {
		if err := ca.certStore.StoreCRL(crl); err != nil {
			slog.Warn("ca: failed to warm crl cache", "err", err)
		}
	}

	return crlDER, nil
}

// CRL returns the current CRL DER for the CA's issuing certificate. It
// regenerates and persists a new CRL first when none has been published yet
// or when the published artifact's NextUpdate has passed; otherwise it
// returns the persisted DER without performing a signing operation.
//
// certStore's in-memory CRL cache (StoreCRL/GetCRL) is checked first as a
// fast path -- it is warmed by every call on this instance that
// (re)generates a CRL. The persisted artifact in ca.revocationStore is the
// source of truth every instance reads from.
//
// Any instance may serve this call; there is no leader election and no
// background scheduler (go-xkms#275, option A). Staleness is detected and
// repaired on read.
//
// Returns ErrNotInitialized if the CA has not been initialized.
// Returns ErrCRLGenerationFailed if regeneration is required and fails.
//
// Thread-safe: Yes
func (ca *CA) CRL(ctx context.Context) ([]byte, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}

	ca.mu.RLock()
	issuingCert := ca.getIssuingCertificate()
	ca.mu.RUnlock()

	if issuingCert == nil {
		return nil, ErrCRLGenerationFailed
	}

	if ca.certStore != nil {
		if cached, err := ca.certStore.GetCRL(issuingCert.Subject.CommonName); err == nil &&
			cached != nil && !ca.now().After(cached.NextUpdate) {
			return cached.Raw, nil
		}
	}

	rec, err := ca.getCRLBlob(ctx, issuingCert.SubjectKeyId)
	if err != nil {
		if !errors.Is(err, ErrCRLNotFound) {
			return nil, err
		}
		return ca.generateAndPersistCRL(ctx)
	}
	if ca.now().After(rec.NextUpdate) {
		return ca.generateAndPersistCRL(ctx)
	}

	return rec.DER, nil
}
