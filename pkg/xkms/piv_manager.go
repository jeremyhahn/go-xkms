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

package xkms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"sync"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

var (
	// ErrPIVNotInitialized is returned when PIV manager is not initialized.
	ErrPIVNotInitialized = errors.New("piv manager not initialized")

	// ErrPIVBackendNotFound is returned when the specified PIV backend is not found.
	ErrPIVBackendNotFound = errors.New("piv backend not found")

	// ErrPIVInvalidAlgorithm is returned when an invalid algorithm is specified.
	ErrPIVInvalidAlgorithm = errors.New("piv: invalid algorithm")

	// ErrPIVInvalidSlot is returned when an invalid PIV slot is specified.
	ErrPIVInvalidSlot = errors.New("piv: invalid slot")

	// ErrPIVInvalidFormat is returned when an invalid certificate format is specified.
	ErrPIVInvalidFormat = errors.New("piv: invalid format")

	// ErrPIVKeyNotFound is returned when no key exists in the specified slot.
	ErrPIVKeyNotFound = errors.New("piv: key not found in slot")

	// ErrPIVBackendResolverNotSet is returned when no backend resolver is configured.
	ErrPIVBackendResolverNotSet = errors.New("piv: backend resolver not configured")

	// ErrPIVSignerNotAvailable is returned when no signer is available for the slot.
	ErrPIVSignerNotAvailable = errors.New("piv: signer not available for slot")

	// ErrPIVInvalidOutputFormat is returned when an unsupported output format is specified.
	ErrPIVInvalidOutputFormat = errors.New("piv: invalid output format (must be self-signed, public-key, csr, or ca-signed)")

	// ErrPIVCASignFuncNotSet is returned when ca-signed output is requested but no CA signing function is configured.
	ErrPIVCASignFuncNotSet = errors.New("piv: CA signing not available (no CA configured)")

	// ErrPIVAttestLevelLookupFailed is returned by
	// PIVManager.AttestLevelForCertificate when a registered backend's PIV
	// store cannot be listed, or its generator cannot be resolved. It is
	// never returned for "no enrolled slot matches this certificate" — that
	// is a false found value, not an error.
	ErrPIVAttestLevelLookupFailed = errors.New("piv: attest level lookup failed")

	// ErrPIVConfigRequired is returned when InitializePIV is called with a nil config.
	ErrPIVConfigRequired = errors.New("piv: config cannot be nil")

	// ErrPIVInvalidCACertificate is returned when the CA returns a certificate
	// PEM that does not decode.
	ErrPIVInvalidCACertificate = errors.New("piv: CA returned invalid certificate PEM")
)

// PIV output format constants.
const (
	PIVOutputSelfSigned = "self-signed"
	PIVOutputPublicKey  = "public-key"
	PIVOutputCSR        = "csr"
	PIVOutputCASigned   = "ca-signed"
)

// PIVCASignFunc signs a CSR using a CA. The profile maps to a CA certificate
// profile (e.g., "piv-authentication" for slot 9a). Set via SetPIVCASignFunc.
type PIVCASignFunc func(ctx context.Context, csrPEM []byte, profile string, validityDays int) (certPEM, chainPEM []byte, err error)

// PIVKeyGenerator generates cryptographic keys for PIV slots.
type PIVKeyGenerator interface {
	// GeneratePIVKey generates a new key for the given PIV slot and algorithm.
	// Returns a crypto.Signer that can be used for certificate creation.
	GeneratePIVKey(slot pivcert.PIVSlot, algorithm string, cn string) (crypto.Signer, error)

	// GetPIVSigner returns a signer for an existing key in the given PIV slot.
	GetPIVSigner(slot pivcert.PIVSlot, cn string) (crypto.Signer, error)
}

// PIVBackendResolver maps a backend name to a PIVKeyGenerator.
type PIVBackendResolver func(backendName string) (PIVKeyGenerator, error)

// PIVParentProvider is an optional interface that backends can implement
// to provide parent key attributes for PIV key generation (e.g., TPM2 PlatformSRK).
type PIVParentProvider interface {
	PIVParentAttributes() (*types.KeyAttributes, error)
}

// PIVKeyOriginReporter is an optional capability a PIVKeyGenerator may
// implement to report how a slot's key arrived: generated in place, or
// imported.
//
// AttestPIVSlot needs the answer because an attestation over an imported key
// asserts residency but not exclusivity, and it must refuse rather than issue
// a statement a verifier would read as stronger than it is. A generator that
// cannot answer reports types.KeyOriginUnknown, which is the absence of a
// claim; see AttestPIVSlot for what is done with that.
type PIVKeyOriginReporter interface {
	// PIVKeyOrigin returns the origin of the key in the given slot.
	//
	// The bool reports whether a key record was found at all, and it is not
	// the same question as the origin. A generator that holds no key for the
	// slot returns false: the slot's certificate may well predate this
	// process, and there is no key here whose provenance could be judged. A
	// generator that DOES hold the key returns true, and the origin it returns
	// is then authoritative — including KeyOriginUnknown, which at that point
	// means a record was written without an origin and is a defect rather than
	// a legacy key.
	//
	// Keeping the two apart is what lets a caller fail closed on an
	// unrecognised origin without also refusing every slot whose key simply
	// is not held here.
	PIVKeyOrigin(slot pivcert.PIVSlot, cn string) (origin types.KeyOrigin, found bool, err error)
}

// PIVAttestLevelReporter is an optional capability a PIVKeyGenerator may
// implement to classify the key it backs a slot with: hardware-resident,
// software, or unattested.
//
// It differs from PIVKeyOriginReporter in what question it answers and how.
// Origin is a fact about one specific key — generated here or imported —
// that can only be known by consulting the record that key was written
// with, so PIVKeyOrigin has a "found" return: the record may not exist.
// Attestation level is a fact about the GENERATOR — whether the backend it
// talks to is hardware or software — which does not vary from key to key,
// so AttestLevel needs no persisted per-key record and is always answerable
// by a generator that implements this interface at all. A generator that
// cannot back any claim about its hardware backing simply does not
// implement PIVAttestLevelReporter; see pivAttestLevel for how a caller
// holding only a plain PIVKeyGenerator falls back when the capability is
// absent.
type PIVAttestLevelReporter interface {
	// AttestLevel classifies the key the generator backs for the given
	// slot: types.AttestLevelHardware for a hardware-backed generator,
	// types.AttestLevelSoftware for a software one. Returning
	// types.AttestLevelUnattested is valid too, for a generator that holds
	// a key but cannot itself back a stronger claim about it.
	AttestLevel(slot pivcert.PIVSlot, cn string) (types.AttestLevel, error)
}

// pivAttestLevel derives the attestation level to record for a key a
// generator just produced or accepted, at enrollment time: the reporter's
// own answer when the generator implements PIVAttestLevelReporter, and
// types.AttestLevelUnattested otherwise.
//
// A generator with no reporter is exactly the "cannot attest" case, and it
// fails closed to the weakest claim rather than to one this call has no
// basis for. An error from the reporter is treated the same way: a
// generator that tried to answer and could not still leaves the key
// unattested rather than enrolled with a guess.
func pivAttestLevel(generator PIVKeyGenerator, slot pivcert.PIVSlot, cn string) types.AttestLevel {
	reporter, ok := generator.(PIVAttestLevelReporter)
	if !ok {
		return types.AttestLevelUnattested
	}
	level, err := reporter.AttestLevel(slot, cn)
	if err != nil {
		return types.AttestLevelUnattested
	}
	return level
}

// PIVKeyImporter is an optional capability a PIVKeyGenerator may implement to
// accept an externally held private key into a slot.
//
// It is a separate interface rather than a method on PIVKeyGenerator because
// not every generator can honour it: a hardware PIV applet may refuse import
// for some slots or algorithms, and that refusal must be reportable rather
// than silent. A generator that does not implement this interface causes
// ImportPIVKey to return ErrPIVImportNotSupported.
//
// Importing establishes a different trust class from generating. A
// slot-generated key cannot have existed anywhere before it existed in the
// slot; an imported one can, and the slot cannot afterwards tell a key that
// was only ever there from a copy. Attestation over an imported key therefore
// asserts residency but not exclusivity.
type PIVKeyImporter interface {
	// ImportPIVKey installs an externally held private key in the given slot
	// and returns a crypto.Signer backed by it. The algorithm is the PIV
	// algorithm name the key was resolved to, and cn is the slot's common
	// name, matching the convention GeneratePIVKey uses.
	ImportPIVKey(ctx context.Context, slot pivcert.PIVSlot, algorithm string, cn string, key crypto.PrivateKey) (crypto.Signer, error)
}

// pivSlotCNMap provides O(1) lookup from PIV slot to common name identifier.
var pivSlotCNMap = map[string]string{
	"9a": "piv-9a",
	"9c": "piv-9c",
	"9d": "piv-9d",
	"9e": "piv-9e",
	"f9": "piv-f9",
	// Retired Key Management slots
	"82": "piv-82", "83": "piv-83", "84": "piv-84", "85": "piv-85",
	"86": "piv-86", "87": "piv-87", "88": "piv-88", "89": "piv-89",
	"8a": "piv-8a", "8b": "piv-8b", "8c": "piv-8c", "8d": "piv-8d",
	"8e": "piv-8e", "8f": "piv-8f", "90": "piv-90", "91": "piv-91",
	"92": "piv-92", "93": "piv-93", "94": "piv-94", "95": "piv-95",
}

// PivSlotCN returns the common name identifier for a PIV slot.
// Returns "piv-{slot}" for known slots and "piv-{slot}" for unknown slots.
func PivSlotCN(slot pivcert.PIVSlot) string {
	if cn, ok := pivSlotCNMap[string(slot)]; ok {
		return cn
	}
	return "piv-" + string(slot)
}

// PIV manager singleton
var (
	pivManager  *PIVManager
	pivInitOnce sync.Once
	pivInitMu   sync.RWMutex
)

// PIVStoreFactory creates a PIVCertificateStorage for a given backend name.
// Used to lazily create stores for dynamically-added backends (e.g., PKCS#11
// modules added via the admin area after startup).
type PIVStoreFactory func(backendName string) (pivcert.PIVCertificateStorage, error)

// PIVManager manages PIV certificate storage and key generation across backends.
type PIVManager struct {
	stores            map[string]pivcert.PIVCertificateStorage // keyed by backend name
	backendResolver   PIVBackendResolver
	caSignFunc        PIVCASignFunc   // optional CA signing for ca-signed output
	softwareGenerator PIVKeyGenerator // cached fallback generator
	storeFactory      PIVStoreFactory // lazy store creation for unknown backends
	mu                sync.RWMutex
}

// PIVManagerConfig configures the PIV manager.
type PIVManagerConfig struct {
	// Stores maps backend names to their PIV certificate storage.
	Stores map[string]pivcert.PIVCertificateStorage

	// StoreFactory creates stores for backends not pre-registered in Stores.
	// When set, pivStore() will call this factory to create a store on demand
	// if the backend name isn't found in the Stores map.
	StoreFactory PIVStoreFactory
}

// InitializePIV sets up the PIV manager singleton.
func InitializePIV(config *PIVManagerConfig) error {
	var initErr error

	pivInitOnce.Do(func() {
		if config == nil {
			initErr = ErrPIVConfigRequired
			return
		}

		stores := config.Stores
		if stores == nil {
			stores = make(map[string]pivcert.PIVCertificateStorage)
		}

		pivManager = &PIVManager{
			stores:       stores,
			storeFactory: config.StoreFactory,
		}
	})

	return initErr
}

// ResetPIV clears the PIV manager singleton (useful for testing).
func ResetPIV() {
	pivInitMu.Lock()
	defer pivInitMu.Unlock()

	if pivManager != nil {
		pivManager.mu.Lock()
		for _, store := range pivManager.stores {
			_ = store.Close()
		}
		pivManager.stores = nil
		pivManager.backendResolver = nil
		pivManager.softwareGenerator = nil
		pivManager.mu.Unlock()
	}

	pivManager = nil
	pivInitOnce = sync.Once{}
}

// SetPIVBackendResolver configures the backend resolver for PIV key generation.
func SetPIVBackendResolver(resolver PIVBackendResolver) error {
	if pivManager == nil {
		return ErrPIVNotInitialized
	}

	pivManager.mu.Lock()
	defer pivManager.mu.Unlock()

	pivManager.backendResolver = resolver
	return nil
}

// SetPIVCASignFunc configures the CA signing function used when
// GeneratePIVKey is called with OutputFormat "ca-signed".
func SetPIVCASignFunc(fn PIVCASignFunc) error {
	if pivManager == nil {
		return ErrPIVNotInitialized
	}

	pivManager.mu.Lock()
	defer pivManager.mu.Unlock()

	pivManager.caSignFunc = fn
	return nil
}

// pivSlotToCAProfile maps a PIV slot to its CA certificate profile name.
var pivSlotToCAProfile = map[string]string{
	"9a": "piv-authentication",
	"9c": "piv-signature",
	"9d": "piv-key-management",
	"9e": "piv-card-auth",
}

// pivBackend resolves a PIVKeyGenerator for the given backend name.
// Falls back to softwarePIVKeyGenerator when no resolver is configured.
func pivBackend(backendName string) (PIVKeyGenerator, error) {
	if pivManager == nil {
		return nil, ErrPIVNotInitialized
	}
	return pivManager.resolveGenerator(backendName)
}

// resolveGenerator is pivBackend's logic as a method on m itself, so a
// caller holding a *PIVManager directly (AttestLevelForCertificate, tests)
// can resolve a generator without going through the package-level
// singleton. Falls back to cached software key generation when no resolver
// is configured, exactly as pivBackend always has.
func (m *PIVManager) resolveGenerator(backendName string) (PIVKeyGenerator, error) {
	m.mu.RLock()
	resolver := m.backendResolver
	m.mu.RUnlock()

	if resolver != nil {
		return resolver(backendName)
	}

	m.mu.Lock()
	if m.softwareGenerator == nil {
		m.softwareGenerator = NewSoftwarePIVKeyGenerator()
	}
	gen := m.softwareGenerator
	m.mu.Unlock()
	return gen, nil
}

// GetPIVManager returns the package-level PIV manager singleton.
//
// It exists for callers that need the *PIVManager itself rather than one of
// the package-level convenience functions above — chiefly, wiring
// PIVManager.AttestLevelForCertificate as rest.PIVLoginOptions.RecordedLevel
// at server composition, which needs a method value bound to a live manager
// instance rather than a function that reaches for the singleton on every
// call. Returns ErrPIVNotInitialized when no manager has been created; a
// caller wiring an optional capability should treat that as "unavailable",
// not fail composition over it.
func GetPIVManager() (*PIVManager, error) {
	pivInitMu.RLock()
	defer pivInitMu.RUnlock()
	if pivManager == nil {
		return nil, ErrPIVNotInitialized
	}
	return pivManager, nil
}

// AttestLevelForCertificate reports the attestation level xkms itself
// recorded for cert's public key, by scanning the enrolled PIV slots of
// every backend with a registered PIV store for one whose stored
// certificate carries the same SubjectPublicKeyInfo as cert.
//
// The match is computed with qrdbsdk.ComputeSPKIThumbprint — the one
// cert-binding algorithm this stack uses everywhere an mTLS identity is
// resolved (admin cert binding, the PIV login user lookup itself), never a
// second thumbprint invented for this lookup. It is computed over the
// public key rather than the whole certificate, so a renewed login
// certificate for the same enrolled key still matches.
//
// found is false when no enrolled slot's key matches cert. That is the
// ordinary case for most callers — the certificate may not correspond to
// any PIV enrollment at all — and it is deliberately not an error:
// rest.PIVLoginOptions.attestationLevel reads a false found as "no recorded
// level, fall back to the certificate chain," which is the correct answer
// for an unrelated certificate. A backend whose PIV store cannot be listed,
// or whose generator cannot be resolved, IS an error
// (ErrPIVAttestLevelLookupFailed): a caller deciding a login's trust level
// needs to know the lookup itself failed rather than silently reading a
// partial scan as "no match".
//
// Only backends already registered with this manager (RegisterPIVStore, or
// resolved once through the configured backend resolver) are scanned. A
// backend name this manager has never seen is not probed — there is no
// enumerable universe of "every possible backend name" to try, and doing so
// would trigger lazy store creation (see pivStore's StoreFactory) for
// backends this lookup has no reason to touch.
func (m *PIVManager) AttestLevelForCertificate(ctx context.Context, cert *x509.Certificate) (types.AttestLevel, bool, error) {
	if m == nil || cert == nil {
		return types.AttestLevelUnattested, false, nil
	}
	if err := ctx.Err(); err != nil {
		return types.AttestLevelUnattested, false, err
	}

	target := qrdbsdk.ComputeSPKIThumbprint(cert)
	if target == "" {
		return types.AttestLevelUnattested, false, nil
	}

	m.mu.RLock()
	names := make([]string, 0, len(m.stores))
	for name := range m.stores {
		names = append(names, name)
	}
	m.mu.RUnlock()

	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return types.AttestLevelUnattested, false, err
		}

		m.mu.RLock()
		store, ok := m.stores[name]
		m.mu.RUnlock()
		if !ok {
			// Deleted between the snapshot above and here; nothing to scan.
			continue
		}

		slots, err := store.List()
		if err != nil {
			return types.AttestLevelUnattested, false, &errs.Detail{
				Err:    ErrPIVAttestLevelLookupFailed,
				Detail: "list slots for backend " + name + ": " + err.Error(),
			}
		}

		for _, info := range slots {
			slotCert, retrieveErr := store.Retrieve(info.Slot)
			if retrieveErr != nil {
				// A slot the List above reported occupied but that is no
				// longer retrievable is a benign race with a concurrent
				// delete, not a lookup failure — skip it rather than fail
				// the whole scan over one slot.
				continue
			}
			if qrdbsdk.ComputeSPKIThumbprint(slotCert) != target {
				continue
			}

			generator, genErr := m.resolveGenerator(name)
			if genErr != nil {
				return types.AttestLevelUnattested, false, &errs.Detail{
					Err:    ErrPIVAttestLevelLookupFailed,
					Detail: "resolve generator for backend " + name + ": " + genErr.Error(),
				}
			}
			return pivAttestLevel(generator, info.Slot, PivSlotCN(info.Slot)), true, nil
		}
	}

	return types.AttestLevelUnattested, false, nil
}

// RegisterPIVStore registers a PIV certificate store for a backend.
func RegisterPIVStore(backendName string, store pivcert.PIVCertificateStorage) error {
	if pivManager == nil {
		return ErrPIVNotInitialized
	}

	pivManager.mu.Lock()
	defer pivManager.mu.Unlock()

	pivManager.stores[backendName] = store
	return nil
}

// pivStore returns the PIV store for the given backend. If the backend
// isn't pre-registered but a StoreFactory is configured, a new store is
// created on demand and cached for future calls.
func pivStore(backendName string) (pivcert.PIVCertificateStorage, error) {
	if pivManager == nil {
		return nil, ErrPIVNotInitialized
	}

	// Fast path: check under read lock.
	pivManager.mu.RLock()
	store, ok := pivManager.stores[backendName]
	pivManager.mu.RUnlock()
	if ok {
		slog.Debug("PIV store found", "backend", backendName)
		return store, nil
	}

	// Slow path: try to create via factory under write lock.
	if pivManager.storeFactory != nil {
		pivManager.mu.Lock()
		defer pivManager.mu.Unlock()

		// Double-check after acquiring write lock.
		if store, ok = pivManager.stores[backendName]; ok {
			return store, nil
		}

		newStore, err := pivManager.storeFactory(backendName)
		if err != nil {
			slog.Debug("PIV store not found", "backend", backendName)
			return nil, ErrPIVBackendNotFound
		}
		pivManager.stores[backendName] = newStore
		slog.Info("PIV store created on demand", "backend", backendName)
		return newStore, nil
	}

	slog.Debug("PIV store not found", "backend", backendName)
	return nil, ErrPIVBackendNotFound
}

// ListPIVSlots returns the status of all PIV slots for the specified backend.
func ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	slog.Debug("ListPIVSlots", "backend", req.Backend)
	store, err := pivStore(req.Backend)
	if err != nil {
		return nil, err
	}

	slotInfos, err := store.List()
	if err != nil {
		return nil, err
	}

	// Build a set of occupied slots from certificate store.
	occupied := make(map[string]pivcert.PIVSlotInfo, len(slotInfos))
	for _, info := range slotInfos {
		occupied[info.Slot.String()] = info
	}

	// Build a set of key-only slots by querying the key backend.
	// Keys generated with "public-key" or "csr" output format have no
	// certificate but are stored with CN like "piv-9d".
	keyOnlySlots := make(map[string]string) // slot -> algorithm string
	keys, keyErr := ListKeys(ctx, req.Backend)
	if keyErr != nil {
		slog.Debug("ListPIVSlots: unable to query key backend, showing cert-only data",
			"backend", req.Backend, "error", keyErr)
	} else {
		for _, ka := range keys {
			if len(ka.CN) < 4 || ka.CN[:4] != "piv-" {
				continue
			}
			slotID := ka.CN[4:] // e.g. "9d" from "piv-9d"
			if _, hasCert := occupied[slotID]; hasCert {
				continue
			}
			keyOnlySlots[slotID] = ka.KeyAlgorithm.String()
		}
	}

	// Return all slots with their status.
	allSlots := pivcert.AllSlots()
	result := make([]transport.PIVSlotStatus, 0, len(allSlots))
	for _, slot := range allSlots {
		status := transport.PIVSlotStatus{
			Slot:        slot.String(),
			Name:        pivcert.SlotName(slot),
			Description: pivcert.SlotDescription(slot),
			Backend:     req.Backend,
		}

		if info, ok := occupied[slot.String()]; ok {
			status.HasCert = true
			status.HasKey = true
			status.Subject = info.Subject
			status.Issuer = info.Issuer
			status.Algorithm = info.Algorithm
			status.KeySize = info.KeySize
			status.NotAfter = info.NotAfter
			status.Fingerprint = info.Fingerprint
		} else if algo, ok := keyOnlySlots[slot.String()]; ok {
			status.HasKey = true
			status.Algorithm = algo
		}

		result = append(result, status)
	}

	slog.Debug("ListPIVSlots result",
		"slots", len(slotInfos), "occupied", len(occupied), "key_only", len(keyOnlySlots))

	return &transport.ListPIVSlotsResponse{Slots: result}, nil
}

// GetPIVCertificate retrieves a certificate from a PIV slot.
func GetPIVCertificate(_ context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	store, err := pivStore(req.Backend)
	if err != nil {
		return nil, err
	}

	slot, err := pivcert.ParseSlot(req.Slot)
	if err != nil {
		return nil, ErrPIVInvalidSlot
	}

	format := parseCertFormat(req.Format)
	if format < 0 {
		return nil, ErrPIVInvalidFormat
	}

	data, err := store.Export(slot, format)
	if err != nil {
		return nil, err
	}

	return &transport.GetPIVCertificateResponse{
		Slot:        req.Slot,
		Certificate: data,
		Format:      req.Format,
	}, nil
}

// StorePIVCertificate stores a certificate in a PIV slot.
func StorePIVCertificate(_ context.Context, req *transport.StorePIVCertificateRequest) error {
	store, err := pivStore(req.Backend)
	if err != nil {
		return err
	}

	slot, err := pivcert.ParseSlot(req.Slot)
	if err != nil {
		return ErrPIVInvalidSlot
	}

	format := parseCertFormat(req.Format)
	if format < 0 {
		return ErrPIVInvalidFormat
	}

	if err := store.Import(slot, req.Certificate, format); err != nil {
		slog.Error("PIV import certificate failed",
			"slot", req.Slot, "backend", req.Backend, "error", err)
		return err
	}

	slog.Info("audit", "component", "audit", "operation", "piv_cert_imported", "success", true,
		"timestamp", time.Now().Format(time.RFC3339),
		"slot", req.Slot, "backend", req.Backend)

	return nil
}

// DeletePIVCertificate removes a certificate from a PIV slot.
func DeletePIVCertificate(_ context.Context, req *transport.DeletePIVCertificateRequest) error {
	store, err := pivStore(req.Backend)
	if err != nil {
		return err
	}

	slot, err := pivcert.ParseSlot(req.Slot)
	if err != nil {
		return ErrPIVInvalidSlot
	}

	if err := store.Delete(slot); err != nil {
		slog.Error("PIV delete certificate failed",
			"slot", req.Slot, "backend", req.Backend, "error", err)
		return err
	}

	slog.Info("audit", "component", "audit", "operation", "piv_cert_deleted", "success", true,
		"timestamp", time.Now().Format(time.RFC3339),
		"slot", req.Slot, "backend", req.Backend)

	return nil
}

// GeneratePIVKey generates a new key pair in a PIV slot. The output depends
// on req.OutputFormat:
//   - "" or "self-signed": generate key + self-signed certificate (default)
//   - "public-key": generate key, return public key PEM only
//   - "csr": generate key + CSR, return CSR PEM
//   - "ca-signed": generate key + CSR, sign with CA, store CA-signed cert
func GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	slot, err := pivcert.ParseSlot(req.Slot)
	if err != nil {
		return nil, ErrPIVInvalidSlot
	}

	// Validate output format early.
	format := req.OutputFormat
	if format == "" {
		format = PIVOutputSelfSigned
	}
	switch format {
	case PIVOutputSelfSigned, PIVOutputPublicKey, PIVOutputCSR, PIVOutputCASigned:
	default:
		return nil, ErrPIVInvalidOutputFormat
	}

	// Resolve key generator for the backend.
	generator, err := pivBackend(req.Backend)
	if err != nil {
		return nil, err
	}

	// Generate the key pair.
	cn := PivSlotCN(slot)
	signer, err := generator.GeneratePIVKey(slot, req.Algorithm, cn)
	if err != nil {
		slog.Error("PIV generate key failed",
			"slot", req.Slot, "algorithm", req.Algorithm, "backend", req.Backend,
			"output_format", format, "error", err)
		return nil, err
	}

	// Encode public key.
	pubKeyDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyDER})

	// Public key only — no certificate, no storage.
	if format == PIVOutputPublicKey {
		slog.Info("audit", "component", "audit", "operation", "piv_key_generated", "success", true,
			"timestamp", time.Now().Format(time.RFC3339),
			"slot", req.Slot, "algorithm", req.Algorithm, "backend", req.Backend, "output_format", format)
		return &transport.GeneratePIVKeyResponse{
			Slot:      req.Slot,
			PublicKey: pubKeyPEM,
		}, nil
	}

	// Build the X.509 subject from request fields.
	subject := buildPIVSubject(req, slot)

	// CSR and CA-signed both need a CSR.
	if format == PIVOutputCSR || format == PIVOutputCASigned {
		csrPEM, csrErr := buildPIVCSR(signer, subject)
		if csrErr != nil {
			return nil, csrErr
		}

		// CSR only — return CSR PEM, no storage.
		if format == PIVOutputCSR {
			slog.Info("audit", "component", "audit", "operation", "piv_key_generated", "success", true,
				"timestamp", time.Now().Format(time.RFC3339),
				"slot", req.Slot, "algorithm", req.Algorithm, "backend", req.Backend, "output_format", format)
			return &transport.GeneratePIVKeyResponse{
				Slot:      req.Slot,
				PublicKey: pubKeyPEM,
				CSR:       csrPEM,
			}, nil
		}

		// CA-signed — sign CSR with CA, store the cert.
		resp, caErr := pivGenerateCASigned(ctx, req, slot, signer, pubKeyPEM, csrPEM)
		if caErr != nil {
			slog.Error("PIV generate key failed",
				"slot", req.Slot, "algorithm", req.Algorithm, "backend", req.Backend,
				"output_format", format, "error", caErr)
			return nil, caErr
		}
		slog.Info("audit", "component", "audit", "operation", "piv_key_generated", "success", true,
			"timestamp", time.Now().Format(time.RFC3339),
			"slot", req.Slot, "algorithm", req.Algorithm, "backend", req.Backend, "output_format", format)
		return resp, nil
	}

	// Self-signed — create cert and store it.
	resp, ssErr := pivGenerateSelfSigned(req, slot, signer, pubKeyPEM, subject)
	if ssErr != nil {
		slog.Error("PIV generate key failed",
			"slot", req.Slot, "algorithm", req.Algorithm, "backend", req.Backend,
			"output_format", format, "error", ssErr)
		return nil, ssErr
	}
	slog.Info("audit", "component", "audit", "operation", "piv_key_generated", "success", true,
		"timestamp", time.Now().Format(time.RFC3339),
		"slot", req.Slot, "algorithm", req.Algorithm, "backend", req.Backend, "output_format", format)
	return resp, nil
}

// buildPIVSubject constructs a pkix.Name from the request fields.
func buildPIVSubject(req *transport.GeneratePIVKeyRequest, slot pivcert.PIVSlot) pkix.Name {
	cn := req.Subject
	if cn == "" {
		cn = pivcert.SlotName(slot)
	}
	name := pkix.Name{CommonName: cn}
	if req.Organization != "" {
		name.Organization = []string{req.Organization}
	}
	if req.Country != "" {
		name.Country = []string{req.Country}
	}
	return name
}

// buildPIVCSR creates a PKCS#10 CSR signed by the given signer.
func buildPIVCSR(signer crypto.Signer, subject pkix.Name) ([]byte, error) {
	csrTemplate := &x509.CertificateRequest{Subject: subject}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, signer)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// pivGenerateSelfSigned creates a self-signed certificate and stores it.
// SelfSignExistingPIVKey builds and stores a self-signed certificate for a
// PIV slot whose key was previously generated (e.g., via public-key-only or
// CSR output). It does NOT generate a new key — the existing key in the
// backend is used to sign the certificate. Returns the PEM-encoded cert.
func SelfSignExistingPIVKey(ctx context.Context, backend, slotStr, commonName string, validityDays int) (string, error) {
	slot, err := pivcert.ParseSlot(slotStr)
	if err != nil {
		return "", ErrPIVInvalidSlot
	}

	// Locate the existing key by CN.
	cn := PivSlotCN(slot)
	keys, err := ListKeys(ctx, backend)
	if err != nil {
		slog.Error("SelfSignExistingPIVKey: list keys failed", "backend", backend, "error", err)
		return "", err
	}
	var attrs *types.KeyAttributes
	for _, ka := range keys {
		if ka.CN == cn {
			attrs = ka
			break
		}
	}
	if attrs == nil {
		return "", ErrPIVNotInitialized
	}

	signer, err := Signer(ctx, attrs)
	if err != nil {
		return "", err
	}

	subject := pkix.Name{CommonName: commonName}
	if commonName == "" {
		subject.CommonName = pivcert.SlotName(slot)
	}

	return buildAndStoreSelfSigned(backend, slot, signer, subject, validityDays)
}

// buildAndStoreSelfSigned factors the cert-template + CreateCertificate +
// store logic out of pivGenerateSelfSigned so it can be shared with the
// "self-sign existing key" path.
func buildAndStoreSelfSigned(backend string, slot pivcert.PIVSlot, signer crypto.Signer, subject pkix.Name, validityDays int) (string, error) {
	store, err := pivStore(backend)
	if err != nil {
		return "", err
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", err
	}
	meta, err := pivcert.DefaultSlotMetadata(slot)
	if err != nil {
		return "", err
	}
	validity := 10 * 365 * 24 * time.Hour
	if validityDays > 0 {
		validity = time.Duration(validityDays) * 24 * time.Hour
	}
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              meta.KeyUsage,
		ExtKeyUsage:           meta.ExtKeyUsage,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return "", err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", err
	}
	if err := store.Store(slot, cert); err != nil {
		return "", err
	}
	slog.Info("audit", "component", "audit",
		"operation", "piv_self_signed_cert_issued", "success", true,
		"timestamp", time.Now().Format(time.RFC3339),
		"slot", slot.String(), "backend", backend,
		"subject", subject.CommonName)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})), nil
}

// pivGenerateSelfSigned creates a self-signed certificate for a freshly
// generated PIV key and stores it. The template + CreateCertificate + store
// logic lives in buildAndStoreSelfSigned, which this shares with
// SelfSignExistingPIVKey so the two entry points can never drift onto
// different certificate shapes for the same slot.
func pivGenerateSelfSigned(
	req *transport.GeneratePIVKeyRequest,
	slot pivcert.PIVSlot,
	signer crypto.Signer,
	pubKeyPEM []byte,
	subject pkix.Name,
) (*transport.GeneratePIVKeyResponse, error) {

	certPEM, err := buildAndStoreSelfSigned(req.Backend, slot, signer, subject, req.ValidityDays)
	if err != nil {
		return nil, err
	}

	return &transport.GeneratePIVKeyResponse{
		Slot:        req.Slot,
		Certificate: []byte(certPEM),
		PublicKey:   pubKeyPEM,
	}, nil
}

// pivGenerateCASigned signs a CSR with the configured CA and stores the cert.
func pivGenerateCASigned(
	ctx context.Context,
	req *transport.GeneratePIVKeyRequest,
	slot pivcert.PIVSlot,
	signer crypto.Signer,
	pubKeyPEM, csrPEM []byte,
) (*transport.GeneratePIVKeyResponse, error) {

	if pivManager == nil {
		return nil, ErrPIVNotInitialized
	}

	pivManager.mu.RLock()
	caSign := pivManager.caSignFunc
	pivManager.mu.RUnlock()

	if caSign == nil {
		return nil, ErrPIVCASignFuncNotSet
	}

	// Map slot to CA profile.
	profile, ok := pivSlotToCAProfile[req.Slot]
	if !ok {
		profile = "piv-authentication" // safe default
	}

	validityDays := req.ValidityDays
	if validityDays == 0 {
		validityDays = 1095 // 3 years default for CA-signed
	}

	certPEM, chainPEM, err := caSign(ctx, csrPEM, profile, validityDays)
	if err != nil {
		return nil, err
	}

	// Parse and store the CA-signed certificate.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, ErrPIVInvalidCACertificate
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	store, err := pivStore(req.Backend)
	if err != nil {
		return nil, err
	}
	if err := store.Store(slot, cert); err != nil {
		return nil, err
	}

	return &transport.GeneratePIVKeyResponse{
		Slot:        req.Slot,
		Certificate: certPEM,
		PublicKey:   pubKeyPEM,
		CSR:         csrPEM,
		ChainPEM:    chainPEM,
	}, nil
}

// ImportPIVCertificate imports a certificate into a PIV slot.
func ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return StorePIVCertificate(ctx, req)
}

// ExportPIVCertificate exports a certificate from a PIV slot.
func ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return GetPIVCertificate(ctx, req)
}

// GeneratePIVCSR generates a certificate signing request for a PIV slot key.
func GeneratePIVCSR(_ context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	_, err := pivStore(req.Backend)
	if err != nil {
		return nil, err
	}

	slot, err := pivcert.ParseSlot(req.Slot)
	if err != nil {
		return nil, ErrPIVInvalidSlot
	}

	// Resolve PIVKeyGenerator for the requested backend
	generator, err := pivBackend(req.Backend)
	if err != nil {
		return nil, err
	}

	cn := PivSlotCN(slot)
	signer, err := generator.GetPIVSigner(slot, cn)
	if err != nil {
		return nil, err
	}

	subject := req.Subject
	if subject == "" {
		subject = "PIV Slot " + slot.String()
	}

	// Build a complete Distinguished Name from the request fields. Empty
	// fields are simply omitted from the resulting DN so callers that only
	// supply a CN (pre-DN-field clients) continue to work unchanged.
	name := pkix.Name{CommonName: subject}
	if req.Organization != "" {
		name.Organization = []string{req.Organization}
	}
	if req.OrganizationalUnit != "" {
		name.OrganizationalUnit = []string{req.OrganizationalUnit}
	}
	if req.Country != "" {
		name.Country = []string{req.Country}
	}
	if req.State != "" {
		name.Province = []string{req.State}
	}
	if req.Locality != "" {
		name.Locality = []string{req.Locality}
	}

	csrTemplate := &x509.CertificateRequest{Subject: name}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, signer)
	if err != nil {
		return nil, err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return &transport.GeneratePIVCSRResponse{
		Slot: req.Slot,
		CSR:  csrPEM,
	}, nil
}

// parseCertFormat converts a string format to pivcert.CertFormat.
// Returns -1 if the format is invalid.
func parseCertFormat(format string) pivcert.CertFormat {
	switch format {
	case "pem", "PEM":
		return pivcert.FormatPEM
	case "der", "DER":
		return pivcert.FormatDER
	default:
		return pivcert.CertFormat(-1)
	}
}
