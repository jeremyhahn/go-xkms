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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
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
)

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
			initErr = errors.New("piv config cannot be nil")
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

// pivBackend resolves a PIVKeyGenerator for the given backend name.
// Falls back to softwarePIVKeyGenerator when no resolver is configured.
func pivBackend(backendName string) (PIVKeyGenerator, error) {
	if pivManager == nil {
		return nil, ErrPIVNotInitialized
	}

	pivManager.mu.RLock()
	resolver := pivManager.backendResolver
	pivManager.mu.RUnlock()

	if resolver != nil {
		return resolver(backendName)
	}

	// No resolver set: fall back to cached software key generation
	pivManager.mu.Lock()
	if pivManager.softwareGenerator == nil {
		pivManager.softwareGenerator = NewSoftwarePIVKeyGenerator()
	}
	gen := pivManager.softwareGenerator
	pivManager.mu.Unlock()
	return gen, nil
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
func ListPIVSlots(_ context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	slog.Debug("ListPIVSlots", "backend", req.Backend)
	store, err := pivStore(req.Backend)
	if err != nil {
		return nil, err
	}

	slotInfos, err := store.List()
	if err != nil {
		return nil, err
	}

	// Build a set of occupied slots
	occupied := make(map[string]pivcert.PIVSlotInfo, len(slotInfos))
	for _, info := range slotInfos {
		occupied[info.Slot.String()] = info
	}

	// Return all slots with their status
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
			status.Subject = info.Subject
			status.Issuer = info.Issuer
			status.Algorithm = info.Algorithm
			status.KeySize = info.KeySize
			status.NotAfter = info.NotAfter
			status.Fingerprint = info.Fingerprint
		}

		result = append(result, status)
	}

	slog.Debug("ListPIVSlots result", "slots", len(slotInfos), "occupied", len(occupied))

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

	return store.Import(slot, req.Certificate, format)
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

	return store.Delete(slot)
}

// GeneratePIVKey generates a new key pair in a PIV slot with a self-signed certificate.
func GeneratePIVKey(_ context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	store, err := pivStore(req.Backend)
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
	signer, err := generator.GeneratePIVKey(slot, req.Algorithm, cn)
	if err != nil {
		return nil, err
	}

	// Create self-signed certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	subject := req.Subject
	if subject == "" {
		subject = "PIV Slot " + slot.String()
	}

	// Get slot metadata for key usage
	meta, err := pivcert.DefaultSlotMetadata(slot)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: subject,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              meta.KeyUsage,
		ExtKeyUsage:           meta.ExtKeyUsage,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	// Store certificate
	if err := store.Store(slot, cert); err != nil {
		return nil, err
	}

	// Encode certificate as PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode public key as PEM
	pubKeyDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	})

	return &transport.GeneratePIVKeyResponse{
		Slot:        req.Slot,
		Certificate: certPEM,
		PublicKey:   pubKeyPEM,
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

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: subject,
		},
	}

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
