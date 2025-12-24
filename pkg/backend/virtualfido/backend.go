// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package virtualfido

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	virtualfido "github.com/bulwarkid/virtual-fido"
	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// BackendTypeVirtualFIDO is the backend type identifier.
const BackendTypeVirtualFIDO types.BackendType = "virtualfido"

// StoreTypeVirtualFIDO is the store type identifier for KeyAttributes.
const StoreTypeVirtualFIDO types.StoreType = "virtualfido"

// Backend implements types.Backend for a virtual FIDO2 security key.
// It wraps the github.com/bulwarkid/virtual-fido library to provide
// both PIV key operations and FIDO2 device emulation.
type Backend struct {
	config  *Config
	storage *StorageAdapter
	slots   map[PIVSlot]*SlotData
	mu      sync.RWMutex
	closed  atomic.Bool

	// FIDO2 client from virtual-fido library
	fidoClient *fido_client.DefaultFIDOClient

	// Retry counters
	pinRetries atomic.Int32
	pukRetries atomic.Int32
}

// NewBackend creates a new VirtualFIDO backend with the given configuration.
func NewBackend(config *Config) (*Backend, error) {
	if config == nil {
		return nil, ErrConfigNil
	}

	// Set defaults and validate
	config.SetDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Create storage adapter
	storage, err := NewStorageAdapter(config.Storage, config.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage adapter: %w", err)
	}

	b := &Backend{
		config:  config,
		storage: storage,
		slots:   make(map[PIVSlot]*SlotData),
	}

	// Initialize retry counters
	b.pinRetries.Store(int32(config.PINRetries))
	b.pukRetries.Store(int32(config.PUKRetries))

	// Initialize FIDO2 client
	if err := b.initFIDOClient(); err != nil {
		_ = storage.Close()
		return nil, fmt.Errorf("failed to initialize FIDO2 client: %w", err)
	}

	// Load any persisted state (not fatal if fails - may be a fresh device)
	_ = b.loadState()

	return b, nil
}

// initFIDOClient initializes the virtual-fido client.
func (b *Backend) initFIDOClient() error {
	// Generate self-signed attestation certificate and key
	attestCert, attestPrivKey, encryptionKey, err := b.generateAttestationCredentials()
	if err != nil {
		return fmt.Errorf("failed to generate attestation credentials: %w", err)
	}

	// Wrap ECDSA private key in COSE format
	cosePrivKey := &cose.SupportedCOSEPrivateKey{ECDSA: attestPrivKey}

	// Create the virtual FIDO client with our storage adapter
	b.fidoClient = fido_client.NewDefaultClient(
		attestCert,      // Attestation certificate
		cosePrivKey,     // Attestation private key
		encryptionKey,   // 32-byte encryption key
		true,            // Enable PIN
		&autoApprover{}, // ClientRequestApprover interface (auto-approve for tests)
		b.storage,       // ClientDataSaver interface
	)

	return nil
}

// generateAttestationCredentials creates self-signed attestation credentials.
func (b *Backend) generateAttestationCredentials() (*x509.Certificate, *ecdsa.PrivateKey, [32]byte, error) {
	// Generate P-256 private key for attestation
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, [32]byte{}, fmt.Errorf("failed to generate attestation key: %w", err)
	}

	// Generate self-signed attestation certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, [32]byte{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "VirtualFIDO Attestation",
			Organization: []string{"go-keychain"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(25, 0, 0), // 25 years
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, [32]byte{}, fmt.Errorf("failed to create attestation certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, [32]byte{}, fmt.Errorf("failed to parse attestation certificate: %w", err)
	}

	// Generate 32-byte encryption key
	var encryptionKey [32]byte
	if _, err := rand.Read(encryptionKey[:]); err != nil {
		return nil, nil, [32]byte{}, fmt.Errorf("failed to generate encryption key: %w", err)
	}

	return cert, privKey, encryptionKey, nil
}

// loadState loads persisted device state from storage.
func (b *Backend) loadState() error {
	// Load PIV slots
	slots, err := b.storage.ListPIVSlots()
	if err != nil {
		return err
	}

	for _, slot := range slots {
		data, err := b.storage.LoadPIVSlot(slot)
		if err != nil {
			continue // Skip slots that fail to load
		}
		b.slots[slot] = data
	}

	return nil
}

// Type returns the backend type identifier.
func (b *Backend) Type() types.BackendType {
	return BackendTypeVirtualFIDO
}

// Capabilities returns what features this backend supports.
func (b *Backend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:                true,
		HardwareBacked:      false, // This is a software implementation
		Signing:             true,
		Decryption:          true,
		KeyRotation:         true,
		SymmetricEncryption: true,
		Sealing:             false,
		Import:              true,
		Export:              true,
		KeyAgreement:        true, // ECDH key agreement
		ECIES:               true,
	}
}

// GenerateKey generates a new private key with the given attributes.
func (b *Backend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Determine the slot to use (or allocate one)
	slot := b.allocateSlot(attrs)

	var privKey crypto.PrivateKey
	var err error

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		keySize := 2048
		if attrs.Hash == crypto.SHA384 || attrs.Hash == crypto.SHA512 {
			keySize = 4096
		}
		privKey, err = rsa.GenerateKey(rand.Reader, keySize)

	case x509.ECDSA:
		curve := b.curveFromHash(attrs.Hash)
		privKey, err = ecdsa.GenerateKey(curve, rand.Reader)

	case x509.Ed25519:
		_, privKey, err = ed25519.GenerateKey(rand.Reader)

	default:
		return nil, fmt.Errorf("%w: %v", ErrKeyAlgorithmNotSupported, attrs.KeyAlgorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Store the key in the slot
	slotData := &SlotData{
		PrivateKey:  privKey,
		Algorithm:   attrs.KeyAlgorithm,
		CreatedAt:   time.Now(),
		TouchPolicy: TouchPolicyNever,
		PINPolicy:   PINPolicyDefault,
	}

	b.slots[slot] = slotData

	// Persist to storage (log but don't fail - key is in memory)
	_ = b.storage.SavePIVSlot(slot, slotData)

	return privKey, nil
}

// GetKey retrieves an existing private key by its attributes.
func (b *Backend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	slot := b.findSlot(attrs)
	if slot == 0 {
		return nil, ErrKeyNotFound
	}

	slotData, ok := b.slots[slot]
	if !ok {
		return nil, ErrKeyNotFound
	}

	return slotData.PrivateKey, nil
}

// DeleteKey removes a key identified by its attributes.
func (b *Backend) DeleteKey(attrs *types.KeyAttributes) error {
	if b.closed.Load() {
		return ErrBackendClosed
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	slot := b.findSlot(attrs)
	if slot == 0 {
		return ErrKeyNotFound
	}

	delete(b.slots, slot)

	// Remove from storage
	return b.storage.DeletePIVSlot(slot)
}

// ListKeys returns attributes for all keys managed by this backend.
func (b *Backend) ListKeys() ([]*types.KeyAttributes, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	attrs := make([]*types.KeyAttributes, 0, len(b.slots))
	for slot, data := range b.slots {
		attrs = append(attrs, &types.KeyAttributes{
			CN:           slot.String(),
			KeyAlgorithm: data.Algorithm,
			StoreType:    StoreTypeVirtualFIDO,
		})
	}

	return attrs, nil
}

// Signer returns a crypto.Signer for the key identified by attrs.
func (b *Backend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}

	key, err := b.GetKey(attrs)
	if err != nil {
		return nil, err
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: key does not implement crypto.Signer", ErrOperationNotSupported)
	}

	return &virtualSigner{
		backend: b,
		signer:  signer,
		attrs:   attrs,
	}, nil
}

// Decrypter returns a crypto.Decrypter for the key identified by attrs.
func (b *Backend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}

	key, err := b.GetKey(attrs)
	if err != nil {
		return nil, err
	}

	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("%w: key does not implement crypto.Decrypter", ErrOperationNotSupported)
	}

	return &virtualDecrypter{
		backend:   b,
		decrypter: decrypter,
		attrs:     attrs,
	}, nil
}

// RotateKey rotates/updates a key identified by attrs.
func (b *Backend) RotateKey(attrs *types.KeyAttributes) error {
	if b.closed.Load() {
		return ErrBackendClosed
	}

	// Get current key to preserve algorithm
	currentKey, err := b.GetKey(attrs)
	if err != nil {
		return err
	}

	// Determine algorithm from current key
	newAttrs := *attrs
	switch currentKey.(type) {
	case *rsa.PrivateKey:
		newAttrs.KeyAlgorithm = x509.RSA
	case *ecdsa.PrivateKey:
		newAttrs.KeyAlgorithm = x509.ECDSA
	case ed25519.PrivateKey:
		newAttrs.KeyAlgorithm = x509.Ed25519
	}

	// Delete old key
	if err := b.DeleteKey(attrs); err != nil {
		return err
	}

	// Generate new key with same algorithm
	_, err = b.GenerateKey(&newAttrs)
	return err
}

// Close releases any resources held by the backend.
func (b *Backend) Close() error {
	if b.closed.Swap(true) {
		return nil // Already closed
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Clear sensitive data
	for slot := range b.slots {
		delete(b.slots, slot)
	}

	if b.storage != nil {
		return b.storage.Close()
	}

	return nil
}

// allocateSlot finds an available slot for a new key.
func (b *Backend) allocateSlot(attrs *types.KeyAttributes) PIVSlot {
	// Try to find a slot based on key type
	switch attrs.KeyType {
	case types.KeyTypeSigning:
		if _, ok := b.slots[SlotSignature]; !ok {
			return SlotSignature
		}
	case types.KeyTypeEncryption:
		if _, ok := b.slots[SlotKeyManagement]; !ok {
			return SlotKeyManagement
		}
	}

	// Use authentication slot by default
	if _, ok := b.slots[SlotAuthentication]; !ok {
		return SlotAuthentication
	}

	// Find first available retired slot
	for _, slot := range AllRetiredSlots() {
		if _, ok := b.slots[slot]; !ok {
			return slot
		}
	}

	// All slots full - use authentication (will overwrite)
	return SlotAuthentication
}

// findSlot finds the slot containing a key matching the attributes.
func (b *Backend) findSlot(attrs *types.KeyAttributes) PIVSlot {
	// First try to match by CN (which may be slot name)
	for slot := range b.slots {
		if slot.String() == attrs.CN {
			return slot
		}
	}

	// Try to match by key type
	switch attrs.KeyType {
	case types.KeyTypeSigning:
		if _, ok := b.slots[SlotSignature]; ok {
			return SlotSignature
		}
	case types.KeyTypeEncryption:
		if _, ok := b.slots[SlotKeyManagement]; ok {
			return SlotKeyManagement
		}
	}

	// Return authentication slot as default
	if _, ok := b.slots[SlotAuthentication]; ok {
		return SlotAuthentication
	}

	return 0
}

// curveFromHash returns an appropriate elliptic curve for the given hash.
func (b *Backend) curveFromHash(hash crypto.Hash) elliptic.Curve {
	switch hash {
	case crypto.SHA384:
		return elliptic.P384()
	case crypto.SHA512:
		return elliptic.P521()
	default:
		return elliptic.P256()
	}
}

// FIDOClient returns the underlying virtual-fido client.
func (b *Backend) FIDOClient() virtualfido.FIDOClient {
	return b.fidoClient
}

// SerialNumber returns the virtual device serial number.
func (b *Backend) SerialNumber() string {
	return b.config.SerialNumber
}

// Manufacturer returns the manufacturer name.
func (b *Backend) Manufacturer() string {
	return b.config.Manufacturer
}

// Product returns the product name.
func (b *Backend) Product() string {
	return b.config.Product
}

// virtualSigner wraps a crypto.Signer to add backend-specific behavior.
type virtualSigner struct {
	backend *Backend
	signer  crypto.Signer
	attrs   *types.KeyAttributes
}

func (s *virtualSigner) Public() crypto.PublicKey {
	return s.signer.Public()
}

func (s *virtualSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.backend.closed.Load() {
		return nil, ErrBackendClosed
	}

	return s.signer.Sign(rand, digest, opts)
}

// virtualDecrypter wraps a crypto.Decrypter to add backend-specific behavior.
type virtualDecrypter struct {
	backend   *Backend
	decrypter crypto.Decrypter
	attrs     *types.KeyAttributes
}

func (d *virtualDecrypter) Public() crypto.PublicKey {
	return d.decrypter.Public()
}

func (d *virtualDecrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if d.backend.closed.Load() {
		return nil, ErrBackendClosed
	}

	return d.decrypter.Decrypt(rand, ciphertext, opts)
}

// autoApprover implements virtual-fido's ClientRequestApprover interface.
// It automatically approves all FIDO2 operations for testing purposes.
type autoApprover struct{}

func (a *autoApprover) ApproveClientAction(action fido_client.ClientAction, params fido_client.ClientActionRequestParams) bool {
	return true
}

// KeyAgreement implementation

// DeriveSharedSecret performs ECDH key agreement.
func (b *Backend) DeriveSharedSecret(attrs *types.KeyAttributes, peerPublicKey crypto.PublicKey) ([]byte, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}

	privKey, err := b.GetKey(attrs)
	if err != nil {
		return nil, err
	}

	ecdsaPriv, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: ECDH requires ECDSA key", ErrOperationNotSupported)
	}

	// Convert to ecdh types
	ecdhPriv, err := ecdsaPriv.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key: %w", err)
	}

	var ecdhPub *ecdh.PublicKey
	switch pub := peerPublicKey.(type) {
	case *ecdsa.PublicKey:
		ecdhPub, err = pub.ECDH()
		if err != nil {
			return nil, fmt.Errorf("failed to convert peer public key: %w", err)
		}
	case *ecdh.PublicKey:
		ecdhPub = pub
	default:
		return nil, fmt.Errorf("%w: unsupported peer public key type", ErrOperationNotSupported)
	}

	return ecdhPriv.ECDH(ecdhPub)
}

// SetPIN sets a new PIN for the virtual device.
func (b *Backend) SetPIN(oldPIN, newPIN string) error {
	if b.closed.Load() {
		return ErrBackendClosed
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Verify old PIN
	if b.config.PIN != "" && oldPIN != b.config.PIN {
		return ErrPINInvalid
	}

	// Validate new PIN
	if len(newPIN) < 4 || len(newPIN) > 8 {
		return fmt.Errorf("virtualfido: PIN must be 4-8 characters")
	}

	b.config.PIN = newPIN

	// Update FIDO client PIN if supported
	if b.fidoClient != nil && b.fidoClient.SupportsPIN() {
		b.fidoClient.SetPIN([]byte(newPIN))
	}

	return nil
}

// VerifyPIN verifies the user PIN.
func (b *Backend) VerifyPIN(pin string) error {
	if b.closed.Load() {
		return ErrBackendClosed
	}

	if b.pinRetries.Load() <= 0 {
		return ErrPINBlocked
	}

	if pin != b.config.PIN {
		b.pinRetries.Add(-1)
		if b.pinRetries.Load() <= 0 {
			return ErrPINBlocked
		}
		return ErrPINInvalid
	}

	// Reset retries on success
	b.pinRetries.Store(int32(b.config.PINRetries))
	return nil
}

// UnblockPIN uses the PUK to reset the PIN.
func (b *Backend) UnblockPIN(puk, newPIN string) error {
	if b.closed.Load() {
		return ErrBackendClosed
	}

	if b.pukRetries.Load() <= 0 {
		return ErrPUKBlocked
	}

	if puk != b.config.PUK {
		b.pukRetries.Add(-1)
		if b.pukRetries.Load() <= 0 {
			return ErrPUKBlocked
		}
		return ErrPUKInvalid
	}

	// Reset PIN
	b.config.PIN = newPIN
	b.pinRetries.Store(int32(b.config.PINRetries))
	b.pukRetries.Store(int32(b.config.PUKRetries))

	return nil
}

// GetRetryCount returns the current PIN and PUK retry counts.
func (b *Backend) GetRetryCount() (pinRetries, pukRetries int, err error) {
	if b.closed.Load() {
		return 0, 0, ErrBackendClosed
	}

	return int(b.pinRetries.Load()), int(b.pukRetries.Load()), nil
}

// ResetDevice performs a factory reset of the virtual device.
func (b *Backend) ResetDevice() error {
	if b.closed.Load() {
		return ErrBackendClosed
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Clear all slots
	for slot := range b.slots {
		_ = b.storage.DeletePIVSlot(slot)
		delete(b.slots, slot)
	}

	// Reset PIN/PUK to defaults
	b.config.PIN = DefaultPIN
	b.config.PUK = DefaultPUK
	b.config.ManagementKey = defaultManagementKey()

	// Reset retry counters
	b.pinRetries.Store(int32(b.config.PINRetries))
	b.pukRetries.Store(int32(b.config.PUKRetries))

	return nil
}

// Ensure Backend implements required interfaces.
var (
	_ types.Backend      = (*Backend)(nil)
	_ types.KeyAgreement = (*Backend)(nil)
)
