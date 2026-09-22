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

package hardware

import (
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/cespare/xxhash/v2"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

const (
	// certRecordMagic identifies an NV blob that carries an ID header.
	certRecordMagic = "XKC1"

	// certRecordHeaderSize is the size of the magic plus the ID length field.
	certRecordHeaderSize = len(certRecordMagic) + 2

	// maxCertIDLength is the largest certificate ID the header can encode.
	maxCertIDLength = 1<<16 - 1

	// certIndexSpan is the size of the NV index range certificates are hashed
	// into, starting at the configured base index.
	certIndexSpan = 0x00400000

	// nvHandleQueryCount is the number of NV handles requested per
	// TPM2_GetCapability call when enumerating certificates.
	nvHandleQueryCount = 256
)

// TPM2CertStorage implements HardwareCertStorage for TPM 2.0 devices.
// Certificates are stored in TPM NV (Non-Volatile) RAM.
//
// Thread Safety:
// All operations are serialized by a mutex. A TPM transport carries one
// command and its response at a time, so even read operations must hold the
// lock exclusively: two concurrent readers would interleave their commands on
// the wire and receive each other's responses.
//
// Certificate Storage:
//   - Each certificate is stored in a dedicated NV index
//   - NV indices are derived from a base index + hash(ID)
//   - Certificates are stored as a self-describing record that carries the
//     certificate ID alongside the PEM-encoded data
//   - NV index attributes provide access control
//
// NV Index Layout:
//
//	Base Index: 0x01800000 (TPM_NV_INDEX_FIRST)
//	Cert Index: Base + (xxhash64 of ID % 0x003FFFFF)
//
// NV Record Layout:
//
//	 0..3  magic "XKC1"
//	 4..5  certificate ID length (big endian uint16)
//	 6..n  certificate ID
//	n+1..  PEM-encoded certificate or chain
//
// Storing the ID in NV RAM is what makes ListCerts report the same IDs that
// GetCert accepts: the hash that maps an ID onto an NV index is one-way, so
// the ID has to be persisted next to the certificate. Because the record
// lives in the TPM itself, the mapping survives process restarts without any
// host-side index file or in-memory table.
//
// Limitations:
//   - Limited NV RAM capacity (typically 2KB-8KB total)
//   - Each certificate consumes ~2KB (including overhead)
//   - Practical limit: 2-4 certificates per TPM
//   - No built-in chain support (stored as single blob)
type TPM2CertStorage struct {
	tpm       transport.TPMCloser // TPM device connection
	baseIndex uint32              // Base NV index for certificates
	maxSize   int                 // Maximum certificate size (bytes)
	ownerAuth []byte              // Owner hierarchy password
	mu        sync.Mutex          // Serializes TPM access
	closed    bool                // Tracks if storage is closed
}

// TPM2CertStorageConfig configures TPM2 certificate storage
type TPM2CertStorageConfig struct {
	// BaseIndex is the starting NV index for certificate storage
	// Default: 0x01800000 (TPM_NV_INDEX_FIRST)
	BaseIndex uint32

	// MaxCertSize is the maximum certificate size in bytes
	// Default: 2048 bytes
	MaxCertSize int

	// OwnerAuth is the owner hierarchy password
	// Required for creating/deleting NV indices
	OwnerAuth []byte
}

// DefaultTPM2CertStorageConfig returns safe defaults for TPM2 certificate storage
func DefaultTPM2CertStorageConfig() *TPM2CertStorageConfig {
	return &TPM2CertStorageConfig{
		BaseIndex:   0x01800000, // TPM_NV_INDEX_FIRST
		MaxCertSize: 2048,
		OwnerAuth:   nil, // No password by default
	}
}

// NewTPM2CertStorage creates a new TPM2 certificate storage instance.
//
// Parameters:
//   - tpm: Open TPM device connection
//   - config: Storage configuration
//
// Returns an error if NV RAM is inaccessible or config is invalid.
func NewTPM2CertStorage(
	tpm transport.TPMCloser,
	config *TPM2CertStorageConfig,
) (HardwareCertStorage, error) {
	if tpm == nil {
		return nil, ErrNilTPM
	}

	if config == nil {
		config = DefaultTPM2CertStorageConfig()
	}

	// Validate base index is in NV RAM range
	if config.BaseIndex < 0x01000000 || config.BaseIndex > 0x01BFFFFF {
		return nil, &errs.Detail{Err: ErrInvalidBaseIndex, Detail: fmt.Sprintf("got %#x", config.BaseIndex)}
	}

	if config.MaxCertSize < 512 || config.MaxCertSize > 4096 {
		return nil, &errs.Detail{Err: ErrInvalidCertSize, Detail: fmt.Sprintf("got %d bytes", config.MaxCertSize)}
	}

	return &TPM2CertStorage{
		tpm:       tpm,
		baseIndex: config.BaseIndex,
		maxSize:   config.MaxCertSize,
		ownerAuth: config.OwnerAuth,
	}, nil
}

// SaveCert stores a certificate in TPM NV RAM.
// The certificate is PEM-encoded and written to a dedicated NV index.
//
// NV Index Attributes:
//   - TPMA_NV_AUTHWRITE: Requires authorization to write
//   - TPMA_NV_AUTHREAD: Requires authorization to read
//   - TPMA_NV_NO_DA: Not subject to dictionary attack protection
//   - TPMA_NV_OWNERWRITE: Owner hierarchy can write
//   - TPMA_NV_OWNERREAD: Owner hierarchy can read
func (t *TPM2CertStorage) SaveCert(id string, cert *x509.Certificate) error {
	if id == "" {
		return storage.ErrInvalidID
	}
	if isReservedChainID(id) {
		return &errs.Detail{Err: ErrIDReservedForChain, Detail: fmt.Sprintf("%q", id)}
	}
	if cert == nil {
		return storage.ErrInvalidData
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return ErrStorageClosed
	}

	// PEM encode certificate
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return t.saveRecord(id, pemData, "write certificate to NV RAM")
}

// saveRecord writes a certificate record (ID header plus PEM payload) to the
// NV index derived from the ID. Callers must hold the write lock.
func (t *TPM2CertStorage) saveRecord(id string, pemData []byte, op string) error {
	record, err := encodeCertRecord(id, pemData)
	if err != nil {
		return err
	}

	if len(record) > t.maxSize {
		return ErrCertificateTooLarge
	}

	nvIndex := t.certIndexFromID(id)

	// Refuse to clobber a different certificate that hashed to the same index.
	existing, err := t.readNVIndex(nvIndex)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return NewOperationError(op, err)
	}
	if err == nil {
		existingID, _, ok := decodeCertRecord(existing)
		if !ok {
			return &errs.Detail{
				Err:    ErrCertRecordMissingHeader,
				Detail: fmt.Sprintf("index %#x", nvIndex),
			}
		}
		if existingID != id {
			return &errs.Detail{
				Err:    ErrNVIndexUnavailable,
				Detail: fmt.Sprintf("index %#x holds certificate %q", nvIndex, existingID),
			}
		}
	}

	// Write to NV RAM (creates if doesn't exist)
	if err := t.writeNVIndex(nvIndex, record); err != nil {
		return NewOperationError(op, err)
	}

	return nil
}

// GetCert retrieves a certificate from TPM NV RAM.
func (t *TPM2CertStorage) GetCert(id string) (*x509.Certificate, error) {
	if id == "" {
		return nil, storage.ErrInvalidID
	}
	if isReservedChainID(id) {
		return nil, &errs.Detail{Err: ErrIDReservedForChain, Detail: fmt.Sprintf("%q", id)}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, ErrStorageClosed
	}

	// Resolve the ID to the NV index that actually holds it
	_, payload, err := t.lookupCert(id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, storage.ErrNotFound
		}
		return nil, NewOperationError("read certificate from NV RAM", err)
	}
	// The index holds one record and it says which kind it is; a chain
	// record is not the certificate record, so a certificate read of it is
	// absence, exactly as the two-record stores answer for a missing
	// certificate object beside a stored chain.
	if recordIsChain(payload) {
		return nil, storage.ErrNotFound
	}

	// Decode PEM
	block, _ := pem.Decode(payload)
	if block == nil {
		return nil, ErrInvalidCertificate
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, NewOperationError("parse certificate", err)
	}

	return cert, nil
}

// DeleteCert removes a certificate by undefining its NV index.
func (t *TPM2CertStorage) DeleteCert(id string) error {
	if id == "" {
		return storage.ErrInvalidID
	}
	if isReservedChainID(id) {
		return &errs.Detail{Err: ErrIDReservedForChain, Detail: fmt.Sprintf("%q", id)}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return ErrStorageClosed
	}

	return t.releaseRecordLocked(id, false, "delete certificate from NV RAM")
}

// releaseRecordLocked releases the record stored under id when it is of the
// kind the caller addresses: a certificate record for DeleteCert, a chain
// record for DeleteCertChain. An id's NV index holds whichever of SaveCert
// and SaveCertChain wrote last, and the record says which it is, so the
// method whose kind it is not answers ErrNotFound and leaves it in place,
// exactly as the two-record stores leave the sibling. Callers hold the write
// lock.
func (t *TPM2CertStorage) releaseRecordLocked(id string, wantChain bool, op string) error {
	index, payload, err := t.lookupCert(id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return storage.ErrNotFound
		}
		return NewOperationError(op, err)
	}
	if recordIsChain(payload) != wantChain {
		return storage.ErrNotFound
	}
	if err := t.deleteNVIndex(index); err != nil {
		return NewOperationError(op, err)
	}
	return nil
}

// recordIsChain reports whether an NV payload is a chain record: one whose
// PEM blocks carry the chain marker SaveCertChain stamps on every block it
// writes. A block with no marker is a certificate record.
func recordIsChain(payload []byte) bool {
	block, _ := pem.Decode(payload)
	if block == nil {
		return false
	}
	return block.Headers[recordKindHeader] == recordKindChain
}

// DeleteCertChain removes the chain stored under id. TPM2 keeps the
// certificate and the chain of one id in ONE NV record, holding whichever of
// SaveCert and SaveCertChain wrote last, so there is no sibling to leave in
// place: this releases that record exactly as DeleteCert does, and a caller
// addressing the chain record releases what the id holds. Absent, it is a
// no-op, as DeleteCert is.
func (t *TPM2CertStorage) DeleteCertChain(id string) error {
	if id == "" {
		return storage.ErrInvalidID
	}
	if isReservedChainID(id) {
		return &errs.Detail{Err: ErrIDReservedForChain, Detail: fmt.Sprintf("%q", id)}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return ErrStorageClosed
	}

	return t.releaseRecordLocked(id, true, "delete certificate chain from NV RAM")
}

// SaveCertChain stores a certificate chain as a PEM-encoded bundle.
// All certificates are concatenated and stored in a single NV index.
func (t *TPM2CertStorage) SaveCertChain(id string, chain []*x509.Certificate) error {
	if id == "" {
		return storage.ErrInvalidID
	}
	if isReservedChainID(id) {
		return &errs.Detail{Err: ErrIDReservedForChain, Detail: fmt.Sprintf("%q", id)}
	}
	if len(chain) == 0 {
		return storage.ErrInvalidData
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return ErrStorageClosed
	}

	// Concatenate PEM-encoded certificates. Every block carries the chain
	// marker, so the record's kind survives in the NV blob itself and a
	// one-member chain is never mistaken for a certificate.
	var pemData []byte
	for _, cert := range chain {
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:    "CERTIFICATE",
			Headers: map[string]string{recordKindHeader: recordKindChain},
			Bytes:   cert.Raw,
		})
		pemData = append(pemData, pemBlock...)
	}

	return t.saveRecord(id, pemData, "write certificate chain to NV RAM")
}

// GetCertChain retrieves and parses a certificate chain bundle.
func (t *TPM2CertStorage) GetCertChain(id string) ([]*x509.Certificate, error) {
	if id == "" {
		return nil, storage.ErrInvalidID
	}
	if isReservedChainID(id) {
		return nil, &errs.Detail{Err: ErrIDReservedForChain, Detail: fmt.Sprintf("%q", id)}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, ErrStorageClosed
	}

	// Resolve the ID to the NV index that actually holds it
	_, payload, err := t.lookupCert(id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, storage.ErrNotFound
		}
		return nil, NewOperationError("read certificate chain from NV RAM", err)
	}
	// A certificate record is not a chain: answering it as a one-member
	// chain would let a TPM2 certificate hide a chain that overflowed to the
	// external side, and resurrect itself as a phantom chain after that
	// chain was released.
	if !recordIsChain(payload) {
		return nil, storage.ErrNotFound
	}

	// Parse all PEM blocks
	var chain []*x509.Certificate
	remaining := payload
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, NewOperationError("parse certificate in chain", err)
		}

		chain = append(chain, cert)
		remaining = rest
	}

	if len(chain) == 0 {
		return nil, ErrInvalidCertificate
	}

	return chain, nil
}

// ListCerts returns the certificate IDs stored in TPM NV RAM.
//
// Every ID returned here is accepted by GetCert, GetCertChain, CertExists and
// DeleteCert: the ID is read back out of the record header stored in NV RAM.
// An NV index in range that holds data without that header belongs to
// another subsystem, not to this storage, and is skipped -- every record
// this storage writes carries the header.
//
// Note: This is expensive as it requires querying TPM capabilities and reading
// every NV index in the certificate range.
func (t *TPM2CertStorage) ListCerts() ([]string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.listCertsUnlocked()
}

// CertExists checks if an NV index exists for the certificate.
func (t *TPM2CertStorage) CertExists(id string) (bool, error) {
	if id == "" {
		return false, storage.ErrInvalidID
	}
	if isReservedChainID(id) {
		return false, &errs.Detail{Err: ErrIDReservedForChain, Detail: fmt.Sprintf("%q", id)}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return false, ErrStorageClosed
	}

	// Resolve the ID to the NV index that actually holds it; a chain record
	// under the id is not the certificate, so it does not count.
	_, payload, err := t.lookupCert(id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return false, nil
		}
		return false, NewOperationError("check certificate in NV RAM", err)
	}

	return !recordIsChain(payload), nil
}

// Close releases TPM resources (NV handles are persistent, no cleanup needed).
func (t *TPM2CertStorage) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return ErrStorageClosed
	}

	t.closed = true
	return nil
}

// GetCapacity queries TPM NV RAM capacity and usage.
// Note: This is an approximation based on max cert size and available space.
func (t *TPM2CertStorage) GetCapacity() (total int, available int, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return 0, 0, ErrStorageClosed
	}

	// Typical TPM NV RAM: 2KB-8KB total
	// Conservative estimate: 8KB total, each cert ~2KB = 4 certs max
	// This is a simplified implementation - real TPMs vary widely
	estimatedTotal := 4

	// Count existing certificates
	certIDs, err := t.listCertsUnlocked()
	if err != nil {
		return 0, 0, NewOperationError("count certificates", err)
	}

	used := len(certIDs)
	available = estimatedTotal - used
	if available < 0 {
		available = 0
	}

	return estimatedTotal, available, nil
}

// SupportsChains returns true (chains stored as concatenated PEM).
func (t *TPM2CertStorage) SupportsChains() bool {
	return true
}

// IsHardwareBacked returns true.
func (t *TPM2CertStorage) IsHardwareBacked() bool {
	return true
}

// Compact defragments TPM NV RAM if supported (TPM 2.0 spec optional).
// Most TPMs don't support this, so we return ErrNotSupported.
func (t *TPM2CertStorage) Compact() error {
	return ErrNotSupported
}

// certIndexFromID computes the NV index for a certificate ID
// using xxhash64 (truncated to 32 bits) to distribute IDs across index space.
func (t *TPM2CertStorage) certIndexFromID(id string) uint32 {
	hash := uint32(xxhash.Sum64String(id))

	// Map to NV index range (0x01800000 - 0x01BFFFFF)
	// Use modulo to wrap into 0x00400000 range
	offset := hash % certIndexSpan
	return t.baseIndex + offset
}

// lookupCert resolves a certificate ID to the NV index that holds it and
// returns that index along with the PEM payload stored there.
//
// IDs are resolved by hash, and the ID in the record header must match: an
// index whose record belongs to a different ID is a hash collision, not a
// hit.
//
// Returns storage.ErrNotFound if no NV index holds the certificate, and
// ErrCertRecordMissingHeader if the index this lookup lands on holds data
// without the required ID header -- every record this storage writes has
// one, so that data is not a certificate this storage produced.
func (t *TPM2CertStorage) lookupCert(id string) (uint32, []byte, error) {
	hashedIndex := t.certIndexFromID(id)

	data, err := t.readNVIndex(hashedIndex)
	if err != nil {
		return 0, nil, err
	}

	recordID, payload, ok := decodeCertRecord(data)
	if !ok {
		return 0, nil, &errs.Detail{
			Err:    ErrCertRecordMissingHeader,
			Detail: fmt.Sprintf("index %#x", hashedIndex),
		}
	}
	if recordID != id {
		// Hash collision: this index belongs to a different certificate.
		return 0, nil, storage.ErrNotFound
	}

	return hashedIndex, payload, nil
}

// recordKindHeader is the PEM header SaveCertChain stamps on every block of
// a chain record, with recordKindChain as its value. A certificate record
// carries no such header. The kind therefore lives in the NV blob itself,
// which is what lets DeleteCert and DeleteCertChain each release only the
// record they address although an id has one NV index.
const (
	recordKindHeader = "Record"
	recordKindChain  = "chain"
)

// encodeCertRecord serializes a certificate ID and its PEM payload into the NV
// record format.
func encodeCertRecord(id string, payload []byte) ([]byte, error) {
	if len(id) > maxCertIDLength {
		return nil, &errs.Detail{
			Err:    storage.ErrInvalidID,
			Detail: fmt.Sprintf("certificate ID exceeds %d bytes", maxCertIDLength),
		}
	}

	record := make([]byte, 0, certRecordHeaderSize+len(id)+len(payload))
	record = append(record, certRecordMagic...)
	record = binary.BigEndian.AppendUint16(record, uint16(len(id)))
	record = append(record, id...)
	record = append(record, payload...)

	return record, nil
}

// decodeCertRecord splits an NV blob into its certificate ID and PEM payload.
// The final return value reports whether the blob carries a well-formed ID
// header; every record this storage writes has one, so a caller reading
// false back is holding a blob this storage did not write, or one it wrote
// and something else corrupted -- either way, not a shape to interpret.
func decodeCertRecord(data []byte) (string, []byte, bool) {
	if len(data) < certRecordHeaderSize || string(data[:len(certRecordMagic)]) != certRecordMagic {
		return "", data, false
	}

	idLen := int(binary.BigEndian.Uint16(data[len(certRecordMagic):certRecordHeaderSize]))
	if certRecordHeaderSize+idLen > len(data) {
		// Truncated header: treat the blob as opaque so the caller fails on
		// the PEM decode rather than reporting a bogus ID.
		return "", data, false
	}

	id := string(data[certRecordHeaderSize : certRecordHeaderSize+idLen])
	if id == "" {
		return "", data, false
	}

	return id, data[certRecordHeaderSize+idLen:], true
}

// isMissingNVIndex reports whether an NVReadPublic failure means the index is
// undefined rather than that the TPM could not be reached. An undefined index
// answers with TPM_RC_HANDLE; a transport or device failure carries no TPM
// response code at all and must never be mistaken for an absent certificate.
func isMissingNVIndex(err error) bool {
	var rc tpm2.TPMRC
	if !errors.As(err, &rc) {
		return false
	}
	return errors.Is(rc, tpm2.TPMRCHandle) || errors.Is(rc, tpm2.TPMRCValue)
}

// readNVIndex reads data from an NV index with authorization.
func (t *TPM2CertStorage) readNVIndex(index uint32) ([]byte, error) {
	// Read NV public to get size
	readPubResp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(index),
	}.Execute(t.tpm)

	if err != nil {
		if isMissingNVIndex(err) {
			return nil, storage.ErrNotFound
		}
		return nil, NewOperationError("read NV public", err)
	}

	nvPublic, err := readPubResp.NVPublic.Contents()
	if err != nil {
		return nil, NewOperationError("get NV public contents", err)
	}

	// Read data in chunks (TPM has max read size limits)
	const maxChunkSize = 1024
	totalSize := int(nvPublic.DataSize)
	result := make([]byte, 0, totalSize)
	offset := uint16(0)

	for offset < uint16(totalSize) {
		chunkSize := uint16(maxChunkSize)
		if int(offset)+int(chunkSize) > totalSize {
			chunkSize = uint16(totalSize) - offset
		}

		readResp, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(t.ownerAuth),
			},
			NVIndex: tpm2.NamedHandle{
				Handle: tpm2.TPMHandle(index),
				Name:   readPubResp.NVName,
			},
			Size:   chunkSize,
			Offset: offset,
		}.Execute(t.tpm)

		if err != nil {
			return nil, NewOperationError(fmt.Sprintf("NV read at offset %d", offset), err)
		}

		result = append(result, readResp.Data.Buffer...)
		offset += chunkSize
	}

	return result, nil
}

// writeNVIndex writes data to an NV index, creating if necessary.
func (t *TPM2CertStorage) writeNVIndex(index uint32, data []byte) error {
	// Check if index exists
	readPubResp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(index),
	}.Execute(t.tpm)

	if err != nil {
		// Index doesn't exist, create it
		if err := t.defineNVIndex(index, len(data)); err != nil {
			return NewOperationError("define NV index", err)
		}

		// Re-read public to get name
		readPubResp, err = tpm2.NVReadPublic{
			NVIndex: tpm2.TPMHandle(index),
		}.Execute(t.tpm)

		if err != nil {
			return NewOperationError("read NV public after define", err)
		}
	} else {
		// Index exists - check if size matches
		nvPublic, err := readPubResp.NVPublic.Contents()
		if err != nil {
			return NewOperationError("get NV public contents", err)
		}

		if int(nvPublic.DataSize) != len(data) {
			// Size mismatch - delete and recreate
			if err := t.deleteNVIndex(index); err != nil {
				return NewOperationError("delete existing NV index", err)
			}

			if err := t.defineNVIndex(index, len(data)); err != nil {
				return NewOperationError("redefine NV index", err)
			}

			// Re-read public to get name
			readPubResp, err = tpm2.NVReadPublic{
				NVIndex: tpm2.TPMHandle(index),
			}.Execute(t.tpm)

			if err != nil {
				return NewOperationError("read NV public after redefine", err)
			}
		}
	}

	// Write data in chunks (TPM has max write size limits)
	// Typical max: 1024 bytes per write
	const maxChunkSize = 1024
	offset := uint16(0)

	for offset < uint16(len(data)) {
		chunkEnd := int(offset) + maxChunkSize
		if chunkEnd > len(data) {
			chunkEnd = len(data)
		}

		chunk := data[offset:chunkEnd]

		_, err = tpm2.NVWrite{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(t.ownerAuth),
			},
			NVIndex: tpm2.NamedHandle{
				Handle: tpm2.TPMHandle(index),
				Name:   readPubResp.NVName,
			},
			Data: tpm2.TPM2BMaxNVBuffer{
				Buffer: chunk,
			},
			Offset: offset,
		}.Execute(t.tpm)

		if err != nil {
			return NewOperationError(fmt.Sprintf("NV write at offset %d", offset), err)
		}

		offset += uint16(len(chunk))
	}

	return nil
}

// defineNVIndex creates a new NV index with the specified size.
func (t *TPM2CertStorage) defineNVIndex(index uint32, size int) error {
	// Define NV index with appropriate attributes
	nvPublic := tpm2.TPMSNVPublic{
		NVIndex: tpm2.TPMHandle(index),
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			AuthWrite:  true,
			AuthRead:   true,
			NoDA:       true,
			OwnerWrite: true,
			OwnerRead:  true,
			// Note: WriteDefine not set to allow updates
		},
		DataSize: uint16(size),
	}

	_, err := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(t.ownerAuth),
		},
		PublicInfo: tpm2.New2B(nvPublic),
	}.Execute(t.tpm)

	if err != nil {
		return NewOperationError("NV define", err)
	}

	return nil
}

// deleteNVIndex undefines an NV index to free NV RAM.
func (t *TPM2CertStorage) deleteNVIndex(index uint32) error {
	// Read public to get name
	readPubResp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(index),
	}.Execute(t.tpm)

	if err != nil {
		if isMissingNVIndex(err) {
			// Index doesn't exist, treat as success (idempotent)
			return nil
		}
		return NewOperationError("read NV public before undefine", err)
	}

	// Undefine the index
	_, err = tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(t.ownerAuth),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(index),
			Name:   readPubResp.NVName,
		},
	}.Execute(t.tpm)

	if err != nil {
		return NewOperationError("NV undefine", err)
	}

	return nil
}

// listCertsUnlocked is the unlocked version of ListCerts for internal use
func (t *TPM2CertStorage) listCertsUnlocked() ([]string, error) {
	if t.closed {
		return nil, ErrStorageClosed
	}

	// Query TPM for NV indices in our range
	// TPM2_GetCapability with TPM_CAP_HANDLES
	capResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      t.baseIndex,
		PropertyCount: nvHandleQueryCount,
	}.Execute(t.tpm)

	if err != nil {
		return nil, NewOperationError("query NV indices", err)
	}

	handles, err := capResp.CapabilityData.Data.Handles()
	if err != nil {
		return nil, NewOperationError("get NV handles", err)
	}

	var certIDs []string
	for _, handle := range handles.Handle {
		// Only include indices in our range
		if handle < tpm2.TPMHandle(t.baseIndex) || handle >= tpm2.TPMHandle(t.baseIndex+certIndexSpan) {
			continue
		}

		// Read the record back to recover the certificate ID. Indices that
		// cannot be read belong to another subsystem, not to this storage.
		data, err := t.readNVIndex(uint32(handle))
		if err != nil {
			continue
		}

		// A record without the required ID header was not written by this
		// storage -- every record it writes carries one -- so it belongs to
		// another subsystem sharing the NV index range, exactly like an
		// index that cannot be read at all.
		recordID, payload, ok := decodeCertRecord(data)
		if !ok {
			continue
		}

		// A chain record is not a certificate: the certificate reads treat
		// it as absent, so listing it would hand a caller a key it cannot
		// read. ListCerts lists certificate records only, as it does on
		// every other store.
		if recordIsChain(payload) {
			continue
		}

		certIDs = append(certIDs, recordID)
	}

	return certIDs, nil
}

// Ensure interface compliance at compile time
var _ HardwareCertStorage = (*TPM2CertStorage)(nil)
