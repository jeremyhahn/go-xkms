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

// Package module provides PKCS#11 (Cryptoki) v3.0 PIV integration.
//
// This file implements PIV (Personal Identity Verification) certificate and key
// discovery for the PKCS#11 module. It bridges PIV slots from backends into
// PKCS#11 objects, enabling standard PKCS#11 clients to access PIV credentials.
//
// For each occupied PIV slot, LoadPIVObjects creates three linked PKCS#11 objects:
//   - CKO_CERTIFICATE with the DER-encoded X.509 certificate
//   - CKO_PUBLIC_KEY with the extracted public key components
//   - CKO_PRIVATE_KEY as a handle for signing/decryption operations
//
// All three objects share the same CKA_ID (SHA-256 of the public key, truncated
// to 20 bytes), following standard PIV-to-PKCS#11 mapping conventions.
//
// References:
//   - NIST SP 800-73-4: Interfaces for Personal Identity Verification
//   - OASIS PKCS#11 v3.0: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html
package module

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// CKC_X_509 is the PKCS#11 certificate type for X.509 certificates.
// Reference: OASIS PKCS#11 Base Specification v3.0, Section 4.6.2
const CKC_X_509 uint32 = 0x00000000

// PIV-specific typed errors.
var (
	// ErrPIVListSlots indicates failure to list PIV slots from the backend.
	ErrPIVListSlots = errors.New("pkcs11/module: failed to list PIV slots")

	// ErrPIVGetCertificate indicates failure to retrieve a PIV certificate.
	ErrPIVGetCertificate = errors.New("pkcs11/module: failed to get PIV certificate")

	// ErrPIVParseCertificate indicates failure to parse a PIV certificate.
	ErrPIVParseCertificate = errors.New("pkcs11/module: failed to parse PIV certificate")

	// ErrPIVUnsupportedKeyType indicates the PIV certificate contains an unsupported key type.
	ErrPIVUnsupportedKeyType = errors.New("pkcs11/module: unsupported PIV key type")

	// ErrPIVAddObject indicates failure to add a PIV object to the object manager.
	ErrPIVAddObject = errors.New("pkcs11/module: failed to add PIV object")

	// ErrPIVEmptyBackend indicates an empty backend name was provided.
	ErrPIVEmptyBackend = errors.New("pkcs11/module: backend name is required")

	// ErrPIVGenerateKey indicates failure to generate a PIV key pair.
	ErrPIVGenerateKey = errors.New("pkcs11/module: failed to generate PIV key")

	// ErrPIVNilClient indicates the transport client is nil.
	ErrPIVNilClient = errors.New("pkcs11/module: transport client is nil")

	// ErrPIVNilObjectManager indicates the object manager is nil.
	ErrPIVNilObjectManager = errors.New("pkcs11/module: object manager is nil")

	// ErrPIVStoreCertificate indicates failure to store a PIV certificate.
	ErrPIVStoreCertificate = errors.New("pkcs11/module: failed to store PIV certificate")

	// ErrPIVDeleteCertificate indicates failure to delete a PIV certificate.
	ErrPIVDeleteCertificate = errors.New("pkcs11/module: failed to delete PIV certificate")

	// ErrPIVImportCertificate indicates failure to import a PIV certificate.
	ErrPIVImportCertificate = errors.New("pkcs11/module: failed to import PIV certificate")

	// ErrPIVExportCertificate indicates failure to export a PIV certificate.
	ErrPIVExportCertificate = errors.New("pkcs11/module: failed to export PIV certificate")

	// ErrPIVGenerateCSR indicates failure to generate a PIV CSR.
	ErrPIVGenerateCSR = errors.New("pkcs11/module: failed to generate PIV CSR")

	// ErrPIVEmptySlot indicates an empty slot name was provided.
	ErrPIVEmptySlot = errors.New("pkcs11/module: slot name is required")
)

// pivKeyInfo holds extracted key type information for PKCS#11 object creation.
type pivKeyInfo struct {
	keyType    KeyType
	attributes map[AttributeType][]byte
}

// pivKeyExtractor is a function type for extracting key info from a public key.
type pivKeyExtractor func(pubKey interface{}) (*pivKeyInfo, error)

// pivKeyExtractors provides O(1) dispatch for key type extraction.
var pivKeyExtractors = map[string]pivKeyExtractor{
	"*rsa.PublicKey":    extractRSAKeyInfo,
	"*ecdsa.PublicKey":  extractECDSAKeyInfo,
	"ed25519.PublicKey": extractEd25519KeyInfo,
}

// extractRSAKeyInfo extracts PKCS#11 attributes from an RSA public key.
func extractRSAKeyInfo(pubKey interface{}) (*pivKeyInfo, error) {
	rsaKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrPIVUnsupportedKeyType
	}
	modBytes := rsaKey.N.Bytes()
	expBytes := big.NewInt(int64(rsaKey.E)).Bytes()
	modulusBits := make([]byte, 4)
	binary.LittleEndian.PutUint32(modulusBits, uint32(rsaKey.N.BitLen()))

	return &pivKeyInfo{
		keyType: CKK_RSA,
		attributes: map[AttributeType][]byte{
			CKA_MODULUS:         modBytes,
			CKA_PUBLIC_EXPONENT: expBytes,
			CKA_MODULUS_BITS:    modulusBits,
		},
	}, nil
}

// extractECDSAKeyInfo extracts PKCS#11 attributes from an ECDSA public key.
func extractECDSAKeyInfo(pubKey interface{}) (*pivKeyInfo, error) {
	ecKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrPIVUnsupportedKeyType
	}

	ecPoint, err := ecKey.Bytes()
	if err != nil {
		return nil, ErrPIVUnsupportedKeyType
	}
	ecPointDER, err := asn1.Marshal(ecPoint)
	if err != nil {
		return nil, ErrPIVUnsupportedKeyType
	}

	ecParams, err := marshalECCurveOID(ecKey.Curve)
	if err != nil {
		return nil, ErrPIVUnsupportedKeyType
	}

	return &pivKeyInfo{
		keyType: CKK_EC,
		attributes: map[AttributeType][]byte{
			CKA_EC_POINT:  ecPointDER,
			CKA_EC_PARAMS: ecParams,
		},
	}, nil
}

// extractEd25519KeyInfo extracts PKCS#11 attributes from an Ed25519 public key.
func extractEd25519KeyInfo(pubKey interface{}) (*pivKeyInfo, error) {
	edKey, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		return nil, ErrPIVUnsupportedKeyType
	}
	ecPointDER, err := asn1.Marshal([]byte(edKey))
	if err != nil {
		return nil, ErrPIVUnsupportedKeyType
	}

	return &pivKeyInfo{
		keyType: CKK_EC_EDWARDS,
		attributes: map[AttributeType][]byte{
			CKA_EC_POINT: ecPointDER,
		},
	}, nil
}

// ecCurveOIDs maps elliptic curves to their DER-encoded ASN.1 OIDs.
var ecCurveOIDs = map[elliptic.Curve]asn1.ObjectIdentifier{
	elliptic.P224(): {1, 3, 132, 0, 33},
	elliptic.P256(): {1, 2, 840, 10045, 3, 1, 7},
	elliptic.P384(): {1, 3, 132, 0, 34},
	elliptic.P521(): {1, 3, 132, 0, 35},
}

// marshalECCurveOID returns the DER-encoded ASN.1 OID for the given curve.
func marshalECCurveOID(curve elliptic.Curve) ([]byte, error) {
	oid, ok := ecCurveOIDs[curve]
	if !ok {
		return nil, ErrPIVUnsupportedKeyType
	}
	return asn1.Marshal(oid)
}

// computePIVObjectID computes the CKA_ID for PIV objects.
// Uses SHA-256 of the raw public key bytes, truncated to 20 bytes,
// consistent with standard PIV-to-PKCS#11 mapping.
func computePIVObjectID(cert *x509.Certificate) []byte {
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hash[:20]
}

// extractPIVKeyInfo extracts key type and attributes from a certificate's public key.
func extractPIVKeyInfo(cert *x509.Certificate) (*pivKeyInfo, error) {
	pubKey := cert.PublicKey
	typeName := publicKeyTypeName(pubKey)
	extractor, ok := pivKeyExtractors[typeName]
	if !ok {
		return nil, ErrPIVUnsupportedKeyType
	}
	return extractor(pubKey)
}

// publicKeyTypeName returns a string identifier for the public key type.
// Used for map-based dispatch instead of type switch.
func publicKeyTypeName(pubKey interface{}) string {
	switch pubKey.(type) {
	case *rsa.PublicKey:
		return "*rsa.PublicKey"
	case *ecdsa.PublicKey:
		return "*ecdsa.PublicKey"
	case ed25519.PublicKey:
		return "ed25519.PublicKey"
	default:
		return ""
	}
}

// LoadPIVObjects discovers PIV certificates from a backend and creates PKCS#11 objects.
// For each occupied PIV slot, it creates:
//   - CKO_CERTIFICATE with CKA_VALUE = DER cert, CKA_LABEL = "piv:{slot}", CKA_ID = SHA-256(pubkey)[:20]
//   - CKO_PUBLIC_KEY with CKA_LABEL = "piv:{slot}", CKA_ID = SHA-256(pubkey)[:20]
//   - CKO_PRIVATE_KEY with CKA_LABEL = "piv:{slot}", CKA_ID = SHA-256(pubkey)[:20]
//
// The private key object is a handle -- actual cryptographic operations route through
// the transport.Client using the Object's KeyID ("piv/{slot}") and BackendName.
func (m *Module) LoadPIVObjects(ctx context.Context, backend string) error {
	if backend == "" {
		return ErrPIVEmptyBackend
	}
	if m.client == nil {
		return ErrPIVNilClient
	}
	if m.objectManager == nil {
		return ErrPIVNilObjectManager
	}

	slotsResp, err := m.client.ListPIVSlots(ctx, &transport.ListPIVSlotsRequest{
		Backend: backend,
	})
	if err != nil {
		return ErrPIVListSlots
	}

	for i := range slotsResp.Slots {
		slot := &slotsResp.Slots[i]
		if !slot.HasCert {
			continue
		}

		if err := m.loadPIVSlotObjects(ctx, backend, slot); err != nil {
			return err
		}
	}

	return nil
}

// loadPIVSlotObjects creates the three PKCS#11 objects for a single occupied PIV slot.
func (m *Module) loadPIVSlotObjects(ctx context.Context, backend string, slot *transport.PIVSlotStatus) error {
	certResp, err := m.client.GetPIVCertificate(ctx, &transport.GetPIVCertificateRequest{
		Backend: backend,
		Slot:    slot.Slot,
		Format:  "der",
	})
	if err != nil {
		return ErrPIVGetCertificate
	}

	cert, err := x509.ParseCertificate(certResp.Certificate)
	if err != nil {
		return ErrPIVParseCertificate
	}

	keyInfo, err := extractPIVKeyInfo(cert)
	if err != nil {
		return err
	}

	ckaID := computePIVObjectID(cert)
	label := "piv:" + slot.Slot
	keyID := "piv/" + slot.Slot

	if err := m.addPIVCertificateObject(cert, ckaID, label, backend, keyID); err != nil {
		return err
	}

	if err := m.addPIVPublicKeyObject(keyInfo, ckaID, label, backend, keyID); err != nil {
		return err
	}

	if err := m.addPIVPrivateKeyObject(keyInfo, ckaID, label, backend, keyID); err != nil {
		return err
	}

	return nil
}

// addPIVCertificateObject creates a CKO_CERTIFICATE object from a PIV certificate.
func (m *Module) addPIVCertificateObject(cert *x509.Certificate, ckaID []byte, label, backend, keyID string) error {
	obj := NewObject(CKO_CERTIFICATE)
	obj.KeyID = keyID
	obj.BackendName = backend
	obj.IsToken = true

	obj.SetAttribute(CKA_CERTIFICATE_TYPE, NewUint32Attribute(CKA_CERTIFICATE_TYPE, CKC_X_509).Value)
	obj.SetAttribute(CKA_VALUE, cert.Raw)
	obj.SetAttribute(CKA_LABEL, []byte(label))
	obj.SetAttribute(CKA_ID, ckaID)
	obj.SetAttribute(CKA_SUBJECT, cert.RawSubject)
	obj.SetAttribute(CKA_ISSUER, cert.RawIssuer)

	serialBytes, err := asn1.Marshal(cert.SerialNumber)
	if err == nil {
		obj.SetAttribute(CKA_SERIAL_NUMBER, serialBytes)
	}

	obj.SetAttribute(CKA_TOKEN, []byte{1})
	obj.SetAttribute(CKA_PRIVATE, []byte{0})

	if err := m.objectManager.AddObject(obj); err != nil {
		return ErrPIVAddObject
	}
	return nil
}

// addPIVPublicKeyObject creates a CKO_PUBLIC_KEY object from a PIV certificate's public key.
func (m *Module) addPIVPublicKeyObject(keyInfo *pivKeyInfo, ckaID []byte, label, backend, keyID string) error {
	obj := NewKeyObject(CKO_PUBLIC_KEY, keyInfo.keyType)
	obj.KeyID = keyID
	obj.BackendName = backend
	obj.IsToken = true

	obj.SetAttribute(CKA_LABEL, []byte(label))
	obj.SetAttribute(CKA_ID, ckaID)
	obj.SetAttribute(CKA_TOKEN, []byte{1})
	obj.SetAttribute(CKA_PRIVATE, []byte{0})
	obj.SetAttribute(CKA_VERIFY, []byte{1})
	obj.SetAttribute(CKA_ENCRYPT, []byte{1})

	for attrType, attrValue := range keyInfo.attributes {
		obj.SetAttribute(attrType, attrValue)
	}

	if err := m.objectManager.AddObject(obj); err != nil {
		return ErrPIVAddObject
	}
	return nil
}

// addPIVPrivateKeyObject creates a CKO_PRIVATE_KEY handle object for a PIV slot.
// This object does not contain key material; cryptographic operations are delegated
// to the backend via the transport.Client using KeyID and BackendName.
func (m *Module) addPIVPrivateKeyObject(keyInfo *pivKeyInfo, ckaID []byte, label, backend, keyID string) error {
	obj := NewKeyObject(CKO_PRIVATE_KEY, keyInfo.keyType)
	obj.KeyID = keyID
	obj.BackendName = backend
	obj.IsToken = true
	obj.IsPrivate = true
	obj.IsSensitive = true

	obj.SetAttribute(CKA_LABEL, []byte(label))
	obj.SetAttribute(CKA_ID, ckaID)
	obj.SetAttribute(CKA_TOKEN, []byte{1})
	obj.SetAttribute(CKA_PRIVATE, []byte{1})
	obj.SetAttribute(CKA_SENSITIVE, []byte{1})
	obj.SetAttribute(CKA_SIGN, []byte{1})
	obj.SetAttribute(CKA_DECRYPT, []byte{1})
	obj.SetAttribute(CKA_EXTRACTABLE, []byte{0})
	obj.SetAttribute(CKA_NEVER_EXTRACTABLE, []byte{1})
	obj.SetAttribute(CKA_ALWAYS_SENSITIVE, []byte{1})

	for attrType, attrValue := range keyInfo.attributes {
		// Skip value-related attributes for private key objects
		if attrType == CKA_MODULUS || attrType == CKA_PUBLIC_EXPONENT ||
			attrType == CKA_EC_POINT || attrType == CKA_EC_PARAMS ||
			attrType == CKA_MODULUS_BITS {
			obj.SetAttribute(attrType, attrValue)
		}
	}

	if err := m.objectManager.AddObject(obj); err != nil {
		return ErrPIVAddObject
	}
	return nil
}

// GeneratePIVKeyPair generates a key pair in a PIV slot via the transport client,
// then creates the corresponding PKCS#11 objects. This is used when
// C_GenerateKeyPair is called with a CKA_LABEL starting with "piv:".
func (m *Module) GeneratePIVKeyPair(ctx context.Context, backend, slot, algorithm, subject string) (ObjectHandle, ObjectHandle, error) {
	if backend == "" {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), ErrPIVEmptyBackend
	}
	if m.client == nil {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), ErrPIVNilClient
	}
	if m.objectManager == nil {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), ErrPIVNilObjectManager
	}

	resp, err := m.client.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{
		Backend:   backend,
		Slot:      slot,
		Algorithm: algorithm,
		Subject:   subject,
	})
	if err != nil {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), ErrPIVGenerateKey
	}

	// Parse the self-signed certificate returned by the PIV backend.
	cert, err := x509.ParseCertificate(resp.Certificate)
	if err != nil {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), ErrPIVParseCertificate
	}

	keyInfo, err := extractPIVKeyInfo(cert)
	if err != nil {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), err
	}

	ckaID := computePIVObjectID(cert)
	label := "piv:" + slot
	keyID := "piv/" + slot

	// Create public key object and capture its handle.
	pubObj := NewKeyObject(CKO_PUBLIC_KEY, keyInfo.keyType)
	pubObj.KeyID = keyID
	pubObj.BackendName = backend
	pubObj.IsToken = true
	pubObj.SetAttribute(CKA_LABEL, []byte(label))
	pubObj.SetAttribute(CKA_ID, ckaID)
	pubObj.SetAttribute(CKA_TOKEN, []byte{1})
	pubObj.SetAttribute(CKA_PRIVATE, []byte{0})
	pubObj.SetAttribute(CKA_VERIFY, []byte{1})
	pubObj.SetAttribute(CKA_ENCRYPT, []byte{1})
	for attrType, attrValue := range keyInfo.attributes {
		pubObj.SetAttribute(attrType, attrValue)
	}
	if err := m.objectManager.AddObject(pubObj); err != nil {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), ErrPIVAddObject
	}

	// Create private key object and capture its handle.
	privObj := NewKeyObject(CKO_PRIVATE_KEY, keyInfo.keyType)
	privObj.KeyID = keyID
	privObj.BackendName = backend
	privObj.IsToken = true
	privObj.IsPrivate = true
	privObj.IsSensitive = true
	privObj.SetAttribute(CKA_LABEL, []byte(label))
	privObj.SetAttribute(CKA_ID, ckaID)
	privObj.SetAttribute(CKA_TOKEN, []byte{1})
	privObj.SetAttribute(CKA_PRIVATE, []byte{1})
	privObj.SetAttribute(CKA_SENSITIVE, []byte{1})
	privObj.SetAttribute(CKA_SIGN, []byte{1})
	privObj.SetAttribute(CKA_DECRYPT, []byte{1})
	privObj.SetAttribute(CKA_EXTRACTABLE, []byte{0})
	privObj.SetAttribute(CKA_NEVER_EXTRACTABLE, []byte{1})
	privObj.SetAttribute(CKA_ALWAYS_SENSITIVE, []byte{1})
	for attrType, attrValue := range keyInfo.attributes {
		if attrType == CKA_MODULUS || attrType == CKA_PUBLIC_EXPONENT ||
			attrType == CKA_EC_POINT || attrType == CKA_EC_PARAMS ||
			attrType == CKA_MODULUS_BITS {
			privObj.SetAttribute(attrType, attrValue)
		}
	}
	if err := m.objectManager.AddObject(privObj); err != nil {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), ErrPIVAddObject
	}

	// Also create the certificate object.
	if err := m.addPIVCertificateObject(cert, ckaID, label, backend, keyID); err != nil {
		return ObjectHandle(InvalidHandle), ObjectHandle(InvalidHandle), err
	}

	return pubObj.Handle, privObj.Handle, nil
}

// StorePIVCertificate stores a certificate in a PIV slot via the transport client,
// then creates the corresponding PKCS#11 objects for the new certificate.
func (m *Module) StorePIVCertificate(ctx context.Context, backend, slot string, certDER []byte) error {
	if backend == "" {
		return ErrPIVEmptyBackend
	}
	if slot == "" {
		return ErrPIVEmptySlot
	}
	if m.client == nil {
		return ErrPIVNilClient
	}
	if m.objectManager == nil {
		return ErrPIVNilObjectManager
	}

	if err := m.client.StorePIVCertificate(ctx, &transport.StorePIVCertificateRequest{
		Backend:     backend,
		Slot:        slot,
		Certificate: certDER,
		Format:      "der",
	}); err != nil {
		return ErrPIVStoreCertificate
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return ErrPIVParseCertificate
	}

	keyInfo, err := extractPIVKeyInfo(cert)
	if err != nil {
		return err
	}

	ckaID := computePIVObjectID(cert)
	label := "piv:" + slot
	keyID := "piv/" + slot

	if err := m.addPIVCertificateObject(cert, ckaID, label, backend, keyID); err != nil {
		return err
	}

	if err := m.addPIVPublicKeyObject(keyInfo, ckaID, label, backend, keyID); err != nil {
		return err
	}

	if err := m.addPIVPrivateKeyObject(keyInfo, ckaID, label, backend, keyID); err != nil {
		return err
	}

	return nil
}

// DeletePIVCertificate removes a PIV certificate from a slot via the transport client
// and removes all corresponding PKCS#11 objects (certificate, public key, private key).
// The PKCS#11 object store is refreshed on the next LoadPIVObjects call.
func (m *Module) DeletePIVCertificate(ctx context.Context, backend, slot string) error {
	if backend == "" {
		return ErrPIVEmptyBackend
	}
	if slot == "" {
		return ErrPIVEmptySlot
	}
	if m.client == nil {
		return ErrPIVNilClient
	}
	if m.objectManager == nil {
		return ErrPIVNilObjectManager
	}

	if err := m.client.DeletePIVCertificate(ctx, &transport.DeletePIVCertificateRequest{
		Backend: backend,
		Slot:    slot,
	}); err != nil {
		return ErrPIVDeleteCertificate
	}

	return nil
}

// ImportPIVCertificate imports an externally issued certificate into a PIV slot via the
// transport client, then creates the corresponding PKCS#11 objects.
func (m *Module) ImportPIVCertificate(ctx context.Context, backend, slot string, certDER []byte) error {
	if backend == "" {
		return ErrPIVEmptyBackend
	}
	if slot == "" {
		return ErrPIVEmptySlot
	}
	if m.client == nil {
		return ErrPIVNilClient
	}
	if m.objectManager == nil {
		return ErrPIVNilObjectManager
	}

	if err := m.client.ImportPIVCertificate(ctx, &transport.StorePIVCertificateRequest{
		Backend:     backend,
		Slot:        slot,
		Certificate: certDER,
		Format:      "der",
	}); err != nil {
		return ErrPIVImportCertificate
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return ErrPIVParseCertificate
	}

	keyInfo, err := extractPIVKeyInfo(cert)
	if err != nil {
		return err
	}

	ckaID := computePIVObjectID(cert)
	label := "piv:" + slot
	keyID := "piv/" + slot

	if err := m.addPIVCertificateObject(cert, ckaID, label, backend, keyID); err != nil {
		return err
	}

	if err := m.addPIVPublicKeyObject(keyInfo, ckaID, label, backend, keyID); err != nil {
		return err
	}

	if err := m.addPIVPrivateKeyObject(keyInfo, ckaID, label, backend, keyID); err != nil {
		return err
	}

	return nil
}

// ExportPIVCertificate exports the certificate from a PIV slot in the requested format.
func (m *Module) ExportPIVCertificate(ctx context.Context, backend, slot, format string) ([]byte, error) {
	if backend == "" {
		return nil, ErrPIVEmptyBackend
	}
	if slot == "" {
		return nil, ErrPIVEmptySlot
	}
	if m.client == nil {
		return nil, ErrPIVNilClient
	}

	resp, err := m.client.ExportPIVCertificate(ctx, &transport.GetPIVCertificateRequest{
		Backend: backend,
		Slot:    slot,
		Format:  format,
	})
	if err != nil {
		return nil, ErrPIVExportCertificate
	}

	return resp.Certificate, nil
}

// GeneratePIVCSR generates a certificate signing request for a PIV slot key.
func (m *Module) GeneratePIVCSR(ctx context.Context, backend, slot, subject string) ([]byte, error) {
	if backend == "" {
		return nil, ErrPIVEmptyBackend
	}
	if slot == "" {
		return nil, ErrPIVEmptySlot
	}
	if m.client == nil {
		return nil, ErrPIVNilClient
	}

	resp, err := m.client.GeneratePIVCSR(ctx, &transport.GeneratePIVCSRRequest{
		Backend: backend,
		Slot:    slot,
		Subject: subject,
	})
	if err != nil {
		return nil, ErrPIVGenerateCSR
	}

	return resp.CSR, nil
}
