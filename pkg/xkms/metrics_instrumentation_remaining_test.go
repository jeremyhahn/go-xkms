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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// This file covers the go-xkms#720 follow-up (go-xkms#825): the remaining
// KeyServicer and CryptoServicer methods instrumented in
// pkg/xkms/metrics_instrumentation.go, servicer_key.go and servicer_crypto.go
// -- CopyKey, WrapKey, UnwrapKey, WrapKeyByID, UnwrapKeyByID,
// ExportKeyMaterial, GetImportParameters, DeriveKey, DeriveKeyECDH, and
// AttestKey. It reuses setupKeyOpsService/keyOpsService and the capability
// providers from servicer_keyops_test.go (a full backend.ImportExportBackend
// double, a raw-material-releasing provider, an attesting provider, and a key
// -agreement provider), and counterValue/histogramSampleCount/gaugeValue from
// metrics_instrumentation_test.go.

// ===========================================================================
// CopyKey
// ===========================================================================

// TestServiceBoundary_CopyKey_RecordsOperationAndIncrementsKeysTotal asserts
// CopyKey is metered under the destination backend -- where the copy's
// effect lands -- and that a successful copy increments that backend's
// keys-total gauge by a direct Inc(), the same contract GenerateKey/ImportKey
// already hold.
func TestServiceBoundary_CopyKey_RecordsOperationAndIncrementsKeysTotal(t *testing.T) {
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{
		"src-be": newBoostIEKeyProvider(),
		"dst-be": newBoostIEKeyProvider(),
	})
	addKeyOpsKey(t, stores["src-be"], &types.KeyAttributes{CN: "src-key", KeyAlgorithm: x509.ECDSA})
	svc := keyOpsService(t)
	metrics.Enable()

	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpCopyKey, "dst-be", metrics.StatusSuccess)
	beforeSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpCopyKey, "dst-be")
	beforeKeys := gaugeValue(t, metrics.KeysTotal, "dst-be")

	resp, err := svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceBackend: "src-be",
		SourceKeyID:   "src-key",
		DestBackend:   "dst-be",
		DestKeyID:     "dst-key",
	})
	require.NoError(t, err)
	require.True(t, resp.Success)

	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpCopyKey, "dst-be", metrics.StatusSuccess)
	afterSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpCopyKey, "dst-be")
	afterKeys := gaugeValue(t, metrics.KeysTotal, "dst-be")

	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{operation=copy_key,backend=dst-be,status=success}")
	assert.Equal(t, beforeSamples+1, afterSamples, "xkms_operation_duration_seconds sample count")
	assert.Equal(t, beforeKeys+1, afterKeys, "xkms_keys_total{backend=dst-be}")
}

// TestServiceBoundary_CopyKey_NoListKeysCallOnDestination asserts the
// destination gauge update costs zero ListKeys calls on the destination
// backend: CopyKey increments it directly rather than recounting by listing
// (go-xkms#720 follow-up).
func TestServiceBoundary_CopyKey_NoListKeysCallOnDestination(t *testing.T) {
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{
		"src-be": newBoostIEKeyProvider(),
		"dst-be": newBoostIEKeyProvider(),
	})
	addKeyOpsKey(t, stores["src-be"], &types.KeyAttributes{CN: "src-key", KeyAlgorithm: x509.ECDSA})
	svc := keyOpsService(t)

	counting := &countingBackend{Backend: stores["dst-be"]}
	require.NoError(t, RegisterServiceBackend("dst-be", counting))

	_, err := svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceBackend: "src-be",
		SourceKeyID:   "src-key",
		DestBackend:   "dst-be",
		DestKeyID:     "dst-key",
	})
	require.NoError(t, err)

	assert.Equal(t, 0, counting.listKeysCalls)
}

// TestServiceBoundary_CopyKey_RecordsError asserts a destination backend that
// cannot import (no backend.ImportExportBackend) still records the failed
// attempt under the destination backend label.
func TestServiceBoundary_CopyKey_RecordsError(t *testing.T) {
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"src-be": newBoostIEKeyProvider()})
	addKeyOpsKey(t, stores["src-be"], &types.KeyAttributes{CN: "src-key", KeyAlgorithm: x509.ECDSA})
	svc := keyOpsService(t)
	metrics.Enable()

	wantErrType := errorTypeLabel(&ErrBackendUnsupported{})
	beforeErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpCopyKey, "software", wantErrType)
	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpCopyKey, "software", metrics.StatusError)

	_, err := svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
		SourceBackend: "src-be",
		SourceKeyID:   "src-key",
		DestBackend:   "software", // capability-free: cannot import
		DestKeyID:     "dst-key",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))

	afterErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpCopyKey, "software", wantErrType)
	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpCopyKey, "software", metrics.StatusError)

	assert.Equal(t, beforeErrors+1, afterErrors, "xkms_errors_total")
	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{status=error}")
}

// ===========================================================================
// WrapKey
// ===========================================================================

func TestServiceBoundary_WrapKey_RecordsOperation(t *testing.T) {
	provider := newBoostIEKeyProvider()
	setupKeyOpsService(t, map[string]types.KeyProvider{"wrap-be": provider})
	svc := keyOpsService(t)
	metrics.Enable()

	pubDER, err := x509.MarshalPKIXPublicKey(&provider.wrappingKey.PublicKey)
	require.NoError(t, err)

	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpWrapKey, "wrap-be", metrics.StatusSuccess)
	beforeSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpWrapKey, "wrap-be")

	resp, err := svc.WrapKey(context.Background(), &transport.WrapKeyRequest{
		Backend:           "wrap-be",
		KeyMaterial:       []byte("plaintext-key-bytes"),
		WrappingPublicKey: pubDER,
		Algorithm:         string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.WrappedKeyMaterial)

	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpWrapKey, "wrap-be", metrics.StatusSuccess)
	afterSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpWrapKey, "wrap-be")

	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{operation=wrap_key,backend=wrap-be,status=success}")
	assert.Equal(t, beforeSamples+1, afterSamples, "xkms_operation_duration_seconds sample count")
}

func TestServiceBoundary_WrapKey_RecordsError(t *testing.T) {
	setupKeyOpsService(t, nil)
	svc := keyOpsService(t)
	metrics.Enable()

	wantErrType := errorTypeLabel(&ErrBackendUnsupported{})
	beforeErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpWrapKey, "software", wantErrType)
	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpWrapKey, "software", metrics.StatusError)

	_, err := svc.WrapKey(context.Background(), &transport.WrapKeyRequest{
		Backend:     "software", // capability-free: no ImportExportBackend
		KeyMaterial: []byte("plaintext-key-bytes"),
		Algorithm:   string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))

	afterErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpWrapKey, "software", wantErrType)
	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpWrapKey, "software", metrics.StatusError)

	assert.Equal(t, beforeErrors+1, afterErrors, "xkms_errors_total")
	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{status=error}")
}

// ===========================================================================
// UnwrapKey
// ===========================================================================

func TestServiceBoundary_UnwrapKey_RecordsOperation(t *testing.T) {
	provider := newBoostIEKeyProvider()
	setupKeyOpsService(t, map[string]types.KeyProvider{"wrap-be": provider})
	svc := keyOpsService(t)
	metrics.Enable()

	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpUnwrapKey, "wrap-be", metrics.StatusSuccess)
	beforeSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpUnwrapKey, "wrap-be")

	resp, err := svc.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{
		Backend:            "wrap-be",
		WrappedKeyMaterial: []byte("wrapped-blob"),
		Algorithm:          string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.KeyMaterial)

	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpUnwrapKey, "wrap-be", metrics.StatusSuccess)
	afterSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpUnwrapKey, "wrap-be")

	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{operation=unwrap_key,backend=wrap-be,status=success}")
	assert.Equal(t, beforeSamples+1, afterSamples, "xkms_operation_duration_seconds sample count")
}

func TestServiceBoundary_UnwrapKey_RecordsError(t *testing.T) {
	setupKeyOpsService(t, nil)
	svc := keyOpsService(t)
	metrics.Enable()

	wantErrType := errorTypeLabel(&ErrBackendUnsupported{})
	beforeErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpUnwrapKey, "software", wantErrType)
	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpUnwrapKey, "software", metrics.StatusError)

	_, err := svc.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{
		Backend:            "software", // capability-free: no ImportExportBackend
		WrappedKeyMaterial: []byte("wrapped-blob"),
		Algorithm:          string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))

	afterErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpUnwrapKey, "software", wantErrType)
	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpUnwrapKey, "software", metrics.StatusError)

	assert.Equal(t, beforeErrors+1, afterErrors, "xkms_errors_total")
	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{status=error}")
}

// ===========================================================================
// WrapKeyByID
// ===========================================================================

// TestServiceBoundary_WrapKeyByID_RecordsOperation asserts WrapKeyByID is
// metered under the wrapping key's backend -- the backend that does the
// cryptographic work -- symmetric with how Sign/Verify/Encrypt/Decrypt meter
// the backend holding the operating key.
func TestServiceBoundary_WrapKeyByID_RecordsOperation(t *testing.T) {
	target := newMaterialProvider([]byte("target-key-material"))
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"target-be": target, "kek-be": nil})
	addKeyOpsKey(t, stores["target-be"], &types.KeyAttributes{
		CN: "target-key", KeyType: types.KeyTypeSecret, SymmetricAlgorithm: types.SymmetricAES256GCM, Exportable: true,
	})
	addKeyOpsRSAKey(t, stores["kek-be"], &types.KeyAttributes{CN: "kek"})
	svc := keyOpsService(t)
	metrics.Enable()

	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpWrapKeyByID, "kek-be", metrics.StatusSuccess)
	beforeSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpWrapKeyByID, "kek-be")

	resp, err := svc.WrapKeyByID(context.Background(), &transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "kek-be",
		TargetKeyID:        "target-key",
		TargetKeyBackend:   "target-be",
		Algorithm:          string(types.WrapRSAOAEPSHA256),
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.WrappedKey)

	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpWrapKeyByID, "kek-be", metrics.StatusSuccess)
	afterSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpWrapKeyByID, "kek-be")

	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{operation=wrap_key_by_id,backend=kek-be,status=success}")
	assert.Equal(t, beforeSamples+1, afterSamples, "xkms_operation_duration_seconds sample count")
}

func TestServiceBoundary_WrapKeyByID_RecordsError(t *testing.T) {
	setupKeyOpsService(t, nil)
	svc := keyOpsService(t)
	metrics.Enable()

	wantErrType := errorTypeLabel(&ErrValidation{})
	beforeErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpWrapKeyByID, "software", wantErrType)
	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpWrapKeyByID, "software", metrics.StatusError)

	_, err := svc.WrapKeyByID(context.Background(), &transport.WrapKeyByIDRequest{
		WrappingKeyBackend: "software",
		// WrappingKeyID deliberately empty
		TargetKeyID:      "target",
		TargetKeyBackend: "software",
		Algorithm:        string(types.WrapAESKW),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingRequiredField))

	afterErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpWrapKeyByID, "software", wantErrType)
	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpWrapKeyByID, "software", metrics.StatusError)

	assert.Equal(t, beforeErrors+1, afterErrors, "xkms_errors_total")
	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{status=error}")
}

// ===========================================================================
// UnwrapKeyByID
// ===========================================================================

// TestServiceBoundary_UnwrapKeyByID_RecordsOperationAndIncrementsKeysTotal
// asserts UnwrapKeyByID is metered under the unwrapping key's backend (the
// backend that does the decrypt), while the keys-total gauge it also updates
// tracks the TARGET backend -- where the recovered key actually lands. The
// two need not be the same backend.
func TestServiceBoundary_UnwrapKeyByID_RecordsOperationAndIncrementsKeysTotal(t *testing.T) {
	targetProvider := newMaterialProvider([]byte("target-material"))
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"kek-be": nil, "target-be": targetProvider})
	kekKey := addKeyOpsRSAKey(t, stores["kek-be"], &types.KeyAttributes{CN: "kek"})
	svc := keyOpsService(t)
	metrics.Enable()

	plaintext := []byte("unwrapped-key-material-32-bytes")
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &kekKey.PublicKey, plaintext, nil)
	require.NoError(t, err)

	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpUnwrapKeyByID, "kek-be", metrics.StatusSuccess)
	beforeSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpUnwrapKeyByID, "kek-be")
	beforeKeys := gaugeValue(t, metrics.KeysTotal, "target-be")

	req := newUnwrapRequest()
	req.WrappedKey = wrapped
	resp, err := svc.UnwrapKeyByID(context.Background(), &req)
	require.NoError(t, err)
	require.True(t, resp.Success)

	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpUnwrapKeyByID, "kek-be", metrics.StatusSuccess)
	afterSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpUnwrapKeyByID, "kek-be")
	afterKeys := gaugeValue(t, metrics.KeysTotal, "target-be")

	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{operation=unwrap_key_by_id,backend=kek-be,status=success}")
	assert.Equal(t, beforeSamples+1, afterSamples, "xkms_operation_duration_seconds sample count")
	assert.Equal(t, beforeKeys+1, afterKeys, "xkms_keys_total{backend=target-be}")
}

// TestServiceBoundary_UnwrapKeyByID_NoListKeysCallOnTarget asserts the
// target-backend gauge update costs zero ListKeys calls on the target
// backend (go-xkms#720 follow-up).
func TestServiceBoundary_UnwrapKeyByID_NoListKeysCallOnTarget(t *testing.T) {
	targetProvider := newMaterialProvider([]byte("target-material"))
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"kek-be": nil, "target-be": targetProvider})
	kekKey := addKeyOpsRSAKey(t, stores["kek-be"], &types.KeyAttributes{CN: "kek"})
	svc := keyOpsService(t)

	counting := &countingBackend{Backend: stores["target-be"]}
	require.NoError(t, RegisterServiceBackend("target-be", counting))

	plaintext := []byte("unwrapped-key-material-32-bytes")
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &kekKey.PublicKey, plaintext, nil)
	require.NoError(t, err)

	req := newUnwrapRequest()
	req.WrappedKey = wrapped
	_, err = svc.UnwrapKeyByID(context.Background(), &req)
	require.NoError(t, err)

	assert.Equal(t, 0, counting.listKeysCalls)
}

func TestServiceBoundary_UnwrapKeyByID_RecordsError(t *testing.T) {
	setupKeyOpsService(t, nil)
	svc := keyOpsService(t)
	metrics.Enable()

	wantErrType := errorTypeLabel(&ErrValidation{})
	beforeErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpUnwrapKeyByID, "software", wantErrType)
	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpUnwrapKeyByID, "software", metrics.StatusError)

	req := newUnwrapRequest()
	req.UnwrappingKeyBackend = "software"
	req.UnwrappingKeyID = "" // trigger the required-field guard before any lookup
	_, err := svc.UnwrapKeyByID(context.Background(), &req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingRequiredField))

	afterErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpUnwrapKeyByID, "software", wantErrType)
	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpUnwrapKeyByID, "software", metrics.StatusError)

	assert.Equal(t, beforeErrors+1, afterErrors, "xkms_errors_total")
	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{status=error}")
}

// ===========================================================================
// ExportKeyMaterial
// ===========================================================================

func TestServiceBoundary_ExportKeyMaterial_RecordsOperation(t *testing.T) {
	material := []byte("0123456789abcdef0123456789abcdef")
	provider := newMaterialProvider(material)
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"hsm": provider})
	addKeyOpsKey(t, stores["hsm"], &types.KeyAttributes{
		CN:                 "aes-key",
		KeyType:            types.KeyTypeSecret,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	})
	svc := keyOpsService(t)
	metrics.Enable()

	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpExportKeyMaterial, "hsm", metrics.StatusSuccess)
	beforeSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpExportKeyMaterial, "hsm")

	resp, err := svc.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{
		KeyID:   "aes-key",
		Backend: "hsm",
	})
	require.NoError(t, err)
	assert.Equal(t, material, resp.KeyMaterial)

	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpExportKeyMaterial, "hsm", metrics.StatusSuccess)
	afterSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpExportKeyMaterial, "hsm")

	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{operation=export_key_material,backend=hsm,status=success}")
	assert.Equal(t, beforeSamples+1, afterSamples, "xkms_operation_duration_seconds sample count")
}

func TestServiceBoundary_ExportKeyMaterial_RecordsError(t *testing.T) {
	setupKeyOpsService(t, nil)
	svc := keyOpsService(t)
	metrics.Enable()

	wantErrType := errorTypeLabel(&ErrValidation{})
	beforeErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpExportKeyMaterial, "software", wantErrType)
	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpExportKeyMaterial, "software", metrics.StatusError)

	_, err := svc.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{
		Backend: "software", // key_id deliberately empty
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingRequiredField))

	afterErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpExportKeyMaterial, "software", wantErrType)
	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpExportKeyMaterial, "software", metrics.StatusError)

	assert.Equal(t, beforeErrors+1, afterErrors, "xkms_errors_total")
	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{status=error}")
}

// ===========================================================================
// GetImportParameters
// ===========================================================================

func TestServiceBoundary_GetImportParameters_RecordsOperation(t *testing.T) {
	provider := newBoostIEKeyProvider()
	setupKeyOpsService(t, map[string]types.KeyProvider{"wrap-be": provider})
	svc := keyOpsService(t)
	metrics.Enable()

	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpGetImportParameters, "wrap-be", metrics.StatusSuccess)
	beforeSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpGetImportParameters, "wrap-be")

	resp, err := svc.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{
		Backend:   "wrap-be",
		KeyID:     "future-key",
		Algorithm: string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.WrappingPublicKey)

	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpGetImportParameters, "wrap-be", metrics.StatusSuccess)
	afterSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpGetImportParameters, "wrap-be")

	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{operation=get_import_parameters,backend=wrap-be,status=success}")
	assert.Equal(t, beforeSamples+1, afterSamples, "xkms_operation_duration_seconds sample count")
}

func TestServiceBoundary_GetImportParameters_RecordsError(t *testing.T) {
	setupKeyOpsService(t, nil)
	svc := keyOpsService(t)
	metrics.Enable()

	wantErrType := errorTypeLabel(&ErrBackendUnsupported{})
	beforeErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpGetImportParameters, "software", wantErrType)
	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpGetImportParameters, "software", metrics.StatusError)

	_, err := svc.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{
		Backend:   "software", // capability-free: no ImportExportBackend
		KeyID:     "future-key",
		Algorithm: string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))

	afterErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpGetImportParameters, "software", wantErrType)
	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpGetImportParameters, "software", metrics.StatusError)

	assert.Equal(t, beforeErrors+1, afterErrors, "xkms_errors_total")
	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{status=error}")
}

// ===========================================================================
// DeriveKey
// ===========================================================================

func TestServiceBoundary_DeriveKey_RecordsOperation(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	metrics.Enable()

	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpDeriveKey, "software", metrics.StatusSuccess)
	beforeSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpDeriveKey, "software")

	resp, err := svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Algorithm:        "hkdf",
		InputKeyMaterial: []byte("secret-input-key-material-32byte"),
		KeyLength:        32,
		Hash:             "SHA-256",
	})
	require.NoError(t, err)
	assert.Len(t, resp.DerivedKey, 32)

	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpDeriveKey, "software", metrics.StatusSuccess)
	afterSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpDeriveKey, "software")

	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{operation=derive_key,backend=software,status=success}")
	assert.Equal(t, beforeSamples+1, afterSamples, "xkms_operation_duration_seconds sample count")
}

func TestServiceBoundary_DeriveKey_RecordsError(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	metrics.Enable()

	wantErrType := errorTypeLabel(&ErrValidation{})
	beforeErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpDeriveKey, "software", wantErrType)
	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpDeriveKey, "software", metrics.StatusError)

	_, err = svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Algorithm: "hkdf",
		// neither input_key_material nor key_id supplied
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidKeyAttributes))

	afterErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpDeriveKey, "software", wantErrType)
	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpDeriveKey, "software", metrics.StatusError)

	assert.Equal(t, beforeErrors+1, afterErrors, "xkms_errors_total")
	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{status=error}")
}

// ===========================================================================
// DeriveKeyECDH
// ===========================================================================

func TestServiceBoundary_DeriveKeyECDH_RecordsOperation(t *testing.T) {
	derived := []byte("derived-shared-secret-32-bytes!!")
	provider := newAgreementProvider(derived)
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"hsm": provider})
	addKeyOpsKey(t, stores["hsm"], &types.KeyAttributes{CN: "ecdh-key", KeyAlgorithm: x509.ECDSA})
	svc := keyOpsService(t)
	metrics.Enable()

	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpDeriveKeyECDH, "hsm", metrics.StatusSuccess)
	beforeSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpDeriveKeyECDH, "hsm")

	resp, err := svc.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{
		KeyID:         "ecdh-key",
		Backend:       "hsm",
		PeerPublicKey: []byte("peer-public-key"),
		KDFAlgorithm:  "hkdf",
		KDFHash:       "sha384",
		KeyLength:     16,
	})
	require.NoError(t, err)
	assert.Equal(t, derived, resp.DerivedKey)

	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpDeriveKeyECDH, "hsm", metrics.StatusSuccess)
	afterSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpDeriveKeyECDH, "hsm")

	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{operation=derive_key_ecdh,backend=hsm,status=success}")
	assert.Equal(t, beforeSamples+1, afterSamples, "xkms_operation_duration_seconds sample count")
}

func TestServiceBoundary_DeriveKeyECDH_RecordsError(t *testing.T) {
	setupKeyOpsService(t, nil)
	svc := keyOpsService(t)
	metrics.Enable()

	wantErrType := errorTypeLabel(&ErrValidation{})
	beforeErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpDeriveKeyECDH, "software", wantErrType)
	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpDeriveKeyECDH, "software", metrics.StatusError)

	_, err := svc.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{
		Backend:       "software",
		PeerPublicKey: []byte("peer-public-key"),
		// key_id deliberately empty
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingRequiredField))

	afterErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpDeriveKeyECDH, "software", wantErrType)
	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpDeriveKeyECDH, "software", metrics.StatusError)

	assert.Equal(t, beforeErrors+1, afterErrors, "xkms_errors_total")
	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{status=error}")
}

// ===========================================================================
// AttestKey
// ===========================================================================

func TestServiceBoundary_AttestKey_RecordsOperation(t *testing.T) {
	stmt := testAttestationStatement(t)
	provider := newAttestingProvider(stmt)
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"tpm2": provider})
	addKeyOpsKey(t, stores["tpm2"], &types.KeyAttributes{CN: "idevid", KeyAlgorithm: x509.ECDSA})
	svc := keyOpsService(t)
	metrics.Enable()

	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpAttestKey, "tpm2", metrics.StatusSuccess)
	beforeSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpAttestKey, "tpm2")

	resp, err := svc.AttestKey(context.Background(), &transport.AttestKeyRequest{
		Backend: "tpm2",
		KeyID:   "idevid",
		Nonce:   []byte("challenge"),
	})
	require.NoError(t, err)
	assert.Equal(t, "tpm2", resp.Format)

	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpAttestKey, "tpm2", metrics.StatusSuccess)
	afterSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpAttestKey, "tpm2")

	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{operation=attest_key,backend=tpm2,status=success}")
	assert.Equal(t, beforeSamples+1, afterSamples, "xkms_operation_duration_seconds sample count")
}

func TestServiceBoundary_AttestKey_RecordsError(t *testing.T) {
	setupKeyOpsService(t, nil)
	svc := keyOpsService(t)
	metrics.Enable()

	wantErrType := errorTypeLabel(&ErrValidation{})
	beforeErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpAttestKey, "software", wantErrType)
	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpAttestKey, "software", metrics.StatusError)

	_, err := svc.AttestKey(context.Background(), &transport.AttestKeyRequest{
		Backend: "software", // key_id deliberately empty
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingRequiredField))

	afterErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpAttestKey, "software", wantErrType)
	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpAttestKey, "software", metrics.StatusError)

	assert.Equal(t, beforeErrors+1, afterErrors, "xkms_errors_total")
	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{status=error}")
}
