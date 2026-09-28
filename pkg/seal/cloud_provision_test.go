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

package seal

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cloudProvisionProvider is a test double implementing types.KeyProvider,
// types.Sealer and types.SymmetricKeyProvider so BuildCloudKMSStrategy and
// EnsureSealKey can be exercised without a real cloud KMS client. Behaviour
// is controlled per-test via the exported fields.
type cloudProvisionProvider struct {
	// canSeal controls types.Sealer.CanSeal.
	canSeal bool
	// getKeyErr is returned by GetSymmetricKey; nil means "key exists".
	getKeyErr error
	// genKeyErr is returned by GenerateSymmetricKey.
	genKeyErr    error
	genKeyCalled bool
	// loginErr, when the test double embeds loginSupport, is returned by Login.
	loginErr    error
	loginCalled bool
	// saveErr, when the test double embeds saveSupport, is returned by Save.
	saveErr    error
	savedAttrs *types.KeyAttributes
	savedData  []byte
	// operatorKeyID, when non-empty, is returned by OperatorSealKeyID to
	// simulate an operator-configured CMK (AWS KMS Config.KeyID).
	operatorKeyID string
}

func (p *cloudProvisionProvider) Type() types.BackendType          { return "test-cloud" }
func (p *cloudProvisionProvider) Capabilities() types.Capabilities { return types.Capabilities{} }
func (p *cloudProvisionProvider) GenerateKey(_ context.Context, _ *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}
func (p *cloudProvisionProvider) GetKey(_ context.Context, _ *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}
func (p *cloudProvisionProvider) DeleteKey(_ context.Context, _ *types.KeyAttributes) error {
	return nil
}
func (p *cloudProvisionProvider) ListKeys(_ context.Context) ([]*types.KeyAttributes, error) {
	return nil, nil
}
func (p *cloudProvisionProvider) Signer(_ context.Context, _ *types.KeyAttributes) (crypto.Signer, error) {
	return nil, nil
}
func (p *cloudProvisionProvider) Decrypter(_ context.Context, _ *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, nil
}
func (p *cloudProvisionProvider) RotateKey(_ context.Context, _ *types.KeyAttributes) error {
	return nil
}
func (p *cloudProvisionProvider) Close() error { return nil }

func (p *cloudProvisionProvider) Seal(_ context.Context, data []byte, _ *types.SealOptions) (*types.SealedData, error) {
	return &types.SealedData{Ciphertext: data}, nil
}
func (p *cloudProvisionProvider) Unseal(_ context.Context, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	return sealed.Ciphertext, nil
}
func (p *cloudProvisionProvider) CanSeal() bool { return p.canSeal }

func (p *cloudProvisionProvider) GetSymmetricKey(_ context.Context, _ *types.KeyAttributes) (types.SymmetricKey, error) {
	if p.getKeyErr != nil {
		return nil, p.getKeyErr
	}
	return nil, nil
}
func (p *cloudProvisionProvider) GenerateSymmetricKey(_ context.Context, _ *types.KeyAttributes) (types.SymmetricKey, error) {
	p.genKeyCalled = true
	return nil, p.genKeyErr
}
func (p *cloudProvisionProvider) SymmetricEncrypter(_ context.Context, _ *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	return nil, nil
}

func (p *cloudProvisionProvider) Login() error {
	p.loginCalled = true
	return p.loginErr
}

func (p *cloudProvisionProvider) Save(attrs *types.KeyAttributes, data []byte, _ types.FSExtension, _ bool) error {
	p.savedAttrs = attrs
	p.savedData = data
	return p.saveErr
}

func (p *cloudProvisionProvider) OperatorSealKeyID() string {
	return p.operatorKeyID
}

var (
	_ types.KeyProvider          = (*cloudProvisionProvider)(nil)
	_ types.Sealer               = (*cloudProvisionProvider)(nil)
	_ types.SymmetricKeyProvider = (*cloudProvisionProvider)(nil)
	_ SealLoginProvider          = (*cloudProvisionProvider)(nil)
	_ SealMetadataSaver          = (*cloudProvisionProvider)(nil)
	_ SealOperatorKeyProvider    = (*cloudProvisionProvider)(nil)
)

// notSymmetricProvider implements types.KeyProvider and types.Sealer but,
// unlike cloudProvisionProvider, has no GenerateSymmetricKey/GetSymmetricKey/
// SymmetricEncrypter methods at all, so it does NOT satisfy
// types.SymmetricKeyProvider -- exercising EnsureSealKey's type-assertion
// failure branch.
type notSymmetricProvider struct {
	notSealerKeyProvider
}

func (p *notSymmetricProvider) Seal(_ context.Context, data []byte, _ *types.SealOptions) (*types.SealedData, error) {
	return &types.SealedData{Ciphertext: data}, nil
}
func (p *notSymmetricProvider) Unseal(_ context.Context, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	return sealed.Ciphertext, nil
}
func (p *notSymmetricProvider) CanSeal() bool { return true }

var (
	_ types.KeyProvider = (*notSymmetricProvider)(nil)
	_ types.Sealer      = (*notSymmetricProvider)(nil)
)

func TestSealKeyAttributes_Fields(t *testing.T) {
	attrs := SealKeyAttributes(types.StoreAWSKMS)
	require.NotNil(t, attrs)
	assert.Equal(t, SealKeyCN, attrs.CN)
	assert.Equal(t, types.StoreAWSKMS, attrs.StoreType)
	assert.Equal(t, types.KeyTypeEncryption, attrs.KeyType)
	assert.Equal(t, x509.UnknownPublicKeyAlgorithm, attrs.KeyAlgorithm)
	assert.Equal(t, types.SymmetricAES256GCM, attrs.SymmetricAlgorithm)
}

func TestIsCloudSealStrategy(t *testing.T) {
	cases := []struct {
		id   StrategyID
		want bool
	}{
		{StrategyAWSKMS, true},
		{StrategyGCPKMS, true},
		{StrategyAzureKV, true},
		{StrategyVault, true},
		{StrategyTPM2, false},
		{StrategyPKCS11, false},
		{StrategyPassphrase, false},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, IsCloudSealStrategy(c.id), "id=%s", c.id)
	}
}

func TestEnsureSealKey_KeyAlreadyExists(t *testing.T) {
	prov := &cloudProvisionProvider{}
	keyAttrs := SealKeyAttributes(types.StoreAWSKMS)
	err := EnsureSealKey(context.Background(), StrategyAWSKMS, prov, keyAttrs)
	require.NoError(t, err)
	assert.False(t, prov.genKeyCalled, "GenerateSymmetricKey must not run when the key already exists")
}

func TestEnsureSealKey_GeneratesOnNotFound(t *testing.T) {
	prov := &cloudProvisionProvider{getKeyErr: backend.ErrKeyNotFound}
	keyAttrs := SealKeyAttributes(types.StoreGCPKMS)
	err := EnsureSealKey(context.Background(), StrategyGCPKMS, prov, keyAttrs)
	require.NoError(t, err)
	assert.True(t, prov.genKeyCalled, "GenerateSymmetricKey must run on first init")
}

func TestEnsureSealKey_GenerateAlreadyExistsIsIdempotent(t *testing.T) {
	prov := &cloudProvisionProvider{
		getKeyErr: backend.ErrKeyNotFound,
		genKeyErr: backend.ErrKeyAlreadyExists,
	}
	keyAttrs := SealKeyAttributes(types.StoreAzureKV)
	err := EnsureSealKey(context.Background(), StrategyAzureKV, prov, keyAttrs)
	require.NoError(t, err)
}

func TestEnsureSealKey_GetKeyGenuineErrorPropagates(t *testing.T) {
	prov := &cloudProvisionProvider{getKeyErr: errors.New("kms unreachable")}
	keyAttrs := SealKeyAttributes(types.StoreVault)
	err := EnsureSealKey(context.Background(), StrategyVault, prov, keyAttrs)
	require.Error(t, err)
	assert.False(t, prov.genKeyCalled)
}

func TestEnsureSealKey_NotSymmetricProvider(t *testing.T) {
	prov := &notSymmetricProvider{}
	keyAttrs := SealKeyAttributes(types.StoreAWSKMS)
	err := EnsureSealKey(context.Background(), StrategyAWSKMS, prov, keyAttrs)
	require.Error(t, err)
	var notAvail *ErrSealBackendUnavailable
	assert.True(t, errors.As(err, &notAvail))
}

// TestErrSealBackendUnavailable_Error covers both of Error's branches: a
// Purpose-qualified message (what EnsureSealKey/BuildCloudKMSStrategy
// actually construct) and the unqualified fallback for a caller that leaves
// Purpose empty.
func TestErrSealBackendUnavailable_Error(t *testing.T) {
	withPurpose := &ErrSealBackendUnavailable{Strategy: "aws-kms", Purpose: "sealing"}
	assert.Equal(t, `backend "aws-kms" not available for sealing`, withPurpose.Error())

	withoutPurpose := &ErrSealBackendUnavailable{Strategy: "aws-kms"}
	assert.Equal(t, `backend "aws-kms" not available`, withoutPurpose.Error())
}

// TestErrNotCloudSealStrategy_Error covers ErrNotCloudSealStrategy.Error's
// message formatting.
func TestErrNotCloudSealStrategy_Error(t *testing.T) {
	err := &ErrNotCloudSealStrategy{Strategy: "tpm2"}
	assert.Equal(t, `seal: "tpm2" is not a cloud KMS strategy`, err.Error())
}

func TestEnsureSealKey_LoginCalledBeforeKeyResolution(t *testing.T) {
	prov := &cloudProvisionProvider{}
	keyAttrs := SealKeyAttributes(types.StorePKCS11)
	err := EnsureSealKey(context.Background(), StrategyPKCS11, prov, keyAttrs)
	require.NoError(t, err)
	assert.True(t, prov.loginCalled)
}

func TestEnsureSealKey_LoginErrorPropagates(t *testing.T) {
	prov := &cloudProvisionProvider{loginErr: errors.New("token login failed")}
	keyAttrs := SealKeyAttributes(types.StorePKCS11)
	err := EnsureSealKey(context.Background(), StrategyPKCS11, prov, keyAttrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token login failed")
}

// TestEnsureSealKey_AWSKMSOperatorKeyIDSeeded proves that an
// operator-configured CMK (SealOperatorKeyProvider.OperatorSealKeyID, backed
// by awskms.Config.KeyID) seeds the metadata store with that real key
// identifier -- never the seal key's CN (go-xkms#839).
func TestEnsureSealKey_AWSKMSOperatorKeyIDSeeded(t *testing.T) {
	prov := &cloudProvisionProvider{operatorKeyID: "arn:aws:kms:us-east-1:123456789012:key/operator-cmk"}
	keyAttrs := SealKeyAttributes(types.StoreAWSKMS)
	err := EnsureSealKey(context.Background(), StrategyAWSKMS, prov, keyAttrs)
	require.NoError(t, err)
	require.NotNil(t, prov.savedAttrs)
	assert.Equal(t, keyAttrs.CN, prov.savedAttrs.CN)
	assert.Contains(t, string(prov.savedData), prov.operatorKeyID)
	assert.NotContains(t, string(prov.savedData), keyAttrs.CN,
		"the seal key's CN must never be persisted as a KMS key identifier")
}

// TestEnsureSealKey_AWSKMSOperatorKeyIDSaveErrorPropagates proves a metadata
// store failure while seeding an operator-configured CMK surfaces as an
// error rather than silently falling through to key creation.
func TestEnsureSealKey_AWSKMSOperatorKeyIDSaveErrorPropagates(t *testing.T) {
	prov := &cloudProvisionProvider{
		operatorKeyID: "arn:aws:kms:us-east-1:123456789012:key/operator-cmk",
		saveErr:       errors.New("metadata store unavailable"),
	}
	keyAttrs := SealKeyAttributes(types.StoreAWSKMS)
	err := EnsureSealKey(context.Background(), StrategyAWSKMS, prov, keyAttrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metadata store unavailable")
}

// TestEnsureSealKey_AWSKMSNoOperatorKeyCreatesOne proves that without an
// operator-configured CMK, EnsureSealKey seeds nothing (go-xkms#839: the
// previous behavior seeded the seal key's CN itself, which made
// GenerateSymmetricKey's own "already exists" guard skip CreateKey on every
// boot) and instead falls through to GenerateSymmetricKey so the backend
// creates a real CMK.
func TestEnsureSealKey_AWSKMSNoOperatorKeyCreatesOne(t *testing.T) {
	prov := &cloudProvisionProvider{getKeyErr: backend.ErrKeyNotFound}
	keyAttrs := SealKeyAttributes(types.StoreAWSKMS)
	err := EnsureSealKey(context.Background(), StrategyAWSKMS, prov, keyAttrs)
	require.NoError(t, err)
	assert.Nil(t, prov.savedAttrs, "no metadata should be pre-seeded without an operator-configured key")
	assert.True(t, prov.genKeyCalled, "GenerateSymmetricKey must run to create the seal key")
}

// TestEnsureSealKey_AWSKMSOperatorKeyNotFoundFailsClosed proves that when an
// operator-configured CMK (Config.KeyID) resolves to backend.ErrKeyNotFound
// -- the key genuinely does not exist -- EnsureSealKey fails closed with a
// typed ErrOperatorSealKeyNotFound instead of falling through to
// GenerateSymmetricKey and silently provisioning an unrelated CMK
// (go-xkms#842).
func TestEnsureSealKey_AWSKMSOperatorKeyNotFoundFailsClosed(t *testing.T) {
	const operatorKeyID = "arn:aws:kms:us-east-1:123456789012:key/does-not-exist"
	prov := &cloudProvisionProvider{
		operatorKeyID: operatorKeyID,
		getKeyErr:     backend.ErrKeyNotFound,
	}
	keyAttrs := SealKeyAttributes(types.StoreAWSKMS)
	err := EnsureSealKey(context.Background(), StrategyAWSKMS, prov, keyAttrs)
	require.Error(t, err)
	assert.False(t, prov.genKeyCalled, "GenerateSymmetricKey must never run for a missing operator-configured CMK")

	var notFound *ErrOperatorSealKeyNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, string(StrategyAWSKMS), notFound.Strategy)
	assert.Equal(t, operatorKeyID, notFound.KeyID)
	assert.True(t, errors.Is(err, backend.ErrKeyNotFound), "ErrOperatorSealKeyNotFound must unwrap to backend.ErrKeyNotFound")
}

// TestErrOperatorSealKeyNotFound_Error covers ErrOperatorSealKeyNotFound's
// message formatting and its Unwrap contract.
func TestErrOperatorSealKeyNotFound_Error(t *testing.T) {
	cause := errors.New("describe key: not found")
	err := &ErrOperatorSealKeyNotFound{Strategy: "aws_kms", KeyID: "alias/missing", Err: cause}
	assert.Contains(t, err.Error(), "aws_kms")
	assert.Contains(t, err.Error(), "alias/missing")
	assert.Contains(t, err.Error(), cause.Error())
	assert.Same(t, cause, err.Unwrap())
}

func TestBuildCloudKMSStrategy_AllFourStrategies(t *testing.T) {
	cases := []struct {
		id    StrategyID
		store types.StoreType
	}{
		{StrategyAWSKMS, types.StoreAWSKMS},
		{StrategyGCPKMS, types.StoreGCPKMS},
		{StrategyAzureKV, types.StoreAzureKV},
		{StrategyVault, types.StoreVault},
	}
	for _, c := range cases {
		prov := &cloudProvisionProvider{canSeal: true}
		strategy, err := BuildCloudKMSStrategy(context.Background(), c.id, c.store, prov)
		require.NoError(t, err, "id=%s", c.id)
		require.NotNil(t, strategy)
		assert.Equal(t, c.id, strategy.ID())
		assert.True(t, strategy.Available())
		assert.True(t, strategy.HardwareBacked())
	}
}

func TestBuildCloudKMSStrategy_RejectsNonCloudStrategy(t *testing.T) {
	prov := &cloudProvisionProvider{canSeal: true}
	_, err := BuildCloudKMSStrategy(context.Background(), StrategyTPM2, types.StoreTPM2, prov)
	require.Error(t, err)
	var notCloud *ErrNotCloudSealStrategy
	assert.True(t, errors.As(err, &notCloud))
}

func TestBuildCloudKMSStrategy_ProviderNotSealer(t *testing.T) {
	prov := &notSealerKeyProvider{}
	_, err := BuildCloudKMSStrategy(context.Background(), StrategyAWSKMS, types.StoreAWSKMS, prov)
	require.Error(t, err)
	var notAvail *ErrSealBackendUnavailable
	assert.True(t, errors.As(err, &notAvail))
	assert.Equal(t, "sealing", notAvail.Purpose)
}

// notSealerKeyProvider implements types.KeyProvider but neither types.Sealer
// nor types.SymmetricKeyProvider.
type notSealerKeyProvider struct{}

func (p *notSealerKeyProvider) Type() types.BackendType          { return "test-not-sealer" }
func (p *notSealerKeyProvider) Capabilities() types.Capabilities { return types.Capabilities{} }
func (p *notSealerKeyProvider) GenerateKey(_ context.Context, _ *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}
func (p *notSealerKeyProvider) GetKey(_ context.Context, _ *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}
func (p *notSealerKeyProvider) DeleteKey(_ context.Context, _ *types.KeyAttributes) error {
	return nil
}
func (p *notSealerKeyProvider) ListKeys(_ context.Context) ([]*types.KeyAttributes, error) {
	return nil, nil
}
func (p *notSealerKeyProvider) Signer(_ context.Context, _ *types.KeyAttributes) (crypto.Signer, error) {
	return nil, nil
}
func (p *notSealerKeyProvider) Decrypter(_ context.Context, _ *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, nil
}
func (p *notSealerKeyProvider) RotateKey(_ context.Context, _ *types.KeyAttributes) error {
	return nil
}
func (p *notSealerKeyProvider) Close() error { return nil }

var _ types.KeyProvider = (*notSealerKeyProvider)(nil)

func TestBuildCloudKMSStrategy_EnsureSealKeyErrorWrapped(t *testing.T) {
	prov := &cloudProvisionProvider{canSeal: true, getKeyErr: errors.New("kms transient failure")}
	_, err := BuildCloudKMSStrategy(context.Background(), StrategyVault, types.StoreVault, prov)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kms transient failure")
}
