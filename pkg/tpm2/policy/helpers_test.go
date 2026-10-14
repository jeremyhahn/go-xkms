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

package policy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/vtpm"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// testPCR is the PCR the test policies select. PCR 23 is the application PCR
// a locality-0 caller may extend, and it is not the platform PCR (16) that
// the scope secrets and authorities are bound to.
const testPCR = 23

// errSignatureInvalid is returned by fixture.sign when the TPM's signature
// does not verify against the key's public area.
var errSignatureInvalid = errors.New("test: signature does not verify")

// quietLogger discards the TPM's chatty logging.
var quietLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// provisionedTPM opens a TPM over params and provisions it (EK, SSRK and
// Platform SRK) when it is fresh, as the service does for a vTPM.
func provisionedTPM(t *testing.T, params *pkgtpm2.Params) *pkgtpm2.TPM2 {
	t.Helper()
	opened, err := pkgtpm2.NewTPM2(params)
	require.ErrorIs(t, err, pkgtpm2.ErrNotInitialized, "a fresh TPM reports it needs provisioning")
	tpm, ok := opened.(*pkgtpm2.TPM2)
	require.True(t, ok)
	t.Cleanup(func() { require.NoError(t, tpm.Close()) })
	require.NoError(t, pkgtpm2.ProvisionFresh(tpm, tpm.Config()))
	return tpm
}

// fixture is a Service over one physical TPM and in-memory stores.
type fixture struct {
	t          *testing.T
	ctx        context.Context
	svc        *Service
	cfg        Config
	tpm        *pkgtpm2.TPM2
	tenantKeys *store.BlobStore
	registry   *Registry
}

// memoryBlobs returns an in-memory BlobStore, closed when the test ends.
func memoryBlobs(t *testing.T) *store.BlobStore {
	t.Helper()
	factory, err := store.NewMemoryStorageFactory(quietLogger)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, factory.Close()) })
	return factory.KeyBackend()
}

// newFixture builds a Service over tpm, whose own key store is keys. A nil
// vtpmCfg leaves vtpm mode unavailable.
func newFixture(t *testing.T, tpm *pkgtpm2.TPM2, keys store.KeyBackend, vtpmCfg *vtpm.Config) *fixture {
	t.Helper()
	srk, err := tpm.PlatformSRKAttributes()
	require.NoError(t, err)
	registry, err := NewRegistry(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	f := &fixture{
		t:          t,
		ctx:        context.Background(),
		tpm:        tpm,
		tenantKeys: memoryBlobs(t),
		registry:   registry,
	}
	f.cfg = Config{
		Registry:    registry,
		TPM:         tpm,
		PlatformSRK: srk,
		Keys:        keys,
		TenantKeys:  f.tenantKeys,
		Sealer:      tpm,
		VTPM:        vtpmCfg,
		Logger:      quietLogger,
	}
	f.svc, err = NewService(f.cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.svc.Close()) })
	return f
}

// restart replaces the Service with a new one over the same TPM and stores,
// as a process restart does: nothing is cached, and every scope is opened
// and reconciled again on first use.
func (f *fixture) restart() {
	f.t.Helper()
	require.NoError(f.t, f.svc.Close())
	svc, err := NewService(f.cfg)
	require.NoError(f.t, err)
	f.svc = svc
}

// createPolicy creates a SHA-256 policy over testPCR.
func (f *fixture) createPolicy(tenant, name string) *Policy {
	f.t.Helper()
	p, err := f.svc.CreatePolicy(f.ctx, tenant, CreatePolicyRequest{Name: name, Branches: []Branch{PCRBranch("sha256", testPCR)}})
	require.NoError(f.t, err)
	return p
}

// scopeTPM returns tenant's ScopeTPM; the caller closes it.
func (f *fixture) scopeTPM(tenant string) *ScopeTPM {
	f.t.Helper()
	st, err := f.svc.ScopeTPM(f.ctx, tenant)
	require.NoError(f.t, err)
	return st
}

// closeScopeTPM closes st, failing the test on error.
func (f *fixture) closeScopeTPM(st *ScopeTPM) {
	f.t.Helper()
	require.NoError(f.t, st.Close())
}

// mustPassword wraps pin as a types.Password; nil pin is no password.
func mustPassword(t *testing.T, pin []byte) types.Password {
	t.Helper()
	if pin == nil {
		return nil
	}
	pw, err := types.NewPassword(pin)
	require.NoError(t, err)
	// Passwords are mlocked enclaves with no finalizer; release this one
	// when the test ends so the suite never exhausts RLIMIT_MEMLOCK.
	t.Cleanup(pw.Clear)
	return pw
}

// createKey creates an ECDSA P-256 signing key bound to policy in tenant's
// scope and records the assignment, as the key backend does.
func (f *fixture) createKey(tenant, cn, policy string, pin []byte) *types.KeyAttributes {
	f.t.Helper()
	st := f.scopeTPM(tenant)
	defer f.closeScopeTPM(st)
	attrs := &types.KeyAttributes{
		CN:                 cn,
		Hash:               crypto.SHA256,
		KeyAlgorithm:       x509.ECDSA,
		KeyType:            types.KeyTypeSigning,
		Parent:             st.Parent,
		Password:           mustPassword(f.t, pin),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		StoreType:          types.StoreTPM2,
		TenantID:           tenant,
		TPMPolicy:          policy,
		ECCAttributes:      &types.ECCAttributes{Curve: elliptic.P256()},
		TPMAttributes:      &types.TPMAttributes{Hierarchy: tpm2.TPMRHOwner},
	}
	_, err := st.TPM.CreateECDSA(attrs, st.Keys, false)
	require.NoError(f.t, err)
	public, err := st.Keys.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	require.NoError(f.t, err)
	publicArea := tpm2.BytesAs2B[tpm2.TPMTPublic](public)
	pub, err := publicArea.Contents()
	require.NoError(f.t, err)
	require.NoError(f.t, f.svc.Assign(f.ctx, tenant, ObjectKey, cn, policy, pub.AuthPolicy.Buffer))
	return attrs
}

// sign signs a fixed digest with key in tenant's scope, under the scope's
// current parent, and verifies the signature against the key's public area,
// so a pass means the TPM really used that key.
func (f *fixture) sign(tenant string, key *types.KeyAttributes) error {
	f.t.Helper()
	st := f.scopeTPM(tenant)
	defer f.closeScopeTPM(st)
	attrs := *key
	attrs.Parent = st.Parent
	digest := sha256.Sum256([]byte("tpm policy service test message"))
	signature, err := st.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{KeyAttributes: &attrs, Backend: st.Keys})
	if err != nil {
		return err
	}
	public, err := st.Keys.Get(key, store.FSEXT_PUBLIC_BLOB)
	if err != nil {
		return err
	}
	pub, err := st.TPM.ParsePublicKey(public)
	if err != nil {
		return err
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(ecPub, digest[:], signature) {
		return errSignatureInvalid
	}
	return nil
}

// withoutPassword returns a copy of key that presents no password.
func withoutPassword(key *types.KeyAttributes) *types.KeyAttributes {
	c := *key
	c.Password = nil
	return &c
}

// blobs returns key's private and public blobs from tenant's key store.
func (f *fixture) blobs(tenant string, key *types.KeyAttributes) ([]byte, []byte) {
	f.t.Helper()
	st := f.scopeTPM(tenant)
	defer f.closeScopeTPM(st)
	private, err := st.Keys.Get(key, store.FSEXT_PRIVATE_BLOB)
	require.NoError(f.t, err)
	public, err := st.Keys.Get(key, store.FSEXT_PUBLIC_BLOB)
	require.NoError(f.t, err)
	return private, public
}

// extendPCR moves testPCR on t: the state a policy captured no longer holds.
func extendPCR(t *testing.T, tpm transport.TPM) {
	t.Helper()
	_, err := tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(testPCR), Auth: tpm2.PasswordAuth(nil)},
		Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{
			HashAlg: tpm2.TPMAlgSHA256,
			Digest:  make([]byte, sha256.Size),
		}}},
	}.Execute(tpm)
	require.NoError(t, err)
}

// replayResolver answers every approval request with fixed approvals, as an
// attacker replaying a stored copy would.
type replayResolver struct {
	*Service
	approvals []*pkgtpm2.PolicyApproval
}

// Approvals returns the replayed approvals.
func (r replayResolver) Approvals(string, string) ([]*pkgtpm2.PolicyApproval, error) {
	return r.approvals, nil
}

// pcrBranch is a branch of one pcr condition over testPCR.
func pcrBranch() Branch {
	return PCRBranch("sha256", testPCR)
}

// authValueBranch is a branch of one auth_value condition.
func authValueBranch() Branch {
	return Branch{Conditions: []Condition{{Type: ConditionAuthValue}}}
}

// createComposite creates a policy of branches in tenant's scope.
func (f *fixture) createComposite(tenant, name string, branches ...Branch) *Policy {
	f.t.Helper()
	p, err := f.svc.CreatePolicy(f.ctx, tenant, CreatePolicyRequest{Name: name, Branches: branches})
	require.NoError(f.t, err)
	return p
}
