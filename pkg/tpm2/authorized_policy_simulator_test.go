//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPolicyPCR is the PCR the test policy approves. PCR 23 is the
// application PCR a locality-0 caller may extend, and it is not the platform
// PCR the authority's own platform policy reads.
const testPolicyPCR = 23

// testPolicyName is the named policy the tests bind objects to.
const testPolicyName = "boot"

// errUnknownTestPolicy is the test resolver's answer for a policy it holds no
// entry for.
var errUnknownTestPolicy = errors.New("test resolver: unknown policy")

// testPolicyResolver is an in-memory PolicyBindingResolver: the registry the
// real policy service keeps, reduced to what the TPM consults.
type testPolicyResolver struct {
	mu        sync.Mutex
	indices   map[string]tpm2.TPMHandle
	hashAlg   tpm2.TPMAlgID
	approvals map[string]*PolicyApproval
	requested []string
}

func newTestPolicyResolver() *testPolicyResolver {
	return &testPolicyResolver{
		indices:   make(map[string]tpm2.TPMHandle),
		hashAlg:   tpm2.TPMAlgSHA256,
		approvals: make(map[string]*PolicyApproval),
	}
}

func (r *testPolicyResolver) PolicyIndex(scope, name string) (tpm2.TPMHandle, tpm2.TPMAlgID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requested = append(r.requested, scope+"/"+name)
	index, ok := r.indices[scope+"/"+name]
	if !ok {
		return 0, 0, errUnknownTestPolicy
	}
	return index, r.hashAlg, nil
}

func (r *testPolicyResolver) Approval(scope, name string) (*PolicyApproval, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	approval, ok := r.approvals[scope+"/"+name]
	if !ok {
		return nil, errUnknownTestPolicy
	}
	return approval, nil
}

func (r *testPolicyResolver) setApproval(scope, name string, approval *PolicyApproval) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.approvals[scope+"/"+name] = approval
}

// policyFixture is a provisioned simulator with one named policy, "boot" in
// the system scope, bound to an authority under the Platform SRK and approved
// at the counter's current epoch for the live value of testPolicyPCR.
type policyFixture struct {
	h         *simHarness
	srk       *types.KeyAttributes
	resolver  *testPolicyResolver
	counter   tpm2.TPMHandle
	index     tpm2.TPMHandle
	authority *types.KeyAttributes
}

func newPolicyFixture(t *testing.T) *policyFixture {
	t.Helper()
	h := newSimHarness(t, nil)
	f := &policyFixture{
		h:        h,
		srk:      createPlatformPolicySRK(t, h, mustPassword([]byte("platform-srk-pin"))),
		resolver: newTestPolicyResolver(),
	}

	var err error
	f.counter, err = h.TPM.FindFreeNVIndex(NVOwnerIndexFirst, NVOwnerIndexLast)
	require.NoError(t, err)
	_, err = h.TPM.DefineCounterIndex(f.counter, policyWriteAuth, nil)
	require.NoError(t, err)

	f.index, err = h.TPM.FindFreeNVIndex(NVOwnerIndexFirst, NVOwnerIndexLast)
	require.NoError(t, err)
	_, err = h.TPM.DefinePolicyIndex(f.index, tpm2.TPMAlgSHA256, policyWriteAuth, nil)
	require.NoError(t, err)

	f.authority = f.createAuthority(t, "policy-authority-1")
	f.pointIndexAt(t, f.authority)

	f.resolver.indices[SystemPolicyScope+"/"+testPolicyName] = f.index
	h.TPM.SetPolicyBindingResolver(f.resolver)
	f.resolver.setApproval(SystemPolicyScope, testPolicyName, f.approve(t, f.authority))
	return f
}

// createAuthority creates an ECDSA P-256 authority under the Platform SRK,
// bound to the platform policy and carrying its own auth value.
func (f *policyFixture) createAuthority(t *testing.T, cn string) *types.KeyAttributes {
	t.Helper()
	attrs := f.keyAttrs(cn, mustPassword([]byte(cn+"-auth-value")))
	attrs.TPMPolicy = types.TPMPolicyPlatform
	_, err := f.h.TPM.CreateECDSA(attrs, f.h.Backend, false)
	require.NoError(t, err)
	return attrs
}

// keyAttrs returns ECDSA P-256 signing key attributes under the Platform SRK.
func (f *policyFixture) keyAttrs(cn string, password types.Password) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:                 cn,
		Hash:               crypto.SHA256,
		KeyAlgorithm:       x509.ECDSA,
		KeyType:            types.KeyTypeSigning,
		Parent:             f.srk,
		Password:           password,
		StoreType:          types.StoreTPM2,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ECCAttributes:      &types.ECCAttributes{Curve: elliptic.P256()},
		TPMAttributes:      &types.TPMAttributes{Hierarchy: tpm2.TPMRHOwner},
	}
}

// createBoundKey creates an ECDSA key bound to the "boot" policy.
func (f *policyFixture) createBoundKey(t *testing.T, cn string, password types.Password) *types.KeyAttributes {
	t.Helper()
	attrs := f.keyAttrs(cn, password)
	attrs.TPMPolicy = testPolicyName
	_, err := f.h.TPM.CreateECDSA(attrs, f.h.Backend, false)
	require.NoError(t, err)
	return attrs
}

// pointIndexAt writes the policy index so it names authority.
func (f *policyFixture) pointIndexAt(t *testing.T, authority *types.KeyAttributes) {
	t.Helper()
	name, _, err := f.h.TPM.AuthorityName(authority, f.h.Backend)
	require.NoError(t, err)
	digest, err := AuthorizeDigest(tpm2.TPMAlgSHA256, name, PolicyRef(SystemPolicyScope, testPolicyName))
	require.NoError(t, err)
	_, err = f.h.TPM.WritePolicyIndex(f.index, policyWriteAuth, digest, tpm2.TPMAlgSHA256)
	require.NoError(t, err)
}

// livePCRDigest returns the TPM2_PolicyPCR operand for the live value of
// testPolicyPCR.
func (f *policyFixture) livePCRDigest(t *testing.T) []byte {
	t.Helper()
	banks, err := f.h.TPM.ReadPCRs([]uint{testPolicyPCR})
	require.NoError(t, err)
	for _, bank := range banks {
		if strings.EqualFold(bank.Algorithm, PCRBankSHA256) {
			digest, err := PCRCompositeDigest(PCRBankSHA256, []int{testPolicyPCR}, map[string]string{
				"sha256:23": hex.EncodeToString(bank.PCRs[0].Value),
			})
			require.NoError(t, err)
			return digest
		}
	}
	require.FailNow(t, "the simulator has no SHA-256 PCR bank")
	return nil
}

// approve signs, with authority, an approval of the live value of
// testPolicyPCR at the counter's current epoch.
func (f *policyFixture) approve(t *testing.T, authority *types.KeyAttributes) *PolicyApproval {
	t.Helper()
	tpm := f.h.TPM

	epoch, err := tpm.ReadCounter(f.counter)
	require.NoError(t, err)
	counterName, err := tpm.NVIndexName(f.counter)
	require.NoError(t, err)

	selection := PolicyPCRSelection(tpm2.TPMAlgSHA256, testPolicyPCR)
	pcrDigest := f.livePCRDigest(t)
	approved, err := ApprovedPolicyDigest(tpm2.TPMAlgSHA256, selection, pcrDigest, counterName, epoch)
	require.NoError(t, err)

	ref := PolicyRef(SystemPolicyScope, testPolicyName)
	aHash, err := ApprovalDigest(tpm2.TPMAlgSHA256, approved, ref)
	require.NoError(t, err)
	signature, err := tpm.SignApproval(authority, f.h.Backend, aHash)
	require.NoError(t, err)
	_, public, err := tpm.AuthorityName(authority, f.h.Backend)
	require.NoError(t, err)

	return &PolicyApproval{
		HashAlg:         tpm2.TPMAlgSHA256,
		PCRSelection:    selection,
		PCRDigest:       pcrDigest,
		Counter:         f.counter,
		Epoch:           epoch,
		PolicyRef:       ref,
		AuthorityPublic: public,
		Signature:       *signature,
		Index:           f.index,
	}
}

// extendPolicyPCR moves testPolicyPCR: the platform state the approval
// described no longer holds.
func (f *policyFixture) extendPolicyPCR(t *testing.T) {
	t.Helper()
	_, err := tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(testPolicyPCR), Auth: tpm2.PasswordAuth(nil)},
		Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{
			HashAlg: tpm2.TPMAlgSHA256,
			Digest:  make([]byte, 32),
		}}},
	}.Execute(f.h.TPM.transport)
	require.NoError(t, err)
}

// update re-approves the live PCR value at the next epoch, as a policy update
// does, and returns the new approval.
func (f *policyFixture) update(t *testing.T, authority *types.KeyAttributes) *PolicyApproval {
	t.Helper()
	_, err := f.h.TPM.IncrementCounter(f.counter, policyWriteAuth)
	require.NoError(t, err)
	approval := f.approve(t, authority)
	f.resolver.setApproval(SystemPolicyScope, testPolicyName, approval)
	return approval
}

// sign signs a fixed digest with key and verifies the signature against the
// key's public area, so a pass means the TPM really used that key.
func (f *policyFixture) sign(key *types.KeyAttributes) error {
	digest := sha256.Sum256([]byte("authorized policy test message"))
	signature, err := f.h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: key,
		Backend:       f.h.Backend,
	})
	if err != nil {
		return err
	}
	pub, err := f.h.TPM.ParsePublicKey(f.mustBlob(key, store.FSEXT_PUBLIC_BLOB))
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), digest[:], signature) {
		return errors.New("signature does not verify")
	}
	return nil
}

func (f *policyFixture) mustBlob(key *types.KeyAttributes, ext types.FSExtension) []byte {
	blob, err := f.h.Backend.Get(key, ext)
	if err != nil {
		panic(err)
	}
	return blob
}

// withoutPassword returns a copy of key that presents no password.
func withoutPassword(key *types.KeyAttributes) *types.KeyAttributes {
	c := *key
	c.Password = nil
	return &c
}

// TestAuthorizedPolicy_DigestsMatchLiveSession proves every trial digest the
// package computes is the digest a real session reaches at the same step:
// ApprovedPolicyDigest after PolicyPCR+PolicyNV, AuthorizeDigest (the index
// content) after PolicyAuthorize, and AuthorizedObjectPolicy's branch and OR
// digests after PolicyAuthorizeNV and PolicyOR.
func TestAuthorizedPolicy_DigestsMatchLiveSession(t *testing.T) {
	f := newPolicyFixture(t)
	tpm := f.h.TPM
	approval, err := f.resolver.Approval(SystemPolicyScope, testPolicyName)
	require.NoError(t, err)

	session, closer, err := tpm2.PolicySession(tpm.transport, tpm2.TPMAlgSHA256, sessionNonceSize)
	require.NoError(t, err)
	defer func() { require.NoError(t, closer()) }()
	sessionDigest := func() []byte {
		rsp, err := tpm2.PolicyGetDigest{PolicySession: session.Handle()}.Execute(tpm.transport)
		require.NoError(t, err)
		return rsp.PolicyDigest.Buffer
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: session.Handle(),
		PcrDigest:     tpm2.TPM2BDigest{Buffer: approval.PCRDigest},
		Pcrs:          approval.PCRSelection,
	}.Execute(tpm.transport)
	require.NoError(t, err)
	counterName, err := tpm.NVIndexName(f.counter)
	require.NoError(t, err)
	require.NoError(t, tpm.policyNVEpoch(session, f.counter, counterName, approval.Epoch))
	approved, err := ApprovedPolicyDigest(tpm2.TPMAlgSHA256, approval.PCRSelection, approval.PCRDigest, counterName, approval.Epoch)
	require.NoError(t, err)
	assert.Equal(t, approved, sessionDigest(), "ApprovedPolicyDigest")

	aHash, err := ApprovalDigest(tpm2.TPMAlgSHA256, approved, approval.PolicyRef)
	require.NoError(t, err)
	ticket, authorityName, err := tpm.verifyApproval(approval.AuthorityPublic, aHash, approval.Signature)
	require.NoError(t, err)
	_, err = tpm2.PolicyAuthorize{
		PolicySession:  session.Handle(),
		ApprovedPolicy: tpm2.TPM2BDigest{Buffer: approved},
		PolicyRef:      tpm2.TPM2BDigest{Buffer: approval.PolicyRef},
		KeySign:        authorityName,
		CheckTicket:    *ticket,
	}.Execute(tpm.transport)
	require.NoError(t, err)
	authorize, err := AuthorizeDigest(tpm2.TPMAlgSHA256, authorityName, approval.PolicyRef)
	require.NoError(t, err)
	assert.Equal(t, authorize, sessionDigest(), "AuthorizeDigest")
	_, indexDigest, err := tpm.ReadPolicyIndex(f.index)
	require.NoError(t, err)
	assert.Equal(t, authorize, indexDigest, "the policy index holds AuthorizeDigest")

	require.NoError(t, tpm.policyAuthorizeNV(session, f.index))
	indexName, err := tpm.NVIndexName(f.index)
	require.NoError(t, err)
	noAuthPolicy, _, err := AuthorizedObjectPolicy(tpm2.TPMAlgSHA256, indexName, false)
	require.NoError(t, err)
	assert.Equal(t, noAuthPolicy, sessionDigest(), "AuthorizedObjectPolicy without auth value")

	withAuthPolicy, branches, err := AuthorizedObjectPolicy(tpm2.TPMAlgSHA256, indexName, true)
	require.NoError(t, err)
	require.NoError(t, tpm.policyORBranches(session, branches))
	assert.Equal(t, withAuthPolicy, sessionDigest(), "AuthorizedObjectPolicy with auth value")
}

// TestAuthorizedPolicy_KeysSignUnderApproval proves keys bound to a named
// policy sign under its current approval: the key without a password through
// the approved branch alone, the key with one through its password branch,
// and that key again without its password through the approved branch of its
// PolicyOR.
func TestAuthorizedPolicy_KeysSignUnderApproval(t *testing.T) {
	f := newPolicyFixture(t)
	noPassword := f.createBoundKey(t, "bound-no-password", nil)
	withPassword := f.createBoundKey(t, "bound-with-password", mustPassword([]byte("bound-key-pin")))

	require.NoError(t, f.sign(noPassword))
	require.NoError(t, f.sign(withPassword))
	require.NoError(t, f.sign(withoutPassword(withPassword)))

	blob := f.mustBlob(noPassword, store.FSEXT_PUBLIC_BLOB)
	public := tpm2.BytesAs2B[tpm2.TPMTPublic](blob)
	pub, err := public.Contents()
	require.NoError(t, err)
	assert.False(t, pub.ObjectAttributes.UserWithAuth, "the policy must be the only way to use the key")
}

// TestAuthorizedPolicy_PCRChangeRefusesApprovedBranch proves the TPM, not
// software, refuses the approved branch once the approved PCR moves, and that
// the refusal is reported as a PCR mismatch carrying the TPM's response code.
// The password branch does not depend on the approval and still signs.
func TestAuthorizedPolicy_PCRChangeRefusesApprovedBranch(t *testing.T) {
	f := newPolicyFixture(t)
	noPassword := f.createBoundKey(t, "pcr-no-password", nil)
	withPassword := f.createBoundKey(t, "pcr-with-password", mustPassword([]byte("bound-key-pin")))

	f.extendPolicyPCR(t)

	err := f.sign(noPassword)
	var mismatch *PolicyPCRMismatchError
	require.ErrorAs(t, err, &mismatch)
	assert.Equal(t, testPolicyName, mismatch.Policy)
	assert.ErrorIs(t, err, tpm2.TPMRCValue)

	require.NoError(t, f.sign(withPassword))
}

// TestAuthorizedPolicy_UpdateReapprovesWithoutRekey proves a policy update --
// the next epoch, approving the new PCR value -- restores the approved branch
// of the very same key blobs.
func TestAuthorizedPolicy_UpdateReapprovesWithoutRekey(t *testing.T) {
	f := newPolicyFixture(t)
	noPassword := f.createBoundKey(t, "update-no-password", nil)
	withPassword := f.createBoundKey(t, "update-with-password", mustPassword([]byte("bound-key-pin")))
	privBefore := f.mustBlob(noPassword, store.FSEXT_PRIVATE_BLOB)
	pubBefore := f.mustBlob(noPassword, store.FSEXT_PUBLIC_BLOB)

	f.extendPolicyPCR(t)
	require.Error(t, f.sign(noPassword))

	approval := f.update(t, f.authority)
	assert.Equal(t, uint64(2), approval.Epoch, "DefineCounterIndex leaves the counter at 1, the update moves it to 2")

	require.NoError(t, f.sign(noPassword))
	require.NoError(t, f.sign(withPassword))
	require.NoError(t, f.sign(withoutPassword(withPassword)))
	assert.Equal(t, privBefore, f.mustBlob(noPassword, store.FSEXT_PRIVATE_BLOB), "no re-key")
	assert.Equal(t, pubBefore, f.mustBlob(noPassword, store.FSEXT_PUBLIC_BLOB), "no re-key")
}

// TestAuthorizedPolicy_ReplayOfSupersededApprovalRefused proves an approval
// from an earlier epoch is refused by the TPM (TPM2_PolicyNV) even when the
// PCR value it approved still holds, and is reported as revoked.
func TestAuthorizedPolicy_ReplayOfSupersededApprovalRefused(t *testing.T) {
	f := newPolicyFixture(t)
	key := f.createBoundKey(t, "replay-no-password", nil)

	old, err := f.resolver.Approval(SystemPolicyScope, testPolicyName)
	require.NoError(t, err)
	f.update(t, f.authority)
	require.NoError(t, f.sign(key))

	f.resolver.setApproval(SystemPolicyScope, testPolicyName, old)
	err = f.sign(key)
	var revoked *PolicyApprovalRevokedError
	require.ErrorAs(t, err, &revoked)
	assert.Equal(t, old.Epoch, revoked.Epoch)
	assert.ErrorIs(t, err, tpm2.TPMRCPolicy)
}

// TestAuthorizedPolicy_AuthorityRotation proves rewriting the policy index
// moves every bound key to a new authority without re-keying, and that an
// approval signed by the old authority no longer authorizes them.
func TestAuthorizedPolicy_AuthorityRotation(t *testing.T) {
	f := newPolicyFixture(t)
	key := f.createBoundKey(t, "rotation-no-password", nil)
	require.NoError(t, f.sign(key))

	authority2 := f.createAuthority(t, "policy-authority-2")
	f.pointIndexAt(t, authority2)
	oldAuthority := f.update(t, f.authority)
	newAuthority := f.approve(t, authority2)

	f.resolver.setApproval(SystemPolicyScope, testPolicyName, newAuthority)
	require.NoError(t, f.sign(key))

	f.resolver.setApproval(SystemPolicyScope, testPolicyName, oldAuthority)
	err := f.sign(key)
	require.Error(t, err, "an approval by the replaced authority must not authorize the key")
	assert.ErrorIs(t, err, tpm2.TPMRCValue, "TPM2_PolicyAuthorizeNV refuses a digest the index does not hold")
	var mismatch *PolicyPCRMismatchError
	assert.False(t, errors.As(err, &mismatch), "the PCRs did not move")
}

// TestAuthorizedPolicy_SealedObject proves a sealed object bound to a named
// policy unseals under its approval and is refused once the PCR moves.
func TestAuthorizedPolicy_SealedObject(t *testing.T) {
	f := newPolicyFixture(t)
	secret := []byte("sealed under the boot policy")
	attrs := sealedKeyAttrsUnder(f.srk, "bound-sealed", nil)
	attrs.TPMPolicy = testPolicyName
	attrs.SealData = types.NewSealData(secret)

	_, err := f.h.TPM.SealKey(attrs, f.h.Backend, false)
	require.NoError(t, err)

	got, err := f.h.TPM.UnsealKey(attrs, f.h.Backend)
	require.NoError(t, err)
	assert.Equal(t, secret, got)

	f.extendPolicyPCR(t)
	_, err = f.h.TPM.UnsealKey(attrs, f.h.Backend)
	var mismatch *PolicyPCRMismatchError
	require.ErrorAs(t, err, &mismatch)
}

// TestAuthorizedPolicy_BindingRecordLifecycle proves the binding record is
// written beside the key with the policy it names, removed with the key, and
// that a damaged record makes the key unusable rather than silently
// authorized along another path.
func TestAuthorizedPolicy_BindingRecordLifecycle(t *testing.T) {
	f := newPolicyFixture(t)
	key := f.createBoundKey(t, "binding-record", mustPassword([]byte("bound-key-pin")))

	binding, err := f.h.TPM.loadPolicyBinding(key, f.h.Backend)
	require.NoError(t, err)
	require.NotNil(t, binding)
	assert.Equal(t, &store.TPMPolicyBinding{
		Scope:           SystemPolicyScope,
		Policy:          testPolicyName,
		Index:           uint32(f.index),
		HashAlg:         uint16(tpm2.TPMAlgSHA256),
		AuthValueBranch: true,
	}, binding)

	require.NoError(t, f.h.Backend.Save(key, []byte("XTPB-garbage"), store.FSEXT_TPM_POLICY, true))
	var formatErr *store.TPMPolicyBindingFormatError
	require.ErrorAs(t, f.sign(key), &formatErr)

	require.NoError(t, f.h.TPM.DeleteKeyPair(key, f.h.Backend))
	binding, err = f.h.TPM.loadPolicyBinding(key, f.h.Backend)
	require.NoError(t, err)
	assert.Nil(t, binding, "deleting the key deletes its binding")
}

// TestAuthorizedPolicy_ResolverUnset proves a named policy is refused when no
// resolver is set, both when creating a key and when using one.
func TestAuthorizedPolicy_ResolverUnset(t *testing.T) {
	f := newPolicyFixture(t)
	key := f.createBoundKey(t, "resolver-unset", nil)

	f.h.TPM.SetPolicyBindingResolver(nil)

	require.ErrorIs(t, f.sign(key), ErrPolicyResolverUnset)
	_, err := f.h.TPM.CreateECDSA(f.withPolicy(f.keyAttrs("resolver-unset-2", nil)), f.h.Backend, false)
	require.ErrorIs(t, err, ErrPolicyResolverUnset)
}

func (f *policyFixture) withPolicy(attrs *types.KeyAttributes) *types.KeyAttributes {
	attrs.TPMPolicy = testPolicyName
	return attrs
}

// TestAuthorizedPolicy_CreateRefusals proves a key is never bound to a policy
// it could not be used under: an unknown policy, a tenant scope the resolver
// does not know, an index that was never written, or a hash algorithm that
// differs from the key's name algorithm.
func TestAuthorizedPolicy_CreateRefusals(t *testing.T) {
	f := newPolicyFixture(t)

	_, err := f.h.TPM.CreateECDSA(func() *types.KeyAttributes {
		attrs := f.keyAttrs("unknown-policy", nil)
		attrs.TPMPolicy = "no-such-policy"
		return attrs
	}(), f.h.Backend, false)
	require.ErrorIs(t, err, errUnknownTestPolicy)

	tenantKey := f.withPolicy(f.keyAttrs("tenant-key", nil))
	tenantKey.TenantID = "tenant-a"
	_, err = f.h.TPM.CreateECDSA(tenantKey, f.h.Backend, false)
	require.ErrorIs(t, err, errUnknownTestPolicy)
	assert.Contains(t, f.resolver.requested, "tenant-a/"+testPolicyName, "a tenant key resolves in its tenant's scope")

	unwritten, err := f.h.TPM.FindFreeNVIndex(NVOwnerIndexFirst, NVOwnerIndexLast)
	require.NoError(t, err)
	_, err = f.h.TPM.DefinePolicyIndex(unwritten, tpm2.TPMAlgSHA256, policyWriteAuth, nil)
	require.NoError(t, err)
	f.resolver.indices[SystemPolicyScope+"/unwritten"] = unwritten
	unwrittenKey := f.keyAttrs("unwritten-index", nil)
	unwrittenKey.TPMPolicy = "unwritten"
	_, err = f.h.TPM.CreateECDSA(unwrittenKey, f.h.Backend, false)
	require.ErrorIs(t, err, ErrPolicyIndexUnwritten)

	f.resolver.hashAlg = tpm2.TPMAlgSHA384
	_, err = f.h.TPM.CreateECDSA(f.withPolicy(f.keyAttrs("hash-mismatch", nil)), f.h.Backend, false)
	require.ErrorIs(t, err, ErrPolicyHashMismatch)
}

// TestAuthorizedPolicy_RSAAndSecretKeysBind proves CreateRSA and
// CreateSecretKey bind to a named policy the same way CreateECDSA does.
func TestAuthorizedPolicy_RSAAndSecretKeysBind(t *testing.T) {
	f := newPolicyFixture(t)

	rsaKey := f.withPolicy(f.keyAttrs("bound-rsa", nil))
	rsaKey.KeyAlgorithm = x509.RSA
	rsaKey.SignatureAlgorithm = x509.SHA256WithRSA
	rsaKey.ECCAttributes = nil
	rsaKey.RSAAttributes = &types.RSAAttributes{KeySize: 2048}
	_, err := f.h.TPM.CreateRSA(rsaKey, f.h.Backend, false)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("rsa under the boot policy"))
	_, err = f.h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{KeyAttributes: rsaKey, Backend: f.h.Backend})
	require.NoError(t, err)

	secretKey := f.withPolicy(f.keyAttrs("bound-secret", nil))
	require.NoError(t, f.h.TPM.CreateSecretKey(secretKey, f.h.Backend))
	binding, err := f.h.TPM.loadPolicyBinding(secretKey, f.h.Backend)
	require.NoError(t, err)
	require.NotNil(t, binding)
	assert.Equal(t, testPolicyName, binding.Policy)
}

// TestSignApproval_Errors proves the authority helpers refuse inputs they
// cannot turn into a verifiable approval.
func TestSignApproval_Errors(t *testing.T) {
	f := newPolicyFixture(t)

	_, err := f.h.TPM.SignApproval(f.authority, f.h.Backend, []byte("not a digest"))
	require.ErrorIs(t, err, ErrInvalidAuthoritySignature)

	_, _, err = f.h.TPM.AuthorityName(f.keyAttrs("no-such-authority", nil), f.h.Backend)
	require.ErrorIs(t, err, storage.ErrNotFound)

	_, _, err = f.h.TPM.AuthorityName(nil, f.h.Backend)
	require.ErrorIs(t, err, store.ErrInvalidKeyAttributes)
}

// TestCreateStorageKey_ParentForChildKeys proves a storage key created under
// the Platform SRK with its own auth value can be loaded and used as the
// parent of further keys, authorized by that auth value.
func TestCreateStorageKey_ParentForChildKeys(t *testing.T) {
	f := newPolicyFixture(t)

	storageKey := &types.KeyAttributes{
		CN:            "tenant-a-storage",
		KeyAlgorithm:  x509.RSA,
		KeyType:       types.KeyTypeStorage,
		Parent:        f.srk,
		Password:      mustPassword([]byte("tenant-a-storage-secret")),
		StoreType:     types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{Hierarchy: tpm2.TPMRHOwner},
	}
	require.NoError(t, f.h.TPM.CreateStorageKey(storageKey, f.h.Backend))
	assert.True(t, storageKey.TPMAttributes.Public.ObjectAttributes.Restricted)
	assert.True(t, storageKey.TPMAttributes.Public.ObjectAttributes.Decrypt)

	loaded, err := f.h.TPM.LoadKeyPair(storageKey, nil, f.h.Backend)
	require.NoError(t, err)
	defer f.h.TPM.Flush(loaded.ObjectHandle)
	storageKey.TPMAttributes.Handle = loaded.ObjectHandle
	storageKey.TPMAttributes.Name = loaded.Name

	child := f.keyAttrs("tenant-a-child", nil)
	child.Parent = storageKey
	_, err = f.h.TPM.CreateECDSA(child, f.h.Backend, false)
	require.NoError(t, err)
	require.NoError(t, f.sign(child))

	wrongSecret := *storageKey
	wrongSecret.Password = mustPassword([]byte("another tenant's secret"))
	child.Parent = &wrongSecret
	require.Error(t, f.sign(child), "a child cannot be loaded without its parent's secret")
}

// TestCreateStorageKey_RejectsMissingParent proves a storage key needs a
// parent.
func TestCreateStorageKey_RejectsMissingParent(t *testing.T) {
	h := newSimHarness(t, nil)
	err := h.TPM.CreateStorageKey(&types.KeyAttributes{CN: "orphan"}, h.Backend)
	require.ErrorIs(t, err, store.ErrInvalidParentAttributes)
	require.ErrorIs(t, h.TPM.CreateStorageKey(nil, h.Backend), store.ErrInvalidKeyAttributes)
}

// TestAuthorizedPolicy_SealedObjectFromBlobsInCallerStore proves a sealed
// object whose blobs the caller presents in memory is authorized by the
// binding record in the key store the caller names -- a tenant's store --
// not the TPM's default store, where no record exists for it.
func TestAuthorizedPolicy_SealedObjectFromBlobsInCallerStore(t *testing.T) {
	f := newPolicyFixture(t)
	tenantStore := store.NewFileBackend(f.h.Logger, storage.NewMemory())

	secret := []byte("sealed in a tenant's store")
	attrs := sealedKeyAttrsUnder(f.srk, "tenant-sealed", nil)
	attrs.TPMPolicy = testPolicyName
	attrs.SealData = types.NewSealData(secret)
	_, err := f.h.TPM.SealKey(attrs, tenantStore, false)
	require.NoError(t, err)

	pub, err := tenantStore.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	require.NoError(t, err)
	priv, err := tenantStore.Get(attrs, store.FSEXT_PRIVATE_BLOB)
	require.NoError(t, err)

	unsealAttrs := sealedKeyAttrsUnder(f.srk, "tenant-sealed", nil)
	got, err := f.h.TPM.Unseal(context.Background(),
		&types.SealedData{Backend: types.BackendTypeTPM2, TPMPublic: pub, TPMPrivate: priv},
		&types.UnsealOptions{KeyAttributes: unsealAttrs, Backend: tenantStore})
	require.NoError(t, err)
	assert.Equal(t, secret, got)
}

// TestSymmetricKey_UnderATenantStorageKey proves a symmetric key can live
// under a tenant's storage key (a child of the Platform SRK) in the tenant's
// own key store -- a shared-mode tenant's symmetric keys -- while a
// symmetric key parented on the Shared SRK is still refused.
func TestSymmetricKey_UnderATenantStorageKey(t *testing.T) {
	f := newPolicyFixture(t)
	tenantStore := store.NewFileBackend(f.h.Logger, storage.NewMemory())

	storageKey := &types.KeyAttributes{
		CN:            "acme-storage",
		KeyAlgorithm:  x509.RSA,
		KeyType:       types.KeyTypeStorage,
		Parent:        f.srk,
		Password:      mustPassword([]byte("acme-storage-secret")),
		StoreType:     types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{Hierarchy: tpm2.TPMRHOwner},
	}
	require.NoError(t, f.h.TPM.CreateStorageKey(storageKey, tenantStore))
	loaded, err := f.h.TPM.LoadKeyPair(storageKey, nil, tenantStore)
	require.NoError(t, err)
	defer f.h.TPM.Flush(loaded.ObjectHandle)
	storageKey.TPMAttributes.Handle = loaded.ObjectHandle
	storageKey.TPMAttributes.Name = loaded.Name

	attrs := psrkSymmetricAttrs("acme-aes", storageKey)
	_, err = f.h.TPM.GenerateSymmetricKeyIn(attrs, tenantStore)
	require.NoError(t, err)
	_, err = f.h.Backend.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	require.Error(t, err, "the key lives in the tenant's store, not the default one")

	encrypter, err := f.h.TPM.SymmetricEncrypterIn(attrs, tenantStore)
	require.NoError(t, err)
	encrypted, err := encrypter.Encrypt([]byte("tenant data"), nil)
	require.NoError(t, err)
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("tenant data"), decrypted)

	ssrk, err := f.h.TPM.SSRKAttributes()
	require.NoError(t, err)
	_, err = f.h.TPM.GenerateSymmetricKeyIn(psrkSymmetricAttrs("ssrk-aes", ssrk), tenantStore)
	require.ErrorIs(t, err, ErrSymmetricKeyParent)

	notStorage := *storageKey
	notStorage.KeyType = types.KeyTypeSigning
	_, err = f.h.TPM.GenerateSymmetricKeyIn(psrkSymmetricAttrs("bad-parent-aes", &notStorage), tenantStore)
	require.ErrorIs(t, err, ErrSymmetricKeyParent)
}
