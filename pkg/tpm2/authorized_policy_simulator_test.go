//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
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
	mu                  sync.Mutex
	indices             map[string]tpm2.TPMHandle
	authValueConditions map[string]bool
	hashAlg             tpm2.TPMAlgID
	approvals           map[string][]*PolicyApproval
	requested           []string
}

func newTestPolicyResolver() *testPolicyResolver {
	return &testPolicyResolver{
		indices:             make(map[string]tpm2.TPMHandle),
		authValueConditions: make(map[string]bool),
		hashAlg:             tpm2.TPMAlgSHA256,
		approvals:           make(map[string][]*PolicyApproval),
	}
}

func (r *testPolicyResolver) PolicyIndex(scope, name string) (PolicyIndexInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requested = append(r.requested, scope+"/"+name)
	index, ok := r.indices[scope+"/"+name]
	if !ok {
		return PolicyIndexInfo{}, errUnknownTestPolicy
	}
	return PolicyIndexInfo{
		Index:              index,
		HashAlg:            r.hashAlg,
		AuthValueCondition: r.authValueConditions[scope+"/"+name],
	}, nil
}

func (r *testPolicyResolver) Approvals(scope, name string) ([]*PolicyApproval, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	approvals, ok := r.approvals[scope+"/"+name]
	if !ok {
		return nil, errUnknownTestPolicy
	}
	return approvals, nil
}

func (r *testPolicyResolver) setApprovals(scope, name string, approvals []*PolicyApproval) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.approvals[scope+"/"+name] = approvals
}

// branchSpec describes one branch of the fixture's policy: a pcr condition
// approves the live value of testPolicyPCR, and localities, when set, is a
// locality condition.
type branchSpec struct {
	pcr        bool
	authValue  bool
	localities []uint
}

// pcrOnly is the single-branch policy every pre-composite test used.
var pcrOnly = []branchSpec{{pcr: true}}

// policyFixture is a provisioned simulator with one named policy, "boot" in
// the system scope, bound to an authority under the Platform SRK and with
// every branch approved at the counter's current epoch.
type policyFixture struct {
	h         *simHarness
	srk       *types.KeyAttributes
	resolver  *testPolicyResolver
	counter   tpm2.TPMHandle
	index     tpm2.TPMHandle
	authority *types.KeyAttributes
	branches  []branchSpec
}

// newPolicyFixture builds the fixture with a single pcr branch.
func newPolicyFixture(t *testing.T) *policyFixture {
	t.Helper()
	return newCompositePolicyFixture(t, pcrOnly...)
}

// newCompositePolicyFixture builds the fixture with the given branches.
func newCompositePolicyFixture(t *testing.T, branches ...branchSpec) *policyFixture {
	t.Helper()
	h := newSimHarness(t, nil)
	f := &policyFixture{
		h:        h,
		srk:      createPlatformPolicySRK(t, h, mustPassword(t, []byte("platform-srk-pin"))),
		resolver: newTestPolicyResolver(),
		branches: branches,
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

	key := SystemPolicyScope + "/" + testPolicyName
	f.resolver.indices[key] = f.index
	for _, b := range branches {
		f.resolver.authValueConditions[key] = f.resolver.authValueConditions[key] || b.authValue
	}
	h.TPM.SetPolicyBindingResolver(f.resolver)
	f.resolver.setApprovals(SystemPolicyScope, testPolicyName, f.approve(t, f.authority))
	return f
}

// createAuthority creates an ECDSA P-256 authority under the Platform SRK,
// bound to the platform policy and carrying its own auth value.
func (f *policyFixture) createAuthority(t *testing.T, cn string) *types.KeyAttributes {
	t.Helper()
	attrs := f.keyAttrs(cn, mustPassword(t, []byte(cn+"-auth-value")))
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

// branch builds the PolicyBranch of spec over the live PCRs. The conditions
// are listed auth value first, the reverse of canonical order, so every test
// also proves the order they are listed in does not matter.
func (f *policyFixture) branch(t *testing.T, spec branchSpec) PolicyBranch {
	t.Helper()
	var b PolicyBranch
	if spec.authValue {
		b.Conditions = append(b.Conditions, PolicyCondition{Type: PolicyConditionAuthValue})
	}
	if spec.pcr {
		b.Conditions = append(b.Conditions, PolicyCondition{
			Type:         PolicyConditionPCR,
			PCRSelection: PolicyPCRSelection(tpm2.TPMAlgSHA256, testPolicyPCR),
			PCRDigest:    f.livePCRDigest(t),
		})
	}
	if len(spec.localities) > 0 {
		locality, err := PolicyLocalitySelection(spec.localities...)
		require.NoError(t, err)
		b.Conditions = append(b.Conditions, PolicyCondition{Type: PolicyConditionLocality, Locality: locality})
	}
	return b
}

// approve signs, with authority, an approval of every branch of the fixture's
// policy over the live PCRs at the counter's current epoch.
func (f *policyFixture) approve(t *testing.T, authority *types.KeyAttributes) []*PolicyApproval {
	t.Helper()
	tpm := f.h.TPM

	epoch, err := tpm.ReadCounter(f.counter)
	require.NoError(t, err)
	counterName, err := tpm.NVIndexName(f.counter)
	require.NoError(t, err)
	_, public, err := tpm.AuthorityName(authority, f.h.Backend)
	require.NoError(t, err)
	ref := PolicyRef(SystemPolicyScope, testPolicyName)

	approvals := make([]*PolicyApproval, 0, len(f.branches))
	for _, spec := range f.branches {
		branch := f.branch(t, spec)
		approved, err := ApprovedPolicyDigest(tpm2.TPMAlgSHA256, branch, counterName, epoch)
		require.NoError(t, err)
		aHash, err := ApprovalDigest(tpm2.TPMAlgSHA256, approved, ref)
		require.NoError(t, err)
		signature, err := tpm.SignApproval(authority, f.h.Backend, aHash)
		require.NoError(t, err)
		approvals = append(approvals, &PolicyApproval{
			HashAlg:         tpm2.TPMAlgSHA256,
			Branch:          branch,
			Counter:         f.counter,
			Epoch:           epoch,
			PolicyRef:       ref,
			AuthorityPublic: public,
			Signature:       *signature,
			Index:           f.index,
		})
	}
	return approvals
}

// currentApprovals returns the approvals the resolver holds.
func (f *policyFixture) currentApprovals(t *testing.T) []*PolicyApproval {
	t.Helper()
	approvals, err := f.resolver.Approvals(SystemPolicyScope, testPolicyName)
	require.NoError(t, err)
	return approvals
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

// update re-approves every branch over the live PCRs at the next epoch, as a
// policy update does, and returns the new approvals.
func (f *policyFixture) update(t *testing.T, authority *types.KeyAttributes) []*PolicyApproval {
	t.Helper()
	_, err := f.h.TPM.IncrementCounter(f.counter, policyWriteAuth)
	require.NoError(t, err)
	approvals := f.approve(t, authority)
	f.resolver.setApprovals(SystemPolicyScope, testPolicyName, approvals)
	return approvals
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

// withPassword returns a copy of key that presents password.
func withPassword(t testing.TB, key *types.KeyAttributes, password string) *types.KeyAttributes {
	c := *key
	c.Password = mustPassword(t, []byte(password))
	return &c
}

// TestAuthorizedPolicy_DigestsMatchLiveSession proves every trial digest the
// package computes is the digest a real session reaches at the same step:
// ApprovedPolicyDigest after a composite branch's assertions (listed out of
// canonical order) and PolicyNV, AuthorizeDigest (the index content) after
// PolicyAuthorize, and AuthorizedObjectPolicy's branch and OR digests after
// PolicyAuthorizeNV and PolicyOR.
func TestAuthorizedPolicy_DigestsMatchLiveSession(t *testing.T) {
	f := newCompositePolicyFixture(t, branchSpec{pcr: true, authValue: true, localities: []uint{0, 2}})
	tpm := f.h.TPM
	approval := f.currentApprovals(t)[0]

	session, closer, err := tpm2.PolicySession(tpm.transport, tpm2.TPMAlgSHA256, sessionNonceSize)
	require.NoError(t, err)
	defer func() { require.NoError(t, closer()) }()
	sessionDigest := func() []byte {
		rsp, err := tpm2.PolicyGetDigest{PolicySession: session.Handle()}.Execute(tpm.transport)
		require.NoError(t, err)
		return rsp.PolicyDigest.Buffer
	}

	require.NoError(t, tpm.assertBranch(session, approval.Branch, branchRef{}))
	counterName, err := tpm.NVIndexName(f.counter)
	require.NoError(t, err)
	require.NoError(t, tpm.policyNVEpoch(session, f.counter, counterName, approval.Epoch))
	approved, err := ApprovedPolicyDigest(tpm2.TPMAlgSHA256, approval.Branch, counterName, approval.Epoch)
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

// TestAuthorizedPolicy_PCRChangeRefusesApprovedBranch proves the TPM, not
// software, refuses the approved branch once the approved PCR moves, and that
// the refusal is reported as a PCR mismatch carrying the TPM's response code.
// The password branch does not depend on the approval and still signs.
func TestAuthorizedPolicy_PCRChangeRefusesApprovedBranch(t *testing.T) {
	f := newPolicyFixture(t)
	noPassword := f.createBoundKey(t, "pcr-no-password", nil)
	withPassword := f.createBoundKey(t, "pcr-with-password", mustPassword(t, []byte("bound-key-pin")))

	f.extendPolicyPCR(t)

	err := f.sign(noPassword)
	var mismatch *PolicyPCRMismatchError
	require.ErrorAs(t, err, &mismatch)
	assert.Equal(t, testPolicyName, mismatch.Policy)
	assert.ErrorIs(t, err, tpm2.TPMRCValue)
	var refused *PolicyBranchesRefusedError
	require.ErrorAs(t, err, &refused)
	assert.Len(t, refused.Branches, 1)

	require.NoError(t, f.sign(withPassword))
}

// TestAuthorizedPolicy_CompositeAND proves a policy of one branch requiring
// both the PCR state and the object's password is enforced as an AND: the
// key signs only with its password while the PCR holds. Its password alone
// does not sign, which proves the object got no outer PolicyAuthValue branch
// that would bypass the PCR condition, and the PCR alone does not sign.
func TestAuthorizedPolicy_CompositeAND(t *testing.T) {
	f := newCompositePolicyFixture(t, branchSpec{pcr: true, authValue: true})
	key := f.createBoundKey(t, "and-key", mustPassword(t, []byte("and-key-pin")))

	binding, err := f.h.TPM.loadPolicyBinding(key, f.h.Backend)
	require.NoError(t, err)
	assert.False(t, binding.AuthValueBranch, "no outer password branch")
	assert.True(t, binding.AuthValueCondition)

	require.NoError(t, f.sign(key), "password and PCR")

	err = f.sign(withoutPassword(key))
	var missing *PolicyAuthValueMissingError
	require.ErrorAs(t, err, &missing, "the PCR alone does not sign")
	assert.Equal(t, 0, missing.Branch)

	require.Error(t, f.sign(withPassword(t, key, "wrong-pin")), "a wrong password does not sign")

	f.extendPolicyPCR(t)
	var mismatch *PolicyPCRMismatchError
	require.ErrorAs(t, f.sign(key), &mismatch, "the password alone does not sign")
}

// TestAuthorizedPolicy_CompositeOR proves a policy of a pcr branch OR a
// password branch: the key signs without a password while the PCR holds,
// with its password once the PCR has moved, and never with a wrong one.
func TestAuthorizedPolicy_CompositeOR(t *testing.T) {
	f := newCompositePolicyFixture(t, branchSpec{pcr: true}, branchSpec{authValue: true})
	key := f.createBoundKey(t, "or-key", mustPassword(t, []byte("or-key-pin")))

	require.NoError(t, f.sign(withoutPassword(key)), "the PCR branch, no password")

	f.extendPolicyPCR(t)
	err := f.sign(withoutPassword(key))
	var refused *PolicyBranchesRefusedError
	require.ErrorAs(t, err, &refused)
	require.Len(t, refused.Branches, 2)
	var mismatch *PolicyPCRMismatchError
	require.ErrorAs(t, refused.Branches[0], &mismatch)
	var missing *PolicyAuthValueMissingError
	require.ErrorAs(t, refused.Branches[1], &missing)
	assert.Equal(t, 1, missing.Branch)

	require.NoError(t, f.sign(key), "the password branch after the PCR moved")
	err = f.sign(withPassword(t, key, "wrong-pin"))
	require.Error(t, err, "a wrong password does not sign")
	assert.ErrorIs(t, err, tpm2.TPMRCAuthFail)
}

// TestAuthorizedPolicy_Locality proves a locality condition allowing the
// command locality (0) signs, one allowing only locality 3 is refused with
// the locality error and moves on to the next branch.
func TestAuthorizedPolicy_Locality(t *testing.T) {
	t.Run("allowed", func(t *testing.T) {
		f := newCompositePolicyFixture(t, branchSpec{localities: []uint{0}})
		require.NoError(t, f.sign(f.createBoundKey(t, "locality-0", nil)))
	})
	t.Run("refused", func(t *testing.T) {
		f := newCompositePolicyFixture(t, branchSpec{localities: []uint{3}})
		err := f.sign(f.createBoundKey(t, "locality-3", nil))
		var mismatch *PolicyLocalityMismatchError
		require.ErrorAs(t, err, &mismatch)
		assert.Equal(t, uint8(commandLocality), mismatch.Locality)
		assert.True(t, mismatch.Allowed.TPMLocThree)
	})
	t.Run("next branch", func(t *testing.T) {
		f := newCompositePolicyFixture(t, branchSpec{localities: []uint{3}}, branchSpec{pcr: true, localities: []uint{0, 1}})
		require.NoError(t, f.sign(f.createBoundKey(t, "locality-or", nil)))
	})
}

// TestPolicyLocality_TPMEnforcesAtUse proves the TPM2_PolicyLocality command
// this package sends reaches its trial digest, and that the TPM itself
// refuses a session restricted to another locality when it authorizes a
// command (TPM_RC_LOCALITY) -- the session code's own check only chooses a
// branch.
func TestPolicyLocality_TPMEnforcesAtUse(t *testing.T) {
	h := newSimHarness(t, nil)
	for _, tc := range []struct {
		locality uint
		want     error
	}{
		{locality: 0},
		{locality: 3, want: tpm2.TPMRCLocality},
	} {
		allowed, err := PolicyLocalitySelection(tc.locality)
		require.NoError(t, err)
		authPolicy, err := trialDigest(tpm2.TPMAlgSHA256, policyLocality{Locality: allowed})
		require.NoError(t, err)
		key, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHNull, Auth: tpm2.PasswordAuth(nil)},
			InPublic:      tpm2.New2B(policySigningTemplate(authPolicy)),
		}.Execute(h.TPM.transport)
		require.NoError(t, err)

		// A salted session, as production starts it (#1532): FIPS 140-only
		// mode refuses an unsalted session with an empty auth value.
		session, closer, err := h.TPM.startPolicySession(tpm2.TPMAlgSHA256, nil)
		require.NoError(t, err)
		require.NoError(t, policyLocality{PolicySession: session.Handle(), Locality: allowed}.Execute(h.TPM.transport))
		digest, err := tpm2.PolicyGetDigest{PolicySession: session.Handle()}.Execute(h.TPM.transport)
		require.NoError(t, err)
		assert.Equal(t, authPolicy, digest.PolicyDigest.Buffer)

		message := sha256.Sum256([]byte("locality"))
		_, err = tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{Handle: key.ObjectHandle, Name: key.Name, Auth: session},
			Digest:    tpm2.TPM2BDigest{Buffer: message[:]},
			InScheme: tpm2.TPMTSigScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
			},
			Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
		}.Execute(h.TPM.transport)
		if tc.want == nil {
			require.NoError(t, err)
		} else {
			require.ErrorIs(t, err, tc.want)
		}
		require.NoError(t, closer())
		h.TPM.Flush(key.ObjectHandle)
	}
}

// policySigningTemplate is an ECDSA P-256 signing key usable only through
// authPolicy.
func policySigningTemplate(authPolicy []byte) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			SignEncrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: authPolicy},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			CurveID: tpm2.TPMECCNistP256,
			Scheme: tpm2.TPMTECCScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
	}
}

// TestAuthorizedPolicy_CompositeRequiresObjectPassword proves an object
// without a password cannot be bound to a policy with an auth_value
// condition, which an empty password would satisfy.
func TestAuthorizedPolicy_CompositeRequiresObjectPassword(t *testing.T) {
	f := newCompositePolicyFixture(t, branchSpec{pcr: true}, branchSpec{authValue: true})
	_, err := f.h.TPM.CreateECDSA(f.withPolicy(f.keyAttrs("no-password", nil)), f.h.Backend, false)
	require.ErrorIs(t, err, ErrPolicyAuthValueRequired)
}

// TestAuthorizedPolicy_UpdateReapprovesWithoutRekey proves a policy update --
// the next epoch, re-approving every branch over the new PCR value --
// restores the very same key blobs through each branch.
func TestAuthorizedPolicy_UpdateReapprovesWithoutRekey(t *testing.T) {
	f := newCompositePolicyFixture(t, branchSpec{pcr: true}, branchSpec{pcr: true, authValue: true})
	key := f.createBoundKey(t, "update-key", mustPassword(t, []byte("bound-key-pin")))
	privBefore := f.mustBlob(key, store.FSEXT_PRIVATE_BLOB)
	pubBefore := f.mustBlob(key, store.FSEXT_PUBLIC_BLOB)

	f.extendPolicyPCR(t)
	require.Error(t, f.sign(withoutPassword(key)))
	require.Error(t, f.sign(key))

	approvals := f.update(t, f.authority)
	require.Len(t, approvals, 2)
	for _, approval := range approvals {
		assert.Equal(t, uint64(2), approval.Epoch, "DefineCounterIndex leaves the counter at 1, the update moves it to 2")
	}

	require.NoError(t, f.sign(withoutPassword(key)), "branch 0 re-approved")
	f.resolver.setApprovals(SystemPolicyScope, testPolicyName, approvals[1:])
	require.NoError(t, f.sign(key), "branch 1 re-approved")
	assert.Equal(t, privBefore, f.mustBlob(key, store.FSEXT_PRIVATE_BLOB), "no re-key")
	assert.Equal(t, pubBefore, f.mustBlob(key, store.FSEXT_PUBLIC_BLOB), "no re-key")
}

// TestAuthorizedPolicy_ReplayOfSupersededApprovalRefused proves approvals
// from an earlier epoch are refused by the TPM (TPM2_PolicyNV), branch by
// branch, even when the PCR value they approved still holds, and are reported
// as revoked.
func TestAuthorizedPolicy_ReplayOfSupersededApprovalRefused(t *testing.T) {
	f := newCompositePolicyFixture(t, branchSpec{pcr: true}, branchSpec{localities: []uint{0}})
	key := f.createBoundKey(t, "replay-no-password", nil)

	old := f.currentApprovals(t)
	f.update(t, f.authority)
	require.NoError(t, f.sign(key))

	f.resolver.setApprovals(SystemPolicyScope, testPolicyName, old)
	err := f.sign(key)
	var refused *PolicyBranchesRefusedError
	require.ErrorAs(t, err, &refused)
	require.Len(t, refused.Branches, 2)
	for i, branchErr := range refused.Branches {
		var revoked *PolicyApprovalRevokedError
		require.ErrorAs(t, branchErr, &revoked)
		assert.Equal(t, old[i].Epoch, revoked.Epoch)
		assert.Equal(t, i, revoked.Branch)
		assert.ErrorIs(t, branchErr, tpm2.TPMRCPolicy)
	}
}

// TestAuthorizedPolicy_AuthorityRotation proves rewriting the policy index
// moves every bound key to a new authority without re-keying, and that
// approvals signed by the old authority no longer authorize them.
func TestAuthorizedPolicy_AuthorityRotation(t *testing.T) {
	f := newCompositePolicyFixture(t, branchSpec{localities: []uint{3}}, branchSpec{pcr: true})
	key := f.createBoundKey(t, "rotation-no-password", nil)
	require.NoError(t, f.sign(key))

	authority2 := f.createAuthority(t, "policy-authority-2")
	f.pointIndexAt(t, authority2)
	oldAuthority := f.update(t, f.authority)
	newAuthority := f.approve(t, authority2)

	f.resolver.setApprovals(SystemPolicyScope, testPolicyName, newAuthority)
	require.NoError(t, f.sign(key))

	f.resolver.setApprovals(SystemPolicyScope, testPolicyName, oldAuthority)
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
	key := f.createBoundKey(t, "binding-record", mustPassword(t, []byte("bound-key-pin")))

	binding, err := f.h.TPM.loadPolicyBinding(key, f.h.Backend)
	require.NoError(t, err)
	require.NotNil(t, binding)
	assert.NotEmpty(t, binding.Authority, "the record carries the scope authority")
	assert.Len(t, binding.Approvals, 1, "the record carries the policy's approval")
	binding.Authority, binding.Approvals = nil, nil
	assert.Equal(t, &store.TPMPolicyBinding{
		Scope:           SystemPolicyScope,
		Policy:          testPolicyName,
		Index:           uint32(f.index),
		HashAlg:         uint16(tpm2.TPMAlgSHA256),
		AuthValueBranch: true,
	}, binding)

	record, err := f.h.Backend.Get(key, store.FSEXT_TPM_POLICY)
	require.NoError(t, err)
	assert.Equal(t, store.TPMPolicyBindingVersion, record[4], "new records are the current version")

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
	require.ErrorIs(t, err, store.ErrBlobNotFound)

	_, _, err = f.h.TPM.AuthorityName(nil, f.h.Backend)
	require.ErrorIs(t, err, store.ErrInvalidKeyAttributes)
}

// TestCreateStorageKey_RejectsMissingParent proves a storage key needs a
// parent.
func TestCreateStorageKey_RejectsMissingParent(t *testing.T) {
	h := newSimHarness(t, nil)
	err := h.TPM.CreateStorageKey(&types.KeyAttributes{CN: "orphan"}, h.Backend)
	require.ErrorIs(t, err, store.ErrInvalidParentAttributes)
	require.ErrorIs(t, h.TPM.CreateStorageKey(nil, h.Backend), store.ErrInvalidKeyAttributes)
}

// TestSymmetricKey_UnderATenantStorageKey proves a symmetric key can live
// under a tenant's storage key (a child of the Platform SRK) in the tenant's
// own key store -- a shared-mode tenant's symmetric keys -- while a
// symmetric key parented on the Shared SRK is still refused.
func TestSymmetricKey_UnderATenantStorageKey(t *testing.T) {
	f := newPolicyFixture(t)
	tenantStore, err := f.h.Backend.Tenant("acme")
	require.NoError(t, err)

	storageKey := &types.KeyAttributes{
		CN:            "acme-storage",
		KeyAlgorithm:  x509.RSA,
		KeyType:       types.KeyTypeStorage,
		Parent:        f.srk,
		Password:      mustPassword(t, []byte("acme-storage-secret")),
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
