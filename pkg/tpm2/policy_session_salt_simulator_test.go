//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"bytes"
	"context"
	"crypto/fips140"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file run under whatever FIPS 140 mode the process is in,
// and must pass both by default and under GODEBUG=fips140=only. Arranging the
// TPM (provisioning, key creation, sealing, NV definition) uses AES-CFB
// parameter encryption, which FIPS 140-only mode refuses, so arrangement runs
// inside fips140.WithoutEnforcement. The policy session under test does not:
// an unsalted one has an Empty Buffer session key, and authorizing a command
// with it panics in crypto/hmac under fips140=only (#1531).

// sessionStartRecorder records the tpmKey of every policy session started
// through it, so a test can prove the session was salted.
type sessionStartRecorder struct {
	inner     transport.TPM
	saltKeys  []tpm2.TPMHandle
	malformed int
}

// Send records the tpmKey of a TPM2_StartAuthSession that starts a policy
// session, then forwards the command.
func (r *sessionStartRecorder) Send(input []byte) ([]byte, error) {
	if tpmKey, sessionType, ok := parseStartAuthSession(input); ok {
		if sessionType == tpm2.TPMSEPolicy {
			r.saltKeys = append(r.saltKeys, tpmKey)
		}
	} else if commandCode(input) == tpm2.TPMCCStartAuthSession {
		r.malformed++
	}
	return r.inner.Send(input)
}

// commandCode returns the command code of a marshalled command.
func commandCode(input []byte) tpm2.TPMCC {
	if len(input) < tpmCCOffset+4 {
		return 0
	}
	return tpm2.TPMCC(binary.BigEndian.Uint32(input[tpmCCOffset : tpmCCOffset+4]))
}

// parseStartAuthSession returns the tpmKey handle and sessionType of a
// marshalled TPM2_StartAuthSession (TPM 2.0 Part 3 §11.1).
func parseStartAuthSession(input []byte) (tpm2.TPMHandle, tpm2.TPMSE, bool) {
	if commandCode(input) != tpm2.TPMCCStartAuthSession {
		return 0, 0, false
	}
	const handlesOffset = tpmCCOffset + 4
	if len(input) < handlesOffset+8 {
		return 0, 0, false
	}
	tpmKey := tpm2.TPMHandle(binary.BigEndian.Uint32(input[handlesOffset:]))
	offset := handlesOffset + 8
	if tpm2.TPMISTCommandTag(binary.BigEndian.Uint16(input)) == tpm2.TPMSTSessions {
		if len(input) < offset+4 {
			return 0, 0, false
		}
		offset += 4 + int(binary.BigEndian.Uint32(input[offset:]))
	}
	// nonceCaller and encryptedSalt are TPM2B values ahead of sessionType.
	for range 2 {
		if len(input) < offset+2 {
			return 0, 0, false
		}
		offset += 2 + int(binary.BigEndian.Uint16(input[offset:]))
	}
	if len(input) < offset+1 {
		return 0, 0, false
	}
	return tpmKey, tpm2.TPMSE(input[offset]), true
}

// saltedSessionSite is one place that starts a policy session to authorize a
// command.
type saltedSessionSite struct {
	name string
	// arrange prepares a TPM, outside FIPS enforcement, and returns it with
	// the operation under test.
	arrange func(t *testing.T) (*TPM2, func(t *testing.T) error)
	// lead is the typed error the site reports a session failure as; nil
	// when the site returns the session error unwrapped.
	lead error
}

// saltedSessionSites lists every policy session that authorizes a command.
func saltedSessionSites() []saltedSessionSite {
	return []saltedSessionSite{
		{
			name: "DevIDAdminSession authorizes Certify",
			arrange: func(t *testing.T) (*TPM2, func(t *testing.T) error) {
				var (
					h                      *simHarness
					public                 *tpm2.TPMTPublic
					name                   tpm2.TPM2BName
					iakAuth, hierarchyAuth []byte
				)
				fips140.WithoutEnforcement(func() {
					h, public, name, iakAuth, hierarchyAuth = createPlatformPolicyIDevID(t)
				})
				return h.TPM, func(t *testing.T) error {
					session, closer, err := h.TPM.DevIDAdminSession(
						DevIDKeySigning, public.NameAlg, tpm2.TPMCCCertify, hierarchyAuth)
					if err != nil {
						assert.Nil(t, session)
						return err
					}
					defer h.TPM.closeSession(closer, "test DevID admin")
					return certifyIDevID(h, name, session, iakAuth)
				}
			},
			lead: ErrDevIDPolicySession,
		},
		{
			name: "NonceSession authorizes Unseal",
			arrange: func(t *testing.T) (*TPM2, func(t *testing.T) error) {
				// PolicySecret(TPM_RH_ENDORSEMENT), the policy a nonce session
				// satisfies.
				h, loaded, secret := sealUnderPolicy(t, "salted-nonce-session", func(*simHarness) []byte {
					digest, err := hex.DecodeString(tcgPolicyUser[tpm2.TPMAlgSHA256])
					require.NoError(t, err)
					return digest
				})
				return h.TPM, func(t *testing.T) error {
					session, closer, err := h.TPM.NonceSession(nil)
					if err != nil {
						assert.Nil(t, session)
						return err
					}
					defer h.TPM.closeSession(closer, "test nonce")
					return unsealWith(t, h, loaded, session, secret)
				}
			},
		},
		{
			name: "WriteDevIDDelegationPolicy authorizes NV_Write",
			arrange: func(t *testing.T) (*TPM2, func(t *testing.T) error) {
				var (
					h          *delegationHarness
					delegation DevIDDelegation
				)
				fips140.WithoutEnforcement(func() {
					h = newDelegationHarness(t, nil)
					var err error
					delegation, err = DevIDSigningDelegation(tpm2.TPMAlgSHA256, tpm2.TPMCCSign)
					require.NoError(t, err)
					require.NoError(t, h.TPM.DefineDevIDPolicyNV(DevIDKeySigning, tpm2.TPMAlgSHA256, h.HierarchyAuth))
				})
				return h.TPM, func(t *testing.T) error {
					return h.TPM.WriteDevIDDelegationPolicy(
						DevIDKeySigning, tpm2.TPMAlgSHA256, delegation.Digest, h.HierarchyAuth)
				}
			},
			lead: ErrDevIDDelegation,
		},
		{
			name: "ReadPolicyIndex authorizes NV_Read",
			arrange: func(t *testing.T) (*TPM2, func(t *testing.T) error) {
				var (
					h     *simHarness
					index tpm2.TPMHandle
				)
				digest := bytes.Repeat([]byte{0xA5}, 32)
				fips140.WithoutEnforcement(func() {
					h = newSimHarness(t, nil)
					var err error
					index, err = h.TPM.FindFreeNVIndex(NVOwnerIndexFirst, NVOwnerIndexLast)
					require.NoError(t, err)
					_, err = h.TPM.DefinePolicyIndex(index, tpm2.TPMAlgSHA256, policyWriteAuth, nil)
					require.NoError(t, err)
					_, err = h.TPM.WritePolicyIndex(index, policyWriteAuth, digest, tpm2.TPMAlgSHA256)
					require.NoError(t, err)
				})
				return h.TPM, func(t *testing.T) error {
					_, got, err := h.TPM.ReadPolicyIndex(index)
					if err == nil {
						assert.Equal(t, digest, got)
					}
					return err
				}
			},
		},
		{
			name: "platformPCRSession authorizes Unseal",
			arrange: func(t *testing.T) (*TPM2, func(t *testing.T) error) {
				h, loaded, secret := sealUnderPolicy(t, "salted-pcr-session", func(h *simHarness) []byte {
					digest, err := h.TPM.platformPCRPolicyDigest()
					require.NoError(t, err)
					return digest.Buffer
				})
				return h.TPM, func(t *testing.T) error {
					session, closer, err := h.TPM.platformPCRSession()
					if err != nil {
						assert.Nil(t, session)
						return err
					}
					defer h.TPM.closeSession(closer, "test platform PCR")
					return unsealWith(t, h, loaded, session, secret)
				}
			},
			lead: ErrPlatformPolicySession,
		},
		{
			name: "activateCredential authorizes ActivateCredential with the EK",
			arrange: func(t *testing.T) (*TPM2, func(t *testing.T) error) {
				var (
					h         *simHarness
					ekAttrs   *types.KeyAttributes
					key       *ActivationKey
					challenge *CredentialChallenge
					secret    []byte
				)
				fips140.WithoutEnforcement(func() {
					h = newSimHarness(t, nil)
					var err error
					ekAttrs, err = h.TPM.EKAttributes()
					require.NoError(t, err)
					key, err = h.TPM.CreateActivationKey()
					require.NoError(t, err)
					t.Cleanup(func() { h.TPM.flushSilent(key.Handle) })
					ekPub, err := h.TPM.EKRSA()
					require.NoError(t, err)
					challenge, secret, err = NewCredentialChallenge(ekPub, key.Name.Buffer)
					require.NoError(t, err)
				})
				return h.TPM, func(t *testing.T) error {
					var (
						got []byte
						err error
					)
					// ActivateCredential returns the credential under AES-CFB
					// parameter encryption, which FIPS 140-only mode refuses;
					// the salting of its EK policy session is proven by the
					// recorder instead.
					fips140.WithoutEnforcement(func() {
						got, err = h.TPM.activateCredential(ekAttrs, key.Handle, key.Name,
							tpm2.PasswordAuth(nil), challenge.CredentialBlob, challenge.EncryptedSecret)
					})
					if err == nil {
						assert.Equal(t, secret, got)
					}
					return err
				}
			},
		},
	}
}

// sealUnderPolicy seals a secret, outside FIPS enforcement, under the policy
// digest returns, and loads it. It returns the harness, the loaded object and
// the secret.
func sealUnderPolicy(t *testing.T, cn string, digest func(*simHarness) []byte) (*simHarness, *tpm2.LoadResponse, []byte) {
	t.Helper()
	var (
		h      *simHarness
		loaded *tpm2.LoadResponse
	)
	secret := []byte(cn)
	fips140.WithoutEnforcement(func() {
		h = newSimHarness(t, nil)
		attrs := sealedKeyAttrs(t, h, cn, false, nil)
		_, err := h.TPM.Seal(context.Background(), secret, &types.SealOptions{
			KeyAttributes: attrs,
			AuthPolicy:    digest(h),
		})
		require.NoError(t, err)
		loaded = loadSealedObject(t, h, attrs)
	})
	return h, loaded, secret
}

// unsealWith unseals loaded under session and checks it returns secret.
func unsealWith(t *testing.T, h *simHarness, loaded *tpm2.LoadResponse, session tpm2.Session, secret []byte) error {
	out, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{Handle: loaded.ObjectHandle, Name: loaded.Name, Auth: session},
	}.Execute(h.TPM.transport)
	if err != nil {
		return err
	}
	assert.Equal(t, secret, out.OutData.Buffer)
	return nil
}

// TestPolicySessions_AreSalted proves every policy session that authorizes a
// command is salted, and that the command it authorizes succeeds, under the
// process's FIPS 140 mode.
func TestPolicySessions_AreSalted(t *testing.T) {
	for _, site := range saltedSessionSites() {
		t.Run(site.name, func(t *testing.T) {
			tpm, run := site.arrange(t)
			recorder := &sessionStartRecorder{inner: tpm.transport}
			tpm.transport = recorder
			t.Cleanup(func() { tpm.transport = recorder.inner })

			require.NoError(t, run(t))
			require.Zero(t, recorder.malformed, "every TPM2_StartAuthSession must parse")
			require.NotEmpty(t, recorder.saltKeys, "the operation must start a policy session")
			for _, saltKey := range recorder.saltKeys {
				assert.NotEqual(t, tpm2.TPMRHNull, saltKey,
					"a policy session that authorizes a command must be salted (#1531)")
			}
		})
	}
}

// TestPolicySessions_SaltKeyFailure proves a site whose salt key cannot be
// read reports ErrSaltKey, wrapped in its own typed error, and leaves no
// session loaded on the TPM.
func TestPolicySessions_SaltKeyFailure(t *testing.T) {
	for _, site := range saltedSessionSites() {
		t.Run(site.name, func(t *testing.T) {
			tpm, run := site.arrange(t)
			// The persistent EK is the salt key, read by TPM2_ReadPublic.
			faulty := &createFaultyTransport{inner: tpm.transport, failCC: tpm2.TPMCCReadPublic}
			tpm.transport = faulty
			t.Cleanup(func() { tpm.transport = faulty.inner })
			loadedBefore := loadedSessionCount(t, faulty.inner)

			err := run(t)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrSaltKey)
			if site.lead != nil {
				assert.ErrorIs(t, err, site.lead)
			}
			assert.Positive(t, faulty.failCount, "the fault must have fired on the salt key read")
			assert.Equal(t, loadedBefore, loadedSessionCount(t, faulty.inner),
				"a failed salt key must leave no session loaded")
		})
	}
}
