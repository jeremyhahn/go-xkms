//go:build tpm_simulator

package tpm2

import (
	"log/slog"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/internal/secretscan"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestNoSecretLogged_AtAnyLevel drives every operation that handles a secret
// or an authorization value -- SRK creation under distinct hierarchy and user
// auth, sealing and unsealing, an NV secret write, credential activation and
// SO PIN provisioning -- with a Debug recorder on both the TPM's logger and
// the process default, then requires that none of those values was logged in
// any form (CA m417).
func TestNoSecretLogged_AtAnyLevel(t *testing.T) {
	rec := secretscan.NewRecorder()
	logger := slog.New(rec)
	previous := slog.Default()
	slog.SetDefault(logger)
	t.Cleanup(func() { slog.SetDefault(previous) })

	h := newSimHarnessWithLogger(t, nil, nil, logger)

	secrets := map[string][]byte{
		"the hierarchy auth (SO PIN)": []byte("hier-auth-m417-4be1c9d07a"),
		"the SRK user auth":           []byte("user-auth-m417-93f2ad6e18"),
		"the sealed object auth":      []byte("object-auth-m417-0c7b5e21"),
		"the sealed HMAC secret":      []byte("sealed-SECRET-m417-6d2a90"),
		"the NV secret":               []byte("nv-SECRET-m417-e81f37c4"),
		"the credential secret":       []byte("cred-SECRET-m417-32-bytes-1a2b3c"),
		"the external-EK credential":  []byte("ext-SECRET-m417-32-bytes-9f8e7d6"),
		"the provisioning SO PIN":     []byte("prov-so-pin-m417-58e0a3b1"),
	}

	// CreateSRK with distinct hierarchy and user auth, after the owner
	// hierarchy auth is changed to the SO PIN.
	psrkAttrs := createPSRK(t, h, secrets["the hierarchy auth (SO PIN)"], secrets["the SRK user auth"])

	// Seal and unseal an HMAC secret under its own object auth.
	keyAttrs := &types.KeyAttributes{
		CN:        "m417-no-secret-logs-seal",
		KeyType:   types.KeyTypeHMAC,
		Parent:    psrkAttrs,
		Password:  mustPassword(t, secrets["the sealed object auth"]),
		TPMPolicy: types.TPMPolicyPlatform,
		SealData:  types.NewSealData(secrets["the sealed HMAC secret"]),
		StoreType: types.StoreTPM2,
	}
	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)
	unsealed, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err)
	require.Equal(t, secrets["the sealed HMAC secret"], unsealed)

	// Write and read back an NV secret under the owner hierarchy auth.
	ekAttrs, err := h.TPM.EKAttributes()
	require.NoError(t, err)
	parent := *ekAttrs
	tpmAttrs := *ekAttrs.TPMAttributes
	tpmAttrs.HierarchyAuth = mustPassword(t, secrets["the hierarchy auth (SO PIN)"])
	parent.TPMAttributes = &tpmAttrs
	nvAttrs := &types.KeyAttributes{
		Parent:   &parent,
		SealData: types.NewSealData(secrets["the NV secret"]),
		TPMAttributes: &types.TPMAttributes{
			Handle:    tpm2.TPMHandle(nvramOwnerIndex),
			HashAlg:   tpm2.TPMAlgSHA256,
			Hierarchy: tpm2.TPMRHOwner,
		},
	}
	require.NoError(t, h.TPM.NVWrite(nvAttrs))
	nvRead, err := h.TPM.NVRead(nvAttrs, uint16(len(secrets["the NV secret"])))
	require.NoError(t, err)
	require.Equal(t, secrets["the NV secret"], nvRead)

	// MakeCredential / ActivateCredential, with the local and an external EK.
	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)
	blob, encSecret, _, err := h.TPM.MakeCredential(iakAttrs.TPMAttributes.Name, secrets["the credential secret"])
	require.NoError(t, err)
	recovered, err := h.TPM.ActivateCredential(blob, encSecret)
	require.NoError(t, err)
	require.Equal(t, secrets["the credential secret"], recovered)

	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	_, iakTPMPub, err := h.TPM.ReadHandle(iakAttrs.TPMAttributes.Handle)
	require.NoError(t, err)
	iak2B := tpm2.New2B(iakTPMPub)
	blob, encSecret, _, err = h.TPM.MakeCredentialWithExternalEK(
		selfSignedCertForKey(t, ekPub), iak2B.Bytes(), secrets["the external-EK credential"])
	require.NoError(t, err)
	recovered, err = h.TPM.ActivateCredential(blob, encSecret)
	require.NoError(t, err)
	require.Equal(t, secrets["the external-EK credential"], recovered)

	// Hierarchy-auth provisioning with an SO PIN: clears the TPM and sets
	// the lockout, endorsement and owner auth.
	require.NoError(t, h.TPM.Provision(mustPassword(t, secrets["the provisioning SO PIN"])))

	output := rec.Output()
	require.Contains(t, output, `"msg":"CreateSRK"`,
		"the recorder must see the TPM's Debug records, or the scan proves nothing")
	for name, secret := range secrets {
		secretscan.RequireAbsent(t, output, name, secret)
	}
}
