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
	"crypto/fips140"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/symmetric"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

// uniqueNonce returns n random bytes. The AEAD guard lives for the life of the
// test binary, so every test that is not about reuse brings fresh nonces.
func uniqueNonce(t *testing.T, n int) []byte {
	t.Helper()
	nonce := make([]byte, n)
	_, err := rand.Read(nonce)
	require.NoError(t, err)
	return nonce
}

// serviceWith installs stores as the service's backends and returns the
// service. The first store is the default backend.
func serviceWith(t *testing.T, stores ...*mockKeyStore) *XKMSService {
	t.Helper()
	Reset()
	t.Cleanup(Reset)

	backends := make(map[string]Backend, len(stores))
	for _, store := range stores {
		backends[store.name] = store
	}
	require.NoError(t, Initialize(&ServiceConfig{Backends: backends, DefaultBackend: stores[0].name}))

	svc, err := Get()
	require.NoError(t, err)
	return svc
}

// newSymmetricStore registers a symmetric key named cn, held by a real
// pkg/keyprovider/symmetric backend over keyStorage, in a mock store named
// name. When generate is false the key must already exist in keyStorage: the
// backend is then a fresh instance that learns of the key only by reading it,
// which is what a backend constructed after a restart is.
func newSymmetricStore(t *testing.T, name, cn string, alg types.SymmetricAlgorithm, keyStorage storage.Backend, tracker types.AEADSafetyTracker, generate bool) (*mockKeyStore, *types.KeyAttributes) {
	t.Helper()

	symBackend, err := symmetric.NewBackend(&symmetric.Config{KeyStorage: keyStorage, Tracker: tracker})
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:                 cn,
		KeyType:            types.KeyTypeSecret,
		StoreType:          types.ParseStoreType(name),
		SymmetricAlgorithm: alg,
	}
	if generate {
		_, err = symBackend.GenerateSymmetricKey(context.Background(), attrs)
		require.NoError(t, err)
	}

	store := newMockKeyStore(name)
	store.backend = symBackend
	store.keys[attrs.CN] = "placeholder"
	store.keyAttrs[attrs.CN] = attrs
	return store, attrs
}

// encryptWithNonce drives the Encrypt RPC with a caller-supplied nonce.
func encryptWithNonce(svc *XKMSService, store, keyID string, plaintext, nonce []byte) (*transport.EncryptResponse, error) {
	return svc.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend:   store,
		KeyID:     keyID,
		Plaintext: plaintext,
		Nonce:     nonce,
	})
}

// requireCallerNonceEncryptRefusedUnderFIPS is the GODEBUG=fips140=only half
// of every AES-GCM caller-nonce test: that mode has no arbitrary-IV GCM, so
// the premise of the test cannot arise and the encryption itself is refused.
func requireCallerNonceEncryptRefusedUnderFIPS(t *testing.T) {
	t.Helper()
	store, attrs := newUntrackedAESWrappingBackend(t, "fips-enc-be", "fips-enc-key")
	svc := serviceWith(t, store)
	_, err := encryptWithNonce(svc, store.name, attrs.CN, []byte("fips"), uniqueNonce(t, aesGCMNonceSize))
	require.Error(t, err, "a caller-supplied AES-GCM nonce needs the arbitrary-IV construction fips140=only refuses")
}

// TestEncryptRefusesAReusedCallerNonce is the probe for the flaw: one key, one
// caller-chosen nonce, two plaintexts. The first seal is compared with the
// standard library so the guard cannot pass by emitting something nobody can
// decrypt; the second must be refused before any ciphertext exists, because it
// would leak the XOR of the two plaintexts and the GHASH subkey.
func TestEncryptRefusesAReusedCallerNonce(t *testing.T) {
	if fips140.Enforced() {
		requireCallerNonceEncryptRefusedUnderFIPS(t)
		return
	}

	store, attrs := newUntrackedAESWrappingBackend(t, "enc-reuse-be", "enc-reuse-key")
	svc := serviceWith(t, store)
	key := rawKeyBytes(t, store, attrs)
	nonce := uniqueNonce(t, aesGCMNonceSize)

	plaintext := []byte("the victim's plaintext")
	first, err := encryptWithNonce(svc, store.name, attrs.CN, plaintext, nonce)
	require.NoError(t, err, "the first use of a nonce under a key is legitimate")
	assert.Equal(t, gcmSealOracle(t, key, nonce, plaintext, nil), append(first.Ciphertext, first.Tag...))

	second, err := encryptWithNonce(svc, store.name, attrs.CN, []byte("attacker's chosen text"), nonce)
	require.Error(t, err, "a second encryption under the same (key, nonce) must be refused")
	assert.Nil(t, second, "a refused encryption returns no ciphertext")
	assert.True(t, errors.Is(err, aead.ErrNonceReuse), "the refusal must name the reuse: got %v", err)
}

// TestEncryptRefusesAReusedNonceUnderChaCha20Poly1305 covers the other AEAD
// the Encrypt RPC serves. ChaCha20-Poly1305 fails exactly as GCM does under a
// repeated pair: the keystream repeats, and so does the one-time Poly1305 key.
func TestEncryptRefusesAReusedNonceUnderChaCha20Poly1305(t *testing.T) {
	store, attrs := newSymmetricStore(t, "chacha-be", "chacha-key", types.SymmetricChaCha20Poly1305,
		storage.New(), permissiveTracker{}, true)
	svc := serviceWith(t, store)
	nonce := uniqueNonce(t, chacha20poly1305.NonceSize)

	_, err := encryptWithNonce(svc, store.name, attrs.CN, []byte("first"), nonce)
	require.NoError(t, err)

	_, err = encryptWithNonce(svc, store.name, attrs.CN, []byte("second"), nonce)
	require.Error(t, err)
	assert.True(t, errors.Is(err, aead.ErrNonceReuse), "got %v", err)
}

// TestEncryptAcceptsDistinctNonces is the other half of the guard: a fresh
// nonce under the same key is an ordinary encryption.
func TestEncryptAcceptsDistinctNonces(t *testing.T) {
	store, attrs := newSymmetricStore(t, "distinct-be", "distinct-key", types.SymmetricChaCha20Poly1305,
		storage.New(), permissiveTracker{}, true)
	svc := serviceWith(t, store)

	for range 3 {
		_, err := encryptWithNonce(svc, store.name, attrs.CN, []byte("payload"), uniqueNonce(t, chacha20poly1305.NonceSize))
		require.NoError(t, err, "every fresh nonce must be accepted")
	}
}

// TestEncryptAdmitsExactlyOneOfConcurrentSameNonceCalls is the race the
// provider tracker loses: its check and its record are separate steps, so two
// callers presenting one nonce at once could both pass. The guard claims in
// one atomic step, so exactly one wins.
func TestEncryptAdmitsExactlyOneOfConcurrentSameNonceCalls(t *testing.T) {
	store, attrs := newSymmetricStore(t, "race-be", "race-key", types.SymmetricChaCha20Poly1305,
		storage.New(), permissiveTracker{}, true)
	svc := serviceWith(t, store)
	nonce := uniqueNonce(t, chacha20poly1305.NonceSize)

	const callers = 32
	var succeeded, refused atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := encryptWithNonce(svc, store.name, attrs.CN, []byte("racing"), nonce)
			switch {
			case err == nil:
				succeeded.Add(1)
			case errors.Is(err, aead.ErrNonceReuse):
				refused.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	assert.Equal(t, int32(1), succeeded.Load(), "exactly one caller may consume the pair")
	assert.Equal(t, int32(callers-1), refused.Load(), "every other caller is refused as a reuse")
}

// TestEncryptGuardsAKeyCreatedBeforeTheProcessStarted reproduces a restart: the
// key is generated by one backend instance, and the service encrypts through a
// second instance over the same storage that never generated it. That second
// instance's own tracker has no options registered for the key, so -- as the
// first half demonstrates -- it lets a repeated nonce straight through. The
// service guard does not depend on that registration.
func TestEncryptGuardsAKeyCreatedBeforeTheProcessStarted(t *testing.T) {
	keyStorage := storage.New()
	_, attrs := newSymmetricStore(t, "restart-be", "restart-key", types.SymmetricChaCha20Poly1305,
		keyStorage, nil, true)
	store, _ := newSymmetricStore(t, "restart-be", "restart-key", types.SymmetricChaCha20Poly1305,
		keyStorage, nil, false)

	// The premise: the reopened backend's own tracker does not see the key.
	symProvider, ok := store.KeyProvider().(types.SymmetricKeyProvider)
	require.True(t, ok)
	encrypter, err := symProvider.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)
	premiseNonce := uniqueNonce(t, chacha20poly1305.NonceSize)
	for range 2 {
		_, err = encrypter.Encrypt([]byte("premise"), &types.EncryptOptions{Nonce: premiseNonce})
		require.NoError(t, err, "the provider tracker only knows keys generated in this process")
	}

	svc := serviceWith(t, store)
	nonce := uniqueNonce(t, chacha20poly1305.NonceSize)
	_, err = encryptWithNonce(svc, store.name, attrs.CN, []byte("first"), nonce)
	require.NoError(t, err)
	_, err = encryptWithNonce(svc, store.name, attrs.CN, []byte("second"), nonce)
	require.Error(t, err, "a key the provider never registered is still guarded")
	assert.True(t, errors.Is(err, aead.ErrNonceReuse), "got %v", err)
}

// TestEncryptRefusesAReusedNonceAcrossTwoNamesForOneKey is why the identity is
// the key's material: one AES key imported into two backends under two names
// is one key to GCM, and a nonce used through either name is used for both.
func TestEncryptRefusesAReusedNonceAcrossTwoNamesForOneKey(t *testing.T) {
	if fips140.Enforced() {
		requireCallerNonceEncryptRefusedUnderFIPS(t)
		return
	}

	first, firstAttrs := newUntrackedAESWrappingBackend(t, "enc-alias-one", "enc-alias-key-one")
	second, secondAttrs := importAESWrappingKey(t, "enc-alias-two", "enc-alias-key-two", rawKeyBytes(t, first, firstAttrs))
	svc := serviceWith(t, first, second)
	nonce := uniqueNonce(t, aesGCMNonceSize)

	_, err := encryptWithNonce(svc, first.name, firstAttrs.CN, []byte("through the first name"), nonce)
	require.NoError(t, err)
	_, err = encryptWithNonce(svc, second.name, secondAttrs.CN, []byte("through the second name"), nonce)
	require.Error(t, err, "the second name reaches the same key material")
	assert.True(t, errors.Is(err, aead.ErrNonceReuse), "got %v", err)
}

// TestEncryptRecordsAGeneratedNonce closes the attack the issue describes: an
// encrypt-only caller copies the nonce off a victim's ciphertext and encrypts
// chosen plaintext under it. The generated nonce is recorded, so it cannot be
// presented again.
func TestEncryptRecordsAGeneratedNonce(t *testing.T) {
	store, attrs := newUntrackedAESWrappingBackend(t, "enc-generated-be", "enc-generated-key")
	svc := serviceWith(t, store)

	victim, err := encryptWithNonce(svc, store.name, attrs.CN, []byte("victim"), nil)
	require.NoError(t, err)
	require.NotEmpty(t, victim.Nonce, "the provider returns the nonce it generated")

	replay, err := encryptWithNonce(svc, store.name, attrs.CN, []byte("attacker"), victim.Nonce)
	require.Error(t, err, "a generated nonce is consumed exactly like one the caller supplied")
	assert.Nil(t, replay)
	assert.True(t, errors.Is(err, aead.ErrNonceReuse), "got %v", err)
}

// TestEncryptAndWrapShareOneGuard proves the two service-layer AEAD paths claim
// under one identity: an IV consumed by an AES-GCM wrap cannot be reused by
// the Encrypt RPC under the same key.
func TestEncryptAndWrapShareOneGuard(t *testing.T) {
	if fips140.Enforced() {
		requireCallerNonceEncryptRefusedUnderFIPS(t)
		return
	}

	store, attrs := newUntrackedAESWrappingBackend(t, "shared-guard-be", "shared-guard-key")
	svc := serviceWith(t, store)
	iv := uniqueNonce(t, aesGCMNonceSize)

	_, err := wrapKeyMaterial(context.Background(), store, attrs, string(types.WrapAESGCM), gcmParams(iv),
		[]byte("shared-guard-target-32-bytes-key"))
	require.NoError(t, err)

	_, err = encryptWithNonce(svc, store.name, attrs.CN, []byte("after the wrap"), iv)
	require.Error(t, err, "the wrap consumed the pair")
	assert.True(t, errors.Is(err, aead.ErrNonceReuse), "got %v", err)
}

// TestEncryptDoesNotClaimTheIVOfANonAEADMode pins the guard's scope: AES-CBC
// takes an IV, not an AEAD nonce, and a CBC request is neither claimed nor
// refused by it.
func TestEncryptDoesNotClaimTheIVOfANonAEADMode(t *testing.T) {
	store, attrs := newUntrackedAESWrappingBackend(t, "cbc-scope-be", "cbc-scope-key")
	svc := serviceWith(t, store)
	iv := uniqueNonce(t, 16)

	for range 2 {
		_, err := svc.Encrypt(context.Background(), &transport.EncryptRequest{
			Backend:   store.name,
			KeyID:     attrs.CN,
			Plaintext: []byte("0123456789ABCDEF"),
			Mode:      "cbc",
			IV:        iv,
		})
		require.NoError(t, err)
	}
}

// countingSealedProvider is a sealedSymmetricProvider that counts the seals
// its encrypter performs, so a test can see that a refusal came before one.
type countingSealedProvider struct {
	*sealedSymmetricProvider
	seals *atomic.Int32
}

func (p *countingSealedProvider) SymmetricEncrypter(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	inner, err := p.sealedSymmetricProvider.SymmetricEncrypter(ctx, attrs)
	if err != nil {
		return nil, err
	}
	return &countingEncrypter{SymmetricEncrypter: inner, seals: p.seals}, nil
}

type countingEncrypter struct {
	types.SymmetricEncrypter
	seals *atomic.Int32
}

func (e *countingEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	e.seals.Add(1)
	return e.SymmetricEncrypter.Encrypt(plaintext, opts)
}

// newCountingSealedStore builds a store whose key will not release its
// material, the way every HSM, TPM and cloud-KMS key behaves.
func newCountingSealedStore(t *testing.T, name, cn string, rawErr error) (*mockKeyStore, *types.KeyAttributes, *atomic.Int32) {
	t.Helper()
	store, attrs, _ := newSealedWrappingBackend(t, name, cn, rawErr)
	sealed, ok := store.backend.(*sealedSymmetricProvider)
	require.True(t, ok)
	seals := new(atomic.Int32)
	store.backend = &countingSealedProvider{sealedSymmetricProvider: sealed, seals: seals}
	return store, attrs, seals
}

// TestEncryptGuardsASealedKeyByNameAndRefusesBeforeTheSeal covers the backends
// that never release key material: the pair is keyed by the key's name, and
// the repeat is refused before the provider is asked to seal anything.
func TestEncryptGuardsASealedKeyByNameAndRefusesBeforeTheSeal(t *testing.T) {
	if fips140.Enforced() {
		// sealedSymmetricEncrypter uses cipher.NewGCM directly; see
		// TestWrapAESGCMGuardsAKeyWhoseMaterialIsSealed.
		requireCallerNonceEncryptRefusedUnderFIPS(t)
		return
	}

	store, attrs, seals := newCountingSealedStore(t, "enc-sealed-be", "enc-sealed-key", backend.ErrNotSupported)
	svc := serviceWith(t, store)
	nonce := uniqueNonce(t, aesGCMNonceSize)

	_, err := encryptWithNonce(svc, store.name, attrs.CN, []byte("first"), nonce)
	require.NoError(t, err, "a sealed key must still encrypt")
	_, err = encryptWithNonce(svc, store.name, attrs.CN, []byte("second"), nonce)
	require.Error(t, err)
	assert.True(t, errors.Is(err, aead.ErrNonceReuse), "got %v", err)
	assert.Equal(t, int32(1), seals.Load(), "the repeat must be refused before the provider seals")
}

// TestEncryptRefusesAKeyWhoseIdentityCannotBeResolved is the error path of the
// identity: a backend that fails to produce the key for any reason other than
// "sealed" has not said which key the nonce belongs to, so nothing is sealed
// and the backend's own error is reported.
func TestEncryptRefusesAKeyWhoseIdentityCannotBeResolved(t *testing.T) {
	readErr := errors.New("key store is offline")
	store, attrs, seals := newCountingSealedStore(t, "enc-unreadable-be", "enc-unreadable-key", readErr)
	svc := serviceWith(t, store)

	resp, err := encryptWithNonce(svc, store.name, attrs.CN, []byte("payload"), uniqueNonce(t, aesGCMNonceSize))
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.True(t, errors.Is(err, readErr), "the backend's own failure must be reported: got %v", err)
	assert.False(t, errors.Is(err, aead.ErrNonceReuse), "this is not a reuse: got %v", err)
	assert.Zero(t, seals.Load(), "nothing may be sealed under an unresolved identity")
}

// TestAEADKeyIdentityPrefersMaterialOverName proves the identity really is the
// key's bytes wherever they can be had, and that the sealed-key identity is a
// different shape entirely. An identity that always returned the name would
// pass every single-backend refusal test and fail only the aliasing ones.
func TestAEADKeyIdentityPrefersMaterialOverName(t *testing.T) {
	store, attrs := newUntrackedAESWrappingBackend(t, "identity-be", "identity-kek")
	material := rawKeyBytes(t, store, attrs)
	ctx := context.Background()

	identity, release, err := aeadKeyIdentity(ctx, store, attrs, aeadEncryptOperation)
	require.NoError(t, err)
	assert.Equal(t, material, identity, "the identity of a readable key is the key")
	release()

	sealedStore, sealedAttrs, _ := newSealedWrappingBackend(t, "identity-sealed-be", "identity-sealed-kek",
		backend.ErrNotSupported)
	sealedIdentity, sealedRelease, err := aeadKeyIdentity(ctx, sealedStore, sealedAttrs, aeadEncryptOperation)
	require.NoError(t, err)
	defer sealedRelease()
	assert.Contains(t, string(sealedIdentity), sealedKeyGuardDomain,
		"a name-derived identity is tagged so it cannot collide with a key's own bytes")
	assert.Contains(t, string(sealedIdentity), sealedAttrs.ID(),
		"the name-derived identity must name the store and the key")
}

// TestClaimGeneratedAEADNonceToleratesAFullGuard pins the one policy that
// differs between the two claims. Once the guard is full, a caller-supplied
// nonce is refused -- the guard can no longer promise it would notice a
// repeat -- while a generated nonce, fresh by construction, still encrypts.
// A repeat is refused either way.
func TestClaimGeneratedAEADNonceToleratesAFullGuard(t *testing.T) {
	store, attrs := newUntrackedAESWrappingBackend(t, "full-guard-be", "full-guard-key")
	guard, err := aead.NewKeyNonceGuard(rand.Reader, 1)
	require.NoError(t, err)
	ctx := context.Background()

	recorded := uniqueNonce(t, aesGCMNonceSize)
	require.NoError(t, claimGeneratedAEADNonceIn(ctx, guard, store, attrs, recorded), "the guard has room")

	require.NoError(t, claimGeneratedAEADNonceIn(ctx, guard, store, attrs, uniqueNonce(t, aesGCMNonceSize)),
		"a generated nonce still encrypts once the guard is full")

	err = claimAEADNonceIn(ctx, guard, store, attrs, aeadEncryptOperation, uniqueNonce(t, aesGCMNonceSize))
	require.Error(t, err, "a caller nonce cannot be vouched for by a full guard")
	assert.True(t, errors.Is(err, aead.ErrNonceTrackerFull), "got %v", err)

	err = claimGeneratedAEADNonceIn(ctx, guard, store, attrs, recorded)
	require.Error(t, err, "a repeat is a repeat, full guard or not")
	assert.True(t, errors.Is(err, aead.ErrNonceReuse), "got %v", err)
}

// serviceTransport routes a PKCS#11 CryptoManager's Encrypt straight into an
// XKMSService, so the module's own claim and the service's claim meet in one
// process and one shared guard -- the configuration in which colliding
// identities would make the service refuse every module call.
type serviceTransport struct {
	module.PKCS11Transport
	svc *XKMSService
}

func (s *serviceTransport) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	return s.svc.Encrypt(ctx, req)
}

// TestPKCS11EncryptWithACallerIVEncryptsOnceThroughTheService proves the module
// and the service each claim a C_EncryptInit caller IV under their own
// identity -- the module under (backend, key id), the service under the key's
// material -- so the first C_Encrypt succeeds end to end and the reused IV is
// refused by the module before a request is sent.
func TestPKCS11EncryptWithACallerIVEncryptsOnceThroughTheService(t *testing.T) {
	if fips140.Enforced() {
		requireCallerNonceEncryptRefusedUnderFIPS(t)
		return
	}

	store, attrs := newUntrackedAESWrappingBackend(t, "p11-enc-be", "p11-enc-key")
	svc := serviceWith(t, store)
	key := rawKeyBytes(t, store, attrs)
	cm := module.NewCryptoManager(&serviceTransport{svc: svc}, &module.CryptoManagerConfig{DefaultBackend: store.name})
	iv := uniqueNonce(t, aesGCMNonceSize)
	mechanism := func() *module.Mechanism {
		return &module.Mechanism{
			Type:           module.CKM_AES_GCM,
			TypedParameter: &module.AESGCMParams{IV: iv, TagBits: 128},
		}
	}

	plaintext := []byte("pkcs11 plaintext")
	op, err := cm.EncryptInit(mechanism(), 1, attrs.CN, store.name)
	require.NoError(t, err)
	ciphertext, err := cm.Encrypt(context.Background(), op, plaintext)
	require.NoError(t, err, "the module's claim and the service's claim must not collide")
	assert.Equal(t, gcmSealOracle(t, key, iv, plaintext, nil), ciphertext)

	op, err = cm.EncryptInit(mechanism(), 1, attrs.CN, store.name)
	require.NoError(t, err)
	_, err = cm.Encrypt(context.Background(), op, []byte("second plaintext"))
	require.Error(t, err, "a reused C_EncryptInit IV is refused")
	var p11Err *module.PKCS11Error
	require.True(t, errors.As(err, &p11Err), "got %T: %v", err, err)
	assert.Equal(t, module.CKR_MECHANISM_PARAM_INVALID, p11Err.Code)

	// A second module process has its own guard; the service's claim is what
	// refuses the pair there. Reaching the service directly shows it holds.
	_, err = encryptWithNonce(svc, store.name, attrs.CN, []byte("third plaintext"), iv)
	require.Error(t, err)
	assert.True(t, errors.Is(err, aead.ErrNonceReuse), "got %v", err)
}
