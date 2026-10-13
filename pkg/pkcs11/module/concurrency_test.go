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

package module

// Concurrency conformance tests.
//
// PKCS#11 v3.2 §5.1 requires a library initialized with CKF_OS_LOCKING_OK to
// be safe when an application drives it from several threads at once, so
// everything the module shares between sessions -- the session table, the
// object map, the per-session operation state and result cache, the token
// attribute store and the backend transport -- must survive real contention.
// Every test in this file therefore runs its workers against ONE module and
// ONE token, releases them from a common start barrier so the contention is
// genuine, and is meant to be run under the race detector:
//
//	go test -race -count=1 ./pkg/pkcs11/module/ -run Concurren
//
// Correctness is judged against crypto/* (crypto/ecdsa, crypto/sha256), never
// against the module's own inverse operation: a race that swaps operation
// state between two sessions yields a WRONG signature or a WRONG digest rather
// than an error, and a test that only asserted CKR_OK would sail straight past
// it.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"runtime/debug"
	"sort"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
// Fixtures
// ----------------------------------------------------------------------------

// Errors returned by concurrentTransport. They are declared as values so a
// caller can match them with errors.Is instead of comparing strings.
var (
	// errConcurrentUnknownKey reports a key ID the transport never generated.
	errConcurrentUnknownKey = errors.New("module: concurrency transport has no such key")

	// errConcurrentUnsupportedCurve reports a curve the transport cannot make.
	errConcurrentUnsupportedCurve = errors.New("module: concurrency transport does not support curve")

	// errConcurrentUnsupportedHash reports a digest name the transport cannot apply.
	errConcurrentUnsupportedHash = errors.New("module: concurrency transport does not support hash")

	// errConcurrentUnsupported reports a transport method these tests never drive.
	errConcurrentUnsupported = errors.New("module: concurrency transport does not implement this call")
)

// concurrentTransport is a PKCS11Transport that performs genuine ECDSA
// cryptography rather than returning canned bytes.
//
// Real crypto is what makes the concurrency assertions meaningful: the test
// holds the same public key the transport signed with, so it can check every
// signature with crypto/ecdsa over the exact message its own goroutine fed the
// module. A canned "mock-signature" would make every cross-session mix-up look
// identical and prove nothing.
//
// The transport is itself safe for concurrent use; a race reported inside it
// is a bug in the test fixture, and a race reported anywhere else is a bug in
// the module.
type concurrentTransport struct {
	mu   sync.RWMutex
	keys map[string]*ecdsa.PrivateKey
}

func newConcurrentTransport() *concurrentTransport {
	return &concurrentTransport{keys: make(map[string]*ecdsa.PrivateKey)}
}

// Compile-time check: concurrentTransport satisfies the module's transport seam.
var _ PKCS11Transport = (*concurrentTransport)(nil)

func (c *concurrentTransport) Connect(ctx context.Context) error { return nil }

func (c *concurrentTransport) Close() error { return nil }

// publicKey returns the public half of a generated key, which the test uses as
// its independent verification oracle.
func (c *concurrentTransport) publicKey(keyID string) (*ecdsa.PublicKey, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key, ok := c.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", errConcurrentUnknownKey, keyID)
	}
	return &key.PublicKey, nil
}

func curveByName(name string) (elliptic.Curve, error) {
	switch name {
	case "", "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%w: %s", errConcurrentUnsupportedCurve, name)
	}
}

// digestFor applies the digest the module named on the wire. "NONE" means the
// module already produced the digest and the bytes must be signed as-is.
func digestFor(hashName string, data []byte) ([]byte, error) {
	switch hashName {
	case "", "SHA-256":
		sum := sha256.Sum256(data)
		return sum[:], nil
	case "NONE":
		return data, nil
	default:
		return nil, fmt.Errorf("%w: %s", errConcurrentUnsupportedHash, hashName)
	}
}

func (c *concurrentTransport) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	curve, err := curveByName(req.Curve)
	if err != nil {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.keys[req.KeyID] = key
	c.mu.Unlock()

	return &transport.GenerateKeyResponse{
		KeyID:        req.KeyID,
		KeyType:      req.KeyType,
		PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
	}, nil
}

func (c *concurrentTransport) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	c.mu.RLock()
	key, ok := c.keys[req.KeyID]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", errConcurrentUnknownKey, req.KeyID)
	}

	digest, err := digestFor(req.Hash, req.Data)
	if err != nil {
		return nil, err
	}

	// ASN.1 DER is what a real backend returns; the module normalizes it to
	// the raw r || s form PKCS#11 v3.2 §6.3.1 mandates.
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
	if err != nil {
		return nil, err
	}

	return &transport.SignResponse{Signature: sig, Algorithm: "ECDSA"}, nil
}

func (c *concurrentTransport) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	c.mu.RLock()
	key, ok := c.keys[req.KeyID]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", errConcurrentUnknownKey, req.KeyID)
	}

	digest, err := digestFor(req.Hash, req.Data)
	if err != nil {
		return nil, err
	}

	return &transport.VerifyResponse{
		Valid: ecdsa.VerifyASN1(&key.PublicKey, digest, req.Signature),
	}, nil
}

func (c *concurrentTransport) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	return nil, errConcurrentUnsupported
}

func (c *concurrentTransport) EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	return nil, errConcurrentUnsupported
}

func (c *concurrentTransport) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	return nil, errConcurrentUnsupported
}

func (c *concurrentTransport) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return nil, errConcurrentUnsupported
}

func (c *concurrentTransport) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	return nil, errConcurrentUnsupported
}

func (c *concurrentTransport) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return nil, errConcurrentUnsupported
}

func (c *concurrentTransport) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return nil, errConcurrentUnsupported
}

func (c *concurrentTransport) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return nil, errConcurrentUnsupported
}

func (c *concurrentTransport) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	return nil, errConcurrentUnsupported
}

func (c *concurrentTransport) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	return nil, errConcurrentUnsupported
}

func (c *concurrentTransport) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return nil, errConcurrentUnsupported
}

func (c *concurrentTransport) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, errConcurrentUnsupported
}

func (c *concurrentTransport) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return nil, errConcurrentUnsupported
}

func (c *concurrentTransport) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return errConcurrentUnsupported
}

func (c *concurrentTransport) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	return errConcurrentUnsupported
}

func (c *concurrentTransport) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return errConcurrentUnsupported
}

func (c *concurrentTransport) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, errConcurrentUnsupported
}

func (c *concurrentTransport) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return nil, errConcurrentUnsupported
}

// PIN values used by every test in this file. They are constants rather than
// literals so a change to the token provisioning helper cannot drift from the
// logins that follow it.
const (
	concurrentSOPIN   = "so-pin-1234"
	concurrentUserPIN = "user-pin-1234"
)

// p256Params is the DER-encoded ANSI X9.62 OID for prime256v1, the value a
// caller puts in CKA_EC_PARAMS to ask for a P-256 key.
var p256Params = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

// newConcurrentModule builds an initialized module whose token is provisioned
// with an SO PIN and a user PIN, backed by a transport that performs real
// ECDSA. Provisioning happens before any worker starts, so the concurrent
// phase of each test contends over a token that is already in a settled state
// rather than over C_InitToken itself.
func newConcurrentModule(t *testing.T) (*Module, *concurrentTransport) {
	t.Helper()

	client := newConcurrentTransport()
	m, err := New(WithClient(client), WithConfig(DefaultConfig()))
	require.NoError(t, err)

	require.Equal(t, CKR_OK, m.Initialize(nil), "Initialize should succeed")
	t.Cleanup(func() { m.Finalize() })

	require.Equal(t, CKR_OK, m.InitToken(0, []byte(concurrentSOPIN), "Concurrency Token"))

	soSession, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, m.Login(soSession, CKU_SO, []byte(concurrentSOPIN)))
	require.Equal(t, CKR_OK, m.InitPIN(soSession, []byte(concurrentUserPIN)))
	require.Equal(t, CKR_OK, m.Logout(soSession))
	require.Equal(t, CKR_OK, m.CloseSession(soSession))

	return m, client
}

// openLoggedInSession opens a read-write session and authenticates the normal
// user on it. The login state is token-wide, so a session opened while another
// one is already authenticated is reported as CKR_USER_ALREADY_LOGGED_IN and
// is nonetheless usable; both outcomes are accepted, anything else is not.
func openLoggedInSession(m *Module) (SessionHandle, error) {
	handle, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	if rv != CKR_OK {
		return 0, fmt.Errorf("OpenSession returned %s", rv)
	}

	if rv := m.Login(handle, CKU_USER, []byte(concurrentUserPIN)); rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN {
		return 0, fmt.Errorf("Login returned %s", rv)
	}

	return handle, nil
}

// generateP256Pair generates an EC key pair on the given session and returns
// the two handles plus the backend key ID the module bound them to. The key ID
// is what lets the test fetch the matching public key from the transport and
// verify signatures independently.
func generateP256Pair(m *Module, session SessionHandle, label string) (pub, priv ObjectHandle, keyID string, err error) {
	pubTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_EC)),
		NewStringAttribute(CKA_LABEL, label),
		NewAttribute(CKA_EC_PARAMS, p256Params),
		NewBoolAttribute(CKA_VERIFY, true),
		NewBoolAttribute(CKA_TOKEN, false),
	}
	privTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_EC)),
		NewStringAttribute(CKA_LABEL, label),
		NewBoolAttribute(CKA_SIGN, true),
		NewBoolAttribute(CKA_TOKEN, false),
	}

	pub, priv, rv := m.GenerateKeyPair(session, &Mechanism{Type: CKM_EC_KEY_PAIR_GEN}, pubTemplate, privTemplate)
	if rv != CKR_OK {
		return 0, 0, "", fmt.Errorf("GenerateKeyPair returned %s", rv)
	}

	obj, objErr := m.objectManager.getObjectUnchecked(priv)
	if objErr != nil {
		return 0, 0, "", objErr
	}

	return pub, priv, obj.KeyID, nil
}

// verifyECDSARaw checks a PKCS#11 raw r || s ECDSA signature against a message
// with crypto/ecdsa. This is the tests' independent oracle: it never consults
// the module, so a signature the module produced over the wrong session's data
// fails here even though every PKCS#11 call returned CKR_OK.
func verifyECDSARaw(pub *ecdsa.PublicKey, message, signature []byte) bool {
	if len(signature) == 0 || len(signature)%2 != 0 {
		return false
	}

	half := len(signature) / 2
	r := new(big.Int).SetBytes(signature[:half])
	s := new(big.Int).SetBytes(signature[half:])

	digest := sha256.Sum256(message)
	return ecdsa.Verify(pub, digest[:], r, s)
}

// cyclicBarrier releases exactly n goroutines at a time and can be reused for
// successive rounds. It is how these tests interleave multi-part operations
// without sleeping: every worker blocks until all of them have submitted the
// current chunk, so the update calls genuinely overlap on every round instead
// of overlapping only when the scheduler happens to cooperate.
type cyclicBarrier struct {
	n     int
	mu    sync.Mutex
	count int
	gate  chan struct{}
}

func newCyclicBarrier(n int) *cyclicBarrier {
	return &cyclicBarrier{n: n, gate: make(chan struct{})}
}

func (b *cyclicBarrier) wait() {
	b.mu.Lock()
	b.count++
	if b.count == b.n {
		b.count = 0
		close(b.gate)
		b.gate = make(chan struct{})
		b.mu.Unlock()
		return
	}
	gate := b.gate
	b.mu.Unlock()
	<-gate
}

// capturedPanic records a panic that escaped a module entry point together
// with the stack that produced it.
type capturedPanic struct {
	where string
	value any
	stack string
}

// panicGuard runs fn and converts any panic escaping the module into a
// capturedPanic instead of tearing the whole test binary down.
//
// This mirrors recoverCKRV, the guard the real cgo entry points install so a
// Go panic can never cross the C ABI. Capturing here lets the test report
// precisely which entry point panicked under contention -- which is the
// finding -- rather than aborting every other worker before it can report.
func panicGuard(where string, fn func()) (captured *capturedPanic) {
	defer func() {
		if r := recover(); r != nil {
			captured = &capturedPanic{where: where, value: r, stack: string(debug.Stack())}
		}
	}()

	fn()
	return nil
}

// ----------------------------------------------------------------------------
// 1. Many sessions, one token
// ----------------------------------------------------------------------------

// TestConcurrentSessionsSignVerifyOnOneToken drives N application threads
// through the full per-session key lifecycle -- open, login, generate, sign,
// verify, destroy, close -- against a single token, and checks every signature
// against crypto/ecdsa.
//
// The race this catches: any sharing of operation state, key resolution or the
// result cache between sessions. Such a race does not produce an error; it
// produces a signature made over another thread's message or under another
// thread's key. The cross-product assertion at the end therefore requires each
// signature to verify under its own key over its own message AND to fail under
// every other worker's message, which no amount of CKR_OK checking would show.
func TestConcurrentSessionsSignVerifyOnOneToken(t *testing.T) {
	const workers = 8

	m, client := newConcurrentModule(t)

	type result struct {
		message   []byte
		signature []byte
		publicKey *ecdsa.PublicKey
	}

	results := make([]result, workers)
	failures := make([]error, workers)
	panics := make([]*capturedPanic, workers)

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start

			panics[idx] = panicGuard(fmt.Sprintf("worker %d", idx), func() {
				session, err := openLoggedInSession(m)
				if err != nil {
					failures[idx] = err
					return
				}
				defer func() {
					if rv := m.CloseSession(session); rv != CKR_OK {
						failures[idx] = fmt.Errorf("CloseSession returned %s", rv)
					}
				}()

				pubHandle, privHandle, keyID, err := generateP256Pair(m, session, fmt.Sprintf("concurrent-key-%d", idx))
				if err != nil {
					failures[idx] = err
					return
				}

				publicKey, err := client.publicKey(keyID)
				if err != nil {
					failures[idx] = err
					return
				}

				// Each worker signs a message only it knows, so a signature
				// that verifies over someone else's message is proof of a
				// cross-session leak rather than a coincidence.
				message := []byte(fmt.Sprintf("concurrent-message-for-worker-%d", idx))

				if rv := m.SignInit(session, &Mechanism{Type: CKM_ECDSA_SHA256}, privHandle); rv != CKR_OK {
					failures[idx] = fmt.Errorf("SignInit returned %s", rv)
					return
				}

				signature, rv := m.Sign(session, message)
				if rv != CKR_OK {
					failures[idx] = fmt.Errorf("Sign returned %s", rv)
					return
				}
				if rv := m.FinishOperation(session, OperationSign); rv != CKR_OK {
					failures[idx] = fmt.Errorf("FinishOperation(sign) returned %s", rv)
					return
				}

				// Exercise the module's own verify path too, so a race in it
				// is covered; correctness is still judged by crypto/ecdsa below.
				if rv := m.VerifyInit(session, &Mechanism{Type: CKM_ECDSA_SHA256}, pubHandle); rv != CKR_OK {
					failures[idx] = fmt.Errorf("VerifyInit returned %s", rv)
					return
				}
				// C_Verify carries no output buffer, so the two-call
				// convention does not apply to it: it terminates its own
				// operation and needs no FinishOperation confirmation.
				if rv := m.Verify(session, message, signature); rv != CKR_OK {
					failures[idx] = fmt.Errorf("Verify returned %s", rv)
					return
				}
				if rv := m.FinishOperation(session, OperationVerify); rv != CKR_OPERATION_NOT_INITIALIZED {
					failures[idx] = fmt.Errorf("FinishOperation after C_Verify returned %s, want CKR_OPERATION_NOT_INITIALIZED", rv)
					return
				}

				results[idx] = result{message: message, signature: signature, publicKey: publicKey}

				if rv := m.DestroyObject(session, privHandle); rv != CKR_OK {
					failures[idx] = fmt.Errorf("DestroyObject(private) returned %s", rv)
					return
				}
				if rv := m.DestroyObject(session, pubHandle); rv != CKR_OK {
					failures[idx] = fmt.Errorf("DestroyObject(public) returned %s", rv)
					return
				}
			})
		}(i)
	}

	close(start)
	wg.Wait()

	for i := 0; i < workers; i++ {
		if panics[i] != nil {
			t.Fatalf("worker %d panicked: %v\n%s", i, panics[i].value, panics[i].stack)
		}
		require.NoError(t, failures[i], "worker %d", i)
	}

	for i := 0; i < workers; i++ {
		require.True(t, verifyECDSARaw(results[i].publicKey, results[i].message, results[i].signature),
			"worker %d signature must verify against crypto/ecdsa over its own message", i)

		for j := 0; j < workers; j++ {
			if i == j {
				continue
			}
			require.False(t, verifyECDSARaw(results[i].publicKey, results[j].message, results[i].signature),
				"worker %d signature must not verify over worker %d message: operation state leaked between sessions", i, j)
		}
	}
}

// ----------------------------------------------------------------------------
// 2. Shared session object visibility
// ----------------------------------------------------------------------------

// TestConcurrentObjectVisibilityAcrossSessions races object creation in one
// session against object lookup in another.
//
// Both kinds of object are visible to every session of the application: a token
// object because it belongs to the token, and a session object because PKCS#11
// scopes session objects to the application rather than to the one session that
// created them (only their lifetime is tied to that session). The creating
// goroutine and the searching goroutine are released from the same barrier, so
// the search runs while the object map is being mutated -- the window in which a
// torn read of the handle table would surface.
func TestConcurrentObjectVisibilityAcrossSessions(t *testing.T) {
	m, _ := newConcurrentModule(t)

	creator, err := openLoggedInSession(m)
	require.NoError(t, err)
	observer, err := openLoggedInSession(m)
	require.NoError(t, err)

	const tokenLabel = "concurrent-token-object"
	const sessionLabel = "concurrent-session-object"

	newDataTemplate := func(label string, tokenObject bool) []Attribute {
		return []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
			NewStringAttribute(CKA_LABEL, label),
			NewAttribute(CKA_VALUE, []byte(label)),
			NewBoolAttribute(CKA_TOKEN, tokenObject),
			NewBoolAttribute(CKA_PRIVATE, false),
		}
	}

	findByLabel := func(session SessionHandle, label string) ([]ObjectHandle, error) {
		template := []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
			NewStringAttribute(CKA_LABEL, label),
		}
		if rv := m.FindObjectsInit(session, template); rv != CKR_OK {
			return nil, fmt.Errorf("FindObjectsInit returned %s", rv)
		}

		var found []ObjectHandle
		for {
			batch, rv := m.FindObjects(session, 16)
			if rv != CKR_OK {
				return nil, fmt.Errorf("FindObjects returned %s", rv)
			}
			if len(batch) == 0 {
				break
			}
			found = append(found, batch...)
		}

		if rv := m.FindObjectsFinal(session); rv != CKR_OK {
			return nil, fmt.Errorf("FindObjectsFinal returned %s", rv)
		}
		return found, nil
	}

	var (
		tokenHandle    ObjectHandle
		sessionHandleO ObjectHandle
		createErr      error
		searchErr      error
	)

	created := make(chan struct{})
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		<-start

		var rv CK_RV
		tokenHandle, rv = m.CreateObject(creator, newDataTemplate(tokenLabel, true))
		if rv != CKR_OK {
			createErr = fmt.Errorf("CreateObject(token) returned %s", rv)
			close(created)
			return
		}

		sessionHandleO, rv = m.CreateObject(creator, newDataTemplate(sessionLabel, false))
		if rv != CKR_OK {
			createErr = fmt.Errorf("CreateObject(session) returned %s", rv)
		}
		close(created)
	}()

	go func() {
		defer wg.Done()
		<-start

		// Hammer the search while creation is in flight. Every iteration must
		// return a coherent result set: either the object is there or it is
		// not, never a handle that does not resolve.
		for {
			handles, err := findByLabel(observer, tokenLabel)
			if err != nil {
				searchErr = err
				return
			}
			for _, h := range handles {
				probe := []Attribute{{Type: CKA_LABEL}}
				if _, rv := m.GetAttributeValue(observer, h, probe); rv != CKR_OK {
					searchErr = fmt.Errorf("handle %d returned by FindObjects does not resolve: %s", h, rv)
					return
				}
			}

			select {
			case <-created:
				return
			default:
			}
		}
	}()

	close(start)
	wg.Wait()

	require.NoError(t, createErr)
	require.NoError(t, searchErr)
	require.NotEqual(t, ObjectHandle(InvalidHandle), tokenHandle)
	require.NotEqual(t, ObjectHandle(InvalidHandle), sessionHandleO)

	// A TOKEN object created in one session must be visible in another.
	tokenFound, err := findByLabel(observer, tokenLabel)
	require.NoError(t, err)
	require.Contains(t, tokenFound, tokenHandle,
		"a CKA_TOKEN object created in session A must be visible to session B")

	// So must a SESSION object: it is scoped to the application, and only its
	// lifetime is tied to the session that created it.
	sessionFound, err := findByLabel(observer, sessionLabel)
	require.NoError(t, err)
	require.Contains(t, sessionFound, sessionHandleO,
		"a CKA_TOKEN=false object created in session A must be visible to session B of the same application")
}

// ----------------------------------------------------------------------------
// 3. Concurrent C_FindObjects
// ----------------------------------------------------------------------------

// TestConcurrentFindObjectsCursorIsolation runs one search per session
// concurrently over the same population of token objects and proves the
// per-session cursors never interfere.
//
// PKCS#11 v3.2 §5.7.7 permits at most one active search per session, which
// makes the search cursor per-session state; if it were keyed by anything
// coarser, two concurrent searches would advance one another's position and
// each caller would receive a partial, interleaved result set. Draining one
// handle at a time maximises the number of cursor updates, and the module's
// deliberate ascending sort of the match list is asserted as well, since a
// caller that takes the first object of a class depends on it.
func TestConcurrentFindObjectsCursorIsolation(t *testing.T) {
	const (
		workers = 6
		objects = 12
	)

	m, _ := newConcurrentModule(t)

	setup, err := openLoggedInSession(m)
	require.NoError(t, err)

	const label = "concurrent-find-target"
	expected := make([]ObjectHandle, 0, objects)
	for i := 0; i < objects; i++ {
		handle, rv := m.CreateObject(setup, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
			NewStringAttribute(CKA_LABEL, label),
			NewAttribute(CKA_VALUE, []byte(fmt.Sprintf("payload-%d", i))),
			NewBoolAttribute(CKA_TOKEN, true),
			NewBoolAttribute(CKA_PRIVATE, false),
		})
		require.Equal(t, CKR_OK, rv)
		expected = append(expected, handle)
	}
	sort.Slice(expected, func(i, j int) bool { return expected[i] < expected[j] })

	template := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, label),
	}

	found := make([][]ObjectHandle, workers)
	failures := make([]error, workers)

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()

			session, err := openLoggedInSession(m)
			if err != nil {
				failures[idx] = err
				<-start
				return
			}

			<-start

			if rv := m.FindObjectsInit(session, template); rv != CKR_OK {
				failures[idx] = fmt.Errorf("FindObjectsInit returned %s", rv)
				return
			}

			var handles []ObjectHandle
			for {
				// One at a time: every call advances this session's cursor,
				// so a shared cursor shows up as a short or duplicated result.
				batch, rv := m.FindObjects(session, 1)
				if rv != CKR_OK {
					failures[idx] = fmt.Errorf("FindObjects returned %s", rv)
					return
				}
				if len(batch) == 0 {
					break
				}
				handles = append(handles, batch...)
			}

			if rv := m.FindObjectsFinal(session); rv != CKR_OK {
				failures[idx] = fmt.Errorf("FindObjectsFinal returned %s", rv)
				return
			}

			found[idx] = handles

			if rv := m.CloseSession(session); rv != CKR_OK {
				failures[idx] = fmt.Errorf("CloseSession returned %s", rv)
			}
		}(i)
	}

	close(start)
	wg.Wait()

	for i := 0; i < workers; i++ {
		require.NoError(t, failures[i], "worker %d", i)
		require.Equal(t, expected, found[i],
			"worker %d must receive the complete result set in ascending handle order; a short or reordered set means the search cursors were shared", i)
	}
}

// ----------------------------------------------------------------------------
// 4. Operation-state isolation
// ----------------------------------------------------------------------------

// TestConcurrentMultiPartDigestIsolation interleaves multi-part digests over
// DIFFERENT data in different sessions and requires each session to receive
// the digest of its own input.
//
// This is the sharpest test of per-session operation state. C_DigestUpdate
// accumulates into state reached through the session handle; if two sessions
// resolved to one accumulator, the failure is silent -- both callers get a
// well-formed SHA-256 value that simply digests the wrong bytes. The barrier
// forces every session to submit chunk k before any of them submits chunk k+1,
// so the update calls really are interleaved, and the expected value is
// computed with crypto/sha256 rather than by asking the module a second time.
func TestConcurrentMultiPartDigestIsolation(t *testing.T) {
	const (
		workers = 8
		chunks  = 6
	)

	m, _ := newConcurrentModule(t)

	sessions := make([]SessionHandle, workers)
	for i := range sessions {
		session, err := openLoggedInSession(m)
		require.NoError(t, err)
		sessions[i] = session
	}

	barrier := newCyclicBarrier(workers)
	digests := make([][]byte, workers)
	expected := make([][]byte, workers)
	failures := make([]error, workers)

	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()

			session := sessions[idx]
			var own []byte

			barrier.wait()

			if rv := m.DigestInit(session, &Mechanism{Type: CKM_SHA256}); rv != CKR_OK {
				failures[idx] = fmt.Errorf("DigestInit returned %s", rv)
				// Keep participating in the barrier so the other workers are
				// never left waiting on a goroutine that has given up.
				for k := 0; k < chunks+1; k++ {
					barrier.wait()
				}
				return
			}

			for k := 0; k < chunks; k++ {
				barrier.wait()

				// Chunk contents differ per worker AND per round, so a state
				// mix-up cannot be masked by identical inputs.
				chunk := []byte(fmt.Sprintf("worker-%d-chunk-%d-", idx, k))
				own = append(own, chunk...)

				if rv := m.DigestUpdate(session, chunk); rv != CKR_OK {
					failures[idx] = fmt.Errorf("DigestUpdate round %d returned %s", k, rv)
					for j := k; j < chunks; j++ {
						barrier.wait()
					}
					return
				}
			}

			barrier.wait()

			digest, rv := m.DigestFinal(session)
			if rv != CKR_OK {
				failures[idx] = fmt.Errorf("DigestFinal returned %s", rv)
				return
			}
			if rv := m.FinishOperation(session, OperationDigest); rv != CKR_OK {
				failures[idx] = fmt.Errorf("FinishOperation(digest) returned %s", rv)
				return
			}

			sum := sha256.Sum256(own)
			digests[idx] = digest
			expected[idx] = sum[:]
		}(i)
	}

	wg.Wait()

	for i := 0; i < workers; i++ {
		require.NoError(t, failures[i], "worker %d", i)
		require.Equal(t, expected[i], digests[i],
			"worker %d must receive the SHA-256 of its own chunks; a different value means the digest accumulators were shared between sessions", i)
	}

	for _, session := range sessions {
		require.Equal(t, CKR_OK, m.CloseSession(session))
	}
}

// TestConcurrentMultiPartSignIsolation interleaves multi-part signing over
// DIFFERENT data in different sessions and checks each signature against
// crypto/ecdsa over that session's own message.
//
// The race this catches is the signing counterpart of the digest case: a
// shared SignOperation buffer produces a perfectly valid ECDSA signature over
// the concatenation of two sessions' data. That signature satisfies the
// module's own C_Verify -- both sides would be wrong in the same way -- so the
// oracle has to be crypto/ecdsa, and the assertion has to include that a
// signature does NOT verify over another worker's message.
func TestConcurrentMultiPartSignIsolation(t *testing.T) {
	const (
		workers = 6
		chunks  = 5
	)

	m, client := newConcurrentModule(t)

	type worker struct {
		session   SessionHandle
		priv      ObjectHandle
		pub       ObjectHandle
		publicKey *ecdsa.PublicKey
		message   []byte
		signature []byte
	}

	workersState := make([]worker, workers)
	for i := range workersState {
		session, err := openLoggedInSession(m)
		require.NoError(t, err)

		pub, priv, keyID, err := generateP256Pair(m, session, fmt.Sprintf("multipart-key-%d", i))
		require.NoError(t, err)

		publicKey, err := client.publicKey(keyID)
		require.NoError(t, err)

		workersState[i] = worker{session: session, priv: priv, pub: pub, publicKey: publicKey}
	}

	barrier := newCyclicBarrier(workers)
	failures := make([]error, workers)

	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()

			state := &workersState[idx]

			barrier.wait()

			if rv := m.SignInit(state.session, &Mechanism{Type: CKM_ECDSA_SHA256}, state.priv); rv != CKR_OK {
				failures[idx] = fmt.Errorf("SignInit returned %s", rv)
				for k := 0; k < chunks+1; k++ {
					barrier.wait()
				}
				return
			}

			for k := 0; k < chunks; k++ {
				barrier.wait()

				chunk := []byte(fmt.Sprintf("sign-worker-%d-chunk-%d-", idx, k))
				state.message = append(state.message, chunk...)

				if rv := m.SignUpdate(state.session, chunk); rv != CKR_OK {
					failures[idx] = fmt.Errorf("SignUpdate round %d returned %s", k, rv)
					for j := k; j < chunks; j++ {
						barrier.wait()
					}
					return
				}
			}

			barrier.wait()

			signature, rv := m.SignFinal(state.session)
			if rv != CKR_OK {
				failures[idx] = fmt.Errorf("SignFinal returned %s", rv)
				return
			}
			if rv := m.FinishOperation(state.session, OperationSign); rv != CKR_OK {
				failures[idx] = fmt.Errorf("FinishOperation(sign) returned %s", rv)
				return
			}

			state.signature = signature
		}(i)
	}

	wg.Wait()

	for i := 0; i < workers; i++ {
		require.NoError(t, failures[i], "worker %d", i)
		require.True(t, verifyECDSARaw(workersState[i].publicKey, workersState[i].message, workersState[i].signature),
			"worker %d multi-part signature must verify over its own concatenated chunks", i)

		for j := 0; j < workers; j++ {
			if i == j {
				continue
			}
			require.False(t, verifyECDSARaw(workersState[i].publicKey, workersState[j].message, workersState[i].signature),
				"worker %d signature must not verify over worker %d data: the signing buffers were shared", i, j)
		}
	}

	for i := range workersState {
		require.Equal(t, CKR_OK, m.CloseSession(workersState[i].session))
	}
}

// ----------------------------------------------------------------------------
// 5. Login / logout races
// ----------------------------------------------------------------------------

// TestConcurrentLoginLogoutDuringOperations logs the token out while other
// sessions are in the middle of signing with a private key.
//
// Login state is token-wide, so C_Logout on one session revokes the
// authentication every other session is relying on, and PKCS#11 v3.2 §5.6.10
// additionally invalidates handles to private objects at that moment. The only
// acceptable outcomes for an operation caught in that window are a defined
// CKR code or a correct result; what must never happen is a panic, or a
// CKR_OK carrying a signature the module should have refused to make. Every
// successful signature is therefore checked against crypto/ecdsa, and every
// failure is checked against the closed set of codes below.
func TestConcurrentLoginLogoutDuringOperations(t *testing.T) {
	const (
		workers    = 4
		iterations = 25
	)

	m, client := newConcurrentModule(t)

	type worker struct {
		session   SessionHandle
		priv      ObjectHandle
		publicKey *ecdsa.PublicKey
	}

	workersState := make([]worker, workers)
	for i := range workersState {
		session, err := openLoggedInSession(m)
		require.NoError(t, err)

		_, priv, keyID, err := generateP256Pair(m, session, fmt.Sprintf("logout-key-%d", i))
		require.NoError(t, err)

		publicKey, err := client.publicKey(keyID)
		require.NoError(t, err)

		workersState[i] = worker{session: session, priv: priv, publicKey: publicKey}
	}

	churn, err := openLoggedInSession(m)
	require.NoError(t, err)

	// The complete set of results an operation may legitimately produce while
	// authentication is being torn down and re-established underneath it.
	// Anything outside this set is a defect, not a race artefact.
	acceptable := map[CK_RV]bool{
		CKR_OK:                        true,
		CKR_USER_NOT_LOGGED_IN:        true,
		CKR_KEY_HANDLE_INVALID:        true,
		CKR_OBJECT_HANDLE_INVALID:     true,
		CKR_OPERATION_NOT_INITIALIZED: true,
		CKR_SESSION_HANDLE_INVALID:    true,
		CKR_FUNCTION_FAILED:           true,
	}

	failures := make([]error, workers+1)
	panics := make([]*capturedPanic, workers+1)

	start := make(chan struct{})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers + 1)

	// The churn goroutine drives the login state.
	go func() {
		defer wg.Done()
		<-start

		panics[workers] = panicGuard("login/logout churn", func() {
			for i := 0; i < iterations; i++ {
				if rv := m.Logout(churn); rv != CKR_OK && rv != CKR_USER_NOT_LOGGED_IN {
					failures[workers] = fmt.Errorf("Logout returned %s", rv)
					return
				}
				if rv := m.Login(churn, CKU_USER, []byte(concurrentUserPIN)); rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN {
					failures[workers] = fmt.Errorf("Login returned %s", rv)
					return
				}
			}
		})
		close(stop)
	}()

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start

			panics[idx] = panicGuard(fmt.Sprintf("signer %d", idx), func() {
				state := &workersState[idx]
				message := []byte(fmt.Sprintf("logout-race-message-%d", idx))

				for {
					select {
					case <-stop:
						return
					default:
					}

					rv := m.SignInit(state.session, &Mechanism{Type: CKM_ECDSA_SHA256}, state.priv)
					if rv != CKR_OK {
						if !acceptable[rv] {
							failures[idx] = fmt.Errorf("SignInit returned undefined outcome %s", rv)
							return
						}
						continue
					}

					signature, rv := m.Sign(state.session, message)
					if rv != CKR_OK {
						if !acceptable[rv] {
							failures[idx] = fmt.Errorf("Sign returned undefined outcome %s", rv)
							return
						}
						// A failed terminal call has already finalized the
						// operation; nothing left to confirm.
						continue
					}

					if rv := m.FinishOperation(state.session, OperationSign); rv != CKR_OK && !acceptable[rv] {
						failures[idx] = fmt.Errorf("FinishOperation returned undefined outcome %s", rv)
						return
					}

					// A CKR_OK must never be a silent success over garbage.
					if !verifyECDSARaw(state.publicKey, message, signature) {
						failures[idx] = errors.New("Sign returned CKR_OK with a signature that does not verify: the operation was invalidated but reported success")
						return
					}
				}
			})
		}(i)
	}

	close(start)
	wg.Wait()

	for i := range panics {
		if panics[i] != nil {
			t.Fatalf("%s panicked: %v\n%s", panics[i].where, panics[i].value, panics[i].stack)
		}
	}
	for i := range failures {
		require.NoError(t, failures[i], "goroutine %d", i)
	}
}

// ----------------------------------------------------------------------------
// 6. C_Initialize / C_Finalize
// ----------------------------------------------------------------------------

// TestConcurrentInitializeReturnsAlreadyInitialized calls C_Initialize from
// many threads at once on a fresh module.
//
// PKCS#11 v3.2 §5.6.1 allows exactly one successful initialization; every
// other concurrent caller must be told CKR_CRYPTOKI_ALREADY_INITIALIZED. A
// module that only checked a plain bool outside the lock would let two callers
// through and build the slot and object managers twice, silently discarding
// one of them along with any state already stored in it.
func TestConcurrentInitializeReturnsAlreadyInitialized(t *testing.T) {
	const workers = 16

	m, err := New(WithClient(newConcurrentTransport()), WithConfig(DefaultConfig()))
	require.NoError(t, err)
	t.Cleanup(func() { m.Finalize() })

	results := make([]CK_RV, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = m.Initialize(nil)
		}(i)
	}

	close(start)
	wg.Wait()

	okCount := 0
	for i, rv := range results {
		switch rv {
		case CKR_OK:
			okCount++
		case CKR_CRYPTOKI_ALREADY_INITIALIZED:
		default:
			t.Fatalf("worker %d: C_Initialize returned %s, want CKR_OK or CKR_CRYPTOKI_ALREADY_INITIALIZED", i, rv)
		}
	}

	require.Equal(t, 1, okCount, "exactly one concurrent C_Initialize may succeed")
	require.True(t, m.IsInitialized())
}

// TestConcurrentFinalizeDuringActiveSessions finalizes the module while other
// threads are inside ordinary entry points with live sessions.
//
// C_Finalize tears down the slot, object and crypto managers. Any entry point
// that checked the initialized flag before C_Finalize ran, then blocked on the
// module lock, resumes afterwards against those torn-down managers -- so this
// is exactly the window in which a nil dereference reaches the C boundary.
// PKCS#11 v3.2 §5.6.2 permits C_Finalize at any time; the calls it races must
// return a defined CKR value (CKR_CRYPTOKI_NOT_INITIALIZED being the natural
// one) and must never panic.
func TestConcurrentFinalizeDuringActiveSessions(t *testing.T) {
	const workers = 6

	client := newConcurrentTransport()
	m, err := New(WithClient(client), WithConfig(DefaultConfig()))
	require.NoError(t, err)
	require.Equal(t, CKR_OK, m.Initialize(nil))
	t.Cleanup(func() { m.Finalize() })

	require.Equal(t, CKR_OK, m.InitToken(0, []byte(concurrentSOPIN), "Finalize Token"))

	soSession, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, m.Login(soSession, CKU_SO, []byte(concurrentSOPIN)))
	require.Equal(t, CKR_OK, m.InitPIN(soSession, []byte(concurrentUserPIN)))
	require.Equal(t, CKR_OK, m.Logout(soSession))
	require.Equal(t, CKR_OK, m.CloseSession(soSession))

	sessions := make([]SessionHandle, workers)
	for i := range sessions {
		session, err := openLoggedInSession(m)
		require.NoError(t, err)
		sessions[i] = session
	}

	panics := make([]*capturedPanic, workers+1)

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers + 1)

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start

			// Each worker drives a mix of read-only and stateful entry points
			// so the finalize lands somewhere different every run.
			panics[idx] = panicGuard(fmt.Sprintf("entry-point worker %d", idx), func() {
				session := sessions[idx]
				for k := 0; k < 40; k++ {
					m.GetSlotList(true)
					m.GetSlotInfo(0)
					m.GetTokenInfo(0)
					m.GetSessionInfo(session)
					m.GetMechanismList(0)
					m.DigestInit(session, &Mechanism{Type: CKM_SHA256})
					m.DigestUpdate(session, []byte("finalize-race"))
					m.DigestFinal(session)
					m.FinishOperation(session, OperationDigest)
					m.FindObjectsInit(session, []Attribute{NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA))})
					m.FindObjects(session, 8)
					m.FindObjectsFinal(session)
					m.GenerateRandom(session, 16)
				}
			})
		}(i)
	}

	go func() {
		defer wg.Done()
		<-start

		panics[workers] = panicGuard("finalize", func() {
			m.Finalize()
		})
	}()

	close(start)
	wg.Wait()

	for i := range panics {
		if panics[i] != nil {
			t.Fatalf("%s panicked during C_Finalize race: %v\n%s", panics[i].where, panics[i].value, panics[i].stack)
		}
	}
}

// ----------------------------------------------------------------------------
// 7. No panic across the C boundary
// ----------------------------------------------------------------------------

// TestConcurrentAEADParameterGuardsNeverPanic hammers the authenticated
// wrap/unwrap path with malformed AES-GCM parameters from several threads at
// once and requires a defined CKR value every time.
//
// This is a regression test for a defect of exactly this shape: cipher.AEAD's
// Seal and Open PANIC -- they do not return an error -- when handed a nonce
// whose length is not the AEAD's nonce size, so a caller-supplied
// CK_GCM_PARAMS.pIv of the wrong length took the whole daemon down rather than
// producing CKR_MECHANISM_PARAM_INVALID. Guards were added at the call sites;
// this test proves they still hold when many threads drive them at once, and
// that no other malformed-parameter path reaches Seal or Open unguarded.
//
// A panic here would be caught by recoverCKRV at the real C entry point and
// converted to a CKR value, but the operation would still have died in an
// undefined state, so the correct behaviour is to never panic at all.
func TestConcurrentAEADParameterGuardsNeverPanic(t *testing.T) {
	const workers = 8

	m, _ := newConcurrentModule(t)

	setup, err := openLoggedInSession(m)
	require.NoError(t, err)

	// An AES-256 wrapping key and an extractable target key, both created up
	// front so the concurrent phase contends only over the GCM parameter path.
	// The wrapping key's value is fresh per run: the IV guard is process-wide
	// and keyed by this material, so a fixed value would meet the (key, IV)
	// pairs an earlier go test -count=N run already sealed under.
	wrappingKeyValue := make([]byte, 32)
	_, err = rand.Read(wrappingKeyValue)
	require.NoError(t, err)
	wrappingKey, rv := m.CreateObject(setup, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "gcm-wrapping-key"),
		NewAttribute(CKA_VALUE, wrappingKeyValue),
		NewBoolAttribute(CKA_WRAP, true),
		NewBoolAttribute(CKA_UNWRAP, true),
		NewBoolAttribute(CKA_TOKEN, true),
	})
	require.Equal(t, CKR_OK, rv)

	targetKey, rv := m.CreateObject(setup, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "gcm-target-key"),
		NewAttribute(CKA_VALUE, []byte("FEDCBA9876543210FEDCBA9876543210")),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewBoolAttribute(CKA_TOKEN, true),
	})
	require.Equal(t, CKR_OK, rv)

	// Nonce lengths AES-GCM cannot accept. cipher.AEAD panics on every one of
	// them, so each must be rejected before it reaches Seal or Open.
	badNonceLengths := []int{1, 8, 11, 13, 16, 32}

	failures := make([]error, workers)
	panics := make([]*capturedPanic, workers)

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()

			session, err := openLoggedInSession(m)
			if err != nil {
				failures[idx] = err
				<-start
				return
			}

			<-start

			panics[idx] = panicGuard(fmt.Sprintf("aead worker %d", idx), func() {
				for round := 0; round < 8; round++ {
					for _, size := range badNonceLengths {
						mech := &Mechanism{
							Type:           CKM_AES_GCM,
							TypedParameter: &AESGCMParams{IV: make([]byte, size), TagBits: 128},
						}

						_, wrapErr := m.WrapKeyAuthenticated(session, mech, wrappingKey, targetKey, nil)
						if !errorHasCode(wrapErr, CKR_MECHANISM_PARAM_INVALID) {
							failures[idx] = fmt.Errorf("WrapKeyAuthenticated with a %d-byte GCM IV returned %v, want CKR_MECHANISM_PARAM_INVALID", size, wrapErr)
							return
						}

						_, unwrapErr := m.UnwrapKeyAuthenticated(session, mech, wrappingKey,
							make([]byte, GCMTagSize+8), []Attribute{
								NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
								NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
							}, nil)
						if !errorHasCode(unwrapErr, CKR_MECHANISM_PARAM_INVALID) {
							failures[idx] = fmt.Errorf("UnwrapKeyAuthenticated with a %d-byte GCM IV returned %v, want CKR_MECHANISM_PARAM_INVALID", size, unwrapErr)
							return
						}
					}

					// A well-formed round trip in the same loop keeps the
					// guarded and unguarded paths contending with each other
					// rather than letting the bad-parameter path run alone.
					//
					// Every worker and round seals under a distinct IV. All
					// eight workers share one wrapping key, so a fixed IV here
					// would be the same (key, IV) pair sealed 64 times -- the
					// reuse WrapKeyAuthenticated now refuses outright, and the
					// reason it must: two seals under one pair leak the XOR of
					// the two plaintexts, which for a key wrap is the wrapped
					// key material itself.
					goodIV := make([]byte, GCMNonceSize)
					goodIV[0] = byte(idx)
					goodIV[1] = byte(round)
					good := &Mechanism{
						Type:           CKM_AES_GCM,
						TypedParameter: &AESGCMParams{IV: goodIV, TagBits: 128},
					}
					wrapped, wrapErr := m.WrapKeyAuthenticated(session, good, wrappingKey, targetKey, nil)
					if wrapErr != nil {
						failures[idx] = fmt.Errorf("WrapKeyAuthenticated with a valid 12-byte IV failed: %w", wrapErr)
						return
					}
					if len(wrapped) == 0 {
						failures[idx] = errors.New("WrapKeyAuthenticated returned no output for a valid IV")
						return
					}
				}
			})

			if rv := m.CloseSession(session); rv != CKR_OK && failures[idx] == nil {
				failures[idx] = fmt.Errorf("CloseSession returned %s", rv)
			}
		}(i)
	}

	close(start)
	wg.Wait()

	for i := 0; i < workers; i++ {
		if panics[i] != nil {
			t.Fatalf("%s panicked: a malformed AES-GCM parameter reached cipher.AEAD: %v\n%s",
				panics[i].where, panics[i].value, panics[i].stack)
		}
		require.NoError(t, failures[i], "worker %d", i)
	}
}

// errorHasCode reports whether err is a PKCS11Error carrying the given return
// value. It is used instead of string matching so a change to an error message
// cannot quietly turn an assertion into a tautology.
func errorHasCode(err error, want CK_RV) bool {
	if err == nil {
		return false
	}

	var pkcsErr *PKCS11Error
	if errors.As(err, &pkcsErr) {
		return pkcsErr.Code == want
	}
	return false
}
