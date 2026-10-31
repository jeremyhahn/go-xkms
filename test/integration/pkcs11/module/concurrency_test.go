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

//go:build integration
// +build integration

// C-ABI concurrency conformance tests for the PKCS#11 shared library.
//
// PKCS#11 v3.2 §5.1 requires a library initialized with CKF_OS_LOCKING_OK to
// be safe when the application drives it from several native threads. These
// tests dlopen the real build/lib/libxkms_pkcs11.so through
// github.com/miekg/pkcs11 -- so every call crosses the real cgo boundary,
// against a real xkmsd backend -- and drive genuine contention over one token:
// the session table, the object map, the per-session operation state and
// result cache, and the backend connection pool are all shared.
//
// Each test dlopens its own private copy of the library. Two distinct paths
// give two independent Go runtimes inside the process, so one test's
// C_Finalize cannot tear the module out from under another, and every test
// starts from a freshly auto-initialized token.
//
// Correctness is judged with crypto/* (crypto/sha256, crypto/ecdsa) over the
// public key read back from the token, never by asking the module to verify
// its own output: a race that swaps operation state between sessions produces
// a wrong-but-well-formed digest or signature that the module's own inverse
// operation would happily accept.
//
// Required environment (the PKCS#11 Makefile targets export all of these):
//
//	PKCS11_MODULE                 path to libxkms_pkcs11.so
//	XKMS_UNIX_SOCKET              /var/run/xkms/xkms.sock
//	XKMS_PKCS11_AUTO_INIT_TOKEN   true
//	XKMS_PKCS11_SO_PIN            12345678
//	XKMS_PKCS11_USER_PIN          87654321
//	XKMS_PKCS11_TOKEN_LABEL       xkms-token
//	XKMS_PKCS11_STORAGE_TYPE      file
//	XKMS_PKCS11_STORAGE_PATH      /tmp/p11conc
package module

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"sync"
	"testing"

	"github.com/miekg/pkcs11"
)

// ----------------------------------------------------------------------------
// Harness
// ----------------------------------------------------------------------------

// errConcMissingAttribute reports an attribute the token did not return.
var errConcMissingAttribute = errors.New("pkcs11 concurrency: token returned no value for the requested attribute")

// concPINs returns the SO and user PINs the harness provisioned the token with.
func concPINs(t *testing.T) (soPIN, userPIN string) {
	t.Helper()

	soPIN = os.Getenv("XKMS_PKCS11_SO_PIN")
	if soPIN == "" {
		soPIN = "12345678"
	}
	userPIN = os.Getenv("XKMS_PKCS11_USER_PIN")
	if userPIN == "" {
		userPIN = "87654321"
	}
	return soPIN, userPIN
}

// concInstance is one dlopen'd copy of the PKCS#11 library plus the slot its
// token lives on.
type concInstance struct {
	ctx  *pkcs11.Ctx
	slot uint
}

// newConcInstance dlopens a private copy of the built shared library and
// initializes it with CKF_OS_LOCKING_OK, which is what miekg/pkcs11's
// C_Initialize requests and what PKCS#11 v3.2 §5.6.1 defines as "the
// application will be accessing the library from multiple threads".
//
// A private copy rather than the shared path is deliberate: dlopen keys its
// handle cache on the path, so two different paths yield two independent Go
// runtimes and therefore two independent module states. That is what lets the
// C_Finalize test run without destroying the module another test is using.
func newConcInstance(t *testing.T, name string) *concInstance {
	t.Helper()

	src := os.Getenv("PKCS11_MODULE")
	if src == "" {
		t.Fatal("PKCS11_MODULE is not set; the PKCS#11 Makefile targets build " +
			"build/lib/libxkms_pkcs11.so and export this variable")
	}

	dst := filepath.Join(t.TempDir(), name+".so")
	concCopyFile(t, src, dst)

	// Give this instance its own object store so a test that creates token
	// objects cannot perturb another instance's search results.
	storagePath := filepath.Join(t.TempDir(), "storage")
	if err := os.MkdirAll(storagePath, 0o700); err != nil {
		t.Fatalf("creating per-instance storage directory: %v", err)
	}
	t.Setenv("XKMS_PKCS11_STORAGE_PATH", storagePath)

	ctx := pkcs11.New(dst)
	if ctx == nil {
		t.Fatalf("pkcs11.New(%s) returned nil: the library could not be dlopen'd", dst)
	}

	if err := ctx.Initialize(); err != nil {
		t.Fatalf("C_Initialize on %s: %v", dst, err)
	}

	t.Cleanup(func() {
		if err := ctx.Finalize(); err != nil {
			t.Errorf("C_Finalize: %v", err)
		}
		ctx.Destroy()
	})

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		t.Fatalf("C_GetSlotList: %v", err)
	}
	if len(slots) == 0 {
		t.Fatal("C_GetSlotList returned no slots; the module always publishes slot 0 with a token")
	}

	return &concInstance{ctx: ctx, slot: slots[0]}
}

func concCopyFile(t *testing.T, src, dst string) {
	t.Helper()

	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("opening %s: %v", src, err)
	}
	defer func() {
		if cerr := in.Close(); cerr != nil {
			t.Errorf("closing %s: %v", src, cerr)
		}
	}()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatalf("creating %s: %v", dst, err)
	}

	if _, err := io.Copy(out, in); err != nil {
		if cerr := out.Close(); cerr != nil {
			t.Errorf("closing %s: %v", dst, cerr)
		}
		t.Fatalf("copying the module to %s: %v", dst, err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("closing %s: %v", dst, err)
	}
}

// openSession opens a read-write session and logs the normal user in. The
// login state is token-wide, so a session opened while the token is already
// authenticated reports CKR_USER_ALREADY_LOGGED_IN and is nonetheless usable.
func (i *concInstance) openSession(t *testing.T) pkcs11.SessionHandle {
	t.Helper()

	session, err := i.ctx.OpenSession(i.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("C_OpenSession: %v", err)
	}

	_, userPIN := concPINs(t)
	if err := i.ctx.Login(session, pkcs11.CKU_USER, userPIN); err != nil && !concIsCKR(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		t.Fatalf("C_Login: %v", err)
	}

	t.Cleanup(func() {
		// A session already closed by the test itself is not an error worth
		// failing on; anything else is.
		if err := i.ctx.CloseSession(session); err != nil &&
			!concIsCKR(err, pkcs11.CKR_SESSION_HANDLE_INVALID) &&
			!concIsCKR(err, pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED) {
			t.Errorf("C_CloseSession: %v", err)
		}
	})

	return session
}

// concIsCKR reports whether err is the given Cryptoki return value.
func concIsCKR(err error, want pkcs11.Error) bool {
	if err == nil {
		return false
	}
	var got pkcs11.Error
	if errors.As(err, &got) {
		return got == want
	}
	return false
}

// concCKR extracts the Cryptoki return value from err, or reports ok=false for
// an error that is not a CK_RV (a transport failure in the binding itself).
func concCKR(err error) (pkcs11.Error, bool) {
	var got pkcs11.Error
	if errors.As(err, &got) {
		return got, true
	}
	return 0, false
}

// p256OID is the DER-encoded prime256v1 OID a caller puts in CKA_EC_PARAMS.
var p256OID = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

// concGenerateP256 generates a P-256 key pair on the given session and returns
// the two object handles.
func (i *concInstance) concGenerateP256(session pkcs11.SessionHandle, label string) (pub, priv pkcs11.ObjectHandle, err error) {
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, p256OID),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
	}
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
	}

	return i.ctx.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		pubTemplate, privTemplate)
}

// concReadP256PublicKey reads CKA_EC_POINT off a public key object and decodes
// it into a crypto/ecdsa public key.
//
// PKCS#11 v3.2 §6.3.3 defines CKA_EC_POINT as the DER encoding of an ANSI
// X9.62 point wrapped in an OCTET STRING, so the octet string is unwrapped
// before the point is unmarshalled. This is what turns the token's own output
// into an independent verification oracle.
func (i *concInstance) concReadP256PublicKey(session pkcs11.SessionHandle, pub pkcs11.ObjectHandle) (*ecdsa.PublicKey, error) {
	attrs, err := i.ctx.GetAttributeValue(session, pub, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, err
	}
	if len(attrs) != 1 || len(attrs[0].Value) == 0 {
		return nil, fmt.Errorf("%w: CKA_EC_POINT", errConcMissingAttribute)
	}

	var point []byte
	rest, err := asn1.Unmarshal(attrs[0].Value, &point)
	if err != nil {
		return nil, fmt.Errorf("CKA_EC_POINT is not a DER OCTET STRING: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("CKA_EC_POINT has %d trailing bytes after the DER OCTET STRING", len(rest))
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), point)
	if x == nil {
		return nil, errors.New("CKA_EC_POINT does not decode as an uncompressed X9.62 point on P-256")
	}

	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// concVerifyECDSARaw checks a PKCS#11 raw r || s ECDSA signature over a
// message using crypto/ecdsa. PKCS#11 v3.2 §6.3.1 mandates the raw form, so
// the halves are read directly rather than parsed as DER.
func concVerifyECDSARaw(pub *ecdsa.PublicKey, message, signature []byte) bool {
	if len(signature) == 0 || len(signature)%2 != 0 {
		return false
	}

	half := len(signature) / 2
	r := new(big.Int).SetBytes(signature[:half])
	s := new(big.Int).SetBytes(signature[half:])

	digest := sha256.Sum256(message)
	return ecdsa.Verify(pub, digest[:], r, s)
}

// concBarrier releases exactly n goroutines at a time and is reusable across
// rounds. It is how these tests interleave multi-part operations without
// sleeping: no worker submits chunk k+1 until every worker has submitted
// chunk k, so the update calls genuinely overlap on every round.
type concBarrier struct {
	n     int
	mu    sync.Mutex
	count int
	gate  chan struct{}
}

func newConcBarrier(n int) *concBarrier {
	return &concBarrier{n: n, gate: make(chan struct{})}
}

func (b *concBarrier) wait() {
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

// concPanic records a panic that escaped a worker.
type concPanic struct {
	where string
	value any
	stack string
}

// concGuard converts a panic escaping fn into a value the test can report,
// so one failing worker does not abort every other worker before it can
// record its own result.
func concGuard(where string, fn func()) (captured *concPanic) {
	defer func() {
		if r := recover(); r != nil {
			captured = &concPanic{where: where, value: r, stack: string(debug.Stack())}
		}
	}()

	fn()
	return nil
}

// ----------------------------------------------------------------------------
// 1. Many sessions, one token
// ----------------------------------------------------------------------------

// TestConcurrentCABISessionsSignVerify drives N native threads through the
// full per-session key lifecycle against one token over the real C ABI:
// C_OpenSession, C_Login, C_GenerateKeyPair, C_SignInit/C_Sign, C_Verify,
// C_DestroyObject, C_CloseSession.
//
// The race this catches: any sharing of operation state or key resolution
// between sessions. Such a race is silent -- the caller gets CKR_OK and a
// well-formed signature made over another thread's message. The cross-product
// assertion therefore requires each signature to verify with crypto/ecdsa over
// its own message AND to fail over every other worker's message.
func TestConcurrentCABISessionsSignVerify(t *testing.T) {
	const workers = 8

	inst := newConcInstance(t, "conc-sign")

	type result struct {
		message   []byte
		signature []byte
		publicKey *ecdsa.PublicKey
	}

	results := make([]result, workers)
	failures := make([]error, workers)
	panics := make([]*concPanic, workers)

	sessions := make([]pkcs11.SessionHandle, workers)
	for i := range sessions {
		sessions[i] = inst.openSession(t)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start

			panics[idx] = concGuard(fmt.Sprintf("worker %d", idx), func() {
				session := sessions[idx]

				pub, priv, err := inst.concGenerateP256(session, fmt.Sprintf("conc-sign-key-%d", idx))
				if err != nil {
					failures[idx] = fmt.Errorf("C_GenerateKeyPair: %w", err)
					return
				}

				publicKey, err := inst.concReadP256PublicKey(session, pub)
				if err != nil {
					failures[idx] = fmt.Errorf("reading CKA_EC_POINT: %w", err)
					return
				}

				// Every worker signs a message only it knows, so a signature
				// that verifies over another worker's message is proof of a
				// cross-session leak rather than a coincidence.
				message := []byte(fmt.Sprintf("cabi-concurrent-message-worker-%d", idx))

				if err := inst.ctx.SignInit(session,
					[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_SHA256, nil)}, priv); err != nil {
					failures[idx] = fmt.Errorf("C_SignInit: %w", err)
					return
				}

				signature, err := inst.ctx.Sign(session, message)
				if err != nil {
					failures[idx] = fmt.Errorf("C_Sign: %w", err)
					return
				}

				// Exercise the module's own verification path too, so a race
				// in it is covered; correctness is judged by crypto/ecdsa below.
				if err := inst.ctx.VerifyInit(session,
					[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_SHA256, nil)}, pub); err != nil {
					failures[idx] = fmt.Errorf("C_VerifyInit: %w", err)
					return
				}
				if err := inst.ctx.Verify(session, message, signature); err != nil {
					failures[idx] = fmt.Errorf("C_Verify: %w", err)
					return
				}

				results[idx] = result{message: message, signature: signature, publicKey: publicKey}

				if err := inst.ctx.DestroyObject(session, priv); err != nil {
					failures[idx] = fmt.Errorf("C_DestroyObject(private): %w", err)
					return
				}
				if err := inst.ctx.DestroyObject(session, pub); err != nil {
					failures[idx] = fmt.Errorf("C_DestroyObject(public): %w", err)
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
		if failures[i] != nil {
			t.Fatalf("worker %d: %v", i, failures[i])
		}
	}

	for i := 0; i < workers; i++ {
		if !concVerifyECDSARaw(results[i].publicKey, results[i].message, results[i].signature) {
			t.Fatalf("worker %d: the signature does not verify against crypto/ecdsa over its own message", i)
		}
		for j := 0; j < workers; j++ {
			if i == j {
				continue
			}
			if concVerifyECDSARaw(results[i].publicKey, results[j].message, results[i].signature) {
				t.Fatalf("worker %d signature verifies over worker %d message: operation state leaked between sessions", i, j)
			}
		}
	}
}

// ----------------------------------------------------------------------------
// 2. Shared session object visibility
// ----------------------------------------------------------------------------

// TestConcurrentCABIObjectVisibility races object creation in one session
// against object lookup in another over the C ABI.
//
// Both kinds of object are visible to every session of the application: a token
// object because it belongs to the token, and a session object because PKCS#11
// scopes session objects to the application rather than to the one session that
// created them (only their lifetime is tied to that session). Creator and
// observer are released from the same barrier, so the search runs while the
// object map is being mutated -- the window in which a torn read of the handle
// table, or a handle published before the object is complete, would surface.
func TestConcurrentCABIObjectVisibility(t *testing.T) {
	inst := newConcInstance(t, "conc-visibility")

	creator := inst.openSession(t)
	observer := inst.openSession(t)

	const tokenLabel = "conc-cabi-token-object"
	const sessionLabel = "conc-cabi-session-object"

	dataTemplate := func(label string, tokenObject bool) []*pkcs11.Attribute {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte(label)),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenObject),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		}
	}

	findByLabel := func(session pkcs11.SessionHandle, label string) ([]pkcs11.ObjectHandle, error) {
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		}
		if err := inst.ctx.FindObjectsInit(session, template); err != nil {
			return nil, fmt.Errorf("C_FindObjectsInit: %w", err)
		}

		var found []pkcs11.ObjectHandle
		for {
			batch, _, err := inst.ctx.FindObjects(session, 16)
			if err != nil {
				return nil, fmt.Errorf("C_FindObjects: %w", err)
			}
			if len(batch) == 0 {
				break
			}
			found = append(found, batch...)
		}

		if err := inst.ctx.FindObjectsFinal(session); err != nil {
			return nil, fmt.Errorf("C_FindObjectsFinal: %w", err)
		}
		return found, nil
	}

	var (
		tokenObject   pkcs11.ObjectHandle
		sessionObject pkcs11.ObjectHandle
		createErr     error
		searchErr     error
	)

	created := make(chan struct{})
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		<-start

		var err error
		tokenObject, err = inst.ctx.CreateObject(creator, dataTemplate(tokenLabel, true))
		if err != nil {
			createErr = fmt.Errorf("C_CreateObject(token): %w", err)
			close(created)
			return
		}

		sessionObject, err = inst.ctx.CreateObject(creator, dataTemplate(sessionLabel, false))
		if err != nil {
			createErr = fmt.Errorf("C_CreateObject(session): %w", err)
		}
		close(created)
	}()

	go func() {
		defer wg.Done()
		<-start

		// Every handle the search returns must resolve: a handle published
		// before its object is fully inserted would fail here.
		for {
			handles, err := findByLabel(observer, tokenLabel)
			if err != nil {
				searchErr = err
				return
			}
			for _, h := range handles {
				if _, err := inst.ctx.GetAttributeValue(observer, h,
					[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil)}); err != nil {
					searchErr = fmt.Errorf("handle %d returned by C_FindObjects does not resolve: %w", h, err)
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

	if createErr != nil {
		t.Fatal(createErr)
	}
	if searchErr != nil {
		t.Fatal(searchErr)
	}

	tokenFound, err := findByLabel(observer, tokenLabel)
	if err != nil {
		t.Fatal(err)
	}
	if !concContainsHandle(tokenFound, tokenObject) {
		t.Fatalf("a CKA_TOKEN object created in session A is not visible to session B: found %v, want to contain %d",
			tokenFound, tokenObject)
	}

	sessionFound, err := findByLabel(observer, sessionLabel)
	if err != nil {
		t.Fatal(err)
	}
	if !concContainsHandle(sessionFound, sessionObject) {
		t.Fatalf("a CKA_TOKEN=false object created in session A is not visible to session B of the same application: found %v, want to contain %d",
			sessionFound, sessionObject)
	}
}

func concContainsHandle(handles []pkcs11.ObjectHandle, want pkcs11.ObjectHandle) bool {
	for _, h := range handles {
		if h == want {
			return true
		}
	}
	return false
}

// ----------------------------------------------------------------------------
// 3. Concurrent C_FindObjects
// ----------------------------------------------------------------------------

// TestConcurrentCABIFindObjectsCursors runs one search per session
// concurrently over the same population of token objects and proves the
// per-session cursors never interfere.
//
// PKCS#11 v3.2 §5.7.7 permits at most one active search per session, which
// makes the cursor per-session state. If it were keyed by anything coarser,
// concurrent searches would advance one another's position and each caller
// would receive a partial, interleaved result set. Draining one handle per
// C_FindObjects call maximises the number of cursor updates, and the ascending
// order the module deliberately imposes is asserted too, since a caller that
// takes the first object of a class depends on it.
func TestConcurrentCABIFindObjectsCursors(t *testing.T) {
	const (
		workers = 6
		objects = 12
	)

	inst := newConcInstance(t, "conc-find")

	setup := inst.openSession(t)

	const label = "conc-cabi-find-target"
	expected := make([]pkcs11.ObjectHandle, 0, objects)
	for i := 0; i < objects; i++ {
		handle, err := inst.ctx.CreateObject(setup, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte(fmt.Sprintf("payload-%d", i))),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		})
		if err != nil {
			t.Fatalf("C_CreateObject %d: %v", i, err)
		}
		expected = append(expected, handle)
	}
	sort.Slice(expected, func(i, j int) bool { return expected[i] < expected[j] })

	sessions := make([]pkcs11.SessionHandle, workers)
	for i := range sessions {
		sessions[i] = inst.openSession(t)
	}

	found := make([][]pkcs11.ObjectHandle, workers)
	failures := make([]error, workers)

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start

			session := sessions[idx]
			template := []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			}

			if err := inst.ctx.FindObjectsInit(session, template); err != nil {
				failures[idx] = fmt.Errorf("C_FindObjectsInit: %w", err)
				return
			}

			var handles []pkcs11.ObjectHandle
			for {
				batch, _, err := inst.ctx.FindObjects(session, 1)
				if err != nil {
					failures[idx] = fmt.Errorf("C_FindObjects: %w", err)
					return
				}
				if len(batch) == 0 {
					break
				}
				handles = append(handles, batch...)
			}

			if err := inst.ctx.FindObjectsFinal(session); err != nil {
				failures[idx] = fmt.Errorf("C_FindObjectsFinal: %w", err)
				return
			}

			found[idx] = handles
		}(i)
	}

	close(start)
	wg.Wait()

	for i := 0; i < workers; i++ {
		if failures[i] != nil {
			t.Fatalf("worker %d: %v", i, failures[i])
		}
		if len(found[i]) != len(expected) {
			t.Fatalf("worker %d received %d handles, want %d: a shared search cursor truncates concurrent searches",
				i, len(found[i]), len(expected))
		}
		for k := range expected {
			if found[i][k] != expected[k] {
				t.Fatalf("worker %d result %d = %d, want %d: the result set is reordered or interleaved",
					i, k, found[i][k], expected[k])
			}
		}
	}
}

// ----------------------------------------------------------------------------
// 4. Operation-state isolation
// ----------------------------------------------------------------------------

// TestConcurrentCABIDigestIsolation interleaves multi-part digests over
// DIFFERENT data in different sessions and requires each session to receive
// the digest of its own input.
//
// This is the sharpest test of per-session operation state over the C ABI.
// C_DigestUpdate accumulates into state reached through the session handle; if
// two sessions resolved to one accumulator the failure is silent, because both
// callers still receive a well-formed SHA-256 value. The barrier forces every
// session to submit chunk k before any submits chunk k+1, and the expected
// value comes from crypto/sha256 rather than from a second call to the module.
func TestConcurrentCABIDigestIsolation(t *testing.T) {
	const (
		workers = 8
		chunks  = 6
	)

	inst := newConcInstance(t, "conc-digest")

	sessions := make([]pkcs11.SessionHandle, workers)
	for i := range sessions {
		sessions[i] = inst.openSession(t)
	}

	barrier := newConcBarrier(workers)
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

			if err := inst.ctx.DigestInit(session,
				[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256, nil)}); err != nil {
				failures[idx] = fmt.Errorf("C_DigestInit: %w", err)
				// Keep participating so no other worker waits forever.
				for k := 0; k < chunks+1; k++ {
					barrier.wait()
				}
				return
			}

			for k := 0; k < chunks; k++ {
				barrier.wait()

				chunk := []byte(fmt.Sprintf("cabi-worker-%d-chunk-%d-", idx, k))
				own = append(own, chunk...)

				if err := inst.ctx.DigestUpdate(session, chunk); err != nil {
					failures[idx] = fmt.Errorf("C_DigestUpdate round %d: %w", k, err)
					for j := k; j < chunks; j++ {
						barrier.wait()
					}
					return
				}
			}

			barrier.wait()

			digest, err := inst.ctx.DigestFinal(session)
			if err != nil {
				failures[idx] = fmt.Errorf("C_DigestFinal: %w", err)
				return
			}

			sum := sha256.Sum256(own)
			digests[idx] = digest
			expected[idx] = sum[:]
		}(i)
	}

	wg.Wait()

	for i := 0; i < workers; i++ {
		if failures[i] != nil {
			t.Fatalf("worker %d: %v", i, failures[i])
		}
		if len(digests[i]) != len(expected[i]) {
			t.Fatalf("worker %d digest length %d, want %d", i, len(digests[i]), len(expected[i]))
		}
		for k := range expected[i] {
			if digests[i][k] != expected[i][k] {
				t.Fatalf("worker %d received %x, want the SHA-256 of its own chunks %x: the digest accumulators were shared between sessions",
					i, digests[i], expected[i])
			}
		}
	}
}

// TestConcurrentCABIMultiPartSignIsolation interleaves multi-part signing over
// DIFFERENT data in different sessions and checks each signature with
// crypto/ecdsa over that session's own message.
//
// A shared SignOperation buffer produces a perfectly valid ECDSA signature
// over the concatenation of two sessions' data -- one that the module's own
// C_Verify would accept, because both sides would be wrong in the same way.
// The oracle therefore has to be crypto/ecdsa, and the assertion has to
// include that a signature does NOT verify over another worker's data.
func TestConcurrentCABIMultiPartSignIsolation(t *testing.T) {
	const (
		workers = 6
		chunks  = 5
	)

	inst := newConcInstance(t, "conc-multipart-sign")

	type worker struct {
		session   pkcs11.SessionHandle
		priv      pkcs11.ObjectHandle
		publicKey *ecdsa.PublicKey
		message   []byte
		signature []byte
	}

	state := make([]worker, workers)
	for i := range state {
		session := inst.openSession(t)

		pub, priv, err := inst.concGenerateP256(session, fmt.Sprintf("conc-multipart-key-%d", i))
		if err != nil {
			t.Fatalf("C_GenerateKeyPair %d: %v", i, err)
		}

		publicKey, err := inst.concReadP256PublicKey(session, pub)
		if err != nil {
			t.Fatalf("reading CKA_EC_POINT %d: %v", i, err)
		}

		state[i] = worker{session: session, priv: priv, publicKey: publicKey}
	}

	barrier := newConcBarrier(workers)
	failures := make([]error, workers)

	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()

			w := &state[idx]

			barrier.wait()

			if err := inst.ctx.SignInit(w.session,
				[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_SHA256, nil)}, w.priv); err != nil {
				failures[idx] = fmt.Errorf("C_SignInit: %w", err)
				for k := 0; k < chunks+1; k++ {
					barrier.wait()
				}
				return
			}

			for k := 0; k < chunks; k++ {
				barrier.wait()

				chunk := []byte(fmt.Sprintf("cabi-sign-worker-%d-chunk-%d-", idx, k))
				w.message = append(w.message, chunk...)

				if err := inst.ctx.SignUpdate(w.session, chunk); err != nil {
					failures[idx] = fmt.Errorf("C_SignUpdate round %d: %w", k, err)
					for j := k; j < chunks; j++ {
						barrier.wait()
					}
					return
				}
			}

			barrier.wait()

			signature, err := inst.ctx.SignFinal(w.session)
			if err != nil {
				failures[idx] = fmt.Errorf("C_SignFinal: %w", err)
				return
			}
			w.signature = signature
		}(i)
	}

	wg.Wait()

	for i := 0; i < workers; i++ {
		if failures[i] != nil {
			t.Fatalf("worker %d: %v", i, failures[i])
		}
		if !concVerifyECDSARaw(state[i].publicKey, state[i].message, state[i].signature) {
			t.Fatalf("worker %d: the multi-part signature does not verify over its own concatenated chunks", i)
		}
		for j := 0; j < workers; j++ {
			if i == j {
				continue
			}
			if concVerifyECDSARaw(state[i].publicKey, state[j].message, state[i].signature) {
				t.Fatalf("worker %d signature verifies over worker %d data: the signing buffers were shared", i, j)
			}
		}
	}
}

// ----------------------------------------------------------------------------
// 5. Login / logout races
// ----------------------------------------------------------------------------

// TestConcurrentCABILoginLogoutDuringOperations calls C_Logout on one session
// while other sessions are in the middle of signing with a private key.
//
// Login state is token-wide, so C_Logout revokes the authentication every
// other session relies on, and PKCS#11 v3.2 §5.6.10 additionally invalidates
// handles to private objects at that moment. The only acceptable outcomes for
// an operation caught in that window are a defined CK_RV or a correct result.
// A CKR_OK carrying a signature the module should have refused to produce is
// the silent failure this asserts against, so every success is re-checked with
// crypto/ecdsa; CKR_FUNCTION_FAILED is rejected outright because that is the
// value recoverCKRV substitutes when a panic escapes an entry point.
func TestConcurrentCABILoginLogoutDuringOperations(t *testing.T) {
	const (
		workers    = 4
		iterations = 20
	)

	inst := newConcInstance(t, "conc-login")
	_, userPIN := concPINs(t)

	type worker struct {
		session   pkcs11.SessionHandle
		priv      pkcs11.ObjectHandle
		publicKey *ecdsa.PublicKey
	}

	state := make([]worker, workers)
	for i := range state {
		session := inst.openSession(t)

		pub, priv, err := inst.concGenerateP256(session, fmt.Sprintf("conc-logout-key-%d", i))
		if err != nil {
			t.Fatalf("C_GenerateKeyPair %d: %v", i, err)
		}
		publicKey, err := inst.concReadP256PublicKey(session, pub)
		if err != nil {
			t.Fatalf("reading CKA_EC_POINT %d: %v", i, err)
		}

		state[i] = worker{session: session, priv: priv, publicKey: publicKey}
	}

	churn := inst.openSession(t)

	// The complete set of outcomes an operation may legitimately produce while
	// authentication is torn down and re-established underneath it. Anything
	// outside this set -- CKR_FUNCTION_FAILED above all, since that is the
	// recoverCKRV panic signature -- is a defect.
	acceptable := map[pkcs11.Error]bool{
		pkcs11.CKR_USER_NOT_LOGGED_IN:        true,
		pkcs11.CKR_KEY_HANDLE_INVALID:        true,
		pkcs11.CKR_OBJECT_HANDLE_INVALID:     true,
		pkcs11.CKR_OPERATION_NOT_INITIALIZED: true,
		pkcs11.CKR_SESSION_HANDLE_INVALID:    true,
	}

	failures := make([]error, workers+1)
	panics := make([]*concPanic, workers+1)

	start := make(chan struct{})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers + 1)

	go func() {
		defer wg.Done()
		<-start

		panics[workers] = concGuard("login/logout churn", func() {
			for i := 0; i < iterations; i++ {
				if err := inst.ctx.Logout(churn); err != nil && !concIsCKR(err, pkcs11.CKR_USER_NOT_LOGGED_IN) {
					failures[workers] = fmt.Errorf("C_Logout: %w", err)
					return
				}
				if err := inst.ctx.Login(churn, pkcs11.CKU_USER, userPIN); err != nil &&
					!concIsCKR(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
					failures[workers] = fmt.Errorf("C_Login: %w", err)
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

			panics[idx] = concGuard(fmt.Sprintf("signer %d", idx), func() {
				w := &state[idx]
				message := []byte(fmt.Sprintf("cabi-logout-race-message-%d", idx))
				mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_SHA256, nil)}

				for {
					select {
					case <-stop:
						return
					default:
					}

					if err := inst.ctx.SignInit(w.session, mech, w.priv); err != nil {
						rv, ok := concCKR(err)
						if !ok || !acceptable[rv] {
							failures[idx] = fmt.Errorf("C_SignInit returned an undefined outcome: %w", err)
							return
						}
						continue
					}

					signature, err := inst.ctx.Sign(w.session, message)
					if err != nil {
						rv, ok := concCKR(err)
						if !ok || !acceptable[rv] {
							failures[idx] = fmt.Errorf("C_Sign returned an undefined outcome: %w", err)
							return
						}
						continue
					}

					if !concVerifyECDSARaw(w.publicKey, message, signature) {
						failures[idx] = errors.New("C_Sign returned CKR_OK with a signature that does not verify: an invalidated operation reported success")
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
		if failures[i] != nil {
			t.Fatalf("goroutine %d: %v", i, failures[i])
		}
	}
}

// ----------------------------------------------------------------------------
// 6. C_Initialize / C_Finalize
// ----------------------------------------------------------------------------

// TestConcurrentCABIInitializeAlreadyInitialized calls C_Initialize from many
// native threads against an already-initialized library.
//
// PKCS#11 v3.2 §5.6.1 allows exactly one successful initialization per
// library instance; every other concurrent caller must be told
// CKR_CRYPTOKI_ALREADY_INITIALIZED. A module that checked a plain bool outside
// its lock would let a second caller through and rebuild the slot and object
// managers, silently discarding the state the first one had already stored.
func TestConcurrentCABIInitializeAlreadyInitialized(t *testing.T) {
	const workers = 16

	inst := newConcInstance(t, "conc-initialize")

	results := make([]error, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = inst.ctx.Initialize()
		}(i)
	}

	close(start)
	wg.Wait()

	for i, err := range results {
		if err == nil {
			t.Fatalf("worker %d: a second C_Initialize succeeded; v3.2 §5.6.1 requires CKR_CRYPTOKI_ALREADY_INITIALIZED", i)
		}
		if !concIsCKR(err, pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			t.Fatalf("worker %d: C_Initialize returned %v, want CKR_CRYPTOKI_ALREADY_INITIALIZED", i, err)
		}
	}

	// The library must still be usable afterwards.
	session := inst.openSession(t)
	if err := inst.ctx.DigestInit(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256, nil)}); err != nil {
		t.Fatalf("C_DigestInit after the C_Initialize storm: %v", err)
	}
	digest, err := inst.ctx.Digest(session, []byte("still alive"))
	if err != nil {
		t.Fatalf("C_Digest after the C_Initialize storm: %v", err)
	}
	want := sha256.Sum256([]byte("still alive"))
	if string(digest) != string(want[:]) {
		t.Fatalf("C_Digest returned %x after the C_Initialize storm, want %x", digest, want)
	}
}

// TestConcurrentCABIFinalizeDuringActiveSessions calls C_Finalize while other
// native threads are inside ordinary entry points with live sessions.
//
// C_Finalize tears the module's managers down. Any entry point that checked
// the initialized flag before C_Finalize ran, then blocked on the module lock,
// resumes afterwards against those torn-down managers -- the window in which a
// nil dereference reaches the C boundary. PKCS#11 v3.2 §5.6.2 permits
// C_Finalize at any time, so the calls it races must return a defined CK_RV
// (CKR_CRYPTOKI_NOT_INITIALIZED being the natural one) and must never take the
// process down.
//
// recoverCKRV converts a panic into CKR_FUNCTION_FAILED at the boundary, so a
// CKR_FUNCTION_FAILED from a read-only informational call such as
// C_GetSlotList is treated as the panic it almost certainly is: none of those
// calls has any other reason to fail.
//
// This test runs against its own dlopen'd copy of the library so finalizing it
// cannot disturb any other test.
func TestConcurrentCABIFinalizeDuringActiveSessions(t *testing.T) {
	const workers = 6

	src := os.Getenv("PKCS11_MODULE")
	if src == "" {
		t.Fatal("PKCS11_MODULE is not set; the PKCS#11 Makefile targets export it")
	}

	dst := filepath.Join(t.TempDir(), "conc-finalize.so")
	concCopyFile(t, src, dst)

	storagePath := filepath.Join(t.TempDir(), "storage")
	if err := os.MkdirAll(storagePath, 0o700); err != nil {
		t.Fatalf("creating per-instance storage directory: %v", err)
	}
	t.Setenv("XKMS_PKCS11_STORAGE_PATH", storagePath)

	ctx := pkcs11.New(dst)
	if ctx == nil {
		t.Fatalf("pkcs11.New(%s) returned nil", dst)
	}
	defer ctx.Destroy()

	if err := ctx.Initialize(); err != nil {
		t.Fatalf("C_Initialize: %v", err)
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		t.Fatalf("C_GetSlotList: %v", err)
	}
	if len(slots) == 0 {
		t.Fatal("C_GetSlotList returned no slots")
	}
	slot := slots[0]

	_, userPIN := concPINs(t)

	sessions := make([]pkcs11.SessionHandle, workers)
	for i := range sessions {
		session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			t.Fatalf("C_OpenSession %d: %v", i, err)
		}
		if err := ctx.Login(session, pkcs11.CKU_USER, userPIN); err != nil &&
			!concIsCKR(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			t.Fatalf("C_Login %d: %v", i, err)
		}
		sessions[i] = session
	}

	// Read-only informational calls that have no legitimate reason to report
	// CKR_FUNCTION_FAILED, so that value can only mean a panic was recovered.
	type probe struct {
		name string
		call func(session pkcs11.SessionHandle) error
	}
	probes := []probe{
		{"C_GetSlotList", func(pkcs11.SessionHandle) error { _, err := ctx.GetSlotList(true); return err }},
		{"C_GetSlotInfo", func(pkcs11.SessionHandle) error { _, err := ctx.GetSlotInfo(slot); return err }},
		{"C_GetTokenInfo", func(pkcs11.SessionHandle) error { _, err := ctx.GetTokenInfo(slot); return err }},
		{"C_GetMechanismList", func(pkcs11.SessionHandle) error { _, err := ctx.GetMechanismList(slot); return err }},
		{"C_GetSessionInfo", func(s pkcs11.SessionHandle) error { _, err := ctx.GetSessionInfo(s); return err }},
		{"C_GenerateRandom", func(s pkcs11.SessionHandle) error { _, err := ctx.GenerateRandom(s, 16); return err }},
	}

	failures := make([]error, workers+1)
	panics := make([]*concPanic, workers+1)

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers + 1)

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start

			panics[idx] = concGuard(fmt.Sprintf("entry-point worker %d", idx), func() {
				for k := 0; k < 60; k++ {
					for _, p := range probes {
						err := p.call(sessions[idx])
						if err == nil {
							continue
						}
						if concIsCKR(err, pkcs11.CKR_FUNCTION_FAILED) {
							failures[idx] = fmt.Errorf(
								"%s returned CKR_FUNCTION_FAILED while racing C_Finalize; that is the value "+
									"recoverCKRV substitutes for a recovered panic, so an entry point dereferenced "+
									"a manager C_Finalize had already torn down", p.name)
							return
						}
					}
				}
			})
		}(i)
	}

	go func() {
		defer wg.Done()
		<-start

		panics[workers] = concGuard("finalize", func() {
			if err := ctx.Finalize(); err != nil && !concIsCKR(err, pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED) {
				failures[workers] = fmt.Errorf("C_Finalize: %w", err)
			}
		})
	}()

	close(start)
	wg.Wait()

	for i := range panics {
		if panics[i] != nil {
			t.Fatalf("%s panicked: %v\n%s", panics[i].where, panics[i].value, panics[i].stack)
		}
	}
	for i := range failures {
		if failures[i] != nil {
			t.Fatalf("goroutine %d: %v", i, failures[i])
		}
	}
}

// ----------------------------------------------------------------------------
// 7. No panic across the C boundary
// ----------------------------------------------------------------------------

// TestConcurrentCABIMalformedParametersNeverPanic hammers the library with
// malformed mechanism parameters and invalid handles from several threads at
// once, then proves the module is still correct afterwards.
//
// This is a regression test for a defect of exactly this shape:
// cipher.AEAD's Seal and Open PANIC -- they do not return an error -- when
// handed a nonce whose length is not the AEAD's nonce size, so a
// CK_GCM_PARAMS.pIv of the wrong length took the whole daemon down instead of
// producing CKR_MECHANISM_PARAM_INVALID. Guards were added at the call sites.
//
// A panic that still escapes is converted by recoverCKRV into
// CKR_FUNCTION_FAILED, which is why the assertions look for that value rather
// than for a crash: the process survives, but the operation died in an
// undefined state. The final digest check confirms the module is not merely
// alive but still computing correct results after the storm.
func TestConcurrentCABIMalformedParametersNeverPanic(t *testing.T) {
	const workers = 8

	inst := newConcInstance(t, "conc-malformed")

	// Nonce lengths AES-GCM cannot accept: cipher.AEAD panics on every one of
	// them, so each must be rejected before it reaches Seal or Open.
	badNonceLengths := []int{1, 8, 11, 13, 16, 32}

	failures := make([]error, workers)
	panics := make([]*concPanic, workers)

	sessions := make([]pkcs11.SessionHandle, workers)
	for i := range sessions {
		sessions[i] = inst.openSession(t)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start

			panics[idx] = concGuard(fmt.Sprintf("malformed worker %d", idx), func() {
				session := sessions[idx]

				for round := 0; round < 6; round++ {
					for _, size := range badNonceLengths {
						params := pkcs11.NewGCMParams(make([]byte, size), nil, 128)
						mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}

						// An invalid key handle is deliberate: the point is
						// that the module rejects the request cleanly rather
						// than reaching cipher.AEAD with a bad nonce.
						err := inst.ctx.EncryptInit(session, mech, pkcs11.ObjectHandle(0))
						params.Free()

						if concIsCKR(err, pkcs11.CKR_FUNCTION_FAILED) {
							failures[idx] = fmt.Errorf(
								"C_EncryptInit with a %d-byte AES-GCM IV returned CKR_FUNCTION_FAILED; that is "+
									"the value recoverCKRV substitutes for a recovered panic", size)
							return
						}
						if err == nil {
							// A successful init on an invalid handle would be
							// a policy failure in its own right.
							failures[idx] = fmt.Errorf(
								"C_EncryptInit accepted a %d-byte AES-GCM IV on an invalid key handle", size)
							return
						}
					}

					// Malformed digest and sign sequencing in the same loop, so
					// the guarded paths contend with each other rather than
					// running alone.
					if err := inst.ctx.DigestUpdate(session, []byte("no digest is active")); err == nil {
						failures[idx] = errors.New("C_DigestUpdate succeeded with no active digest operation")
						return
					} else if concIsCKR(err, pkcs11.CKR_FUNCTION_FAILED) {
						failures[idx] = errors.New("C_DigestUpdate with no active operation returned CKR_FUNCTION_FAILED (recovered panic)")
						return
					}

					if _, err := inst.ctx.SignFinal(session); err == nil {
						failures[idx] = errors.New("C_SignFinal succeeded with no active sign operation")
						return
					} else if concIsCKR(err, pkcs11.CKR_FUNCTION_FAILED) {
						failures[idx] = errors.New("C_SignFinal with no active operation returned CKR_FUNCTION_FAILED (recovered panic)")
						return
					}

					if _, err := inst.ctx.GetAttributeValue(session, pkcs11.ObjectHandle(0),
						[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)}); err == nil {
						failures[idx] = errors.New("C_GetAttributeValue succeeded on object handle 0")
						return
					} else if concIsCKR(err, pkcs11.CKR_FUNCTION_FAILED) {
						failures[idx] = errors.New("C_GetAttributeValue on an invalid handle returned CKR_FUNCTION_FAILED (recovered panic)")
						return
					}
				}
			})
		}(i)
	}

	close(start)
	wg.Wait()

	for i := 0; i < workers; i++ {
		if panics[i] != nil {
			t.Fatalf("%s panicked: %v\n%s", panics[i].where, panics[i].value, panics[i].stack)
		}
		if failures[i] != nil {
			t.Fatalf("worker %d: %v", i, failures[i])
		}
	}

	// The module must not merely have survived; it must still be correct.
	session := inst.openSession(t)
	message := []byte("the module still computes correct digests after the malformed-parameter storm")
	if err := inst.ctx.DigestInit(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256, nil)}); err != nil {
		t.Fatalf("C_DigestInit after the storm: %v", err)
	}
	digest, err := inst.ctx.Digest(session, message)
	if err != nil {
		t.Fatalf("C_Digest after the storm: %v", err)
	}
	want := sha256.Sum256(message)
	if string(digest) != string(want[:]) {
		t.Fatalf("C_Digest returned %x after the storm, want %x: the module survived but its state is corrupt", digest, want)
	}
}
