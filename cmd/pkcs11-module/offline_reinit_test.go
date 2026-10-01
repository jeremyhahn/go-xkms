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

package main

// Tests for initializing the offline module again after C_Finalize (#1386).
// p11-kit's server initializes a module, finalizes it and initializes it again
// before it serves the first client, so an offline module that cannot come back
// up after C_Finalize cannot be hosted by p11-kit at all.

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// p256OID is the DER-encoded OID of NIST P-256 (secp256r1), CKA_EC_PARAMS.
var p256OID = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

// offlineEnv points offline mode at a fresh directory with the given seal
// strategy, and resets the global module and the library's record of the
// module it built, before and after the test.
func offlineEnv(t *testing.T, sealStrategy string) {
	t.Helper()

	dir := t.TempDir()
	t.Setenv(envMode, "local")
	t.Setenv(envSealStrategy, sealStrategy)
	t.Setenv(envLocalKeyDir, filepath.Join(dir, "keys"))
	t.Setenv(module.EnvStoragePath, filepath.Join(dir, "state"))
	t.Setenv(module.EnvStorageType, "")

	reset := func() {
		module.ResetGlobalModule()
		offlineMu.Lock()
		ownedOffline = nil
		offlineMu.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

// userSession opens a read-write session on slot 0 and logs the user in.
func userSession(t *testing.T, m *module.Module) module.SessionHandle {
	t.Helper()

	session, rv := m.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession (user): %s", rv)
	}
	if rv := m.Login(session, module.CKU_USER, []byte(testUserPIN)); rv != module.CKR_OK {
		t.Fatalf("Login (user): %s", rv)
	}
	return session
}

// provisionOfflineToken initializes the token, sets the user PIN and returns a
// logged-in user session.
func provisionOfflineToken(t *testing.T, m *module.Module) module.SessionHandle {
	t.Helper()

	if rv := m.InitToken(0, []byte(testSOPIN), "Offline Token"); rv != module.CKR_OK {
		t.Fatalf("InitToken: %s", rv)
	}
	soSession, rv := m.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	if rv != module.CKR_OK {
		t.Fatalf("OpenSession (SO): %s", rv)
	}
	if rv := m.Login(soSession, module.CKU_SO, []byte(testSOPIN)); rv != module.CKR_OK {
		t.Fatalf("Login (SO): %s", rv)
	}
	if rv := m.InitPIN(soSession, []byte(testUserPIN)); rv != module.CKR_OK {
		t.Fatalf("InitPIN: %s", rv)
	}
	if rv := m.CloseSession(soSession); rv != module.CKR_OK {
		t.Fatalf("CloseSession (SO): %s", rv)
	}
	return userSession(t, m)
}

// findOne returns the single object of the given class carrying label.
func findOne(t *testing.T, m *module.Module, session module.SessionHandle, class module.ObjectClass, label string) module.ObjectHandle {
	t.Helper()

	template := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(class)),
		module.NewStringAttribute(module.CKA_LABEL, label),
	}
	if rv := m.FindObjectsInit(session, template); rv != module.CKR_OK {
		t.Fatalf("FindObjectsInit(%s): %s", label, rv)
	}
	handles, rv := m.FindObjects(session, 2)
	if rv != module.CKR_OK {
		t.Fatalf("FindObjects(%s): %s", label, rv)
	}
	if rv := m.FindObjectsFinal(session); rv != module.CKR_OK {
		t.Fatalf("FindObjectsFinal(%s): %s", label, rv)
	}
	if len(handles) != 1 {
		t.Fatalf("FindObjects(%s) found %d objects, want 1", label, len(handles))
	}
	return handles[0]
}

// signAndVerify signs a digest with the private key and verifies it with the
// public key, both through the module.
func signAndVerify(t *testing.T, m *module.Module, session module.SessionHandle, priv, pub module.ObjectHandle) {
	t.Helper()

	digest := sha256.Sum256([]byte("IKE_AUTH octets"))
	if rv := m.SignInit(session, &module.Mechanism{Type: module.CKM_ECDSA}, priv); rv != module.CKR_OK {
		t.Fatalf("SignInit: %s", rv)
	}
	signature, rv := m.Sign(session, digest[:])
	if rv != module.CKR_OK {
		t.Fatalf("Sign: %s", rv)
	}
	// C_Sign ends the operation once the signature is delivered.
	if rv := m.FinishOperation(session, module.OperationSign); rv != module.CKR_OK {
		t.Fatalf("FinishOperation(sign): %s", rv)
	}
	if rv := m.VerifyInit(session, &module.Mechanism{Type: module.CKM_ECDSA}, pub); rv != module.CKR_OK {
		t.Fatalf("VerifyInit: %s", rv)
	}
	if rv := m.Verify(session, digest[:], signature); rv != module.CKR_OK {
		t.Fatalf("Verify: %s", rv)
	}
}

// TestCInitialize_OfflineReinitializesAfterFinalize drives the C entry points
// through the sequence p11-kit's server performs, initialize, finalize,
// initialize, and proves the second initialization comes up on the same token:
// the ECDSA key generated before C_Finalize still signs afterwards.
func TestCInitialize_OfflineReinitializesAfterFinalize(t *testing.T) {
	for _, strategy := range []string{sealStrategyNone, sealStrategyPass} {
		t.Run(strategy, func(t *testing.T) {
			offlineEnv(t, strategy)

			if rv, _ := callC(t, C_Initialize, cNull()); rv != module.CKR_OK {
				t.Fatalf("first C_Initialize = %s, want CKR_OK", rv)
			}
			first := module.GetGlobalModule()
			session := provisionOfflineToken(t, first)

			const label = "ike-key"
			pubTemplate := []module.Attribute{
				module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
				module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_EC)),
				module.NewStringAttribute(module.CKA_LABEL, label),
				module.NewAttribute(module.CKA_EC_PARAMS, p256OID),
				module.NewBoolAttribute(module.CKA_VERIFY, true),
				module.NewBoolAttribute(module.CKA_TOKEN, true),
			}
			privTemplate := []module.Attribute{
				module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
				module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_EC)),
				module.NewStringAttribute(module.CKA_LABEL, label),
				module.NewBoolAttribute(module.CKA_SIGN, true),
				module.NewBoolAttribute(module.CKA_TOKEN, true),
			}
			pub, priv, rv := first.GenerateKeyPair(session, &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN}, pubTemplate, privTemplate)
			if rv != module.CKR_OK {
				t.Fatalf("GenerateKeyPair: %s", rv)
			}
			signAndVerify(t, first, session, priv, pub)

			if rv, _ := callC(t, C_Finalize, cNull()); rv != module.CKR_OK {
				t.Fatalf("C_Finalize = %s, want CKR_OK", rv)
			}

			if rv, _ := callC(t, C_Initialize, cNull()); rv != module.CKR_OK {
				t.Fatalf("C_Initialize after C_Finalize = %s, want CKR_OK", rv)
			}
			second := module.GetGlobalModule()
			if second == first {
				t.Fatal("C_Initialize after C_Finalize reused the finalized module; its embedded client is closed")
			}

			session = userSession(t, second)
			priv = findOne(t, second, session, module.CKO_PRIVATE_KEY, label)
			pub = findOne(t, second, session, module.CKO_PUBLIC_KEY, label)
			signAndVerify(t, second, session, priv, pub)

			if rv, _ := callC(t, C_Initialize, cNull()); rv != module.CKR_CRYPTOKI_ALREADY_INITIALIZED {
				t.Fatalf("C_Initialize on the initialized module = %s, want CKR_CRYPTOKI_ALREADY_INITIALIZED", rv)
			}
			if module.GetGlobalModule() != second {
				t.Fatal("C_Initialize on an initialized module replaced it")
			}
		})
	}
}

// TestCInitialize_OfflineLeavesInjectedModuleInPlace proves the rebuild is
// confined to the library's own module: a finalized module a Go caller
// installed (as xkey does) is initialized as it is, never replaced by an
// offline one.
func TestCInitialize_OfflineLeavesInjectedModuleInPlace(t *testing.T) {
	offlineEnv(t, sealStrategyNone)

	injected, err := module.New(
		module.WithClient(offlineTransport{}),
		module.WithConfig(module.DefaultConfig()),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	module.SetGlobalModule(injected)

	if rv, _ := callC(t, C_Initialize, cNull()); rv != module.CKR_OK {
		t.Fatalf("C_Initialize with an injected module = %s, want CKR_OK", rv)
	}
	if rv, _ := callC(t, C_Finalize, cNull()); rv != module.CKR_OK {
		t.Fatalf("C_Finalize = %s, want CKR_OK", rv)
	}

	// Finalize dropped the injected client, so the module now falls back to
	// dialing the default remote target, which is not listening: the library
	// must report that rather than quietly substitute its own offline module.
	if rv, _ := callC(t, C_Initialize, cNull()); rv != module.CKR_DEVICE_ERROR {
		t.Fatalf("C_Initialize of a finalized injected module = %s, want CKR_DEVICE_ERROR", rv)
	}
	if module.GetGlobalModule() != injected {
		t.Fatal("C_Initialize replaced a module the library did not build")
	}
}

// TestCInitialize_OfflineBuildFailureIsDeviceError proves an offline module
// that cannot be built is reported as CKR_DEVICE_ERROR and installs nothing.
func TestCInitialize_OfflineBuildFailureIsDeviceError(t *testing.T) {
	offlineEnv(t, sealStrategyPass)

	// A regular file where the key directory must be created makes the file
	// key store fail to open.
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("create blocker: %v", err)
	}
	t.Setenv(envLocalKeyDir, filepath.Join(blocker, "keys"))

	if rv, _ := callC(t, C_Initialize, cNull()); rv != module.CKR_DEVICE_ERROR {
		t.Fatalf("C_Initialize with an unbuildable offline module = %s, want CKR_DEVICE_ERROR", rv)
	}
	if module.HasGlobalModule() {
		t.Fatal("a failed offline build must not install a global module")
	}
}
