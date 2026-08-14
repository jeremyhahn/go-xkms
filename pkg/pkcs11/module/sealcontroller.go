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

// SealController is the seam through which the module drives the at-rest barrier
// that protects a token's private key material. The module NEVER builds a
// sealer — go-qrdb is the single barrier authority (see
// docs/pkcs11/ROADMAP.md Decisions §C9 and the stack's ownership doc). Instead a
// composition root builds a barrier (via the SDK's seal package) and injects an
// implementation here, so the module only decides WHEN to unseal and reseal,
// keyed by the credential PKCS#11 semantics say owns the key material: the
// normal user's PIN.
//
// Lifecycle, mirroring an industry-standard token:
//   - C_Login(CKU_USER) unseals with the user PIN — the credential every
//     application supplies for day-to-day use. The Security Officer PIN is
//     deliberately NOT the unseal credential: the SO administers the token and
//     cannot see private objects, so sealing under the SO PIN would make the
//     token unusable to any normal application.
//   - C_Logout and C_Finalize reseal, dropping the key from memory.
//
// The token's public partition — label, flags, mechanism info, PIN hashes and
// lockout counters — is NOT behind this barrier: it must stay readable before
// login so C_GetTokenInfo works and the module can verify the PIN it is about
// to unseal with.
type SealController interface {
	// Unseal makes the private key material readable using the supplied
	// passphrase (the user PIN). It is called after the module has already
	// verified the PIN, so a failure here is an at-rest/key-availability fault,
	// not an authentication one.
	Unseal(passphrase []byte) error

	// Seal drops the unsealed key from memory, returning the private material to
	// its protected state. It is called on logout and finalize and must be safe
	// to call when already sealed (idempotent).
	Seal() error

	// Rekey re-protects the private key material under a new passphrase when the
	// user changes their PIN (C_SetPIN). It re-wraps the barrier's key rather
	// than re-encrypting the data, so it is cheap. The old passphrase is needed
	// because the re-wrap runs on the unsealed barrier; when no key material has
	// been created yet (the barrier was never initialized) it is a no-op, since
	// the next login will key the store to the new PIN. It must preserve the
	// seal state — a token whose barrier was sealed before the change (a
	// public-session C_SetPIN) stays sealed after.
	Rekey(oldPassphrase, newPassphrase []byte) error
}

// WithSealController injects the at-rest barrier controller for a token's
// private key material. When set, the module unseals it at C_Login(CKU_USER) and
// reseals it at C_Logout / C_Finalize. When nil (the default), the module runs
// with no at-rest sealing of key material — the transport/backend's own storage
// posture applies (e.g. the offline embedded backend's plain file store, or a
// remote server whose qrdb barrier already protects everything).
func WithSealController(sc SealController) ModuleOption {
	return func(m *Module) error {
		m.sealController = sc
		return nil
	}
}

// unsealPrivateStore unseals the private key barrier if a controller is wired.
// A nil controller means the deployment did not opt into module-driven sealing,
// so it is a no-op success.
func (m *Module) unsealPrivateStore(pin []byte) error {
	if m.sealController == nil {
		return nil
	}
	return m.sealController.Unseal(pin)
}

// sealPrivateStore reseals the private key barrier if a controller is wired.
func (m *Module) sealPrivateStore() {
	if m.sealController == nil {
		return
	}
	// A seal failure at logout/finalize cannot be surfaced through those calls'
	// return codes without contradicting the PKCS#11 contract (logout succeeds
	// once the session state is cleared), and leaving the key unsealed is the
	// unsafe outcome, so the error is recorded rather than dropped silently.
	if err := m.sealController.Seal(); err != nil {
		m.logStorageError("reseal private key store", err)
	}
}

// rekeyPrivateStore re-protects the private key material under the new user PIN
// when a controller is wired. A nil controller is a no-op success.
func (m *Module) rekeyPrivateStore(oldPin, newPin []byte) error {
	if m.sealController == nil {
		return nil
	}
	return m.sealController.Rekey(oldPin, newPin)
}
