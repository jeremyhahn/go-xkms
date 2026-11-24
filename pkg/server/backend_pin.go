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

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/pinselect"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ErrBackendPINNotConfigured reports a backend PIN operation on a server
// with no PKCS#11 backend (and so no backend PIN strategy).
var ErrBackendPINNotConfigured = errors.New("server: no backend PIN strategy (PKCS#11 backend not enabled)")

// errBackendPINNoConfiguredPIN reports a sealed/tpm2 release with no
// resolved backends.pkcs11.pin or active rng.pkcs11.pin.
var errBackendPINNoConfiguredPIN = errors.New("server: neither backends.pkcs11.pin nor rng.pkcs11.pin is set")

// errBackendPINNotBarrierSealed reports a sealed release whose PIN is not
// stored under the barrier (credentials.seal_strategy is not barrier).
var errBackendPINNotBarrierSealed = errors.New("server: backend PIN strategy sealed needs credentials.seal_strategy barrier")

// ErrBackendPINManualUnavailable refuses backend_pin.strategy manual (and
// minimum manual) until manual can be operational: the go-qrdb unseal
// request carries no backend PIN, and the xkms service cannot register a
// keystore after start-up (docs/SPEC.md:78).
var ErrBackendPINManualUnavailable = errors.New("server: backend PIN strategy manual is unavailable: the unseal request carries no backend PIN")

// backendPINDir is <datastore>/pin, the directory pinselect persists the
// backend PIN strategy record in (beside the qrdb PIN strategy record).
func (s *Server) backendPINDir() string {
	return filepath.Join(s.config.Datastore.Path, "pin")
}

// pkcs11Enabled reports an enabled PKCS#11 key backend.
func (s *Server) pkcs11Enabled() bool {
	return s.config.Backends.PKCS11 != nil && s.config.Backends.PKCS11.Enabled
}

// rngPKCS11PINActive reports an rng.pkcs11.pin the RNG can use: a PIN is
// configured and the PKCS#11 RNG is selected (mode pkcs11 or auto, or the
// pkcs11 fallback). An empty rng.mode is auto, as Config.GetRNGConfig and
// the RNG resolver read it.
func (s *Server) rngPKCS11PINActive() bool {
	rng := s.config.RNG
	if rng.PKCS11 == nil || rng.PKCS11.PIN == nil {
		return false
	}
	return rng.Mode == "pkcs11" || rng.Mode == "auto" || rng.Mode == "" || rng.FallbackMode == "pkcs11"
}

// resolveBackendPIN resolves the backend PIN strategy through
// pinselect.ResolveBackendPIN at start-up, beside buildSecretRegistry
// (owner decision 230, #2262). It persists the strategy and installs the
// in-memory holder; it starts nothing. A refused resolution is returned
// unchanged so start-up stops (fail closed, never a silent downgrade).
func (s *Server) resolveBackendPIN() error {
	// The policy covers both backends.pkcs11.pin and rng.pkcs11.pin: an
	// active RNG PIN is resolved and enforced even without the key backend.
	if !s.pkcs11Enabled() && !s.rngPKCS11PINActive() {
		return nil
	}
	// A Raft key on the token resolved the strategy before the pre-node
	// open (resolvePreNodeBackendPIN): install that one, never resolve twice.
	if s.preNodeBackendPIN != "" {
		s.installBackendPIN(s.preNodeBackendPIN)
		return nil
	}
	strategy, err := s.resolveBackendPINStrategy(false)
	if err != nil {
		return err
	}
	// tpm2 over a PIN not stored in the TPM moves the PIN into TPM custody
	// (tpmCustodyBlob); a PIN whose weaker copy cannot be removed is refused.
	if strategy == pinselect.BackendPINTPM2 && s.backendPINStore() != pinselect.BackendPINTPM2 {
		if err := s.checkBackendPINTPMCustody(); err != nil {
			return err
		}
	}
	s.installBackendPIN(strategy)
	return nil
}

// backendPINPolicyPreflight runs the backend PIN policy checks that need
// no secret, before config secret resolution: a refused strategy never
// waits on a PIN reference resolution cannot serve (manual credential
// retrieval blocks until an operator submits it).
func (s *Server) backendPINPolicyPreflight() error {
	if !s.pkcs11Enabled() && !s.rngPKCS11PINActive() {
		return nil
	}
	strategy := pinselect.BackendPINStrategy(s.config.BackendPIN.Strategy)
	minimum := pinselect.BackendPINStrategy(s.config.BackendPIN.Minimum)
	if strategy == pinselect.BackendPINManual || minimum == pinselect.BackendPINManual {
		return ErrBackendPINManualUnavailable
	}
	store := s.backendPINStore()
	if strategy == pinselect.BackendPINSealed {
		if s.barrier == nil {
			return &pinselect.BackendPINUnavailableError{Strategy: strategy, Reason: "no barrier"}
		}
		if store != pinselect.BackendPINSealed {
			return &pinselect.BackendPINStoreError{Strategy: strategy, Store: store}
		}
	}
	if (strategy == pinselect.BackendPINTPM2 || minimum == pinselect.BackendPINTPM2) && store != pinselect.BackendPINTPM2 {
		return s.checkBackendPINTPMCustody()
	}
	return nil
}

// resolveBackendPINStrategy resolves (and on a fresh install persists) the
// backend PIN strategy. preNode raises the minimum to tpm2, so pinselect
// refuses a weaker strategy before it persists a record.
func (s *Server) resolveBackendPINStrategy(preNode bool) (pinselect.BackendPINStrategy, error) {
	// Manual is refused before anything is persisted or released: no
	// unseal request carries the PIN yet (ErrBackendPINManualUnavailable).
	if s.config.BackendPIN.Strategy == string(pinselect.BackendPINManual) ||
		s.config.BackendPIN.Minimum == string(pinselect.BackendPINManual) {
		return "", ErrBackendPINManualUnavailable
	}
	minimum := pinselect.BackendPINStrategy(s.config.BackendPIN.Minimum)
	if preNode && (minimum == "" || minimum == pinselect.BackendPINSealed) {
		minimum = pinselect.BackendPINTPM2
	}
	tpmPresent, barrierAvailable := s.probeBackendPIN()
	store := s.backendPINStore()
	// A TPM PIN not stored in the TPM is sealed to it by the server
	// (tpmSealedBackendPINRelease), so tpm2 needs no second setting. The
	// pre-node release runs before unseal, when only a TPM-stored PIN is
	// readable, so it keeps the store check.
	var tpmSealerErr error
	tpmSealerAvailable := false
	if tpmPresent && !preNode && store != pinselect.BackendPINTPM2 && s.backendPINMayResolveTPM2() {
		if _, tpmSealerErr = s.backendPINTPMSealer(); tpmSealerErr == nil {
			tpmSealerAvailable = true
		}
	}
	strategy, err := pinselect.ResolveBackendPIN(pinselect.BackendPINConfig{
		PINDir:   s.backendPINDir(),
		Strategy: pinselect.BackendPINStrategy(s.config.BackendPIN.Strategy),
		Minimum:  minimum,
		// auto selects tpm2 whenever a TPM 2.0 is present (docs/SPEC.md:78).
		// Store makes the strategy match the PIN's actual storage
		// (credentials.seal_strategy): tpm2 needs a PIN sealed to the TPM,
		// sealed a PIN stored under the barrier. Any other storage is
		// refused before a record is persisted, and a persisted record is
		// refused when the storage changed since (fail closed).
		TPMPresent:         tpmPresent,
		BarrierAvailable:   barrierAvailable,
		SealerIsPKCS11:     s.sealerIsPKCS11(),
		Store:              store,
		TPMSealerAvailable: tpmSealerAvailable,
	})
	if err != nil && tpmSealerErr != nil {
		var storeErr *pinselect.BackendPINStoreError
		if errors.As(err, &storeErr) && storeErr.Strategy == pinselect.BackendPINTPM2 {
			err = errors.Join(err, &BackendPINTPMSealerError{Err: tpmSealerErr})
		}
	}
	if err != nil {
		if preNode {
			return "", preNodeBackendPINError(err)
		}
		return "", err
	}
	if strategy == pinselect.BackendPINManual {
		// A record persisted as manual by an earlier release.
		return "", ErrBackendPINManualUnavailable
	}
	if preNode && strategy != pinselect.BackendPINTPM2 {
		return "", fmt.Errorf("%w: resolved strategy %q", ErrBackendPINNodeKeyBeforeUnseal, strategy)
	}
	return strategy, nil
}

// backendPINMayResolveTPM2 reports whether the backend PIN can resolve to
// tpm2: tpm2 configured, or auto without a persisted strategy other than
// tpm2. Only then is a TPM opened to seal the PIN to.
func (s *Server) backendPINMayResolveTPM2() bool {
	switch pinselect.BackendPINStrategy(s.config.BackendPIN.Strategy) {
	case pinselect.BackendPINTPM2:
		return true
	case pinselect.BackendPINAuto, "":
		persisted, err := pinselect.LoadBackendPINStrategy(s.backendPINDir())
		return err != nil || persisted == pinselect.BackendPINTPM2
	default:
		return false
	}
}

// preNodeBackendPINError marks a refusal of a weaker-than-tpm2 strategy
// for the pre-node open with ErrBackendPINNodeKeyBeforeUnseal, keeping the
// pinselect error in the chain. Before unseal there is no barrier, so a
// sealed strategy is refused as unavailable.
func preNodeBackendPINError(err error) error {
	var below *pinselect.BackendPINBelowMinimumError
	if errors.As(err, &below) {
		return fmt.Errorf("%w: resolved strategy %q: %w", ErrBackendPINNodeKeyBeforeUnseal, below.Strategy, err)
	}
	var unavailable *pinselect.BackendPINUnavailableError
	if errors.As(err, &unavailable) && unavailable.Strategy != pinselect.BackendPINTPM2 {
		return fmt.Errorf("%w: resolved strategy %q: %w", ErrBackendPINNodeKeyBeforeUnseal, unavailable.Strategy, err)
	}
	return err
}

// installBackendPIN installs the in-memory holder for strategy and ties its
// zeroization to the running barrier's seal.
func (s *Server) installBackendPIN(strategy pinselect.BackendPINStrategy) {
	s.backendPIN = pinselect.NewBackendPIN(strategy,
		s.backendPINRelease(strategy, s.primaryBackendPINSecret, &s.backendPINTPMCustody))
	// An active RNG PIN beside the key backend's is resolved and protected
	// on its own: same strategy and minimum, own credential and sealed blob.
	s.rngBackendPIN = nil
	if s.separateRNGPKCS11PIN() {
		s.rngBackendPIN = pinselect.NewBackendPIN(strategy,
			s.backendPINRelease(strategy, s.rngBackendPINSecret, &s.rngBackendPINTPMCustody))
	}
	// Zeroize at every seal of the running barrier, not only at shutdown:
	// the barrier runs this before it wipes its own root key.
	if s.barrier != nil {
		s.barrier.OnSealing(func(context.Context) error {
			return s.SealBackendPIN()
		})
	}
}

// separateRNGPKCS11PIN reports an active RNG PIN beside an enabled key
// backend: the RNG PIN then has its own holder (rngBackendPIN).
func (s *Server) separateRNGPKCS11PIN() bool {
	return s.pkcs11Enabled() && s.rngPKCS11PINActive()
}

// rngBackendPINSecret is the RNG PKCS#11 PIN.
func (s *Server) rngBackendPINSecret() backendPINSecret {
	if s.config.RNG.PKCS11 == nil {
		return backendPINSecret{field: "rng.pkcs11.pin"}
	}
	return backendPINSecret{field: "rng.pkcs11.pin", secret: s.config.RNG.PKCS11.PIN}
}

// backendPINStore maps credentials.seal_strategy, the storage the configured
// PIN (a credential:// reference) is resolved from, to the backend PIN
// strategy it provides: tpm2 for a PIN sealed to the TPM, sealed for a PIN
// stored under the barrier. Any other storage is returned by name (unset is
// manual, the credentials default) and matches no backend PIN strategy.
func (s *Server) backendPINStore() pinselect.BackendPINStrategy {
	switch store := s.config.Credentials.SealStrategy; store {
	case "tpm2":
		return pinselect.BackendPINTPM2
	case "barrier":
		return pinselect.BackendPINSealed
	case "":
		return "manual"
	default:
		return pinselect.BackendPINStrategy(store)
	}
}

// sealerIsPKCS11 reports a PKCS#11 token as the actual sealer of a sealed
// backend PIN: the barrier itself sealed by PKCS#11 (barrier.strategy
// pkcs11), or credentials sealed directly to PKCS#11. Either way the token
// would store its own PIN (docs/SPEC.md:78).
func (s *Server) sealerIsPKCS11() bool {
	return s.config.Barrier.Strategy == "pkcs11" || s.config.Credentials.SealStrategy == "pkcs11"
}

// backendPINRelease is the strategy-specific release: tpm2 and sealed
// re-check at every release that the PIN is still stored as the strategy
// asserts (sealed to the TPM, under the barrier), so a holder never
// releases a PIN whose protection is weaker than the persisted strategy.
func (s *Server) backendPINRelease(strategy pinselect.BackendPINStrategy, pinSecret func() backendPINSecret, custody *atomic.Bool) func(context.Context) ([]byte, error) {
	configured := func(ctx context.Context) ([]byte, error) {
		p := pinSecret()
		if p.secret == nil {
			return nil, errBackendPINNoConfiguredPIN
		}
		return secretPIN(ctx, p.secret)
	}
	if strategy != pinselect.BackendPINTPM2 && strategy != pinselect.BackendPINSealed {
		return configured
	}
	tpmSealed := s.tpmSealedBackendPINRelease(pinSecret, custody)
	return func(ctx context.Context) ([]byte, error) {
		if store := s.backendPINStore(); store != strategy {
			if strategy == pinselect.BackendPINTPM2 {
				// The PIN is not stored in the TPM: the server seals it there.
				return tpmSealed(ctx)
			}
			return nil, errBackendPINNotBarrierSealed
		}
		return configured(ctx)
	}
}

// tpmSealedBackendPINRelease releases a tpm2 backend PIN whose storage is
// not the TPM: the first release reads the configured PIN (after unseal),
// seals it to the TPM and wipes the plaintext; that release and every later
// one unseal the PIN from the TPM-sealed copy, the only copy kept. Any TPM
// failure fails closed with BackendPINTPMSealerError.
func (s *Server) tpmSealedBackendPINRelease(pinSecret func() backendPINSecret, custody *atomic.Bool) func(context.Context) ([]byte, error) {
	var (
		mu     sync.Mutex
		sealed *types.SealedData
	)
	return func(ctx context.Context) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		sealer, err := s.backendPINTPMSealer()
		if err != nil {
			return nil, &BackendPINTPMSealerError{Err: err}
		}
		if sealed == nil {
			blob, err := s.tpmCustodyBlob(ctx, sealer, pinSecret())
			if err != nil {
				return nil, err
			}
			sealed = blob
			custody.Store(true)
		}
		pin, err := sealer.Unseal(ctx, sealed, nil)
		if err != nil {
			return nil, &BackendPINTPMSealerError{Err: err}
		}
		return pin, nil
	}
}

// backendPINTPMEnvelope marks a credential value that is the TPM-sealed
// backend PIN blob, not the PIN: the credential holds it after the PIN
// moved into TPM custody (#2262).
const backendPINTPMEnvelope = "xkms-backend-pin-tpm2-sealed:v1:"

// backendPINSecret is one configured PKCS#11 PIN field and its value.
type backendPINSecret struct {
	field  string
	secret *types.SecretValue
}

// backendPINCredentialStore is the credential storage a backend PIN
// credential:// reference resolves from; the PIN moves into TPM custody
// by replacing the stored PIN with its TPM-sealed blob.
type backendPINCredentialStore interface {
	StoreCredential(ctx context.Context, name string, value []byte) error
	DeleteCredential(ctx context.Context, name string) error
}

// backendPINCredentialStore returns the injected store, else the server's
// credential service, else nil.
func (s *Server) backendPINCredentialStore() backendPINCredentialStore {
	if s.backendPINCredentials != nil {
		return s.backendPINCredentials
	}
	if svc := s.CredentialService(); svc != nil {
		return svc
	}
	return nil
}

// backendPINCredentialName returns the credential name of a credential://
// reference.
func backendPINCredentialName(raw string) (string, bool) {
	name, ok := strings.CutPrefix(raw, "credential://")
	return name, ok && name != ""
}

// checkBackendPINTPMCustody refuses a tpm2 PIN the server cannot move into
// TPM custody: only a credential:// reference under barrier credential
// storage can have its weaker copy replaced by the TPM-sealed blob.
func (s *Server) checkBackendPINTPMCustody() error {
	for _, p := range s.activeBackendPINSecrets() {
		if p.secret == nil {
			continue
		}
		if _, ok := backendPINCredentialName(p.secret.Raw); !ok {
			return &BackendPINTPMCustodyError{Field: p.field, Reason: "the PIN is not a credential:// reference, so its copy outside the TPM cannot be removed"}
		}
		if store := s.backendPINStore(); store != pinselect.BackendPINSealed {
			return &BackendPINTPMCustodyError{Field: p.field, Reason: fmt.Sprintf("credentials.seal_strategy stores the PIN under %q, not barrier", store)}
		}
		if s.backendPINCredentialStore() == nil {
			return &BackendPINTPMCustodyError{Field: p.field, Reason: "no credential service"}
		}
	}
	return nil
}

// tpmCustodyBlob returns the TPM-sealed blob of a PIN. A credential that
// already holds the blob is read as is (never sealed again); a PIN still
// stored in plaintext under the barrier is sealed, and the credential is
// replaced by the blob, so the datastore and barrier credentials alone no
// longer recover it.
func (s *Server) tpmCustodyBlob(ctx context.Context, sealer types.Sealer, p backendPINSecret) (*types.SealedData, error) {
	if p.secret == nil {
		return nil, errBackendPINNoConfiguredPIN
	}
	value, err := secretPIN(ctx, p.secret)
	if err != nil {
		return nil, err
	}
	defer clear(value)
	if envelope, ok := bytes.CutPrefix(value, []byte(backendPINTPMEnvelope)); ok {
		var blob types.SealedData
		if err := json.Unmarshal(envelope, &blob); err != nil {
			return nil, &BackendPINTPMCustodyError{Field: p.field, Reason: "the stored TPM-sealed blob does not decode", Err: err}
		}
		return &blob, nil
	}
	blob, err := sealer.Seal(ctx, value, nil)
	if err != nil {
		return nil, &BackendPINTPMSealerError{Err: err}
	}
	if err := s.replaceBackendPINCredential(ctx, p, value, blob); err != nil {
		return nil, err
	}
	return blob, nil
}

// replaceBackendPINCredential replaces the plaintext PIN credential with
// its TPM-sealed blob. When the blob cannot be stored the PIN is put back,
// so a later start migrates it, and the release fails closed.
func (s *Server) replaceBackendPINCredential(ctx context.Context, p backendPINSecret, pin []byte, blob *types.SealedData) error {
	name, ok := backendPINCredentialName(p.secret.Raw)
	store := s.backendPINCredentialStore()
	if !ok || store == nil {
		return &BackendPINTPMCustodyError{Field: p.field, Reason: "the PIN credential cannot be replaced"}
	}
	encoded, err := json.Marshal(blob)
	if err != nil {
		return &BackendPINTPMCustodyError{Field: p.field, Reason: "the TPM-sealed blob does not encode", Err: err}
	}
	envelope := append([]byte(backendPINTPMEnvelope), encoded...)
	if err := store.DeleteCredential(ctx, name); err != nil {
		return &BackendPINTPMCustodyError{Field: p.field, Reason: "the barrier-stored PIN could not be deleted", Err: err}
	}
	if err := store.StoreCredential(ctx, name, envelope); err != nil {
		restoreErr := store.StoreCredential(ctx, name, pin)
		return &BackendPINTPMCustodyError{Field: p.field, Reason: "the TPM-sealed blob could not be stored", Err: errors.Join(err, restoreErr)}
	}
	return nil
}

// backendPINTPMSealer returns the Platform SRK sealer the backend PIN is
// sealed to. It reuses the TPM an earlier call (or the platform store)
// opened, so the TPM is opened at most once.
func (s *Server) backendPINTPMSealer() (types.Sealer, error) {
	backend, ok := s.platformStoreTPM.(*tpm2backend.Backend)
	if !ok {
		return s.buildTPM2PlatformSealer()
	}
	attrs, err := backend.TPM().PlatformSRKAttributes()
	if err != nil {
		return nil, err
	}
	return seal.NewPlatformPolicySealer(backend, platformStoreSealCN, attrs), nil
}

// BackendPINTPMSealerError reports that the tpm2 backend PIN strategy could
// not seal the PIN to the TPM, or unseal it: start-up fails closed and
// never falls back to sealed.
type BackendPINTPMSealerError struct {
	Err error
}

func (e *BackendPINTPMSealerError) Error() string {
	return "server: backend PIN strategy tpm2 cannot seal the PIN to the TPM: " + e.Err.Error()
}

func (e *BackendPINTPMSealerError) Unwrap() error { return e.Err }

// probeBackendPIN reports a usable TPM 2.0 and a barrier able to seal.
func (s *Server) probeBackendPIN() (bool, bool) {
	if s.backendPINProbe != nil {
		return s.backendPINProbe()
	}
	return s.tpmPresent(), s.barrier != nil
}

// tpmPresent reports TPM 2.0 availability on the host, independently of
// the tpm2 key backend (backends.tpm2.enabled): a TPM the server already
// opened, else the device probe.
func (s *Server) tpmPresent() bool {
	if s.platformStoreTPM != nil || s.nodeSealTPM != nil {
		return true
	}
	if s.tpmDeviceProbe != nil {
		return s.tpmDeviceProbe()
	}
	return defaultTPMDevicePresent(s.config.Backends.TPM2)
}

// defaultTPMDevicePresent probes for a TPM 2.0 device: the configured
// device or simulator, else the kernel's resource manager or raw device.
func defaultTPMDevicePresent(cfg *config.TPM2Config) bool {
	paths := []string{"/dev/tpmrm0", "/dev/tpm0"}
	if cfg != nil {
		if cfg.UseSimulator {
			return true
		}
		if cfg.DevicePath != "" {
			paths = append([]string{cfg.DevicePath}, paths...)
		}
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// primaryBackendPINSecret is the key backend's PIN when it is enabled,
// otherwise the active RNG PIN.
func (s *Server) primaryBackendPINSecret() backendPINSecret {
	switch {
	case s.pkcs11Enabled():
		return backendPINSecret{field: "backends.pkcs11.pin", secret: s.config.Backends.PKCS11.Pin}
	case s.rngPKCS11PINActive():
		return backendPINSecret{field: "rng.pkcs11.pin", secret: s.config.RNG.PKCS11.PIN}
	}
	return backendPINSecret{}
}

// activeBackendPINSecrets lists every configured PIN the backend PIN
// policy protects.
func (s *Server) activeBackendPINSecrets() []backendPINSecret {
	active := []backendPINSecret{s.primaryBackendPINSecret()}
	if s.separateRNGPKCS11PIN() {
		active = append(active, s.rngBackendPINSecret())
	}
	return active
}

// secretPIN copies a secret's bytes into a slice the caller wipes.
func secretPIN(ctx context.Context, secret *types.SecretValue) ([]byte, error) {
	var pin []byte
	err := secret.WithBytes(ctx, func(b []byte) error {
		pin = append([]byte(nil), b...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pin, nil
}

// startPKCS11AfterUnseal starts the PKCS#11 backend once the barrier is
// unsealed: sealed and tpm2 release the PIN and open the token; manual
// waits for UnsealBackendPIN.
func (s *Server) startPKCS11AfterUnseal() error {
	if s.backendPIN == nil || s.backendPIN.Strategy() == pinselect.BackendPINManual {
		return nil
	}
	if err := s.backendPIN.Unseal(s.ctx, nil); err != nil {
		return &ErrBackendInit{Backend: "PKCS#11", Err: err}
	}
	if s.rngBackendPIN != nil {
		if err := s.rngBackendPIN.Unseal(s.ctx, nil); err != nil {
			return &ErrBackendInit{Backend: "PKCS#11 RNG", Err: err}
		}
	}
	if !s.pkcs11Enabled() {
		// Only an RNG PIN is held: released, but no key backend to open.
		return nil
	}
	return s.openPKCS11WithHeldPIN()
}

// UnsealBackendPIN takes the manual backend PIN carried by the unseal
// request, holds a copy in memory only, and starts the PKCS#11 backend.
// It refuses a PIN under any other strategy.
func (s *Server) UnsealBackendPIN(ctx context.Context, pin []byte) error {
	if s.backendPIN == nil {
		return ErrBackendPINNotConfigured
	}
	if s.backendPIN.Strategy() != pinselect.BackendPINManual {
		return pinselect.ErrBackendPINNotManual
	}
	if err := s.backendPIN.Unseal(ctx, pin); err != nil {
		return err
	}
	return s.openPKCS11WithHeldPIN()
}

// openPKCS11WithHeldPIN opens the token with the held PIN and registers it.
func (s *Server) openPKCS11WithHeldPIN() error {
	if _, ok := s.keyProviders["pkcs11"]; ok {
		return nil
	}
	pin, err := s.backendPIN.PIN()
	if err != nil {
		return &ErrBackendInit{Backend: "PKCS#11", Err: err}
	}
	// PIN returns a fresh plaintext copy: wipe it once the opener returns,
	// on success and failure (the opener keeps its own sealed copy).
	defer clear(pin)
	opener := s.pkcs11PINOpener
	if opener == nil {
		opener = s.defaultPKCS11PINOpener
	}
	provider, err := opener(pin)
	if err != nil {
		return &ErrBackendInit{Backend: "PKCS#11", Err: err}
	}
	if s.keyProviders == nil {
		s.keyProviders = map[string]types.KeyProvider{}
	}
	s.keyProviders["pkcs11"] = provider
	return nil
}

// SealBackendPIN runs at seal: under manual the PKCS#11 backend stops;
// under every strategy the held PIN is zeroized.
func (s *Server) SealBackendPIN() error {
	if s.backendPIN == nil {
		return nil
	}
	var closeErr error
	if s.backendPIN.StopsAtSeal() {
		if provider, ok := s.keyProviders["pkcs11"]; ok {
			delete(s.keyProviders, "pkcs11")
			closeErr = provider.Close()
		}
	}
	s.backendPIN.Seal()
	if s.rngBackendPIN != nil {
		s.rngBackendPIN.Seal()
	}
	return closeErr
}

// BackendPINStrategy reports the persisted backend PIN strategy for
// status; empty when no PKCS#11 backend is enabled.
func (s *Server) BackendPINStrategy() string {
	if s.backendPIN == nil {
		return ""
	}
	// Every active PIN is under the strategy, or none is reported.
	separate := s.separateRNGPKCS11PIN()
	if separate && s.rngBackendPIN == nil {
		return ""
	}
	strategy := s.backendPIN.Strategy()
	// tpm2 over a PIN not stored in the TPM is reported only once every
	// PIN is in TPM custody: never while a barrier-stored copy exists.
	if strategy == pinselect.BackendPINTPM2 && s.backendPINStore() != pinselect.BackendPINTPM2 &&
		(!s.backendPINTPMCustody.Load() || (separate && !s.rngBackendPINTPMCustody.Load())) {
		return ""
	}
	return string(strategy)
}
