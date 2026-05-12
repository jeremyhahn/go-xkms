// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	objstorecommon "github.com/jeremyhahn/go-objstore/pkg/common"
	objstorefactory "github.com/jeremyhahn/go-objstore/pkg/factory"
	"github.com/jeremyhahn/go-xkms/pkg/acme/client"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
)

// Compile-time interface check.
var _ AccountManager = (*accountManager)(nil)

// AccountManager manages multiple ACME accounts from the configuration.
type AccountManager interface {
	// Add registers a new account configuration under the given name.
	Add(ctx context.Context, name string, cfg *AccountConfig) error

	// Remove deletes the account configuration and any cached resources.
	Remove(ctx context.Context, name string) error

	// Get returns the account configuration for the given name.
	Get(name string) (*AccountConfig, error)

	// List returns all configured accounts.
	List() map[string]*AccountConfig

	// Client returns a cached or newly created ACME client for the named account.
	Client(ctx context.Context, name string) (*client.Client, error)

	// StorageFactory returns a cached or newly created storage factory for the named account.
	StorageFactory(name string) (storage.Factory, error)
}

// accountManager is the concrete implementation of AccountManager.
type accountManager struct {
	config    *Config
	logger    *slog.Logger
	clients   sync.Map // map[string]*client.Client
	factories sync.Map // map[string]storage.Factory
}

// NewAccountManager creates a new AccountManager backed by the given configuration.
func NewAccountManager(config *Config, logger *slog.Logger) AccountManager {
	return &accountManager{
		config: config,
		logger: logger,
	}
}

// Add registers a new account configuration under the given name.
func (am *accountManager) Add(ctx context.Context, name string, cfg *AccountConfig) error {
	if _, exists := am.config.Accounts[name]; exists {
		return ErrAccountAlreadyExists{Name: name}
	}
	if err := validateAccountConfig(name, cfg); err != nil {
		return err
	}
	am.config.Accounts[name] = cfg
	am.logger.InfoContext(ctx, "account added",
		slog.String("name", name),
		slog.String("email", cfg.Email),
		slog.String("directory", cfg.DirectoryURL),
	)
	return nil
}

// Remove deletes the account configuration, closes any cached client,
// and removes cached storage factories.
func (am *accountManager) Remove(ctx context.Context, name string) error {
	if _, exists := am.config.Accounts[name]; !exists {
		return ErrAccountNotFound{Name: name}
	}
	for _, spec := range am.config.Certificates {
		if spec.Account == name {
			return ErrInvalidAccountConfig{
				Name:   name,
				Reason: "account is referenced by certificate specs",
			}
		}
	}
	if cached, loaded := am.clients.LoadAndDelete(name); loaded {
		if c, ok := cached.(*client.Client); ok {
			if err := c.Close(); err != nil {
				am.logger.WarnContext(ctx, "failed to close cached client",
					slog.String("account", name),
					slog.String("error", err.Error()),
				)
			}
		}
	}
	am.factories.Delete(name)
	delete(am.config.Accounts, name)
	am.logger.InfoContext(ctx, "account removed", slog.String("name", name))
	return nil
}

// Get returns the account configuration for the given name.
func (am *accountManager) Get(name string) (*AccountConfig, error) {
	cfg, exists := am.config.Accounts[name]
	if !exists {
		return nil, ErrAccountNotFound{Name: name}
	}
	return cfg, nil
}

// List returns all configured accounts.
func (am *accountManager) List() map[string]*AccountConfig {
	return am.config.Accounts
}

// Client returns a cached or newly created ACME client for the named account.
func (am *accountManager) Client(ctx context.Context, name string) (*client.Client, error) {
	cfg, err := am.Get(name)
	if err != nil {
		return nil, err
	}
	if cached, ok := am.clients.Load(name); ok {
		return cached.(*client.Client), nil
	}
	signer, err := generateSigner(cfg.Key)
	if err != nil {
		return nil, err
	}
	factory, err := am.StorageFactory(name)
	if err != nil {
		return nil, err
	}
	accountDAO, err := factory.AccountDAO()
	if err != nil {
		return nil, ErrClientCreation{Account: name, Err: err}
	}
	certDAO, err := factory.CertificateDAO()
	if err != nil {
		return nil, ErrClientCreation{Account: name, Err: err}
	}
	// OrderStorage is populated lazily after account registration provides an ID.
	clientCfg := &client.Config{
		DirectoryURL:        cfg.DirectoryURL,
		Timeout:             30 * time.Second,
		SystemCertPool:      false,
		RequestServerBundle: cfg.RequestServerBundle,
		TrustedRoots:        cfg.TrustedRoots,
		RetryAttempts:       3,
		RetryDelay:          1 * time.Second,
		MaxRetryDelay:       30 * time.Second,
	}
	params := &client.Params{
		AccountEmail:       cfg.Email,
		AccountSigner:      signer,
		Config:             clientCfg,
		Logger:             am.logger,
		Storage:            accountDAO,
		CertificateStorage: certDAO,
	}
	c, err := client.NewClient(params)
	if err != nil {
		return nil, ErrClientCreation{Account: name, Err: err}
	}
	actual, _ := am.clients.LoadOrStore(name, c)
	return actual.(*client.Client), nil
}

// StorageFactory returns a cached or newly created storage factory for the named account.
func (am *accountManager) StorageFactory(name string) (storage.Factory, error) {
	if _, err := am.Get(name); err != nil {
		return nil, err
	}
	if cached, ok := am.factories.Load(name); ok {
		return cached.(storage.Factory), nil
	}
	store, err := createObjStorage(am.config.Storage)
	if err != nil {
		return nil, ErrStorageFactory{Err: err}
	}
	var factory storage.Factory
	if am.config.TenantID != "" {
		taf, err := objstore.NewTenantAwareFactory(store)
		if err != nil {
			return nil, ErrStorageFactory{Err: err}
		}
		factory, err = taf.ForTenant(am.config.TenantID)
		if err != nil {
			return nil, ErrStorageFactory{Err: err}
		}
	} else {
		factory, err = objstore.NewFactory(store)
		if err != nil {
			return nil, ErrStorageFactory{Err: err}
		}
	}
	actual, _ := am.factories.LoadOrStore(name, factory)
	return actual.(storage.Factory), nil
}

// signerGenerator is a function that creates a crypto.Signer from a KeyConfig.
type signerGenerator func(keyCfg *KeyConfig) (crypto.Signer, error)

// ecdsaGenerators maps ECC curve names to elliptic.Curve values.
var ecdsaGenerators = map[string]elliptic.Curve{
	"P-256": elliptic.P256(),
	"P-384": elliptic.P384(),
	"P-521": elliptic.P521(),
}

// signerGenerators maps algorithm names to their signer generation functions.
var signerGenerators = map[string]signerGenerator{
	"ECDSA": func(keyCfg *KeyConfig) (crypto.Signer, error) {
		curveName := "P-256"
		if keyCfg.ECC != nil && keyCfg.ECC.Curve != "" {
			curveName = keyCfg.ECC.Curve
		}
		curve, ok := ecdsaGenerators[curveName]
		if !ok {
			return nil, ErrKeyGeneration{
				Algorithm: "ECDSA",
				Err:       fmt.Errorf("unsupported curve: %s", curveName),
			}
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, ErrKeyGeneration{Algorithm: "ECDSA", Err: err}
		}
		return key, nil
	},
	"RSA": func(keyCfg *KeyConfig) (crypto.Signer, error) {
		keySize := 2048
		if keyCfg.RSA != nil && keyCfg.RSA.KeySize > 0 {
			keySize = keyCfg.RSA.KeySize
		}
		key, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return nil, ErrKeyGeneration{Algorithm: "RSA", Err: err}
		}
		return key, nil
	},
	"ED25519": func(keyCfg *KeyConfig) (crypto.Signer, error) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, ErrKeyGeneration{Algorithm: "ED25519", Err: err}
		}
		return key, nil
	},
}

// generateSigner creates a crypto.Signer from a KeyConfig using map-based dispatch.
// Returns ErrMissingKeyConfig when keyCfg is nil so callers receive a typed
// error instead of panicking on a nil-pointer dereference.
func generateSigner(keyCfg *KeyConfig) (crypto.Signer, error) {
	if keyCfg == nil {
		return nil, ErrMissingKeyConfig{Context: "signer generation"}
	}
	algorithm := strings.ToUpper(keyCfg.Algorithm)
	generator, ok := signerGenerators[algorithm]
	if !ok {
		return nil, ErrKeyGeneration{
			Algorithm: keyCfg.Algorithm,
			Err:       fmt.Errorf("unsupported algorithm: %s", keyCfg.Algorithm),
		}
	}
	return generator(keyCfg)
}

// createObjStorage creates a go-objstore Storage backend from StorageConfig.
func createObjStorage(cfg StorageConfig) (objstorecommon.Storage, error) {
	settings := make(map[string]string, len(cfg.Options))
	for k, v := range cfg.Options {
		settings[k] = fmt.Sprintf("%v", v)
	}
	backend := cfg.Backend
	if backend == "" || backend == "filesystem" {
		backend = "local"
	}
	return objstorefactory.NewStorage(backend, settings)
}

// validateAccountConfig checks that the account configuration has all required fields.
func validateAccountConfig(name string, cfg *AccountConfig) error {
	if cfg == nil {
		return ErrInvalidAccountConfig{Name: name, Reason: "configuration is nil"}
	}
	if cfg.DirectoryURL == "" {
		return ErrInvalidAccountConfig{Name: name, Reason: "directory URL is required"}
	}
	if cfg.Email == "" {
		return ErrInvalidAccountConfig{Name: name, Reason: "email is required"}
	}
	if cfg.Key == nil {
		return ErrInvalidAccountConfig{Name: name, Reason: "key configuration is required"}
	}
	if cfg.Key.Algorithm == "" {
		return ErrInvalidAccountConfig{Name: name, Reason: "key algorithm is required"}
	}
	if cfg.Key.Store == "" {
		return ErrInvalidAccountConfig{Name: name, Reason: "key store is required"}
	}
	return nil
}
