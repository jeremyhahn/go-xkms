// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package tpm2

import (
	"errors"
	"sync"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/logging"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

const (
	// DefaultCacheTTLSeconds is the default time-to-live for cached passwords in seconds
	DefaultCacheTTLSeconds = 300 // 5 minutes
)

// PlatformPassword provides just-in-time password retrieval from TPM keyed hash
// (HMAC) objects used for password storage. The password is sealed to the TPM
// and retrieved when the String() or Bytes() method is called, using the platform
// PCR authorization session policy.
//
// When caching is enabled via KeyAttributes.PasswordCache, the unsealed password
// is stored in memory to avoid repeated TPM operations. The cache can be cleared
// manually with Clear() or will expire automatically based on the configured TTL.
type PlatformPassword struct {
	backend  store.KeyBackend
	logger   *logging.Logger
	tpm      TrustedPlatformModule
	keyAttrs *types.KeyAttributes

	// Cache fields protected by mutex
	mu         sync.RWMutex
	cachedData []byte
	cacheTime  time.Time

	types.Password
}

// NewPlatformPassword creates a new PlatformPassword. Caching behavior is
// controlled by the PasswordCache field in the provided KeyAttributes.
//
// Example usage:
//
//	// Without caching (PasswordCache is nil or Enabled=false)
//	attrs := &types.KeyAttributes{CN: "my-key", PlatformPolicy: true}
//	pp := NewPlatformPassword(logger, tpm, attrs, backend)
//
//	// With caching enabled via config
//	attrs := &types.KeyAttributes{
//	    CN:             "my-key",
//	    PlatformPolicy: true,
//	    PasswordCache: &types.PasswordCacheConfig{
//	        Enabled: true,
//	        TTL:     300, // 5 minutes in seconds
//	    },
//	}
//	pp := NewPlatformPassword(logger, tpm, attrs, backend)
func NewPlatformPassword(
	logger *logging.Logger,
	tpm TrustedPlatformModule,
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend) types.Password {

	return &PlatformPassword{
		backend:  backend,
		logger:   logger,
		tpm:      tpm,
		keyAttrs: keyAttrs,
	}
}

// cacheEnabled returns true if caching is enabled for this password.
func (p *PlatformPassword) cacheEnabled() bool {
	return p.keyAttrs.PasswordCache != nil && p.keyAttrs.PasswordCache.Enabled
}

// cacheTTL returns the cache TTL duration.
func (p *PlatformPassword) cacheTTL() time.Duration {
	if p.keyAttrs.PasswordCache == nil {
		return 0
	}
	ttl := p.keyAttrs.PasswordCache.TTL
	if ttl <= 0 {
		ttl = DefaultCacheTTLSeconds
	}
	return time.Duration(ttl) * time.Second
}

// String returns the secret as a string.
func (p *PlatformPassword) String() (string, error) {
	secret := p.Bytes()
	if secret == nil {
		return "", errors.New("failed to retrieve platform password")
	}
	return string(secret), nil
}

// Bytes returns the secret as bytes. If caching is enabled and the cache
// is valid, returns the cached value. Otherwise, unseals from the TPM
// and caches the result (if caching is enabled).
func (p *PlatformPassword) Bytes() []byte {
	// Check cache first if enabled
	if p.cacheEnabled() {
		if cached := p.getCached(); cached != nil {
			if p.keyAttrs.Debug {
				p.logger.Debugf(
					"keystore/tpm2: returning cached platform password: %s",
					p.keyAttrs.CN)
			}
			return cached
		}
	}

	if p.keyAttrs.Debug {
		p.logger.Debugf(
			"keystore/tpm2: retrieving platform password from TPM: %s",
			p.keyAttrs.CN)
	}

	// Copy the key attributes to a new "secret attributes"
	// object so it can be loaded from the backend using the
	// key type
	secretAttrs := *p.keyAttrs
	secretAttrs.KeyType = types.KeyTypeHMAC
	data, err := p.tpm.UnsealKey(&secretAttrs, p.backend)
	if err != nil {
		// Log the error and return nil - this matches the common.Password interface
		// which doesn't allow Bytes() to return an error
		p.logger.Errorf("keystore/tpm2: failed to unseal platform password: %v", err)
		return nil
	}

	// Cache the result if caching is enabled
	if p.cacheEnabled() {
		p.setCache(data)
	}

	return data
}

// Clear clears any cached password data from memory.
// This is important for security-sensitive applications that need to
// minimize the time secrets are held in memory.
func (p *PlatformPassword) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Zero out the cached data before releasing
	if p.cachedData != nil {
		for i := range p.cachedData {
			p.cachedData[i] = 0
		}
		p.cachedData = nil
	}
	p.cacheTime = time.Time{}
}

// IsCached returns true if a valid cached password exists.
func (p *PlatformPassword) IsCached() bool {
	return p.getCached() != nil
}

// CacheExpiry returns the time when the current cache will expire.
// Returns zero time if caching is disabled or no cache exists.
func (p *PlatformPassword) CacheExpiry() time.Time {
	if !p.cacheEnabled() {
		return time.Time{}
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.cachedData == nil {
		return time.Time{}
	}
	return p.cacheTime.Add(p.cacheTTL())
}

// RefreshCache forces a refresh of the cached password by unsealing
// from the TPM, regardless of whether the current cache is still valid.
// Returns the fresh password bytes, or nil on error.
func (p *PlatformPassword) RefreshCache() []byte {
	// Clear existing cache
	p.Clear()

	// Force a fresh unseal
	return p.Bytes()
}

// getCached returns the cached password if it exists and hasn't expired.
// Returns nil if cache is invalid or expired.
func (p *PlatformPassword) getCached() []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.cachedData == nil {
		return nil
	}

	// Check if cache has expired
	if time.Since(p.cacheTime) > p.cacheTTL() {
		return nil
	}

	// Return a copy to prevent external modification
	result := make([]byte, len(p.cachedData))
	copy(result, p.cachedData)
	return result
}

// setCache stores the password in the cache with the current timestamp.
func (p *PlatformPassword) setCache(data []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Clear any existing cached data
	if p.cachedData != nil {
		for i := range p.cachedData {
			p.cachedData[i] = 0
		}
	}

	// Store a copy of the data
	p.cachedData = make([]byte, len(data))
	copy(p.cachedData, data)
	p.cacheTime = time.Now()
}

// Create seals a password to the TPM as a keyed hash object. If the key
// attributes have the platform policy defined, a PlatformSecret is
// returned, otherwise, RequiredPassword which returns ErrPasswordRequired
// when its member methods are invoked. If the provided password is the
// default platform password, a random 32 byte (AES-256) key is generated.
func (p *PlatformPassword) Create() error {

	var passwd []byte
	if p.keyAttrs.Password == nil {
		p.keyAttrs.Password = store.NewClearPassword(nil)
		return nil
	} else {
		// Check if password is valid (error passwords return error from String())
		_, err := p.keyAttrs.Password.String()
		if err != nil {
			return err
		}
		passwd = p.keyAttrs.Password.Bytes()
		if string(passwd) == store.DEFAULT_PASSWORD {
			passwd = make([]byte, 32) // AES-256 key
			rng := p.tpm.RandomSource()
			if _, err := rng.Read(passwd); err != nil {
				return err
			}
			p.keyAttrs.Password = store.NewClearPassword(passwd)
		}
	}
	if _, err := p.tpm.SealKey(p.keyAttrs, p.backend, false); err != nil {
		return err
	}
	if p.keyAttrs.PlatformPolicy {
		p.keyAttrs.Password = p
	} else {
		p.keyAttrs.Password = store.NewRequiredPassword()
	}
	return nil
}
