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

//go:build pkcs11

package rand

import (
	"fmt"
	"sync"

	"github.com/miekg/pkcs11"
)

// pkcs11Resolver uses PKCS#11 hardware security module RNG for random
// number generation. PKCS#11 provides access to certified random number
// generation from HSM devices.
type pkcs11Resolver struct {
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	config  *PKCS11Config
	mu      sync.RWMutex
}

var _ Resolver = (*pkcs11Resolver)(nil)

func newPKCS11Resolver(config *PKCS11Config) (Resolver, error) {
	if config == nil {
		return nil, fmt.Errorf("PKCS#11 configuration required")
	}

	if config.Module == "" {
		return nil, fmt.Errorf("PKCS#11 module path is required")
	}

	// Initialize PKCS#11 context
	ctx := pkcs11.New(config.Module)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", config.Module)
	}

	err := ctx.Initialize()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#11: %w", err)
	}

	// Call GetSlotList to activate slots in this context
	// This is required by some PKCS#11 implementations (e.g., YubiKey)
	_, err = ctx.GetSlotList(true)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("failed to get PKCS#11 slot list: %w", err)
	}

	// Open session
	session, err := ctx.OpenSession(config.SlotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("failed to open PKCS#11 session: %w", err)
	}

	// Login if PIN is required
	if config.PINRequired && config.PIN != "" {
		err = ctx.Login(session, pkcs11.CKU_USER, config.PIN)
		if err != nil {
			ctx.CloseSession(session)
			ctx.Finalize()
			ctx.Destroy()
			return nil, fmt.Errorf("failed to authenticate with PKCS#11: %w", err)
		}
	}

	return &pkcs11Resolver{
		ctx:     ctx,
		session: session,
		config:  config,
	}, nil
}

func pkcs11Available() bool {
	return true
}

func (p *pkcs11Resolver) Rand(n int) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.ctx == nil {
		return nil, fmt.Errorf("PKCS#11 resolver closed")
	}

	// Use PKCS#11 GenerateRandom function
	result, err := p.ctx.GenerateRandom(p.session, n)
	if err != nil {
		return nil, fmt.Errorf("PKCS#11 random generation failed: %w", err)
	}

	return result, nil
}

// Read implements io.Reader for compatibility with crypto/rand.Reader.
// This allows the PKCS#11 resolver to be used with standard library
// functions that expect an io.Reader for randomness, such as
// rsa.GenerateKey, ecdsa.GenerateKey, and x509.CreateCertificate.
func (p *pkcs11Resolver) Read(b []byte) (n int, err error) {
	data, err := p.Rand(len(b))
	if err != nil {
		return 0, err
	}
	copy(b, data)
	return len(data), nil
}

func (p *pkcs11Resolver) Source() Source {
	return &pkcs11Source{resolver: p}
}

func (p *pkcs11Resolver) Available() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.ctx != nil
}

func (p *pkcs11Resolver) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ctx != nil {
		if p.config.PINRequired {
			p.ctx.Logout(p.session)
		}
		p.ctx.CloseSession(p.session)
		p.ctx.Finalize()
		p.ctx.Destroy()
		p.ctx = nil
	}
	return nil
}

type pkcs11Source struct {
	resolver *pkcs11Resolver
}

func (s *pkcs11Source) Rand(n int) ([]byte, error) {
	return s.resolver.Rand(n)
}

func (s *pkcs11Source) Available() bool {
	return s.resolver.Available()
}

func (s *pkcs11Source) Close() error {
	return s.resolver.Close()
}
