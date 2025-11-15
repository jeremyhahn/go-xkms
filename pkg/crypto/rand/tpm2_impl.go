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

//go:build tpm2

package rand

import (
	"fmt"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/tcp"
	"github.com/google/go-tpm/tpmutil"
)

// tpm2Resolver uses TPM2 hardware RNG for random number generation.
// TPM2 provides certified random number generation suitable for
// generating cryptographic key material.
type tpm2Resolver struct {
	rwc    transport.TPMCloser
	config *TPM2Config
	mu     sync.RWMutex
}

var _ Resolver = (*tpm2Resolver)(nil)

func newTPM2Resolver(config *TPM2Config) (Resolver, error) {
	if config == nil {
		config = &TPM2Config{
			Device:         "/dev/tpm0",
			MaxRequestSize: 32,
		}
	}

	// Set defaults for simulator configuration
	if config.UseSimulator {
		if config.SimulatorHost == "" {
			config.SimulatorHost = "localhost"
		}
		if config.SimulatorPort <= 0 {
			config.SimulatorPort = 2321
		}
		if config.SimulatorType == "" {
			config.SimulatorType = "swtpm"
		}
	} else {
		if config.Device == "" {
			config.Device = "/dev/tpm0"
		}
	}

	if config.MaxRequestSize <= 0 {
		config.MaxRequestSize = 32
	}

	var rwc transport.TPMCloser
	var err error

	if config.UseSimulator {
		// Connect to TPM simulator via TCP
		// SWTPM requires both command and platform (ctrl) ports
		cmdAddr := fmt.Sprintf("%s:%d", config.SimulatorHost, config.SimulatorPort)
		platAddr := fmt.Sprintf("%s:%d", config.SimulatorHost, config.SimulatorPort+1)

		rwc, err = tcp.Open(tcp.Config{
			CommandAddress:  cmdAddr,
			PlatformAddress: platAddr,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to TPM simulator at %s (platform: %s): %w", cmdAddr, platAddr, err)
		}
	} else {
		// Open hardware TPM device
		dev, err := tpmutil.OpenTPM(config.Device)
		if err != nil {
			return nil, fmt.Errorf("failed to open TPM2 device %s: %w", config.Device, err)
		}
		rwc = transport.FromReadWriteCloser(dev)
	}

	return &tpm2Resolver{
		rwc:    rwc,
		config: config,
	}, nil
}

func tpm2Available() bool {
	return true
}

func (t *tpm2Resolver) Rand(n int) ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.rwc == nil {
		return nil, fmt.Errorf("TPM2 resolver closed")
	}

	// Handle large requests by making multiple calls
	result := make([]byte, 0, n)
	remaining := n

	for remaining > 0 {
		chunkSize := remaining
		if chunkSize > t.config.MaxRequestSize {
			chunkSize = t.config.MaxRequestSize
		}

		// Use TPM2 GetRandom command
		getRandom := tpm2.GetRandom{
			BytesRequested: uint16(chunkSize),
		}

		rsp, err := getRandom.Execute(t.rwc)
		if err != nil {
			return nil, fmt.Errorf("TPM2 GetRandom failed: %w", err)
		}

		result = append(result, rsp.RandomBytes.Buffer...)
		remaining -= len(rsp.RandomBytes.Buffer)
	}

	return result, nil
}

func (t *tpm2Resolver) Source() Source {
	return &tpm2Source{resolver: t}
}

func (t *tpm2Resolver) Available() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.rwc != nil
}

func (t *tpm2Resolver) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.rwc != nil {
		err := t.rwc.Close()
		t.rwc = nil
		return err
	}
	return nil
}

type tpm2Source struct {
	resolver *tpm2Resolver
}

func (s *tpm2Source) Rand(n int) ([]byte, error) {
	return s.resolver.Rand(n)
}

func (s *tpm2Source) Available() bool {
	return s.resolver.Available()
}

func (s *tpm2Source) Close() error {
	return s.resolver.Close()
}
