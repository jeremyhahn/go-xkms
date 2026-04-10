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

package services

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// SealStoreService errors.
var (
	// ErrSealStoreNoClient indicates the service has no connected client.
	ErrSealStoreNoClient = errors.New("platform_store_service: no connected client")

	// ErrSealStoreInvalidName indicates an empty or invalid secret name.
	ErrSealStoreInvalidName = errors.New("platform_store_service: name is required")

	// ErrSealStoreInvalidSecret indicates an empty secret value.
	ErrSealStoreInvalidSecret = errors.New("platform_store_service: secret is required")
)

// SealStoreStatus describes the current state of the platform store.
type SealStoreStatus struct {
	Available   bool     `json:"available"`
	SealerID    string   `json:"sealer_id,omitempty"`
	SecretCount int      `json:"secret_count"`
	SecretNames []string `json:"secret_names,omitempty"`
}

// SealStoreServiceGUI exposes platform store operations to the frontend.
// It is bound to the Wails runtime so every exported method is callable from
// the Svelte frontend. All operations delegate to the SDK transport client
// which communicates with the xkms server.
type SealStoreServiceGUI struct {
	ctx    context.Context
	log    *slog.Logger
	client atomic.Pointer[transport.Client]
}

// NewSealStoreServiceGUI creates a new SealStoreServiceGUI.
func NewSealStoreServiceGUI() *SealStoreServiceGUI {
	return &SealStoreServiceGUI{
		log: slog.Default().With("component", "platform_store_service"),
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *SealStoreServiceGUI) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetClient sets the transport client used to communicate with the server.
func (s *SealStoreServiceGUI) SetClient(c transport.Client) {
	s.client.Store(&c)
}

// getClient returns the current transport client or ErrSealStoreNoClient.
func (s *SealStoreServiceGUI) getClient() (transport.Client, error) {
	ptr := s.client.Load()
	if ptr == nil {
		return nil, ErrSealStoreNoClient
	}
	return *ptr, nil
}

// getContext returns the service context, falling back to context.Background
// if no context has been set.
func (s *SealStoreServiceGUI) getContext() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// Put stores a secret in the platform store.
func (s *SealStoreServiceGUI) Put(name string, secret string) error {
	if name == "" {
		return ErrSealStoreInvalidName
	}
	if secret == "" {
		return ErrSealStoreInvalidSecret
	}

	client, err := s.getClient()
	if err != nil {
		return err
	}

	return client.SealStorePut(s.getContext(), &transport.SealStorePutRequest{
		Name:   name,
		Secret: []byte(secret),
	})
}

// Get retrieves a secret from the platform store by name.
func (s *SealStoreServiceGUI) Get(name string) (string, error) {
	if name == "" {
		return "", ErrSealStoreInvalidName
	}

	client, err := s.getClient()
	if err != nil {
		return "", err
	}

	resp, err := client.SealStoreGet(s.getContext(), &transport.SealStoreGetRequest{
		Name: name,
	})
	if err != nil {
		return "", err
	}

	return string(resp.Secret), nil
}

// Delete removes a secret from the platform store by name.
func (s *SealStoreServiceGUI) Delete(name string) error {
	if name == "" {
		return ErrSealStoreInvalidName
	}

	client, err := s.getClient()
	if err != nil {
		return err
	}

	return client.SealStoreDelete(s.getContext(), &transport.SealStoreDeleteRequest{
		Name: name,
	})
}

// List returns the names of all secrets stored in the platform store.
func (s *SealStoreServiceGUI) List() ([]string, error) {
	client, err := s.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := client.SealStoreList(s.getContext())
	if err != nil {
		return nil, err
	}

	if resp.Names == nil {
		return []string{}, nil
	}
	return resp.Names, nil
}

// Reseal reseals a specific secret with the current sealing key.
func (s *SealStoreServiceGUI) Reseal(name string) error {
	if name == "" {
		return ErrSealStoreInvalidName
	}

	client, err := s.getClient()
	if err != nil {
		return err
	}

	return client.SealStoreReseal(s.getContext(), &transport.SealStoreResealRequest{
		Name: name,
	})
}

// ResealAll reseals all secrets in the platform store. It retrieves the list
// of secret names and reseals each one individually. If any reseal operation
// fails, the error is returned immediately without processing remaining secrets.
func (s *SealStoreServiceGUI) ResealAll() error {
	client, err := s.getClient()
	if err != nil {
		return err
	}

	resp, err := client.SealStoreList(s.getContext())
	if err != nil {
		return err
	}

	for _, name := range resp.Names {
		if err := client.SealStoreReseal(s.getContext(), &transport.SealStoreResealRequest{
			Name: name,
		}); err != nil {
			return err
		}
	}

	return nil
}

// GetStatus returns the current platform store status including availability,
// sealer identity, and the count and names of stored secrets.
func (s *SealStoreServiceGUI) GetStatus() (*SealStoreStatus, error) {
	client, err := s.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := client.SealStoreStatus(s.getContext())
	if err != nil {
		return nil, err
	}

	return &SealStoreStatus{
		Available:   resp.Available,
		SealerID:    resp.SealerID,
		SecretCount: resp.SecretCount,
		SecretNames: resp.SecretNames,
	}, nil
}
