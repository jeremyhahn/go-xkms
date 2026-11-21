package image

import (
	"context"
	"crypto"
)

// RepositorySigners returns the signer of a repository's images: a tenant's
// signing-key service, which signs with the tenant's release key unless the
// tenant named another key for the repository. go-xkms's XKMSService
// implements it (RepositorySigner); its signers sign in the backend.
type RepositorySigners interface {
	RepositorySigner(ctx context.Context, repository string) (crypto.Signer, error)
}

// NewRepositorySigner returns a Signer of the repository's images. When cfg
// sets no Signer, the repository's key from signers signs (the release key
// by default); a Signer cfg sets is kept. cfg is not modified, and its
// Certificate must certify the key that signs (see NewSigner).
func NewRepositorySigner(ctx context.Context, signers RepositorySigners, repository string, cfg *SignerConfig) (*Signer, error) {
	if cfg == nil {
		return nil, ErrSignerRequired
	}
	if cfg.Signer != nil {
		return NewSigner(cfg)
	}
	if signers == nil {
		return nil, ErrSignerRequired
	}
	if repository == "" {
		return nil, ErrRepositoryRequired
	}
	signer, err := signers.RepositorySigner(ctx, repository)
	if err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, ErrSignerRequired
	}
	resolved := *cfg
	resolved.Signer = signer
	return NewSigner(&resolved)
}
