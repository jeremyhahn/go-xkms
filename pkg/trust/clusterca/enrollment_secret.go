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

package clusterca

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
)

// CredentialActivator is the minimal TPM credential-activation surface the
// tpm-kek strategy needs, kept as a narrow local interface so clusterca does not
// depend on the full TPM package (no import cycle; the composition root injects
// it). It is satisfied by pkg/tpm2.TrustedPlatformModule.
//
// MakeCredentialWithExternalEK (server / first node, no local TPM required)
// wraps a secret to an enrolling node's EK certificate + attestation-key name,
// producing a credential blob + encrypted secret only that node's TPM can open.
// ActivateCredential (the enrolling node) recovers the secret using its TPM.
type CredentialActivator interface {
	MakeCredentialWithExternalEK(ekCert *x509.Certificate, iakPubBytes []byte, secret []byte) (credentialBlob, encryptedSecret, plainSecret []byte, err error)
	ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error)
}

// ProvisionedSecret is a piece of wrapped provisioning material a strategy
// delivers to an enrolling node during attested enrollment. Data is wrapped to
// the enrolling node's attestation-bound public key, so it is safe to transit
// any channel — only that node can unwrap it. OID identifies the material so the
// joiner routes it to the right consumer.
type ProvisionedSecret struct {
	// OID identifies the kind of material (e.g. the cluster-seed OID). The
	// joiner uses it to route the material to the correct strategy consumer.
	OID asn1.ObjectIdentifier

	// Data is the wrapped material (wrapped to the enrolling node's
	// attestation-bound public key).
	Data []byte
}

// NodeSecretProvider is the neutral seam that decouples the enrollment protocol
// from any particular custody strategy: given an enrolling node's identity, it
// returns wrapped material to deliver. The enrollment/delivery layer knows only
// this interface — never what a "seed" is — so a new custody strategy plugs in
// without touching enroll-01. A provider that has nothing to deliver for a given
// node returns (nil, nil).
type NodeSecretProvider interface {
	// ProvisionFor returns wrapped material to deliver to the enrolling node
	// identified by req, or nil when there is nothing to provision.
	ProvisionFor(ctx context.Context, req *NodeSecretRequest) (*ProvisionedSecret, error)
}

// NodeSecretRequest identifies the enrolling node a provider wraps material for.
// It carries the TPM attestation material (EK certificate + attestation-key
// public area) the wrapped credential is bound to, plus the node's SPIFFE
// identity for authorization/audit.
type NodeSecretRequest struct {
	// NodeURI is the enrolling node's SPIFFE identity
	// (spiffe://<trust-domain>/node/<raft-address>).
	NodeURI string

	// EKCertificate is the enrolling node's TPM Endorsement Key certificate
	// (from its TCG-CSR-IDEVID). The credential is encrypted to this EK so only
	// the genuine TPM can activate it.
	EKCertificate *x509.Certificate

	// IAKPublic is the marshaled public area of the node's Initial Attestation
	// Key. The credential is bound to this key's name so activation requires the
	// same attestation key that enrolled.
	IAKPublic []byte

	// AttestationPublicKey is the node's attestation-bound public key, retained
	// for providers that key material to it directly (optional).
	AttestationPublicKey crypto.PublicKey
}

// EnrollmentSecretStrategy is OPTIONALLY implemented by a ClusterCAKeyStrategy
// that must deliver wrapped provisioning material to a node during attested
// enrollment (e.g. the tpm-kek cluster seed). It is discovered by type
// assertion, so strategies that need none (barrier, hsm) simply do not implement
// it and the enrollment/delivery layer stays unaware of them. This keeps
// ClusterCAKeyStrategy focused on keystore resolution (open/closed).
type EnrollmentSecretStrategy interface {
	// SecretProvider returns the provider registered with the cluster
	// secret-delivery service so enrolling nodes can fetch wrapped material.
	SecretProvider() NodeSecretProvider

	// ConsumeEnrollmentSecret hands a JOINING node the material it fetched after
	// enrollment so the strategy can recover it (e.g. unseal the seed and derive
	// the KEK) before RuntimeBackend is called. It ignores material whose OID it
	// does not own.
	ConsumeEnrollmentSecret(ctx context.Context, material *ProvisionedSecret) error
}

// EnrollmentSecretStrategyOf returns the EnrollmentSecretStrategy view of a key
// strategy, or (nil, false) when the strategy delivers no enrollment material.
func EnrollmentSecretStrategyOf(strategy ClusterCAKeyStrategy) (EnrollmentSecretStrategy, bool) {
	es, ok := strategy.(EnrollmentSecretStrategy)
	return es, ok
}
