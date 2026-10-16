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

package image

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

const (
	// PayloadTypeInToto is the DSSE payload type of an in-toto statement.
	PayloadTypeInToto = "application/vnd.in-toto+json"

	// StatementTypeV1 is the in-toto statement type pkg/image writes.
	StatementTypeV1 = "https://in-toto.io/Statement/v1"

	// statementTypeV01 is the in-toto statement type cosign writes; it is
	// accepted when verifying.
	statementTypeV01 = "https://in-toto.io/Statement/v0.1"

	// PredicateTypeCosign is cosign's custom predicate type, the type
	// cosign verify-attestation checks when given no --type.
	PredicateTypeCosign = "https://cosign.sigstore.dev/attestation/v1"

	// paeHeader opens DSSE's pre-authentication encoding.
	paeHeader = "DSSEv1"
)

// statementTypes are the in-toto statement types a verifier accepts.
var statementTypes = map[string]struct{}{
	StatementTypeV1:  {},
	statementTypeV01: {},
}

// Envelope is a DSSE envelope. encoding/json writes Payload and every
// signature in standard base64, the encoding DSSE specifies.
type Envelope struct {
	// PayloadType identifies how to interpret Payload.
	PayloadType string `json:"payloadType"`

	// Payload is the signed content, an in-toto statement.
	Payload []byte `json:"payload"`

	// Signatures are the signatures over PAE(PayloadType, Payload).
	Signatures []EnvelopeSignature `json:"signatures"`
}

// EnvelopeSignature is one signature of a DSSE envelope.
type EnvelopeSignature struct {
	// KeyID is an optional hint naming the key; cosign leaves it empty.
	KeyID string `json:"keyid"`

	// Sig is the signature over the envelope's pre-authentication encoding.
	Sig []byte `json:"sig"`
}

// Statement is an in-toto attestation statement.
type Statement struct {
	// Type is the statement type, StatementTypeV1 when pkg/image writes it.
	Type string `json:"_type"`

	// Subject names the artifacts the statement is about: the image.
	Subject []Subject `json:"subject"`

	// PredicateType identifies the predicate's schema.
	PredicateType string `json:"predicateType"`

	// Predicate is the statement's content.
	Predicate json.RawMessage `json:"predicate"`
}

// Subject is one artifact an in-toto statement is about.
type Subject struct {
	// Name is the artifact's name: the image repository.
	Name string `json:"name"`

	// Digest maps digest algorithm names to hex digests.
	Digest map[string]string `json:"digest"`
}

// cosignPredicate is cosign's custom predicate, which wraps arbitrary data.
type cosignPredicate struct {
	Data      string `json:"Data"`
	Timestamp string `json:"Timestamp"`
}

// PAE returns DSSE's pre-authentication encoding of payload, the bytes an
// envelope signature covers:
// "DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload.
func PAE(payloadType string, payload []byte) []byte {
	pae := make([]byte, 0, len(paeHeader)+len(payloadType)+len(payload)+24)
	pae = append(pae, paeHeader...)
	pae = append(pae, ' ')
	pae = strconv.AppendInt(pae, int64(len(payloadType)), 10)
	pae = append(pae, ' ')
	pae = append(pae, payloadType...)
	pae = append(pae, ' ')
	pae = strconv.AppendInt(pae, int64(len(payload)), 10)
	pae = append(pae, ' ')
	return append(pae, payload...)
}

// signatureInput returns what a key signs for message and the hash to sign
// it with: the SHA-256 digest for RSA (PKCS#1 v1.5) and ECDSA keys, which is
// cosign's default signature digest, and message itself for Ed25519, which
// hashes internally.
func signatureInput(publicKey crypto.PublicKey, message []byte) ([]byte, crypto.Hash, error) {
	switch publicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return sha256Sum(message), crypto.SHA256, nil
	case ed25519.PublicKey:
		return message, crypto.Hash(0), nil
	}
	return nil, 0, &errs.Detail{Err: ErrUnsupportedKey, Detail: fmt.Sprintf("%T", publicKey)}
}

// signEnvelope signs payload into a DSSE envelope with signer.
func signEnvelope(signer crypto.Signer, payloadType string, payload []byte) (*Envelope, error) {
	digest, hash, err := signatureInput(signer.Public(), PAE(payloadType, payload))
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(rand.Reader, digest, hash)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrSigningFailed, Cause: err}
	}
	return &Envelope{
		PayloadType: payloadType,
		Payload:     payload,
		Signatures:  []EnvelopeSignature{{Sig: signature}},
	}, nil
}

// verifyEnvelope returns nil when any of env's signatures verifies under
// publicKey. Every check runs through types.SimpleVerifier.
func verifyEnvelope(env *Envelope, publicKey crypto.PublicKey) error {
	if len(env.Signatures) == 0 {
		return &errs.Detail{Err: ErrInvalidEnvelope, Detail: "no signatures"}
	}
	digest, hash, err := signatureInput(publicKey, PAE(env.PayloadType, env.Payload))
	if err != nil {
		return err
	}
	verifier := types.NewVerifier(&types.VerifyOpts{Hash: hash})
	failures := make([]error, 0, len(env.Signatures))
	for _, signature := range env.Signatures {
		err := verifier.Verify(publicKey, digest, signature.Sig)
		if err == nil {
			return nil
		}
		failures = append(failures, err)
	}
	return &errs.Joined{Lead: ErrSignatureInvalid, Cause: errors.Join(failures...)}
}

// parseEnvelope decodes an in-toto DSSE envelope.
func parseEnvelope(data []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, &errs.Joined{Lead: ErrInvalidEnvelope, Cause: err}
	}
	if env.PayloadType != PayloadTypeInToto {
		return nil, &errs.Detail{Err: ErrInvalidEnvelope, Detail: "payload type " + strconv.Quote(env.PayloadType)}
	}
	return &env, nil
}

// newStatement returns the in-toto statement about the image name@digest.
func newStatement(name, digest, predicateType string, predicate json.RawMessage) (*Statement, error) {
	algorithm, encoded, ok := splitDigest(digest)
	if !ok {
		return nil, &errs.Detail{Err: ErrInvalidDigest, Detail: strconv.Quote(digest)}
	}
	return &Statement{
		Type:          StatementTypeV1,
		Subject:       []Subject{{Name: name, Digest: map[string]string{algorithm: encoded}}},
		PredicateType: predicateType,
		Predicate:     predicate,
	}, nil
}

// parseStatement decodes an in-toto statement of an accepted type.
func parseStatement(payload []byte) (*Statement, error) {
	var statement Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return nil, &errs.Joined{Lead: ErrInvalidStatement, Cause: err}
	}
	if _, ok := statementTypes[statement.Type]; !ok {
		return nil, &errs.Detail{Err: ErrInvalidStatement, Detail: "type " + strconv.Quote(statement.Type)}
	}
	if len(statement.Subject) == 0 {
		return nil, &errs.Detail{Err: ErrInvalidStatement, Detail: "no subject"}
	}
	if statement.PredicateType == "" {
		return nil, &errs.Detail{Err: ErrInvalidStatement, Detail: "no predicate type"}
	}
	return &statement, nil
}

// names reports whether digest is among the statement's subjects.
func (s *Statement) names(digest string) bool {
	algorithm, encoded, ok := splitDigest(digest)
	if !ok {
		return false
	}
	for _, subject := range s.Subject {
		if subject.Digest[algorithm] == encoded {
			return true
		}
	}
	return false
}
