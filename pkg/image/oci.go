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
	"encoding/json"
	"slices"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Media types of the OCI image and distribution specifications and of the
// Docker manifests registries still serve.
const (
	// MediaTypeOCIManifest is an OCI image manifest.
	MediaTypeOCIManifest = "application/vnd.oci.image.manifest.v1+json"

	// MediaTypeOCIIndex is an OCI image index, also the referrers API answer.
	MediaTypeOCIIndex = "application/vnd.oci.image.index.v1+json"

	// MediaTypeOCIConfig is an OCI image config.
	MediaTypeOCIConfig = "application/vnd.oci.image.config.v1+json"

	// MediaTypeEmptyJSON is the OCI 1.1 empty descriptor's media type.
	MediaTypeEmptyJSON = "application/vnd.oci.empty.v1+json"

	// MediaTypeDSSEEnvelope is a DSSE envelope layer, as cosign stores it.
	MediaTypeDSSEEnvelope = "application/vnd.dsse.envelope.v1+json"

	// ArtifactTypeAttestation is the artifactType of the OCI 1.1 referrer
	// pkg/image pushes for an attestation.
	ArtifactTypeAttestation = MediaTypeDSSEEnvelope

	// mediaTypeDockerManifest is a Docker image manifest, schema 2.
	mediaTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"

	// mediaTypeDockerManifestList is a Docker manifest list.
	mediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
)

// Annotations cosign reads from an attestation layer.
const (
	annotationSignature     = "dev.cosignproject.cosign/signature"
	annotationCertificate   = "dev.sigstore.cosign/certificate"
	annotationChain         = "dev.sigstore.cosign/chain"
	annotationTimestamp     = "dev.sigstore.cosign/rfc3161timestamp"
	annotationPredicateType = "predicateType"
)

// emptyJSON is the OCI 1.1 empty config blob.
var emptyJSON = []byte("{}")

// manifestAccept lists the manifest media types a resolve accepts.
var manifestAccept = []string{
	MediaTypeOCIManifest,
	MediaTypeOCIIndex,
	mediaTypeDockerManifest,
	mediaTypeDockerManifestList,
}

// Descriptor is an OCI content descriptor.
type Descriptor struct {
	// MediaType is the type of the referenced content.
	MediaType string `json:"mediaType"`

	// Digest is the content's digest.
	Digest string `json:"digest"`

	// Size is the content's length in bytes.
	Size int64 `json:"size"`

	// ArtifactType is the artifact type of a referenced manifest.
	ArtifactType string `json:"artifactType,omitempty"`

	// Annotations are the descriptor's annotations.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Manifest is an OCI image manifest.
type Manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType,omitempty"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Subject       *Descriptor       `json:"subject,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// index is an OCI image index, the referrers API's answer.
type index struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Manifests     []Descriptor `json:"manifests"`
}

// imageConfig is the OCI image config of a cosign ".att" image, whose
// layers are uncompressed so each diff ID is its layer's digest.
type imageConfig struct {
	Architecture string   `json:"architecture"`
	OS           string   `json:"os"`
	Config       struct{} `json:"config"`
	RootFS       rootFS   `json:"rootfs"`
}

type rootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

// cosignTimestamp is the value of the rfc3161timestamp annotation: the
// TSA's whole TimeStampResp, base64 in JSON.
type cosignTimestamp struct {
	SignedRFC3161Timestamp []byte `json:"SignedRFC3161Timestamp"`
}

// Attestation is one signed attestation of an image as the registry holds
// it: a DSSE envelope and the cosign annotations of its layer.
type Attestation struct {
	// Envelope is the DSSE envelope JSON.
	Envelope []byte

	// PredicateType is the statement's predicate type.
	PredicateType string

	// Certificate is the PEM signing certificate.
	Certificate []byte

	// Chain is the PEM chain from the signing certificate's issuer up to,
	// and including, the root.
	Chain []byte

	// Timestamp is the DER RFC 3161 TimeStampResp over Envelope; empty when
	// the attestation is not timestamped.
	Timestamp []byte

	// Invalid, set only by RegistryClient.Attestations, is why the
	// registry's copy of the attestation does not decode; the fields above
	// hold what did. A Verifier refuses the attestation with Invalid as the
	// reason and goes on to the next one. PushAttestation ignores it.
	Invalid error
}

// layer returns the descriptor of a's envelope as a cosign attestation
// layer.
func (a *Attestation) layer() (Descriptor, error) {
	annotations := map[string]string{
		annotationSignature:     "",
		annotationCertificate:   string(a.Certificate),
		annotationChain:         string(a.Chain),
		annotationPredicateType: a.PredicateType,
	}
	if len(a.Timestamp) > 0 {
		timestamp, err := json.Marshal(cosignTimestamp{SignedRFC3161Timestamp: a.Timestamp})
		if err != nil {
			return Descriptor{}, &errs.Joined{Lead: ErrEncodingFailed, Cause: err}
		}
		annotations[annotationTimestamp] = string(timestamp)
	}
	return Descriptor{
		MediaType:   MediaTypeDSSEEnvelope,
		Digest:      sha256Digest(a.Envelope),
		Size:        int64(len(a.Envelope)),
		Annotations: annotations,
	}, nil
}

// attestationFromLayer returns the attestation of a cosign layer whose blob
// is envelope. A layer that does not decode yields an attestation whose
// Invalid says why, so that it fails alone and not every other attestation.
func attestationFromLayer(layer Descriptor, envelope []byte) *Attestation {
	attestation := &Attestation{
		Envelope:      envelope,
		PredicateType: layer.Annotations[annotationPredicateType],
		Certificate:   []byte(layer.Annotations[annotationCertificate]),
		Chain:         []byte(layer.Annotations[annotationChain]),
	}
	if value, ok := layer.Annotations[annotationTimestamp]; ok {
		var timestamp cosignTimestamp
		if err := json.Unmarshal([]byte(value), &timestamp); err != nil {
			attestation.Invalid = &errs.Joined{Lead: ErrInvalidAttestation, Detail: "layer " + layer.Digest + " timestamp annotation", Cause: err}
			return attestation
		}
		attestation.Timestamp = timestamp.SignedRFC3161Timestamp
	}
	return attestation
}

// emptyDescriptor returns the OCI 1.1 empty config descriptor.
func emptyDescriptor() Descriptor {
	return Descriptor{MediaType: MediaTypeEmptyJSON, Digest: sha256Digest(emptyJSON), Size: int64(len(emptyJSON))}
}

// referrerManifest returns the OCI 1.1 referrer manifest of layer, whose
// subject is the image.
func referrerManifest(subject *Descriptor, layer Descriptor) *Manifest {
	return &Manifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIManifest,
		ArtifactType:  ArtifactTypeAttestation,
		Config:        emptyDescriptor(),
		Layers:        []Descriptor{layer},
		Subject:       &Descriptor{MediaType: subject.MediaType, Digest: subject.Digest, Size: subject.Size},
	}
}

// appendAttestationLayer returns the cosign ".att" manifest holding the
// layers of existing, which may be nil, plus layer, and the image config it
// names. A layer already present is not appended twice.
func appendAttestationLayer(existing *Manifest, layer Descriptor) (*Manifest, []byte, error) {
	var layers []Descriptor
	if existing != nil {
		layers = slices.Clone(existing.Layers)
	}
	if !slices.ContainsFunc(layers, func(d Descriptor) bool { return d.Digest == layer.Digest }) {
		layers = append(layers, layer)
	}

	diffIDs := make([]string, len(layers))
	for i, l := range layers {
		diffIDs[i] = l.Digest
	}
	config, err := json.Marshal(imageConfig{RootFS: rootFS{Type: "layers", DiffIDs: diffIDs}})
	if err != nil {
		return nil, nil, &errs.Joined{Lead: ErrEncodingFailed, Cause: err}
	}
	manifest := &Manifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIManifest,
		Config:        Descriptor{MediaType: MediaTypeOCIConfig, Digest: sha256Digest(config), Size: int64(len(config))},
		Layers:        layers,
	}
	return manifest, config, nil
}

// attestationLayers returns the DSSE envelope layers of manifest.
func attestationLayers(manifest *Manifest) []Descriptor {
	layers := make([]Descriptor, 0, len(manifest.Layers))
	for _, layer := range manifest.Layers {
		if layer.MediaType == MediaTypeDSSEEnvelope {
			layers = append(layers, layer)
		}
	}
	return layers
}

// parseManifest decodes an OCI image manifest.
func parseManifest(data []byte) (*Manifest, error) {
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, &errs.Joined{Lead: ErrInvalidManifest, Cause: err}
	}
	if manifest.SchemaVersion != 2 {
		return nil, &errs.Detail{Err: ErrInvalidManifest, Detail: "schema version is not 2"}
	}
	return &manifest, nil
}
