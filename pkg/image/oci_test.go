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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testAttestation(envelope string) *Attestation {
	return &Attestation{
		Envelope:      []byte(envelope),
		PredicateType: PredicateTypeCosign,
		Certificate:   []byte("-----BEGIN CERTIFICATE-----\n"),
		Chain:         []byte("-----BEGIN CERTIFICATE-----\nchain\n"),
	}
}

func TestAttestation_Layer(t *testing.T) {
	attestation := testAttestation(`{"payloadType":"x"}`)
	attestation.Timestamp = []byte{0x30, 0x03, 0x02, 0x01, 0x00}

	layer, err := attestation.layer()
	require.NoError(t, err)
	assert.Equal(t, MediaTypeDSSEEnvelope, layer.MediaType)
	assert.Equal(t, sha256Digest(attestation.Envelope), layer.Digest)
	assert.Equal(t, int64(len(attestation.Envelope)), layer.Size)
	assert.Equal(t, "", layer.Annotations[annotationSignature], "cosign's DSSE layers carry an empty signature")
	assert.Equal(t, string(attestation.Certificate), layer.Annotations[annotationCertificate])
	assert.Equal(t, string(attestation.Chain), layer.Annotations[annotationChain])
	assert.Equal(t, PredicateTypeCosign, layer.Annotations[annotationPredicateType])
	assert.JSONEq(t, `{"SignedRFC3161Timestamp":"MAMCAQA="}`, layer.Annotations[annotationTimestamp])

	assert.Equal(t, attestation, attestationFromLayer(layer, attestation.Envelope))
}

func TestAttestation_LayerWithoutTimestamp(t *testing.T) {
	attestation := testAttestation("{}")

	layer, err := attestation.layer()
	require.NoError(t, err)
	assert.NotContains(t, layer.Annotations, annotationTimestamp)

	parsed := attestationFromLayer(layer, attestation.Envelope)
	require.NoError(t, parsed.Invalid)
	assert.Empty(t, parsed.Timestamp)
}

func TestAttestationFromLayer_InvalidTimestamp(t *testing.T) {
	layer, err := testAttestation("{}").layer()
	require.NoError(t, err)

	for name, value := range map[string]string{
		"not json":   "{",
		"bad base64": `{"SignedRFC3161Timestamp":"!!"}`,
	} {
		t.Run(name, func(t *testing.T) {
			layer.Annotations[annotationTimestamp] = value
			attestation := attestationFromLayer(layer, []byte("{}"))
			require.ErrorIs(t, attestation.Invalid, ErrInvalidAttestation)
			assert.ErrorContains(t, attestation.Invalid, layer.Digest, "the failure names its layer")
			assert.Equal(t, []byte("{}"), attestation.Envelope, "the attestation is kept beside the others")
			assert.Empty(t, attestation.Timestamp)
		})
	}
}

func TestReferrerManifest(t *testing.T) {
	subject := &Descriptor{MediaType: MediaTypeOCIManifest, Digest: testSHA256, Size: 42, Annotations: map[string]string{"a": "b"}}
	layer, err := testAttestation("{}").layer()
	require.NoError(t, err)

	manifest := referrerManifest(subject, layer)
	assert.Equal(t, 2, manifest.SchemaVersion)
	assert.Equal(t, MediaTypeOCIManifest, manifest.MediaType)
	assert.Equal(t, ArtifactTypeAttestation, manifest.ArtifactType)
	assert.Equal(t, emptyDescriptor(), manifest.Config)
	assert.Equal(t, []Descriptor{layer}, manifest.Layers)
	assert.Equal(t, &Descriptor{MediaType: MediaTypeOCIManifest, Digest: testSHA256, Size: 42}, manifest.Subject,
		"the subject descriptor drops the image's annotations")
}

func TestEmptyDescriptor(t *testing.T) {
	descriptor := emptyDescriptor()
	assert.Equal(t, MediaTypeEmptyJSON, descriptor.MediaType)
	assert.Equal(t, int64(2), descriptor.Size)
	assert.True(t, matchesDigest(descriptor.Digest, []byte("{}")))
}

func TestAppendAttestationLayer(t *testing.T) {
	first, err := testAttestation(`{"n":1}`).layer()
	require.NoError(t, err)
	second, err := testAttestation(`{"n":2}`).layer()
	require.NoError(t, err)

	manifest, config, err := appendAttestationLayer(nil, first)
	require.NoError(t, err)
	assert.Equal(t, []Descriptor{first}, manifest.Layers)
	assertDiffIDs(t, manifest, config, first.Digest)

	manifest, config, err = appendAttestationLayer(manifest, second)
	require.NoError(t, err)
	assert.Equal(t, []Descriptor{first, second}, manifest.Layers)
	assertDiffIDs(t, manifest, config, first.Digest, second.Digest)

	again, config, err := appendAttestationLayer(manifest, first)
	require.NoError(t, err)
	assert.Equal(t, []Descriptor{first, second}, again.Layers, "a layer already present is not added twice")
	assertDiffIDs(t, again, config, first.Digest, second.Digest)
}

// assertDiffIDs checks config is manifest's config, listing diffIDs.
func assertDiffIDs(t *testing.T, manifest *Manifest, config []byte, diffIDs ...string) {
	t.Helper()
	assert.Equal(t, MediaTypeOCIConfig, manifest.Config.MediaType)
	assert.Equal(t, sha256Digest(config), manifest.Config.Digest)
	assert.Equal(t, int64(len(config)), manifest.Config.Size)

	var parsed imageConfig
	require.NoError(t, json.Unmarshal(config, &parsed))
	assert.Equal(t, rootFS{Type: "layers", DiffIDs: diffIDs}, parsed.RootFS)
}

func TestAttestationLayers(t *testing.T) {
	attestation, err := testAttestation("{}").layer()
	require.NoError(t, err)
	manifest := &Manifest{Layers: []Descriptor{
		{MediaType: "application/vnd.dev.cosign.simplesigning.v1+json", Digest: testSHA256},
		attestation,
	}}
	assert.Equal(t, []Descriptor{attestation}, attestationLayers(manifest))
	assert.Empty(t, attestationLayers(&Manifest{}))
}

func TestParseManifest(t *testing.T) {
	manifest, err := parseManifest([]byte(`{"schemaVersion":2,"mediaType":"` + MediaTypeOCIManifest + `","layers":[]}`))
	require.NoError(t, err)
	assert.Equal(t, MediaTypeOCIManifest, manifest.MediaType)
}

func TestParseManifest_Invalid(t *testing.T) {
	for name, data := range map[string]string{
		"not json":       "{",
		"schema version": `{"schemaVersion":1}`,
		"no version":     `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			manifest, err := parseManifest([]byte(data))
			require.ErrorIs(t, err, ErrInvalidManifest)
			assert.Nil(t, manifest)
		})
	}
}
