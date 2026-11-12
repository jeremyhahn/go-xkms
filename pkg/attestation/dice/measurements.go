// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package dice

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"
	"strconv"

	"github.com/fxamacker/cbor/v2"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// ErrMeasurementsShape is returned when a measurements claim (273) is not the
// application evidence shape that ApplicationEvidence reads.
var ErrMeasurementsShape = errors.New("dice: the measurements claim is not the application evidence shape")

// The application evidence shape is the one measurements claim value that
// go-xkms accepts (docs/SPEC.md, acme-issuance). RFC 9711 section 4.2.16 makes
// the claim a list of measurements-format pairs [content-type,
// content-format] and requires a CoSWID there to be an evidence CoSWID (RFC
// 9393), untagged:
//
//	273: [ [ 258,                           / CoAP content-format of CoSWID /
//	         << {                           / evidence CoSWID /
//	           0: tstr / bstr .size 16,     / tag-id /
//	           1: tstr,                     / software-name /
//	           2: { 31: tstr, 33: role },   / entity: entity-name, tag-creator /
//	           3: { 17: {                   / evidence: one file /
//	             7: [1, h'<32 bytes>'],     / hash: sha-256 hash-entry /
//	             24: "app" } },             / fs-name /
//	           12: int                      / tag-version /
//	         } >> ] ]
//
// The 32 bytes are the application evidence, opaque to go-xkms. The tag-id,
// tag-version, software-name and entity are the producer's (RFC 9393 section
// 2.3, CA m463): they are checked for presence and type, never for value. The
// shape holds no other field, and the claim and its CoSWID are each accepted
// only in RFC 8949 core deterministic encoding.

// The CoSWID keys (RFC 9393 section 6.1) and values the shape uses.
const (
	coapContentFormatCoSWID = 258
	coswidTagID             = 0
	coswidSoftwareName      = 1
	coswidEntity            = 2
	coswidEvidence          = 3
	coswidHash              = 7
	coswidTagVersion        = 12
	coswidFile              = 17
	coswidFsName            = 24
	coswidEntityName        = 31
	coswidRole              = 33
	coswidRoleTagCreator    = 1

	// coswidTagIDSize is the size of a byte-string tag-id, a UUID (RFC 9393
	// section 2.3).
	coswidTagIDSize = 16

	// hashAlgSHA256 is sha-256's Named Information Hash Algorithm
	// Registry identifier, the hash-alg-id of an RFC 9393 hash-entry.
	hashAlgSHA256 = 1

	// applicationFileName is the fs-name of the shape's one file.
	applicationFileName = "app"
)

// measurementsFormat is RFC 9711's measurements-format pair.
type measurementsFormat struct {
	_             struct{} `cbor:",toarray"`
	ContentType   uint64
	ContentFormat []byte
}

// hashEntry is RFC 9393's hash-entry.
type hashEntry struct {
	_         struct{} `cbor:",toarray"`
	Algorithm int64
	Value     []byte
}

// measurementsDecMode refuses what the shape's encoding never contains: a key
// twice, an indefinite length, a tag, invalid UTF-8.
var measurementsDecMode = mustMeasurementsDecMode(cbor.DecOptions{
	DupMapKey:   cbor.DupMapKeyEnforcedAPF,
	IndefLength: cbor.IndefLengthForbidden,
	TagsMd:      cbor.TagsForbidden,
	UTF8:        cbor.UTF8RejectInvalid,
})

// measurementsEncMode re-encodes a decoded claim in RFC 8949 core
// deterministic encoding, the one encoding the claim is accepted in.
var measurementsEncMode = mustMeasurementsEncMode(cbor.CoreDetEncOptions())

func mustMeasurementsDecMode(opts cbor.DecOptions) cbor.DecMode {
	mode, err := opts.DecMode()
	if err != nil {
		panic("dice: invalid CBOR decode options: " + err.Error())
	}
	return mode
}

func mustMeasurementsEncMode(opts cbor.EncOptions) cbor.EncMode {
	mode, err := opts.EncMode()
	if err != nil {
		panic("dice: invalid CBOR encode options: " + err.Error())
	}
	return mode
}

// ApplicationEvidence reads the 32-byte application evidence out of a
// measurements claim (273) value, and refuses, with ErrMeasurementsShape, a
// claim that is not the shape.
func ApplicationEvidence(measurements []byte) ([]byte, error) {
	if err := deterministic(measurements, "the claim"); err != nil {
		return nil, err
	}
	var entries []cbor.RawMessage
	if err := measurementsDecMode.Unmarshal(measurements, &entries); err != nil {
		return nil, measurementsShapeError("the claim is not a list", err)
	}
	if len(entries) != 1 {
		return nil, measurementsShapeError("the claim holds "+strconv.Itoa(len(entries))+" entries, not one", nil)
	}
	var format measurementsFormat
	if err := measurementsDecMode.Unmarshal(entries[0], &format); err != nil {
		return nil, measurementsShapeError("the entry is not a content-type and a byte string", err)
	}
	if format.ContentType != coapContentFormatCoSWID {
		return nil, measurementsShapeError("the content-type is "+strconv.FormatUint(format.ContentType, 10)+", not CoSWID's 258", nil)
	}
	if err := deterministic(format.ContentFormat, "the payload"); err != nil {
		return nil, err
	}
	var coswid map[int64]cbor.RawMessage
	if err := measurementsDecMode.Unmarshal(format.ContentFormat, &coswid); err != nil {
		return nil, measurementsShapeError("the payload is not an untagged CoSWID", err)
	}
	file, err := evidenceFile(coswid)
	if err != nil {
		return nil, err
	}
	if err := producerFields(coswid); err != nil {
		return nil, err
	}
	return fileEvidence(file)
}

// deterministic refuses data that is not one CBOR item in core deterministic
// encoding.
func deterministic(data []byte, what string) error {
	var decoded any
	if err := measurementsDecMode.Unmarshal(data, &decoded); err != nil {
		return measurementsShapeError(what+" is not one CBOR item", err)
	}
	encoded, err := measurementsEncMode.Marshal(decoded)
	if err != nil {
		return measurementsShapeError(what+" does not re-encode", err)
	}
	if !bytes.Equal(encoded, data) {
		return measurementsShapeError(what+" is not in core deterministic encoding", nil)
	}
	return nil
}

// onlyFields refuses a map holding a key outside keys.
func onlyFields(m map[int64]cbor.RawMessage, what string, keys ...int64) error {
	for key := range m {
		if !slices.Contains(keys, key) {
			return measurementsShapeError(what+" holds field "+strconv.FormatInt(key, 10)+", which the shape does not carry", nil)
		}
	}
	return nil
}

// decodeField decodes the field at key, which must be present.
func decodeField(m map[int64]cbor.RawMessage, key int64, name string) (any, error) {
	raw, present := m[key]
	if !present {
		return nil, measurementsShapeError("the "+name+" is missing", nil)
	}
	var value any
	if err := measurementsDecMode.Unmarshal(raw, &value); err != nil {
		return nil, measurementsShapeError("the "+name+" does not decode", err)
	}
	return value, nil
}

// producerFields checks the producer's fields for presence and type, never
// for value.
func producerFields(coswid map[int64]cbor.RawMessage) error {
	if err := onlyFields(coswid, "the CoSWID", coswidTagID, coswidSoftwareName, coswidEntity, coswidEvidence, coswidTagVersion); err != nil {
		return err
	}
	tagID, err := decodeField(coswid, coswidTagID, "tag-id")
	if err != nil {
		return err
	}
	switch id := tagID.(type) {
	case string:
	case []byte:
		if len(id) != coswidTagIDSize {
			return measurementsShapeError("the tag-id is "+strconv.Itoa(len(id))+" bytes, not a 16-byte UUID", nil)
		}
	default:
		return measurementsShapeError("the tag-id is neither text nor a byte string", nil)
	}
	tagVersion, err := decodeField(coswid, coswidTagVersion, "tag-version")
	if err != nil {
		return err
	}
	if !isInteger(tagVersion) {
		return measurementsShapeError("the tag-version is not an integer", nil)
	}
	softwareName, err := decodeField(coswid, coswidSoftwareName, "software-name")
	if err != nil {
		return err
	}
	if _, ok := softwareName.(string); !ok {
		return measurementsShapeError("the software-name is not text", nil)
	}
	return tagCreator(coswid[coswidEntity])
}

// tagCreator checks the one entity, which must be the tag-creator.
func tagCreator(rawEntity cbor.RawMessage) error {
	if rawEntity == nil {
		return measurementsShapeError("the entity is missing", nil)
	}
	var entity map[int64]cbor.RawMessage
	if err := measurementsDecMode.Unmarshal(rawEntity, &entity); err != nil {
		return measurementsShapeError("the entity is not one entity-entry", err)
	}
	if err := onlyFields(entity, "the entity", coswidEntityName, coswidRole); err != nil {
		return err
	}
	name, err := decodeField(entity, coswidEntityName, "entity-name")
	if err != nil {
		return err
	}
	if _, ok := name.(string); !ok {
		return measurementsShapeError("the entity-name is not text", nil)
	}
	role, err := decodeField(entity, coswidRole, "entity role")
	if err != nil {
		return err
	}
	roles, ok := role.([]any)
	if !ok {
		roles = []any{role}
	}
	creator := false
	for _, r := range roles {
		if _, text := r.(string); !text && !isInteger(r) {
			return measurementsShapeError("the entity role is neither an integer nor text", nil)
		}
		if r == uint64(coswidRoleTagCreator) {
			creator = true
		}
	}
	if !creator {
		return measurementsShapeError("the entity is not the tag-creator", nil)
	}
	return nil
}

// isInteger reports whether a decoded value is a CBOR integer.
func isInteger(value any) bool {
	switch value.(type) {
	case uint64, int64:
		return true
	}
	return false
}

// evidenceFile returns the evidence's one file.
func evidenceFile(coswid map[int64]cbor.RawMessage) (map[int64]cbor.RawMessage, error) {
	rawEvidence, present := coswid[coswidEvidence]
	if !present {
		return nil, measurementsShapeError("the payload is not an evidence CoSWID", nil)
	}
	var evidence map[int64]cbor.RawMessage
	if err := measurementsDecMode.Unmarshal(rawEvidence, &evidence); err != nil {
		return nil, measurementsShapeError("the evidence is not a map", err)
	}
	if err := onlyFields(evidence, "the evidence", coswidFile); err != nil {
		return nil, err
	}
	rawFile, present := evidence[coswidFile]
	if !present {
		return nil, measurementsShapeError("the evidence holds no file", nil)
	}
	var file map[int64]cbor.RawMessage
	if err := measurementsDecMode.Unmarshal(rawFile, &file); err != nil {
		return nil, measurementsShapeError("the evidence does not hold exactly one file", err)
	}
	if err := onlyFields(file, "the file", coswidFsName, coswidHash); err != nil {
		return nil, err
	}
	return file, nil
}

// fileEvidence returns the file's sha-256 digest, the application evidence.
func fileEvidence(file map[int64]cbor.RawMessage) ([]byte, error) {
	name, err := decodeField(file, coswidFsName, "file's fs-name")
	if err != nil {
		return nil, err
	}
	if name != applicationFileName {
		return nil, measurementsShapeError("the file's fs-name is not \""+applicationFileName+"\"", nil)
	}
	var hash hashEntry
	if err := measurementsDecMode.Unmarshal(file[coswidHash], &hash); err != nil {
		return nil, measurementsShapeError("the file's hash is not a hash-entry", err)
	}
	if hash.Algorithm != hashAlgSHA256 {
		return nil, measurementsShapeError("the file's hash algorithm is not sha-256", nil)
	}
	if len(hash.Value) != sha256.Size {
		return nil, measurementsShapeError("the file's digest is "+strconv.Itoa(len(hash.Value))+" bytes, not 32", nil)
	}
	return hash.Value, nil
}

// measurementsShapeError is a shape refusal: ErrMeasurementsShape with the
// detail and the cause, if any.
func measurementsShapeError(detail string, cause error) error {
	if cause == nil {
		return &errs.Detail{Err: ErrMeasurementsShape, Detail: detail}
	}
	return &errs.Joined{Lead: ErrMeasurementsShape, Detail: detail, Cause: cause}
}
