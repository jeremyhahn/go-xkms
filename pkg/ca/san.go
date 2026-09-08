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

package ca

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"net/url"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// oidSubjectAltNameExt is the subjectAltName extension identifier, RFC 5280
// section 4.2.1.6: id-ce-subjectAltName OBJECT IDENTIFIER ::= { id-ce 17 }.
var oidSubjectAltNameExt = asn1.ObjectIdentifier{2, 5, 29, 17}

// GeneralName CHOICE tags from RFC 5280 section 4.2.1.6.
const (
	tagRFC822Name = 1
	tagDNSName    = 2
	tagURI        = 6
	tagIPAddress  = 7
)

// generalName is one primitive, context-tagged GeneralName awaiting encoding.
type generalName struct {
	tag     int
	content []byte
}

// OtherName is one subjectAltName GeneralName of CHOICE otherName.
//
//	OtherName ::= SEQUENCE {
//	    type-id OBJECT IDENTIFIER,
//	    value   [0] EXPLICIT ANY DEFINED BY type-id }
//
// Value is the DER encoding of the value, already marshalled: an otherName's
// content is defined by its type-id and this package does not interpret it.
// The RFC 4108 hardwareModuleName and the RFC 4043 permanentIdentifier that a
// TCG DevID certificate carries are both expressed this way.
type OtherName struct {
	// TypeID names what the value is, e.g. OIDHardwareModuleName.
	TypeID asn1.ObjectIdentifier

	// Value is the DER encoding of the otherName's value.
	Value []byte
}

// BuildSubjectAltName encodes one subjectAltName extension carrying every name
// supplied.
//
// This is the only place go-xkms encodes GeneralNames. crypto/x509 builds the
// extension itself from a template's DNSNames, EmailAddresses, IPAddresses and
// URIs, but it has no otherName support and skips its own encoding entirely
// once an extension with this OID is present in ExtraExtensions. A caller that
// needs an otherName therefore has to encode the standard names too, and doing
// that in two places is how a hardware module name came to silently drop a
// certificate's DNS names.
//
// The extension is critical only when the subject distinguished name is empty,
// which RFC 5280 section 4.2.1.6 requires and TCG DevID v1 r12 §8.1 (spec text
// line 2860) restates for a DevID: "the subjectAltName SHOULD NOT be critical,
// as this could introduce interoperability concerns."
//
// Returns ErrTCGExtensionEncoding when a name cannot be encoded, and
// ErrInvalidCertificate when no names were supplied at all — an empty
// subjectAltName is prohibited by RFC 5280 and every caller here has names.
func BuildSubjectAltName(
	subject pkix.Name,
	dnsNames, emailAddresses []string,
	ipAddresses []net.IP,
	uris []*url.URL,
	others []OtherName,
) (pkix.Extension, error) {
	var names []byte

	// otherNames lead so that the RFC 4108 / RFC 4043 identity of a hardware
	// credential appears first when the extension is read by hand.
	for _, other := range others {
		encoded, err := marshalOtherName(other)
		if err != nil {
			return pkix.Extension{}, err
		}
		names = append(names, encoded...)
	}
	primitives := make([]generalName, 0, len(dnsNames)+len(emailAddresses)+len(ipAddresses)+len(uris))
	for _, name := range dnsNames {
		primitives = append(primitives, generalName{tagDNSName, []byte(name)})
	}
	for _, email := range emailAddresses {
		primitives = append(primitives, generalName{tagRFC822Name, []byte(email)})
	}
	for _, ip := range ipAddresses {
		// RFC 5280 section 4.2.1.6: an iPAddress is 4 or 16 octets. A 4-byte
		// IPv4 address held in a 16-byte net.IP must be written in its 4-byte
		// form or verifiers will not match it.
		addr := ip
		if v4 := ip.To4(); v4 != nil {
			addr = v4
		}
		primitives = append(primitives, generalName{tagIPAddress, addr})
	}
	for _, u := range uris {
		if u == nil {
			continue
		}
		primitives = append(primitives, generalName{tagURI, []byte(u.String())})
	}

	for _, name := range primitives {
		encoded, err := marshalGeneralName(name.tag, name.content)
		if err != nil {
			return pkix.Extension{}, err
		}
		names = append(names, encoded...)
	}

	if len(names) == 0 {
		return pkix.Extension{}, &errs.Detail{
			Err:    ErrInvalidCertificate,
			Detail: "subject alternative name extension requires at least one name",
		}
	}

	value, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      names,
	})
	if err != nil {
		return pkix.Extension{}, ErrTCGExtensionEncoding
	}

	return pkix.Extension{
		Id:       oidSubjectAltNameExt,
		Critical: subjectDNIsEmpty(subject),
		Value:    value,
	}, nil
}

// marshalOtherName encodes one GeneralName of CHOICE otherName, which is
// context tag [0] IMPLICIT over the OtherName SEQUENCE, whose own value is
// wrapped in context tag [0] EXPLICIT.
func marshalOtherName(other OtherName) ([]byte, error) {
	if len(other.TypeID) == 0 {
		return nil, &errs.Detail{Err: ErrTCGExtensionEncoding, Detail: "otherName requires a type identifier"}
	}
	if len(other.Value) == 0 {
		return nil, &errs.Detail{Err: ErrTCGExtensionEncoding, Detail: "otherName requires a value"}
	}

	typeID, err := asn1.Marshal(other.TypeID)
	if err != nil {
		return nil, ErrTCGExtensionEncoding
	}
	value, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      other.Value,
	})
	if err != nil {
		return nil, ErrTCGExtensionEncoding
	}

	encoded, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      append(typeID, value...),
	})
	if err != nil {
		return nil, ErrTCGExtensionEncoding
	}
	return encoded, nil
}

// marshalGeneralName encodes a primitive, context-tagged GeneralName such as
// dNSName [2], rfc822Name [1], uniformResourceIdentifier [6] or iPAddress [7].
// Each is an IMPLICIT tag over an IA5String or OCTET STRING whose content is
// the octets given.
func marshalGeneralName(tag int, content []byte) ([]byte, error) {
	encoded, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tag,
		IsCompound: false,
		Bytes:      content,
	})
	if err != nil {
		return nil, ErrTCGExtensionEncoding
	}
	return encoded, nil
}

// subjectDNIsEmpty reports whether a distinguished name would encode as an
// empty RDNSequence, which is what makes subjectAltName critical.
func subjectDNIsEmpty(subject pkix.Name) bool {
	return len(subject.ToRDNSequence()) == 0
}
