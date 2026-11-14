# Android key attestation: certificate revocation status list

Source: Android Developers, "Verify hardware-backed key pairs with key
attestation",
<https://developer.android.com/privacy-and-security/security-key-attestation>,
retrieved 2026-10-26. The sections below are copied verbatim from that page
(only the parts the revocation check implements); code comments cite them by
section name. The HTTP freshness rules the "Cache-Control header" sentence
relies on are RFC 9111, copied as [rfc-9111.txt](rfc-9111.txt).

## Before you begin: ensure your device supports hardware-level key attestation

Before you verify the properties of a device's hardware-backed keys in a
production-level environment, make sure that the device supports
hardware-level key attestation. To do so, check that the attestation certificate
chain contains a root certificate that is signed with the Google attestation root
key and that the attestationSecurityLevel element within the
key description
data structure is set to the TrustedEnvironment security level or
to the StrongBox security level.

In addition, it's important to verify the signatures in the certificate chain
and to confirm that none of the keys in the chain have been revoked by checking
the certificate revocation status list.
Unless all are valid and the root is the Google root key, don't
fully trust the attestation.

## Retrieve and verify a hardware-backed key pair

To implement key attestation, complete the following steps:

1. Use a KeyStore object's getCertificateChain() method to get a reference to
   the chain of X.509 certificates associated with the hardware-backed
   keystore.
2. Send the certificates to a separate server that you trust for validation.

   Caution: Don't complete the following validation process on the same
   device. If the Android system on that device is compromised, that could
   cause the validation process to trust something that is untrustworthy.
3. Obtain a reference to the X.509 certificate chain parsing and validation
   library that is most appropriate for your toolset. Verify that the root
   public certificate is trustworthy and that each certificate signs the next
   certificate in the chain.
4. Check each certificate's revocation status to ensure that none of the
   certificates have been revoked.

## Certificate revocation status list

Attestation keys can be revoked for a number of reasons, including mishandling or suspected
extraction by an attacker. Therefore, it's critical that the status of each certificate in
an attestation chain be checked against the official certificate revocation status list (CRL).

This list is maintained by Google and published at:

https://android.googleapis.com/attestation/status. The Cache-Control header in
the HTTP response determines how often to check for updates so a network request is not required
for every certificate being verified.

This URL returns a JSON file containing the revocation status for any certificates that don't
have a normal valid status. The format of the JSON file adheres to the following
JSON Schema draft 07 definition:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "entries": {
      "description" : "Each entry represents the status of an attestation key. The dictionary-key is the certificate serial number in lowercase hex.",
      "type": "object",
      "propertyNames": {
        "pattern": "^[a-f1-9][a-f0-9]*$"
      },
      "additionalProperties": {
        "type": "object",
        "properties": {
          "status": {
            "description": "[REQUIRED] Current status of the key.",
            "type": "string",
            "enum": ["REVOKED", "SUSPENDED"]
          },
          "expires": {
            "description": "[OPTIONAL] UTC date when certificate expires in ISO8601 format (YYYY-MM-DD). Can be used to clear expired certificates from the status list.",
            "type": "string",
            "format": "date"
          },
          "reason": {
            "description": "[OPTIONAL] Reason for the current status.",
            "type": "string",
            "enum": ["UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE", "SUPERSEDED", "SOFTWARE_FLAW"]
          },
          "comment": {
            "description": "[OPTIONAL] Free form comment about the key status.",
            "type": "string",
            "maxLength": 140
          }
        },
        "required": ["status"],
        "additionalProperties": false
      }
    }
  },
  "required": ["entries"],
  "additionalProperties": false
}
```

Example CRL:

```json
{
  "entries": {
    "2c8cdddfd5e03bfc": {
      "status": "REVOKED",
      "expires": "2020-11-13",
      "reason": "KEY_COMPROMISE",
      "comment": "Key stored on unsecure system"
    },
    "c8966fcb2fbb0d7a": {
      "status": "SUSPENDED",
      "reason": "SOFTWARE_FLAW",
      "comment": "Bug in keystore causes this key malfunction b/555555"
    }
  }
}
```

### Expired factory keys: Still trustworthy

Devices launched before 2021 have attestation keys with expired certificates. These keys
are still trustworthy unless they appear in the
certificate revocation list. We
recommend that you continue trusting certificates that chain to the root with the subject
SERIALNUMBER=f92009e853b6b045, regardless of certificate validity period.

It's critical, however, to ensure that Remote Key Provisioning (RKP) certificates continue to
have their validity period checked. The shorter expiration period for RKP certificates is an
important consideration of the threat model, and is intended to allow for quicker responses to
compromises.

## Certificate revocation policy

The certificates for Android attestation keys will be revoked when the keys are compromised, due
to the critical nature of attestation validity. This section outlines a policy for when
certificates are revoked. This policy is likely to evolve and enumerate additional cases over
time.

### What qualifies for revocation?

Note: Attestation key leaks only affect the older provisioning mechanism supported in Android and don't
apply to attestation keys certified by the newer Remote Key Provisioning (RKP) mechanism.

Attestation keys that have been leaked are always eligible to have their certificates revoked.

Upon discovery, attestation certificates will be revoked by having their serial numbers added to
the certificate revocation list. Typically
this will happen within several days of discovery, but may take longer in rare cases.
