### Fixed

- **PKCS#11: `C_UnwrapKey` and `C_GenerateKeyPair` now agree about which EC
  curves the module accepts.** The module recognises the Edwards and Montgomery
  OIDs so `CKA_EC_PARAMS` can identify their own key types, but an ECDSA key
  cannot live on them. An unwrap naming one — the X25519 OID is the shape older
  implementations such as NSS emit for Curve25519 — used to resolve as
  recognised, reach the backend, and come back as a generic `invalid curve`
  several layers down, while an OID the module does not carry at all was
  refused at the module with `CKR_CURVE_NOT_SUPPORTED`. One condition, two
  answers, and only the second is one a PKCS#11 caller can act on. Both verbs
  now resolve the curve through one predicate and return
  `CKR_CURVE_NOT_SUPPORTED`.

  `templateCurveName` no longer reports "attribute absent" and "attribute names
  something unusable" with the same value: it returns the name, a presence
  flag, and the `CK_RV` separately. An omitted `CKA_EC_PARAMS` still reaches the
  backend and takes the service default, which PKCS#11 v3.2 Table 13 footnote 6
  requires for an unwrapped EC private key.
