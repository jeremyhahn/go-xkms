- **Import, wrap, unwrap and import-parameters work over the REST and QUIC transports (#522).**
  The two client transports marshalled `transport.ImportKeyRequest`,
  `WrapKeyRequest`, `UnwrapKeyRequest` and `GetImportParametersRequest`
  straight onto routes whose handlers decode the REST body, which spells
  the material `wrapped_key` and carries the wrapping key as PEM: the
  material arrived under a name the handler never read, the wrapping key
  arrived as base64, the import-parameters response came back with no
  wrapping key, and `partition`, `metadata` and `key_spec` were dropped,
  so no step of the ceremony over REST or QUIC could succeed. The REST
  bodies now live in the leaf package `pkg/api/rest/wire`, aliased by the
  handlers and built by name by both transports, which translate the
  wrapping key between DER and PEM and refuse a key that is not DER with
  the typed `wire.ErrWrappingPublicKeyNotDER`. The REST bodies gain
  `partition`, `metadata` and `key_spec`, `GenerateKeyRequest` gains
  `partition`, and a contract test pins every field against the transport
  contract.
