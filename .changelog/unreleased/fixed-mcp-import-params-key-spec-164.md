- **MCP `getImportParameters` can name the algorithm, so `key_spec` is no longer always `UNKNOWN` (#164).**
  The params gain `key_type`, `key_size` and `curve`, the vocabulary the
  import already takes, and the handler resolves the request through the
  service like the import does, so the backend names the spec the import
  will check the material against. The MCP client transport builds the
  params by name and decodes the PEM wrapping key in the result back to the
  DER the contract carries; it used to marshal the contract request and
  decode the contract response, so the caller's key type went nowhere and
  the wrapping key came back empty.
