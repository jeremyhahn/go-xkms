- Feature DAOs over the embedded node (the CA's certificates, WebAuthn
  credentials and every other feature database) now run as xkms's service
  principal through `datastore.WithCallContext`, so xkmsd boots with
  authentication enforced. The principal's grant gains exactly
  `databases:create`, `index:create` and `index:query`.
