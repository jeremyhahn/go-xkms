- **Tenant release key provisioned on first use (owner ruling 134).** The
  first `SignCoRIM` or `SignImage` of an unbound repository, for a tenant that
  holds no `release-signing` key, generates it (ECDSA P-256) through the
  tenant-scoped backend and signs with it, so a tenant no longer has to
  provision the key before it can sign. An existing key is kept, two
  concurrent first uses end in one key, and a binding to a missing key or the
  system tenant is never provisioned. A generate failure is the new
  `ReleaseKeyProvisionError`. No transport, proto or SDK surface changes.
  Code: `pkg/xkms/servicer_signing_keys.go`; docs:
  `docs/image-signing/architecture.md#the-tenants-release-key`.
