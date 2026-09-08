- **`PlatformKeyStore.IsProvisioned()` reports what the SRK handle actually
  holds after a failed PIN change (#448).** A PIN change evicts the persistent
  SRK before recreating it; when the recreate or re-persist failed, the
  store kept reporting provisioned over an empty handle, so the retry through
  `Initialize` took the verify-existing-SRK branch and failed at `ReadHandle`
  instead of recreating the key. The failure path now re-probes the handle,
  the same probe the constructor runs, and sets the provisioned state from
  what is there: gone means unprovisioned and the next `Initialize`
  recreates; present means provisioned but, as before, not auth-ready.
  Recovery stays with the retry; the failure path reports, it does not
  re-provision.
