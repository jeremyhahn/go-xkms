Slice (lane sacmeia, row acme-issuance SPEC.md:41): device-attest-01 finalize matches the possession request's 32-byte application evidence against the reference registered on the provisioned device.
Checks: ProvisionedDevice.ApplicationReference is exactly 32 bytes when set; VerifyPossessionCSR refuses a mismatch (constant-time compare) or an absent reference with ErrPossessionApplicationEvidenceMismatch; table tests for match, one-byte mismatch, missing reference, wrong-length reference.
Results to follow.
