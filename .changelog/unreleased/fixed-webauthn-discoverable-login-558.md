- **A discoverable (usernameless) WebAuthn login can now complete (#558).**
  `finishLoginUser` only fell back to the session's own record of the
  ceremony — discoverable or user-identified — when the caller supplied no
  handle at all. A caller that resolves the assertion to a user afterward and
  passes that handle along, as `pkg/auth_factors`'s `Verify` does once qrdb
  has matched the credential to an enrolled factor, was routed into the
  user-identified branch regardless of how the ceremony began. go-webauthn's
  `ValidateLogin` then compared that non-empty handle against the empty
  `session.UserID` a discoverable `BeginLogin` leaves behind and rejected
  every usernameless login with "ID mismatch for User and Session". The
  session, not the caller-supplied handle, now always decides which ceremony
  is in play, matching the comment already written above the check.
