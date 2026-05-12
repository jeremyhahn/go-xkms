# Client Views

All views are Svelte components in `web/packages/client/src/views/`.

## Dashboard

`Dashboard.svelte` -- Landing view showing client status summary and recent activity.

## Accounts

`Accounts.svelte` -- Multi-account management view.

Displays all configured ACME accounts in a table with name, directory URL, email, key algorithm, and store type. Supports removing accounts with confirmation dialog.

Calls `GET /api/v1/accounts`, `DELETE /api/v1/accounts/{name}`.

## Certificates

`Certificates.svelte` -- Certificate inventory and lifecycle management.

Displays all configured certificate specs with status (issued/pending), account, subject, challenge type, and auto-renewal status. Supports filtering by account. Action buttons per certificate: Request, Renew, Deploy, Revoke.

Calls `GET /api/v1/certificates`, `POST /api/v1/certificate/request`, `POST /api/v1/certificate/renew`, `POST /api/v1/certificates/{name}/deploy`, `POST /api/v1/certificate/revoke`.

## Register

`Register.svelte` -- ACME account registration form.

Fields: contact emails, terms of service agreement, optional EAB credentials (kid + HMAC key).

Calls `POST /api/v1/account/register`.

## Request Certificate

`RequestCert.svelte` -- Request a new certificate.

Fields: domain names (multi-value), key type, key size, challenge type.

Calls `POST /api/v1/certificate/request`.

## Renew Certificate

`RenewCert.svelte` -- Renew an existing certificate by serial number.

Fields: serial number, optional new key type.

Calls `POST /api/v1/certificate/renew`.

## Revoke Certificate

`RevokeCert.svelte` -- Revoke a certificate.

Fields: serial number, revocation reason code.

Calls `POST /api/v1/certificate/revoke`.

## Auto-Renewal

`AutoRenewal.svelte` -- View and configure automatic renewal.

Displays renewal service status, next check time, and tracked certificates with days remaining.

Calls `GET /api/v1/renewal/status`, `GET /api/v1/renewal/config`, `PUT /api/v1/renewal/config`.

## Device Enroll

`DeviceEnroll.svelte` -- TPM device enrollment.

Fields: EK certificate PEM, AK name, device info (manufacturer, model, TPM details).

Calls `POST /api/v1/device/enroll`. Returns EAB credentials for subsequent ACME registration.

## Device Attest

`DeviceAttest.svelte` -- TPM remote attestation.

Fields: AK name, quote, signature, PCR values, nonce.

Calls `POST /api/v1/device/attest`. Returns attestation status and optional certificate.

## Configuration

`Configuration.svelte` -- View and edit client configuration.

Fields: server URL, account URL, key type, key size, challenge type, auto-renew toggle, renew-before-days.

Calls `GET /api/v1/config`, `PUT /api/v1/config`.

## Challenge Config

`ChallengeConfig.svelte` -- Per-challenge-type configuration settings.

## Settings

`Settings.svelte` -- Application-level preferences (theme, display options).
