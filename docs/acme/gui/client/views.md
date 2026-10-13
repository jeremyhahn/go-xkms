# Client Views

> **Status: REFERENCE** · Last verified: 2026-10-12
> Legacy, unabsorbed reference for the views in `pkg/acme/web/packages/client/src/views/`.

Views call the API through `src/lib/api/client-api.ts`.

## Dashboard

`Dashboard.svelte` summarises accounts and certificates (`GET /api/v1/accounts`,
`GET /api/v1/certificates`).

## Accounts

`Accounts.svelte` lists configured accounts and removes one after confirmation
(`GET /api/v1/accounts`, `DELETE /api/v1/accounts/{name}`).

## Certificates

`Certificates.svelte` lists certificate specs and can filter them by account.
Each row has Request, Renew, Deploy and Revoke actions; Revoke uses reason 0
(`POST /api/v1/certificate/{request,renew,revoke}`,
`POST /api/v1/certificates/{name}/deploy`).

## Register

`Register.svelte` adds an account (`POST /api/v1/accounts`). Fields:
- account name, ACME directory URL and contact email
- key algorithm, with an ECC curve or RSA bits
- optional EAB key ID and HMAC key

It does not call `/api/v1/account/register`.

## Request / Renew / Revoke Certificate

`RequestCert.svelte`, `RenewCert.svelte` and `RevokeCert.svelte` each pick a
configured certificate spec by name. Revoke also takes a reason code. They
call `POST /api/v1/certificate/request`, `/renew` and `/revoke` with
`{ name }` (plus `reason`).

## Device Enroll

`DeviceEnroll.svelte` has fields for EK certificate PEM, AK name, device ID,
manufacturer and model. It posts them as `ek_cert_pem`, `ak_name` and
`device_info` to `POST /api/v1/device/enroll`. The handler reads only `name`
and rejects a request without it, so this view currently gets a 400. The same
mismatch applies to the response: the view reads `eab_kid`, which the handler
does not return.

## Device Attest

`DeviceAttest.svelte` has fields for AK name, nonce, quote, signature and PCR
values, and posts them to `POST /api/v1/device/attest`. It has the same `name`
mismatch as Device Enroll.

## Challenges

`ChallengeConfig.svelte` shows read-only descriptions of http-01, dns-01,
tls-alpn-01, endorse-01, enroll-01 and device-attest-01. See
[challenge-types.md](challenge-types.md).

## Settings

`Settings.svelte` offers the theme choice (Light, Dark or System) and shows
the API base URL.
