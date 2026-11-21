// Package continuous re-attests enrolled devices on a schedule and on
// demand, and publishes each verdict.
//
// An Engine fetches fresh evidence through an EvidenceSource under a fresh
// random nonce, appraises it with the attestation verifier
// (appraisal.Appraiser.AppraiseQuote), stores the tenant-scoped Verdict in a
// qrdb DAO collection, and hands it to every Publisher. Evidence that cannot
// be collected or appraised is still a verdict: Verified is false and Cause
// says why, so a device is never silently skipped.
//
// What a consumer does with a verdict (admit, quarantine, remediate,
// disconnect) is outside this package.
package continuous
