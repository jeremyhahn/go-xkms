// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

/**
 * clients-extra.test.ts — wire-contract coverage for the domain-client
 * methods clients.test.ts does not already exercise (list/get/delete
 * variants, secondary lifecycle endpoints, etc.).
 *
 * Every domain client here is a thin, mechanical wrapper: HttpCore does the
 * actual request/response/error work (covered by http.test.ts), so the only
 * thing worth pinning per method is the wire contract — VERB, PATH (incl.
 * path params), and whether each field lands in the body or the query
 * string. A test that doesn't assert method/url/body would still pass if
 * the path string were wrong, so every case below asserts at least one of
 * those. Methods already covered by clients.test.ts or auth.test.ts are not
 * repeated here.
 *
 * `src/clients/factors.ts` is intentionally out of scope — a sibling agent
 * owns FactorsClient and its tests (src/factors.test.ts).
 */

import { describe, it, expect } from 'vitest';
import { createClient } from './client.js';
import { newFakeFetch } from './testutil.js';
import { XkmsApiError } from './errors.js';

const BASE = 'https://xkms.example.com';

function make(fake: ReturnType<typeof newFakeFetch>) {
  return createClient({ baseURL: BASE, fetch: fake.fetch, token: () => 'tk' });
}

describe('HealthClient (liveness probes)', () => {
  it('routes live/ready/startup unauthenticated', async () => {
    const fake = newFakeFetch({ body: { status: 'ok' } });
    const c = make(fake);
    await c.health.live();
    expect(fake.calls[0]?.url).toBe(`${BASE}/health/live`);
    expect(fake.calls[0]?.headers['Authorization']).toBeUndefined();

    await c.health.ready();
    expect(fake.calls[1]?.url).toBe(`${BASE}/health/ready`);

    await c.health.startup();
    expect(fake.calls[2]?.url).toBe(`${BASE}/health/startup`);
  });
});

describe('BackendsClient (BackendCapabilities wire shape)', () => {
  it('decodes capabilities under their PascalCase Go field names (no json tags)', async () => {
    // pkg/types/types.go Capabilities has no json struct tags, so it
    // marshals under its exported (PascalCase) field names, unlike every
    // other DTO in this SDK. A snake_case or camelCase fixture here would
    // silently decode every field to undefined.
    const fake = newFakeFetch({
      body: {
        id: 'tpm2',
        type: 'tpm2',
        hardware_backed: true,
        capabilities: {
          Keys: true,
          HardwareBacked: true,
          Signing: true,
          Decryption: false,
          KeyRotation: true,
          SymmetricEncryption: false,
          Sealing: true,
          Import: false,
          Export: false,
          KeyAgreement: false,
          ECIES: false,
          Attestation: true,
          QuantumSigning: false,
          KeyEncapsulation: false,
        },
      },
    });
    const c = make(fake);
    const info = await c.backends.get('tpm2');
    expect(info.capabilities.Keys).toBe(true);
    expect(info.capabilities.HardwareBacked).toBe(true);
    expect(info.capabilities.Attestation).toBe(true);
    expect(info.capabilities.Decryption).toBe(false);
  });
});

describe('KeysClient (crypto-op and lifecycle endpoints)', () => {
  it('routes list/get/delete with the backend query param', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.keys.list('software');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/keys?backend=software`);

    await c.keys.get('k1', 'software');
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/keys/k1?backend=software`);

    await c.keys.delete('k1', 'software');
    expect(fake.calls[2]?.method).toBe('DELETE');
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/keys/k1?backend=software`);
  });

  it('routes symmetric/asymmetric encrypt-decrypt bodies', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.keys.encrypt('k1', { plaintext: 'cGxhaW4=' });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/keys/k1/encrypt`);
    expect(fake.calls[0]?.body).toEqual({ plaintext: 'cGxhaW4=' });

    await c.keys.decrypt('k1', { ciphertext: 'Y2lwaGVy' });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/keys/k1/decrypt`);

    await c.keys.encryptAsym('k1', { plaintext: 'cGxhaW4=' });
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/keys/k1/encrypt-asym`);
  });

  it('routes import-params, wrap, and unwrap with wrapping_public_key_pem in the body', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.keys.importParams({
      backend: 'software',
      key_id: 'k1',
      key_type: 'aes',
      algorithm: 'RSA_AES_KEY_WRAP_SHA256',
    });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/keys/import-params`);

    await c.keys.wrap({
      backend: 'software',
      key_material: 'bWF0ZXJpYWw=',
      wrapping_public_key_pem: 'PEM',
      algorithm: 'RSA_AES_KEY_WRAP_SHA256',
    });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/keys/wrap`);
    expect(fake.calls[1]?.body).toMatchObject({ wrapping_public_key_pem: 'PEM' });

    await c.keys.unwrap({
      backend: 'software',
      wrapped_key: 'd3JhcHBlZA==',
      wrapping_public_key_pem: 'PEM',
      algorithm: 'RSA_AES_KEY_WRAP_SHA256',
    });
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/keys/unwrap`);
    expect(fake.calls[2]?.body).toMatchObject({ wrapping_public_key_pem: 'PEM' });
  });

  it('routes import, export (backend in body+query), copy, and derive-ecdh', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.keys.import({
      backend: 'software',
      key_id: 'k1',
      key_type: 'aes',
      wrapped_key: 'd3JhcHBlZA==',
      algorithm: 'RSA_AES_KEY_WRAP_SHA256',
    });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/keys/import`);

    await c.keys.export('k1', { backend: 'software', algorithm: 'RSA_AES_KEY_WRAP_SHA256' });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/keys/k1/export?backend=software`);
    expect(fake.calls[1]?.body).toEqual({
      backend: 'software',
      algorithm: 'RSA_AES_KEY_WRAP_SHA256',
    });

    await c.keys.copy({
      source_backend: 'software',
      source_key_id: 'k1',
      dest_backend: 'tpm2',
      dest_key_id: 'k2',
      algorithm: 'ECDSA_P256',
    });
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/keys/copy`);

    await c.keys.deriveECDH({ key_id: 'k1', backend: 'software', peer_public_key: 'cGVlcg==' });
    expect(fake.calls[3]?.url).toBe(`${BASE}/api/v1/keys/derive-ecdh`);
  });

  it('routes unwrap-by-id', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.keys.unwrapById({
      wrapped_key: 'd3JhcHBlZA==',
      unwrapping_key_id: 'w1',
      unwrapping_key_backend: 'tpm2',
      algorithm: 'AES_GCM_256',
      target_key_id: 't1',
      target_key_backend: 'software',
      target_key_type: 'aes',
    });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/keys/unwrap-by-id`);
  });
});

describe('CertsClient (list/get/delete/chain endpoints)', () => {
  it('routes list, get, delete with backend query', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.certs.list('software');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/certs?backend=software`);

    await c.certs.get('c1', 'software');
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/certs/c1?backend=software`);

    await c.certs.delete('c1', 'software');
    expect(fake.calls[2]?.method).toBe('DELETE');
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/certs/c1?backend=software`);
  });

  it('routes saveChain with backend query pulled from the body, and getChain', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.certs.saveChain('c1', { backend: 'software', cert_chain_pem: ['A', 'B'] });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/certs/c1/chain?backend=software`);
    expect(fake.calls[0]?.body).toEqual({ backend: 'software', cert_chain_pem: ['A', 'B'] });

    await c.certs.getChain('c1', 'software');
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/certs/c1/chain?backend=software`);
  });
});

describe('SealClient (seal/unseal)', () => {
  it('routes seal and unseal', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.seal.seal({ backend: 'tpm2', data: 'ZGF0YQ==' });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/seal`);
    expect(fake.calls[0]?.body).toEqual({ backend: 'tpm2', data: 'ZGF0YQ==' });

    await c.seal.unseal({ backend: 'tpm2', ciphertext: 'Y2lwaGVy' });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/unseal`);
  });
});

describe('BarrierClient (initialize/unseal/seal/shamir/recovery)', () => {
  it('routes the plain initialize/unseal/seal lifecycle', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.barrier.initialize({ secret: 'x' });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/barrier/initialize`);

    await c.barrier.unseal({ secret: 'x' });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/barrier/unseal`);

    await c.barrier.seal();
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/barrier/seal`);
    expect(fake.calls[2]?.body).toBeUndefined();
  });

  it('routes shamir batch unseal and rekey', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.barrier.shamirUnsealShares({ shares: ['s1', 's2'] });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/barrier/shamir/unseal-shares`);

    await c.barrier.rekey({ threshold: 2, total: 3 });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/barrier/rekey`);
  });

  it('routes the recovery-key lifecycle', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.barrier.generateRecoveryKeys({ threshold: 2, total: 3 });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/barrier/recovery/generate`);

    await c.barrier.recoverWithKeys({ keys: ['k1', 'k2'] });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/barrier/recovery/recover`);

    await c.barrier.deleteRecoveryKeys();
    expect(fake.calls[2]?.method).toBe('DELETE');
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/barrier/recovery/keys`);

    await c.barrier.generateRootToken({ shares: ['s1', 's2'] });
    expect(fake.calls[3]?.url).toBe(`${BASE}/api/v1/barrier/recovery/root-token`);
  });
});

describe('PinClient (set/change/verify)', () => {
  it('routes the SO and user PIN set/change/verify/reset endpoints', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.pin.setSO({ current_so_pin: 'a', new_so_pin: 'b' });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/pin/so/set`);

    await c.pin.setUser({ so_pin: 'a', new_user_pin: 'b' });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/pin/user/set`);

    await c.pin.changeSO({ current_so_pin: 'a', new_so_pin: 'b' });
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/pin/so/change`);

    await c.pin.changeUser({ current_user_pin: 'a', new_user_pin: 'b' });
    expect(fake.calls[3]?.url).toBe(`${BASE}/api/v1/pin/user/change`);

    await c.pin.verifyUser({ pin: '1234' });
    expect(fake.calls[4]?.url).toBe(`${BASE}/api/v1/pin/user/verify`);

    await c.pin.resetLockout({ so_pin: 'a' });
    expect(fake.calls[5]?.url).toBe(`${BASE}/api/v1/pin/lockout/reset`);
  });
});

describe('CaClient (issue/revoke/tcg endpoints)', () => {
  it('routes certificate lookup and sign-csr/issue/revoke/crl', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.ca.certificate('dev-1');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/ca/certificate?identity=dev-1`);

    await c.ca.signCSR({ csr_pem: 'Q1NS' });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/ca/sign-csr`);

    await c.ca.issue({ profile: 'server', common_name: 'svc.example.com' });
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/ca/issue`);

    await c.ca.revoke({ serial_number: '0A', reason: 1 });
    expect(fake.calls[3]?.url).toBe(`${BASE}/api/v1/ca/revoke`);

    await c.ca.generateCRL();
    expect(fake.calls[4]?.url).toBe(`${BASE}/api/v1/ca/crl`);
    expect(fake.calls[4]?.body).toEqual({});
  });

  it('routes the TCG EK/AK/enroll endpoints', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.ca.issueEK({ common_name: 'tpm-1', ek_public_key: 'RUs=' });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/ca/tcg/ek`);

    await c.ca.issueAK({ common_name: 'tpm-1', public_key: 'QUs=' });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/ca/tcg/ak`);

    await c.ca.enrollDevice({ common_name: 'tpm-1', packed_csr: 'Q1NS' });
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/ca/tcg/enroll`);
  });
});

describe('ClusterClient (status/members, read-only)', () => {
  it('routes status and members list', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.cluster.status();
    expect(fake.calls[0]?.method).toBe('GET');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/cluster/status`);

    await c.cluster.members();
    expect(fake.calls[1]?.method).toBe('GET');
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/cluster/members`);
  });
});

describe('CustodianClient (list/get/delete group + members + distribute)', () => {
  it('routes group list/get/delete', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.custodian.listGroups();
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/custodian/groups/`);

    await c.custodian.getGroup('g1');
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/custodian/groups/g1`);

    fake.respond({ status: 204 });
    await c.custodian.deleteGroup('g1');
    expect(fake.calls[2]?.method).toBe('DELETE');
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/custodian/groups/g1`);
  });

  it('routes addMember and distributeShares', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.custodian.addMember('g1', { user_id: 'u1', username: 'alice', method: 'webauthn' });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/custodian/groups/g1/members`);
    expect(fake.calls[0]?.body).toEqual({ user_id: 'u1', username: 'alice', method: 'webauthn' });

    await c.custodian.distributeShares('g1');
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/custodian/groups/g1/distribute`);
  });
});

describe('SharesClient (submit/list/delete)', () => {
  it('routes submit, list, and delete', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.shares.submit({
      server_url: 'https://s:8443',
      group_id: 'g1',
      share_index: 1,
      share_data: 'ZGF0YQ==',
    });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/shares/submit`);

    await c.shares.list();
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/shares/`);

    fake.respond({ status: 204 });
    await c.shares.delete('https://s:8443', 'g1', 1);
    expect(fake.calls[2]?.method).toBe('DELETE');
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/shares/https%3A%2F%2Fs%3A8443/g1/1`);
  });
});

describe('TenantsClient (list/get/delete/barrier/entitlements)', () => {
  it('routes list, get, delete', async () => {
    const fake = newFakeFetch({ body: { tenant: {} } });
    const c = make(fake);
    await c.tenants.list();
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/tenants/`);

    await c.tenants.get('t1');
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/tenants/t1`);

    fake.respond({ status: 204 });
    await c.tenants.delete('t1');
    expect(fake.calls[2]?.method).toBe('DELETE');
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/tenants/t1`);
  });

  it('routes tenant barrier status/unseal and entitlements update', async () => {
    const fake = newFakeFetch({
      body: { tenant_id: 't1', sealed: false, hardware_backed: false },
    });
    const c = make(fake);
    await c.tenants.barrierStatus('t1');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/tenants/t1/barrier/status`);

    await c.tenants.barrierUnseal('t1', { share: 'c2hhcmU=' });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/tenants/t1/barrier/unseal`);

    fake.respond({ body: { tenant: {} } });
    await c.tenants.updateEntitlements('t1', {
      tenant_id: 't1',
      entitlements: { allow_dedicated_raft: true },
    });
    expect(fake.calls[2]?.method).toBe('PUT');
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/tenants/t1/entitlements`);
  });
});

describe('PasswordsClient (add/get/update/delete/lock/unlock)', () => {
  it('routes the CRUD endpoints', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.passwords.add({ name: 'db-pass', password: 's3cr3t' });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/passwords/`);

    await c.passwords.get('p1');
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/passwords/p1`);

    await c.passwords.update('p1', { password: 'new' });
    expect(fake.calls[2]?.method).toBe('PUT');
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/passwords/p1`);

    await c.passwords.delete('p1');
    expect(fake.calls[3]?.method).toBe('DELETE');
    expect(fake.calls[3]?.url).toBe(`${BASE}/api/v1/passwords/p1`);
  });

  it('routes unlock/lock/status/access-mode', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.passwords.unlock({ pin: '1234' });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/passwords/unlock`);

    await c.passwords.lock();
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/passwords/lock`);
    expect(fake.calls[1]?.body).toBeUndefined();

    await c.passwords.status();
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/passwords/status`);

    await c.passwords.setAccessMode({ mode: 'shared' });
    expect(fake.calls[3]?.url).toBe(`${BASE}/api/v1/passwords/access-mode`);
  });
});

describe('PlatformClient (get/delete/list/reseal/status)', () => {
  it('routes the sealed-secret store endpoints', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.platform.getSecret('db-pass');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/platform/secrets/db-pass`);

    await c.platform.deleteSecret('db-pass');
    expect(fake.calls[1]?.method).toBe('DELETE');
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/platform/secrets/db-pass`);

    await c.platform.listSecrets();
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/platform/secrets`);

    await c.platform.resealSecret('db-pass');
    expect(fake.calls[3]?.method).toBe('POST');
    expect(fake.calls[3]?.url).toBe(`${BASE}/api/v1/platform/secrets/db-pass/reseal`);

    await c.platform.status();
    expect(fake.calls[4]?.url).toBe(`${BASE}/api/v1/platform/status`);
  });
});

describe('TpmPolicyClient (named TPM policy lifecycle)', () => {
  it('routes create/get/update/revoke/objects/auto-unseal/rotate, scoping cross-tenant calls by tenant_id', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);

    await c.tpmPolicies.create({ name: 'boot', bank: 'sha256', pcrs: [0, 1, 7], auto_unseal: true });
    expect(fake.calls[0]?.method).toBe('POST');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/tpm/policies`);
    expect(fake.calls[0]?.body).toEqual({ name: 'boot', bank: 'sha256', pcrs: [0, 1, 7], auto_unseal: true });

    await c.tpmPolicies.get('boot', 't1');
    expect(fake.calls[1]?.method).toBe('GET');
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/tpm/policies/boot?tenant_id=t1`);

    await c.tpmPolicies.update('boot', 't1');
    expect(fake.calls[2]?.method).toBe('POST');
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/tpm/policies/boot/update`);
    expect(fake.calls[2]?.body).toEqual({ tenant_id: 't1', name: 'boot' });

    await c.tpmPolicies.revoke('boot');
    expect(fake.calls[3]?.method).toBe('POST');
    expect(fake.calls[3]?.url).toBe(`${BASE}/api/v1/tpm/policies/boot/revoke`);
    expect(fake.calls[3]?.body).toEqual({ name: 'boot' });

    fake.respond({ body: { name: 'boot', objects: ['key/db-key'] } });
    await c.tpmPolicies.objects('boot', 't1');
    expect(fake.calls[4]?.method).toBe('GET');
    expect(fake.calls[4]?.url).toBe(`${BASE}/api/v1/tpm/policies/boot/objects?tenant_id=t1`);

    await c.tpmPolicies.setAutoUnseal('boot', true);
    expect(fake.calls[5]?.method).toBe('POST');
    expect(fake.calls[5]?.url).toBe(`${BASE}/api/v1/tpm/policies/boot/auto-unseal`);
    expect(fake.calls[5]?.body).toEqual({ name: 'boot', enabled: true });

    fake.respond({ body: { generation: 2, authority_name: 'ab12', epoch: 1 } });
    await c.tpmPolicies.rotateAuthority('t1');
    expect(fake.calls[6]?.method).toBe('POST');
    expect(fake.calls[6]?.url).toBe(`${BASE}/api/v1/tpm/authority/rotate`);
    expect(fake.calls[6]?.body).toEqual({ tenant_id: 't1' });

    fake.respond({ body: { object_id: 'db-key', kind: 'key', policy: 'boot', created_at: '2026-01-01T00:00:00Z' } });
    await c.tpmPolicies.keyPolicy('db-key', { tenantId: 't1', kind: 'sealed' });
    expect(fake.calls[7]?.method).toBe('GET');
    expect(fake.calls[7]?.url).toBe(`${BASE}/api/v1/keys/db-key/tpm-policy?tenant_id=t1&kind=sealed`);
  });

  it('deletes a policy (204, no body) and surfaces a 409 conflict listing its assigned objects', async () => {
    const fake = newFakeFetch({ status: 204 });
    const c = make(fake);
    await c.tpmPolicies.delete('boot', { tenant_id: 't1' });
    expect(fake.calls[0]?.method).toBe('DELETE');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/tpm/policies/boot`);
    expect(fake.calls[0]?.body).toEqual({ tenant_id: 't1' });

    fake.respond({
      status: 409,
      body: { error: 'tpmpolicy: policy in use', message: 'policy "boot" is assigned to key/db-key, sealed/backup' },
    });
    const err = await c.tpmPolicies.delete('boot').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(XkmsApiError);
    expect((err as XkmsApiError).status).toBe(409);
    expect((err as XkmsApiError).message).toBe('policy "boot" is assigned to key/db-key, sealed/backup');
  });
});

describe('TenantsClient (TPM mode and vTPM)', () => {
  it('routes get/set TPM mode and vTPM status/start/stop', async () => {
    const fake = newFakeFetch({ body: { tenant_id: 't1', mode: 'shared' } });
    const c = make(fake);

    await c.tenants.getTPMMode('t1');
    expect(fake.calls[0]?.method).toBe('GET');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/tenants/t1/tpm`);

    await c.tenants.setTPMMode('t1', { tenant_id: 't1', mode: 'vtpm' });
    expect(fake.calls[1]?.method).toBe('PUT');
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/tenants/t1/tpm`);
    expect(fake.calls[1]?.body).toEqual({ tenant_id: 't1', mode: 'vtpm' });

    fake.respond({ body: { tenant_id: 't1', running: false } });
    await c.tenants.vtpmStatus('t1');
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/tenants/t1/tpm/vtpm`);

    fake.respond({ body: { tenant_id: 't1', running: true, pid: 42 } });
    await c.tenants.vtpmStart('t1');
    expect(fake.calls[3]?.method).toBe('POST');
    expect(fake.calls[3]?.url).toBe(`${BASE}/api/v1/tenants/t1/tpm/vtpm/start`);

    fake.respond({ body: { tenant_id: 't1', running: false } });
    await c.tenants.vtpmStop('t1');
    expect(fake.calls[4]?.method).toBe('POST');
    expect(fake.calls[4]?.url).toBe(`${BASE}/api/v1/tenants/t1/tpm/vtpm/stop`);
  });
});

describe('InitClient (claim-cert complete, claim-share, sign-csr)', () => {
  it('routes claim-cert/complete and the claim-share ceremony', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.init.claimCertComplete({ username: 'so1', nonce: 'n', signature: 'c2ln' });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/init/claim-cert/complete`);

    await c.init.claimShareBegin({ username: 'so1' });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/init/claim-share/begin`);

    await c.init.claimShareComplete({ username: 'so1', nonce: 'n', signature: 'c2ln' });
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/init/claim-share/complete`);
  });

  it('routes the authenticated ceremony sign-csr', async () => {
    const fake = newFakeFetch({ body: { cert_pem: 'PEM' } });
    const c = make(fake);
    await c.init.signCSR({ username: 'so1', so_pin: '1234', csr_pem: 'CSR', role: 'so' });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/init/sign-csr`);
    expect(fake.calls[0]?.headers['Authorization']).toBe('Bearer tk');
  });
});

describe('CredentialsClient (submit)', () => {
  it('routes boot-credential submission', async () => {
    const fake = newFakeFetch({ body: { status: 'accepted' } });
    const c = make(fake);
    await c.credentials.submit({ name: 'unseal', value: 'dmFsdWU=' });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/credentials/submit`);
    expect(fake.calls[0]?.body).toEqual({ name: 'unseal', value: 'dmFsdWU=' });
  });
});

describe('UsersClient (list/get/update/delete/credentials)', () => {
  it('routes the remaining user lifecycle endpoints', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.users.list();
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/users/`);

    await c.users.get('bob');
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/users/bob`);

    await c.users.update('bob', { enabled: false });
    expect(fake.calls[2]?.method).toBe('PUT');
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/users/bob`);
    expect(fake.calls[2]?.body).toEqual({ enabled: false });

    await c.users.delete('bob');
    expect(fake.calls[3]?.method).toBe('DELETE');
    expect(fake.calls[3]?.url).toBe(`${BASE}/api/v1/users/bob`);

    await c.users.credentials('bob');
    expect(fake.calls[4]?.url).toBe(`${BASE}/api/v1/users/bob/credentials`);
  });
});

describe('FrostClient (key lifecycle, sign round, verify)', () => {
  it('routes key generate/import/list/get/delete', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.frost.generateKey({ threshold: 2, total: 3 });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/frost/keys`);

    await c.frost.importKey({
      package: {
        key_id: 'fk1',
        algorithm: 'FROST_ED25519',
        threshold: 2,
        total: 3,
        participant_id: 1,
        secret_share: 'aa',
        group_public_key: 'bb',
        verification_shares: { '1': 'cc' },
      },
    });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/frost/keys/import`);

    await c.frost.listKeys();
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/frost/keys`);
    expect(fake.calls[2]?.method).toBe('GET');

    await c.frost.getKey('fk1');
    expect(fake.calls[3]?.url).toBe(`${BASE}/api/v1/frost/keys/fk1`);

    await c.frost.deleteKey('fk1');
    expect(fake.calls[4]?.method).toBe('DELETE');
    expect(fake.calls[4]?.url).toBe(`${BASE}/api/v1/frost/keys/fk1`);
  });

  it('routes sign-round and verify', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.frost.signRound('fk1', {
      key_id: 'fk1',
      message: 'deadbeef',
      session_id: 'sess-1',
      hiding_nonce: 'aa',
      binding_nonce: 'bb',
      hiding_commitment: 'cc',
      binding_commitment: 'dd',
      commitments: [],
    });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/frost/keys/fk1/sign`);

    await c.frost.verify({ key_id: 'fk1', message: 'deadbeef', signature: 'c2ln' });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/frost/verify`);
  });
});

describe('PivClient (slots, store/delete/import/export cert, csr)', () => {
  it('routes listSlots and the per-slot certificate lifecycle', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.piv.listSlots('yubikey');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/piv/slots?backend=yubikey`);

    await c.piv.storeCertificate('9a', { certificate: 'Y2VydA==', format: 'pem' });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/piv/slots/9a/certificate`);
    expect(fake.calls[1]?.method).toBe('POST');

    await c.piv.deleteCertificate('9a', 'yubikey');
    expect(fake.calls[2]?.method).toBe('DELETE');
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/piv/slots/9a/certificate?backend=yubikey`);

    await c.piv.importCertificate('9a', { certificate: 'Y2VydA==', format: 'pem' });
    expect(fake.calls[3]?.url).toBe(`${BASE}/api/v1/piv/slots/9a/import`);

    await c.piv.exportCertificate('9a', 'yubikey', 'der');
    expect(fake.calls[4]?.url).toBe(
      `${BASE}/api/v1/piv/slots/9a/export?backend=yubikey&format=der`,
    );
  });

  it('routes CSR generation', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.piv.generateCSR('9a', { subject: 'CN=device' });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/piv/slots/9a/csr`);
    expect(fake.calls[0]?.body).toEqual({ subject: 'CN=device' });
  });
});

describe('SshClient (generate/import/delete keys, known-hosts, authorized-keys)', () => {
  it('routes key generate/import/delete/export-public', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.ssh.generateKey({ scope: 'user', owner: 'alice', name: 'id1', algorithm: 'ed25519' });
    expect(fake.calls[0]?.url).toBe(`${BASE}/xkms/v1/ssh/keys`);

    await c.ssh.importKey({
      scope: 'user',
      owner: 'alice',
      name: 'id2',
      pem: 'UEVN',
    });
    expect(fake.calls[1]?.url).toBe(`${BASE}/xkms/v1/ssh/keys/import`);

    fake.respond({ status: 204 });
    await c.ssh.deleteKey('user', 'alice', 'id1');
    expect(fake.calls[2]?.method).toBe('DELETE');
    expect(fake.calls[2]?.url).toBe(`${BASE}/xkms/v1/ssh/keys/user/alice/id1`);

    fake.respond({ body: { algorithm: 'ssh-ed25519', line: 'l', fingerprint: 'f' } });
    await c.ssh.exportPublic('user', 'alice', 'id1');
    expect(fake.calls[3]?.url).toBe(`${BASE}/xkms/v1/ssh/keys/user/alice/id1/public`);
  });

  it('routes known-hosts add/list', async () => {
    const fake = newFakeFetch({ status: 204 });
    const c = make(fake);
    await c.ssh.addKnownHost({
      scope: 'user',
      owner: 'alice',
      host: 'db1',
      fingerprint: 'SHA256:x',
    });
    expect(fake.calls[0]?.method).toBe('POST');
    expect(fake.calls[0]?.url).toBe(`${BASE}/xkms/v1/ssh/known-hosts`);

    fake.respond({ body: { items: [] } });
    await c.ssh.listKnownHosts('user', 'alice');
    expect(fake.calls[1]?.url).toBe(`${BASE}/xkms/v1/ssh/known-hosts?scope=user&owner=alice`);
  });

  it('routes authorized-keys add/list/get/remove/verify', async () => {
    const fake = newFakeFetch({ status: 204 });
    const c = make(fake);
    await c.ssh.addAuthorizedKey({
      scope: 'user',
      owner: 'alice',
      name: 'key1',
      line: 'ssh-ed25519 AAAA',
    });
    expect(fake.calls[0]?.method).toBe('POST');
    expect(fake.calls[0]?.url).toBe(`${BASE}/xkms/v1/ssh/authorized-keys`);

    fake.respond({ body: { items: [] } });
    await c.ssh.listAuthorizedKeys('user', 'alice');
    expect(fake.calls[1]?.url).toBe(`${BASE}/xkms/v1/ssh/authorized-keys?scope=user&owner=alice`);

    fake.respond({ body: { scope: 'user', owner: 'alice', name: 'key1', line: 'l' } });
    await c.ssh.getAuthorizedKey('user', 'alice', 'key1');
    expect(fake.calls[2]?.url).toBe(`${BASE}/xkms/v1/ssh/authorized-keys/user/alice/key1`);

    fake.respond({ status: 204 });
    await c.ssh.removeAuthorizedKey('user', 'alice', 'key1');
    expect(fake.calls[3]?.method).toBe('DELETE');
    expect(fake.calls[3]?.url).toBe(`${BASE}/xkms/v1/ssh/authorized-keys/user/alice/key1`);

    fake.respond({ body: { scope: 'user', owner: 'alice', name: 'key1', line: 'l' } });
    await c.ssh.verifyAuthorizedKey({ scope: 'user', owner: 'alice', fingerprint: 'SHA256:x' });
    expect(fake.calls[4]?.url).toBe(`${BASE}/xkms/v1/ssh/authorized-keys/verify`);
  });
});

// ---------------------------------------------------------------------------
// Error propagation: every domain client funnels through the same HttpCore
// path (already thoroughly covered in http.test.ts for status mapping,
// correlation IDs, and non-JSON bodies). One representative check per
// verb/response-shape confirms domain clients don't swallow or reshape it.
// ---------------------------------------------------------------------------

describe('domain client error propagation', () => {
  it('surfaces a non-2xx response as XkmsApiError with status and code intact', async () => {
    const fake = newFakeFetch({
      status: 404,
      body: { error: 'rest: key not found', message: 'no such key' },
    });
    const c = make(fake);
    const err = await c.keys.get('missing', 'software').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(XkmsApiError);
    expect((err as XkmsApiError).status).toBe(404);
    expect((err as XkmsApiError).code).toBe('rest: key not found');
  });

  it('surfaces a non-2xx response on a void (204-shaped) DELETE call as XkmsApiError', async () => {
    const fake = newFakeFetch({ status: 403, body: { error: 'forbidden' } });
    const c = make(fake);
    const err = await c.custodian.deleteGroup('g1').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(XkmsApiError);
    expect((err as XkmsApiError).status).toBe(403);
  });
});
