/**
 * clients.test.ts — URL / method / query / body assertions plus happy-path
 * decodes for the domain clients composed by XkmsClient.
 */

import { describe, it, expect } from 'vitest';
import { createClient } from './client.js';
import { newFakeFetch } from './testutil.js';

const BASE = 'https://xkms.example.com';

function make(fake: ReturnType<typeof newFakeFetch>) {
  return createClient({ baseURL: BASE, fetch: fake.fetch, token: () => 'tk' });
}

describe('HealthClient', () => {
  it('hits the unauthenticated health and algorithms endpoints', async () => {
    const fake = newFakeFetch({ body: { status: 'ok', version: '1.0' } });
    const c = make(fake);
    const h = await c.health.health();
    expect(h.status).toBe('ok');
    expect(fake.calls[0]?.url).toBe(`${BASE}/health`);
    expect(fake.calls[0]?.headers['Authorization']).toBeUndefined();

    fake.respond({ body: { signing: [], key_encapsulation: [] } });
    await c.health.algorithms();
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/algorithms`);
  });
});

describe('BackendsClient', () => {
  it('lists and gets backends', async () => {
    const fake = newFakeFetch({
      body: { backends: [], pagination: { page: 0, page_size: 0, total: 0, has_more: false } },
    });
    const c = make(fake);
    await c.backends.list({ page: 1, page_size: 10 });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/backends?page=1&page_size=10`);
    expect(fake.calls[0]?.headers['Authorization']).toBe('Bearer tk');

    fake.respond({
      body: { id: 'tpm2', type: 'tpm2', hardware_backed: true, capabilities: {} },
    });
    const b = await c.backends.get('tpm2');
    expect(b.id).toBe('tpm2');
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/backends/tpm2`);
  });
});

describe('KeysClient', () => {
  it('generates, signs (backend in body + query), and rotates', async () => {
    const fake = newFakeFetch({ body: { key_id: 'k1', key_type: 'ecdsa' } });
    const c = make(fake);
    await c.keys.generate({ key_id: 'k1', key_type: 'ecdsa', backend: 'software' });
    expect(fake.calls[0]?.method).toBe('POST');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/keys`);

    fake.respond({ body: { signature: 'c2ln' } });
    const sig = await c.keys.sign('k1', { backend: 'tpm2', data: 'ZGF0YQ==' });
    expect(sig.signature).toBe('c2ln');
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/keys/k1/sign?backend=tpm2`);
    expect(fake.calls[1]?.body).toEqual({ backend: 'tpm2', data: 'ZGF0YQ==' });

    fake.respond({ body: { success: true, key_id: 'k1', key_type: 'ecdsa' } });
    await c.keys.rotate('k1', 'tpm2');
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/keys/k1/rotate?backend=tpm2`);

    fake.respond({ body: { valid: true } });
    const v = await c.keys.verify('k1', {
      backend: 'tpm2',
      data: 'ZA==',
      signature: 'cw==',
    });
    expect(v.valid).toBe(true);
    expect(fake.calls[3]?.url).toBe(`${BASE}/api/v1/keys/k1/verify?backend=tpm2`);
  });

  it('routes the hardware keyops endpoints', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.keys.attest({ backend: 'tpm2', key_id: 'k', nonce: 'bg==' });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/attest`);

    await c.keys.exportMaterial('k1', 'software');
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/keys/k1/export-material?backend=software`);
    expect(fake.calls[1]?.method).toBe('POST');

    await c.keys.wrapById({
      wrapping_key_id: 'w',
      wrapping_key_backend: 'tpm2',
      target_key_id: 't',
      target_key_backend: 'software',
      algorithm: 'AES_GCM_256',
    });
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/keys/wrap-by-id`);
  });
});

describe('CertsClient', () => {
  it('saves with key_id/backend query and probes existence via HEAD', async () => {
    const fake = newFakeFetch({ body: { success: true } });
    const c = make(fake);
    await c.certs.save('k1', 'software', { certificate_pem: 'PEM' });
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/certs?key_id=k1&backend=software`);
    expect(fake.calls[0]?.body).toEqual({ certificate_pem: 'PEM' });

    fake.respond({ status: 200 });
    expect(await c.certs.exists('k1', 'software')).toBe(true);
    expect(fake.calls[1]?.method).toBe('HEAD');

    fake.respond({ status: 404 });
    expect(await c.certs.exists('k2', 'software')).toBe(false);

    fake.respond({ body: { key_id: 'k1', certificate_pem: 'PEM', chain_pem: [] } });
    const tls = await c.certs.tlsBundle('k1', 'software');
    expect(tls.key_id).toBe('k1');
    expect(fake.calls[3]?.url).toBe(`${BASE}/api/v1/tls/k1?backend=software`);
  });
});

describe('SealClient / BarrierClient / PinClient', () => {
  it('routes seal, barrier lifecycle, and pin endpoints', async () => {
    const fake = newFakeFetch({ body: { can_seal: true, backend: 'tpm2' } });
    const c = make(fake);
    const cap = await c.seal.capability('tpm2');
    expect(cap.can_seal).toBe(true);
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/seal/capability?backend=tpm2`);

    fake.respond({
      body: { sealed: false, strategy: 'passphrase', hardware_backed: false, initialized_at: '' },
    });
    await c.barrier.status();
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/barrier/status`);

    fake.respond({ body: { shares: ['s1'], threshold: 2, total_shares: 3 } });
    const init = await c.barrier.shamirInitialize({ secret: 'x' });
    expect(init.total_shares).toBe(3);
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/barrier/shamir/initialize`);

    fake.respond({ body: { required: 2, submitted: 1, complete: false } });
    const prog = await c.barrier.shamirUnsealShare({ share: 's1' });
    expect(prog.complete).toBe(false);

    fake.respond({ body: { status: 'started', scope: 'system' } });
    await c.barrier.enableEncryption({ strategy: 'passphrase', passphrase: 'p' });
    expect(fake.calls[4]?.url).toBe(`${BASE}/api/v1/barrier/enable-encryption`);

    fake.respond({ body: { success: true } });
    await c.pin.verifySO({ pin: '1234' });
    expect(fake.calls[5]?.url).toBe(`${BASE}/api/v1/pin/so/verify`);
    expect(fake.calls[5]?.body).toEqual({ pin: '1234' });

    fake.respond({
      body: { failed_attempts: 0, max_attempts: 5, is_locked: false, recovery_seconds: 0 },
    });
    await c.pin.lockoutStatus();
    expect(fake.calls[6]?.url).toBe(`${BASE}/api/v1/pin/lockout`);
  });
});

describe('CaClient', () => {
  it('routes CA + TCG endpoints and fetches the raw bootstrap PEM', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.ca.bundle('tpm2', 'ECDSA');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/ca/bundle?store_type=tpm2&algorithm=ECDSA`);

    await c.ca.isRevoked('0A:BC');
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/ca/revoked/0A%3ABC`);

    await c.ca.signTCGCSR({ common_name: 'dev', tcg_csr: 'YQ==' });
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/ca/tcg/sign-csr`);

    fake.respond({ text: '-----BEGIN CERTIFICATE-----\nabc' });
    const pem = await c.ca.bootstrapBundle();
    expect(pem).toContain('BEGIN CERTIFICATE');
    expect(fake.calls[3]?.url).toBe(`${BASE}/v1/ca/bootstrap`);
    expect(fake.calls[3]?.headers['Authorization']).toBeUndefined();
  });
});

describe('ClusterClient / CustodianClient / SharesClient', () => {
  it('routes cluster, custodian, and share endpoints', async () => {
    const fake = newFakeFetch({ body: { status: {} } });
    const c = make(fake);
    await c.cluster.status();
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/cluster/status`);

    fake.respond({ body: { members: [] } });
    await c.cluster.members();
    expect(fake.calls[1]?.method).toBe('GET');
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/cluster/members`);

    fake.respond({ body: { group: {} } });
    await c.custodian.createGroup({
      id: 'g1',
      name: 'ops',
      purpose: 'unseal',
      threshold: 2,
      total: 3,
    });
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/custodian/groups/`);

    fake.respond({ status: 204 });
    await c.custodian.removeMember('g1', 'user 1');
    expect(fake.calls[3]?.url).toBe(`${BASE}/api/v1/custodian/groups/g1/members/user%201`);

    fake.respond({ body: { server_url: 'https://s', group_id: 'g1', share_index: 1, received_at: '' } });
    await c.shares.get('https://s:8443', 'g1', 1);
    expect(fake.calls[4]?.url).toBe(`${BASE}/api/v1/shares/https%3A%2F%2Fs%3A8443/g1/1`);

    fake.respond({ body: { group_id: 'g1', collected: 2 } });
    await c.shares.collectionStatus('g1');
    expect(fake.calls[5]?.url).toBe(`${BASE}/api/v1/shares/status/g1`);
  });
});

describe('TenantsClient', () => {
  it('routes tenant lifecycle and barrier endpoints', async () => {
    const fake = newFakeFetch({ body: { tenant: { id: 't1', sealed: true } } });
    const c = make(fake);
    const created = await c.tenants.create({ id: 't1', name: 'Tenant One' });
    expect(created.tenant.id).toBe('t1');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/tenants/`);

    fake.respond({
      body: { tenant_id: 't1', sealed: false, strategy: 'passphrase', hardware_backed: false },
    });
    await c.tenants.barrierInit('t1', { passphrase: 'p', strategy: 'passphrase' });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/tenants/t1/barrier/init`);

    fake.respond({ body: { tenant: {} } });
    await c.tenants.updateQuotas('t1', {
      tenant_id: 't1',
      quotas: {
        max_databases: 1,
        max_raft_groups: 1,
        max_replicas_per_group: 1,
        max_total_replicas: 1,
        max_collections: 1,
        max_keys: 1,
        max_storage_bytes: 1,
        max_database_size_bytes: 1,
        max_users: 1,
        max_roles: 1,
        max_certificates: 1,
        max_backups: 1,
        max_vector_dims: 1,
        max_ts_metrics: 1,
        system_barrier_quota: 1,
        max_dedicated_wal_groups: 1,
      },
    });
    expect(fake.calls[2]?.method).toBe('PUT');
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/tenants/t1/quotas`);
  });
});

describe('PasswordsClient / PlatformClient / TpmPolicyClient', () => {
  it('routes password, platform-store, and TPM policy endpoints', async () => {
    const fake = newFakeFetch({ body: { passwords: [], total: 0 } });
    const c = make(fake);
    await c.passwords.list('work', 'tenant');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/passwords/?folder=work&scope=tenant`);

    fake.respond({ body: { password: 'xyz', length: 3 } });
    await c.passwords.generate({ length: 3 });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/passwords/generate`);

    fake.respond({ body: { name: 'db-pass', message: 'ok' } });
    await c.platform.putSecret('db-pass', { name: 'db-pass', secret: 'c2VjcmV0' });
    expect(fake.calls[2]?.method).toBe('PUT');
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/platform/secrets/db-pass`);

    fake.respond({ body: { policies: [] } });
    await c.tpmPolicies.list();
    expect(fake.calls[3]?.url).toBe(`${BASE}/api/v1/tpm/policies`);

    fake.respond({ body: { name: 'boot', match: true, approved: true } });
    await c.tpmPolicies.verify('boot');
    expect(fake.calls[4]?.method).toBe('POST');
    expect(fake.calls[4]?.url).toBe(`${BASE}/api/v1/tpm/policies/boot/verify`);
    expect(fake.calls[4]?.body).toEqual({ name: 'boot' });
  });
});

describe('InitClient / CredentialsClient / UsersClient / CapabilitiesClient', () => {
  it('routes init ceremony, credentials, users, and capabilities endpoints', async () => {
    const fake = newFakeFetch({ body: { state: 'operational' } });
    const c = make(fake);
    await c.init.status();
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/init/status`);

    fake.respond({ body: { nonce: 'n', username: 'so1', expires_at: '' } });
    await c.init.claimCertBegin({ username: 'so1' });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/init/claim-cert/begin`);

    fake.respond({ body: { strategy: 'prompt', auto_unseal: false } });
    await c.credentials.strategy();
    expect(fake.calls[2]?.url).toBe(`${BASE}/api/v1/credentials/strategy`);

    fake.respond({ body: { username: 'bob', enabled: true, created_at: '' } });
    await c.users.create({ username: 'bob', display_name: 'Bob', role: 'admin', tenant_id: '' });
    expect(fake.calls[3]?.url).toBe(`${BASE}/api/v1/users/`);

    fake.respond({ body: { username: 'bob', status: 'bound' } });
    await c.users.bindCert('bob', { thumbprint: 'abc', not_after_unix: 123 });
    expect(fake.calls[4]?.url).toBe(`${BASE}/api/v1/users/bob/cert-bindings`);

    fake.respond({ body: { webauthn: true, ssh: false } });
    const caps = await c.capabilities.get();
    expect(caps['webauthn']).toBe(true);
    expect(fake.calls[5]?.url).toBe(`${BASE}/api/v1/capabilities`);
  });
});

describe('FrostClient / PivClient', () => {
  it('routes frost and piv endpoints', async () => {
    const fake = newFakeFetch({ body: {} });
    const c = make(fake);
    await c.frost.generateNonces('fk1');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/frost/keys/fk1/nonces`);
    expect(fake.calls[0]?.method).toBe('POST');

    await c.frost.aggregate({
      key_id: 'fk1',
      message: 'deadbeef',
      commitments: [],
      shares: [],
      verify: true,
    });
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/frost/aggregate`);

    await c.piv.getCertificate('9a', 'yubikey', 'pem');
    expect(fake.calls[2]?.url).toBe(
      `${BASE}/api/v1/piv/slots/9a/certificate?backend=yubikey&format=pem`,
    );

    await c.piv.generateKey('9a', { algorithm: 'ecdsap256', subject: 'CN=t' });
    expect(fake.calls[3]?.url).toBe(`${BASE}/api/v1/piv/slots/9a/generate`);
  });
});

describe('SshClient', () => {
  it('routes key, known-host, and authorized-key endpoints', async () => {
    const fake = newFakeFetch({ body: { items: [] } });
    const c = make(fake);
    await c.ssh.listKeys('user', 'alice');
    expect(fake.calls[0]?.url).toBe(`${BASE}/xkms/v1/ssh/keys?scope=user&owner=alice`);

    fake.respond({ body: { scope: 'user', owner: 'alice', name: 'id1' } });
    await c.ssh.getKey('user', 'alice', 'id1');
    expect(fake.calls[1]?.url).toBe(`${BASE}/xkms/v1/ssh/keys/user/alice/id1`);

    fake.respond({ body: { format: 'ssh-ed25519', blob: 'AQ==' } });
    await c.ssh.sign('user', 'alice', 'id1', { digest: 'ZGln' });
    expect(fake.calls[2]?.url).toBe(`${BASE}/xkms/v1/ssh/keys/user/alice/id1/sign`);

    fake.respond({ status: 204 });
    await c.ssh.removeKnownHost('db1.example.com', 'user', 'alice');
    expect(fake.calls[3]?.url).toBe(
      `${BASE}/xkms/v1/ssh/known-hosts/db1.example.com?scope=user&owner=alice`,
    );

    fake.respond({ status: 204 });
    await c.ssh.verifyKnownHost('db1', {
      scope: 'user',
      owner: 'alice',
      fingerprint: 'SHA256:x',
    });
    expect(fake.calls[4]?.url).toBe(`${BASE}/xkms/v1/ssh/known-hosts/db1/verify`);

    fake.respond({ body: { line: 'ssh-ed25519 AAAA' } });
    await c.ssh.emitAuthorizedKey({ public_key: 'ssh-ed25519 AAAA' });
    expect(fake.calls[5]?.url).toBe(`${BASE}/xkms/v1/ssh/authorized-keys/emit`);
  });

});
