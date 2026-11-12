<script lang="ts">
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import Input from '$lib/components/Input.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import { addNotification } from '$lib/stores/notifications';
  import { isWailsAvailable, callBackendWithError, callBackendVoidWithError } from '$lib/api/backend';
  import type {
    ACMEConnection, ACMEAccountInfo, ACMERenewRequest, ACMEEnrollRequest, ACMEEnrollmentInfo,
  } from '$lib/api/backend';

  // A thin caller of the bound ACMEService: every call gets the connection
  // built from the form. The view handles paths only, never key material.

  const reasons = [
    'unspecified', 'keyCompromise', 'caCompromise', 'affiliationChanged', 'superseded',
    'cessationOfOperation', 'certificateHold', 'removeFromCRL', 'privilegeWithdrawn', 'aACompromise',
  ];

  const backend = isWailsAvailable();

  let directoryUrl = '';
  let accountKeyPath = '';
  let trustedRoots = '';
  let systemRoots = false;

  let contact = '';
  let contactsText = '';
  let account: ACMEAccountInfo | null = null;
  let deactivateOpen = false;

  let revokePath = '';
  let reason = 'unspecified';

  let renewPath = '';
  let domain = '';
  let authzType = 'dns';
  let challenge = '';
  let csrPath = '';
  let renewedPem = '';

  const deviceChallenges = ['enroll-01', 'endorse-01', 'device-attest-01'];
  let deviceChallenge = 'enroll-01';
  let ipAddress = '';
  let port = '';
  let listenHost = '';
  let commonName = '';
  let pcrsText = '';
  let idevidPem = '';
  let iakPem = '';
  let chainPem = '';
  let ekPem = '';

  let busy = false;
  let error = '';

  $: ready = backend && !busy && directoryUrl.trim() !== '' && accountKeyPath.trim() !== '';
  $: hasIP = ipAddress.trim() !== '';
  $: canEnroll = ready && (hasIP || deviceChallenge === 'device-attest-01');
  $: canEndorse = ready && hasIP;

  function connection(): ACMEConnection {
    return {
      directoryUrl: directoryUrl.trim(),
      accountKeyPath: accountKeyPath.trim(),
      trustedRootPaths: trustedRoots.split('\n').map((l) => l.trim()).filter((l) => l !== ''),
      systemRoots,
    };
  }

  async function run(action: () => Promise<string | undefined>, done: string) {
    if (!ready) return;
    busy = true;
    error = '';
    try {
      const err = await action();
      if (err) {
        error = err;
        addNotification('error', err);
      } else {
        addNotification('success', done);
      }
    } finally {
      busy = false;
    }
  }

  function showAccount(info: ACMEAccountInfo | null) {
    if (info) account = info;
  }

  function register() {
    return run(async () => {
      const { result, error: err } = await callBackendWithError<ACMEAccountInfo>(
        'ACMEService', 'RegisterAccount', connection(), contact.trim());
      showAccount(result);
      return err;
    }, 'ACME account registered');
  }

  function updateContacts() {
    const contacts = contactsText.split(',').map((c) => c.trim()).filter((c) => c !== '');
    return run(async () => {
      const { result, error: err } = await callBackendWithError<ACMEAccountInfo>(
        'ACMEService', 'UpdateAccount', connection(), contacts);
      showAccount(result);
      return err;
    }, 'ACME account contacts updated');
  }

  function confirmDeactivate() {
    deactivateOpen = false;
    return run(async () => {
      const { ok, error: err } = await callBackendVoidWithError(
        'ACMEService', 'DeactivateAccount', connection(), true);
      if (ok && account) account = { ...account, status: 'deactivated' };
      return err;
    }, 'ACME account deactivated');
  }

  function revoke() {
    return run(async () => {
      const { error: err } = await callBackendVoidWithError(
        'ACMEService', 'RevokeCertificate', connection(), revokePath.trim(), reason);
      return err;
    }, 'Certificate revoked');
  }

  function renew() {
    renewedPem = '';
    const req: ACMERenewRequest = {
      certPath: renewPath.trim(),
      domain: domain.trim(),
      authzType: authzType.trim(),
      challenge: challenge.trim(),
      csrPath: csrPath.trim(),
    };
    return run(async () => {
      const { result, error: err } = await callBackendWithError<string>(
        'ACMEService', 'RenewCertificate', connection(), req);
      if (!err && result) renewedPem = result;
      return err;
    }, 'Certificate renewed');
  }

  function enrollRequest(): ACMEEnrollRequest {
    return {
      challenge: deviceChallenge,
      ipAddress: ipAddress.trim(),
      port: Number(port.trim()) || 0,
      listenHost: listenHost.trim(),
      commonName: commonName.trim(),
      pcrs: pcrsText.split(',').map((p) => p.trim()).filter((p) => p !== '').map(Number),
      timeoutSeconds: 0,
    };
  }

  function enroll() {
    if (!canEnroll) return;
    idevidPem = '';
    iakPem = '';
    chainPem = '';
    const req = enrollRequest();
    return run(async () => {
      const { result, error: err } = await callBackendWithError<ACMEEnrollmentInfo>(
        'ACMEService', 'EnrollDevice', connection(), req);
      if (!err && result) {
        idevidPem = result.idevidPem;
        iakPem = result.iakPem;
        chainPem = result.chainPem;
      }
      return err;
    }, 'Device enrolled');
  }

  function endorse() {
    if (!canEndorse) return;
    ekPem = '';
    const req = enrollRequest();
    return run(async () => {
      const { result, error: err } = await callBackendWithError<string>(
        'ACMEService', 'EndorseDevice', connection(), req);
      if (!err && result) ekPem = result;
      return err;
    }, 'EK certificate issued');
  }
</script>

<div class="acme-view">
  <GradientHeader title="ACME" subtitle="Accounts, revocation, renewal and device enrollment on an ACME server" />

  {#if !backend}
    <div class="acme-alert" role="alert">No backend connection</div>
  {/if}
  {#if error}
    <div class="acme-alert" role="alert">{error}</div>
  {/if}

  <Card>
    <h3 class="text-title-medium">Connection</h3>
    <Input id="acme-directory" label="Directory URL" bind:value={directoryUrl} placeholder="https://ca.example/acme/directory" />
    <Input id="acme-account-key" label="Account key path" bind:value={accountKeyPath} monospace />
    <label class="field-label" for="acme-roots">Trusted root paths</label>
    <textarea id="acme-roots" class="field" rows="3" bind:value={trustedRoots} placeholder="One path per line"></textarea>
    <label class="checkbox">
      <input type="checkbox" bind:checked={systemRoots} />
      System roots
    </label>
  </Card>

  <Card>
    <h3 class="text-title-medium">Account</h3>
    <Input id="acme-contact" label="Contact email" bind:value={contact} placeholder="mailto:admin@example.com" />
    <Button disabled={!ready} on:click={register}>Register</Button>
    <Input id="acme-contacts" label="Contacts" bind:value={contactsText} helperText="Comma separated" />
    <Button variant="secondary" disabled={!ready} on:click={updateContacts}>Update contacts</Button>
    <Button variant="danger" disabled={!ready} on:click={() => (deactivateOpen = true)}>Deactivate</Button>
    {#if account}
      <dl class="account" data-testid="acme-account">
        <dt>URI</dt><dd>{account.uri}</dd>
        <dt>Status</dt><dd>{account.status}</dd>
        <dt>Contacts</dt><dd>{(account.contacts ?? []).join(', ')}</dd>
      </dl>
    {/if}
  </Card>

  <Card>
    <h3 class="text-title-medium">Revoke</h3>
    <Input id="acme-revoke-cert" label="Certificate to revoke" bind:value={revokePath} monospace />
    <label class="field-label" for="acme-reason">Revocation reason</label>
    <select id="acme-reason" class="field" bind:value={reason}>
      {#each reasons as r}
        <option value={r}>{r}</option>
      {/each}
    </select>
    <Button variant="danger" disabled={!ready} on:click={revoke}>Revoke</Button>
  </Card>

  <Card>
    <h3 class="text-title-medium">Renew</h3>
    <Input id="acme-renew-cert" label="Certificate to renew" bind:value={renewPath} monospace />
    <Input id="acme-domain" label="Domain" bind:value={domain} />
    <Input id="acme-authz" label="Authorization type" bind:value={authzType} />
    <Input id="acme-challenge" label="Challenge" bind:value={challenge} placeholder="dns-01" />
    <Input id="acme-csr" label="CSR path" bind:value={csrPath} helperText="Optional" monospace />
    <Button disabled={!ready} on:click={renew}>Renew</Button>
    {#if renewedPem}
      <label class="field-label" for="acme-renewed">Renewed certificate</label>
      <textarea id="acme-renewed" class="field mono" rows="8" readonly value={renewedPem}></textarea>
    {/if}
  </Card>

  <Card>
    <h3 class="text-title-medium">Device enrollment</h3>
    <p class="note">These operations use this device's TPM.</p>
    <label class="field-label" for="acme-device-challenge">Device challenge</label>
    <select id="acme-device-challenge" class="field" bind:value={deviceChallenge}>
      {#each deviceChallenges as c}
        <option value={c}>{c}</option>
      {/each}
    </select>
    <Input id="acme-ip" label="IP address" bind:value={ipAddress} />
    <Input id="acme-port" label="Port" bind:value={port} placeholder="8080" />
    <Input id="acme-listen-host" label="Listen host" bind:value={listenHost} />
    <Input id="acme-common-name" label="Common name" bind:value={commonName} />
    <Input id="acme-pcrs" label="PCRs" bind:value={pcrsText} helperText="Comma separated, device-attest-01" />
    <Button disabled={!canEnroll} on:click={enroll}>Enroll</Button>
    <Button variant="secondary" disabled={!canEndorse} on:click={endorse}>Request EK certificate</Button>
    {#if idevidPem}
      <label class="field-label" for="acme-idevid">IDevID certificate</label>
      <textarea id="acme-idevid" class="field mono" rows="8" readonly value={idevidPem}></textarea>
    {/if}
    {#if iakPem}
      <label class="field-label" for="acme-iak">IAK certificate</label>
      <textarea id="acme-iak" class="field mono" rows="8" readonly value={iakPem}></textarea>
    {/if}
    {#if chainPem}
      <label class="field-label" for="acme-chain">Chain</label>
      <textarea id="acme-chain" class="field mono" rows="8" readonly value={chainPem}></textarea>
    {/if}
    {#if ekPem}
      <label class="field-label" for="acme-ek">EK certificate</label>
      <textarea id="acme-ek" class="field mono" rows="8" readonly value={ekPem}></textarea>
    {/if}
  </Card>

  <Modal bind:open={deactivateOpen} title="Deactivate account">
    <p>Deactivation is permanent: the server refuses every later request signed with this account key.</p>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (deactivateOpen = false)}>Cancel</Button>
      <Button variant="danger" on:click={confirmDeactivate}>Deactivate account</Button>
    </svelte:fragment>
  </Modal>
</div>

<style>
  .acme-view {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .acme-alert {
    padding: 8px 12px;
    border-radius: 8px;
    background: var(--md-sys-color-error-container, #fdecea);
    color: var(--md-sys-color-on-error-container, #611a15);
  }
  .field-label {
    display: block;
    margin-top: 8px;
  }
  .field {
    width: 100%;
    box-sizing: border-box;
  }
  .note {
    margin: 4px 0 8px;
  }
  .mono {
    font-family: monospace;
  }
  .checkbox {
    display: flex;
    gap: 8px;
    align-items: center;
    margin: 8px 0;
  }
  .account dt {
    font-weight: 600;
  }
</style>
