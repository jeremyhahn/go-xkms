<script lang="ts">
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import Input from '$lib/components/Input.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import { addNotification } from '$lib/stores/notifications';
  import { isWailsAvailable, callBackendWithError, callBackendVoidWithError } from '$lib/api/backend';
  import type { ACMEConnection, ACMEAccountInfo, ACMERenewRequest } from '$lib/api/backend';

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

  let busy = false;
  let error = '';

  $: ready = backend && !busy && directoryUrl.trim() !== '' && accountKeyPath.trim() !== '';

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
</script>

<div class="acme-view">
  <GradientHeader title="ACME" subtitle="Accounts, revocation and renewal on an ACME server" />

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
