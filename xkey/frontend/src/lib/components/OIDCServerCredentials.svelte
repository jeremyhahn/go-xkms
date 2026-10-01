<script lang="ts">
  /**
   * OIDCServerCredentials manages the connected xkmsd's OIDC credentials
   * through OIDCServerService: named logins the server holds on the tenant
   * barrier and refreshes, shared with the tenant or personal. It renders
   * nothing while no server is connected, so the OIDC view then shows only
   * xKey's local providers. Tokens never reach this component: a copy asks
   * the backend to put a current access token on the clipboard.
   */
  import { onDestroy } from 'svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Input from '$lib/components/Input.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import {
    mdiServerNetwork, mdiPlus, mdiRefresh, mdiImport, mdiCellphone, mdiContentCopy, mdiDelete,
  } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { isServerConnected } from '$lib/stores/connection';
  import { callBackend, callBackendWithError, callBackendVoidWithError } from '$lib/api/backend';
  import type {
    OIDCServerCredentialInfo, OIDCServerCredentialRef, OIDCServerScope, OIDCServerTemplateInfo,
    OIDCServerTokens, OIDCServerDeviceLogin,
  } from '$lib/api/backend';

  const SERVICE = 'OIDCServerService';
  /** RFC 8628's default polling interval, for a provider that names none. */
  const DEFAULT_INTERVAL_SECONDS = 5;

  let connected = false;
  let credentials: OIDCServerCredentialInfo[] = [];
  let templates: OIDCServerTemplateInfo[] = [];
  let loading = false;
  let loadError = '';
  let busy = '';

  // Create dialog
  let showCreate = false;
  let createName = '';
  let createScope: OIDCServerScope = 'user';
  let createTemplate = '';
  let createIssuer = '';
  let createClientID = '';
  let createScopes = '';
  let createDeviceEndpoint = '';
  let createError = '';

  // Import dialog: tokens, or a pasted codex auth.json. The secrets are
  // cleared after every submit.
  let showImport = false;
  let importSource: 'tokens' | 'codex' = 'tokens';
  let importName = '';
  let importScope: OIDCServerScope = 'user';
  let importCreate = true;
  let importTemplate = 'anthropic';
  let importAccessToken = '';
  let importRefreshToken = '';
  let importExpiresAt = '';
  let importCodexJSON = '';
  let importError = '';

  // Device login dialog
  let deviceRef: OIDCServerCredentialRef | null = null;
  let deviceLogin: OIDCServerDeviceLogin | null = null;
  let deviceStatus = '';
  let deviceError = '';
  let showDevice = false;
  let pollTimer: ReturnType<typeof setTimeout> | null = null;

  // Delete dialog
  let deleteTarget: OIDCServerCredentialInfo | null = null;
  let showDelete = false;

  $: selectedTemplate = templates.find((t) => t.name === createTemplate);
  $: createNeedsIssuer = createTemplate === '' || (selectedTemplate?.requires_issuer ?? false);
  $: importTemplates = templates.filter((t) => t.supports_import);
  // Closing the device dialog stops polling.
  $: if (!showDevice) stopPolling();
  // Follow the connection: check on creation and whenever the connection
  // store changes.
  $: $isServerConnected, refresh();

  onDestroy(stopPolling);

  function refOf(c: OIDCServerCredentialInfo): OIDCServerCredentialRef {
    return { tenant_id: c.tenant_id ?? '', scope: c.scope, owner: c.owner ?? '', name: c.name };
  }

  function keyOf(c: OIDCServerCredentialRef): string {
    return `${c.scope}/${c.owner ?? ''}/${c.name}`;
  }

  /** refresh re-checks the connection and reloads the list while connected. */
  async function refresh(): Promise<void> {
    connected = (await callBackend<boolean>(SERVICE, 'Connected')) ?? false;
    if (!connected) {
      credentials = [];
      stopPolling();
      return;
    }
    if (templates.length === 0) {
      templates = (await callBackend<OIDCServerTemplateInfo[]>(SERVICE, 'ServerTemplates')) ?? [];
    }
    await load();
  }

  async function load(): Promise<void> {
    // The spinner shows only on the first load; a reload keeps the table.
    loading = credentials.length === 0;
    const { result, error } = await callBackendWithError<OIDCServerCredentialInfo[]>(SERVICE, 'ListServerCredentials', '');
    loadError = error ?? '';
    credentials = result ?? [];
    loading = false;
  }

  function badge(status: string): { status: 'success' | 'warning' | 'error' | 'neutral'; text: string } {
    switch (status) {
      case 'active':
        return { status: 'success', text: 'Active' };
      case 'relogin_required':
        return { status: 'warning', text: 'Re-login required' };
      case 'expired':
        return { status: 'error', text: 'Expired' };
      default:
        return { status: 'neutral', text: 'Pending' };
    }
  }

  function needsAttention(c: OIDCServerCredentialInfo): boolean {
    return c.status === 'relogin_required' || c.status === 'expired';
  }

  function scopeLabel(c: OIDCServerCredentialInfo): string {
    return c.scope === 'tenant' ? 'Shared' : `Personal${c.owner ? ` (${c.owner})` : ''}`;
  }

  // --- Create ---

  function openCreate(): void {
    createName = '';
    createScope = 'user';
    createTemplate = templates.find((t) => t.name === 'openai') ? 'openai' : '';
    createIssuer = '';
    createClientID = '';
    createScopes = '';
    createDeviceEndpoint = '';
    createError = '';
    showCreate = true;
  }

  async function submitCreate(): Promise<void> {
    if (!createName.trim()) {
      createError = 'A credential name is required.';
      return;
    }
    if (createNeedsIssuer && !createIssuer.trim()) {
      createError = 'This provider needs an issuer URL.';
      return;
    }
    const scopes = createScopes.split(',').map((s) => s.trim()).filter((s) => s !== '');
    const config = {
      template: createTemplate,
      issuer: createIssuer.trim(),
      client_id: createClientID.trim(),
      scopes,
      device_authorization_endpoint: createDeviceEndpoint.trim(),
    };
    busy = 'create';
    const { result, error } = await callBackendWithError<OIDCServerCredentialInfo>(
      SERVICE, 'CreateServerCredential', { scope: createScope, name: createName.trim() }, config,
    );
    busy = '';
    if (error || !result) {
      createError = error ?? 'Failed to create the credential.';
      return;
    }
    showCreate = false;
    addNotification('success', `Server credential "${result.name}" created; log in or import tokens to activate it`);
    await load();
  }

  // --- Import ---

  function openImport(target: OIDCServerCredentialInfo | null): void {
    importSource = target?.template === 'openai' ? 'codex' : 'tokens';
    importName = target?.name ?? '';
    importScope = target?.scope ?? 'user';
    importCreate = target === null;
    importTemplate = target?.template ?? (importTemplates[0]?.name ?? '');
    clearImportSecrets();
    importError = '';
    showImport = true;
  }

  function clearImportSecrets(): void {
    importAccessToken = '';
    importRefreshToken = '';
    importExpiresAt = '';
    importCodexJSON = '';
  }

  async function submitImport(): Promise<void> {
    if (!importName.trim()) {
      importError = 'A credential name is required.';
      return;
    }
    const ref = { scope: importScope, name: importName.trim() };
    let call: Promise<{ result: OIDCServerCredentialInfo | null; error?: string }>;
    if (importSource === 'codex') {
      if (!importCodexJSON.trim()) {
        importError = 'Paste the content of a codex auth.json.';
        return;
      }
      call = callBackendWithError<OIDCServerCredentialInfo>(SERVICE, 'ImportCodexAuth', ref, importCodexJSON, importCreate);
    } else {
      if (!importAccessToken.trim()) {
        importError = 'An access token is required.';
        return;
      }
      const tokens: OIDCServerTokens = {
        access_token: importAccessToken,
        refresh_token: importRefreshToken,
        expires_at: importExpiresAt.trim(),
      };
      call = callBackendWithError<OIDCServerCredentialInfo>(
        SERVICE, 'ImportServerTokens', ref, tokens, importCreate ? importTemplate : '', importCreate,
      );
    }
    clearImportSecrets();
    busy = 'import';
    const { result, error } = await call;
    busy = '';
    if (error || !result) {
      importError = error ?? 'Failed to import the login.';
      return;
    }
    showImport = false;
    addNotification('success', `Login imported into server credential "${result.name}"`);
    await load();
  }

  // --- Device login ---

  async function startDeviceLogin(c: OIDCServerCredentialInfo): Promise<void> {
    stopPolling();
    const ref = refOf(c);
    busy = `device:${keyOf(ref)}`;
    const { result, error } = await callBackendWithError<OIDCServerCredentialInfo>(SERVICE, 'StartServerDeviceLogin', ref);
    busy = '';
    if (error || !result?.device_login) {
      addNotification('error', error ?? 'The server started no device login');
      return;
    }
    deviceRef = ref;
    deviceLogin = result.device_login;
    deviceStatus = result.status;
    deviceError = '';
    showDevice = true;
    schedulePoll(deviceLogin.interval_seconds);
  }

  function schedulePoll(intervalSeconds: number): void {
    const seconds = intervalSeconds > 0 ? intervalSeconds : DEFAULT_INTERVAL_SECONDS;
    pollTimer = setTimeout(pollDeviceLogin, seconds * 1000);
  }

  function stopPolling(): void {
    if (pollTimer !== null) {
      clearTimeout(pollTimer);
      pollTimer = null;
    }
  }

  async function pollDeviceLogin(): Promise<void> {
    pollTimer = null;
    if (!deviceRef || !showDevice) {
      return;
    }
    if (deviceLogin && Date.parse(deviceLogin.expires_at) <= Date.now()) {
      deviceError = 'The device login was not approved in time.';
      deviceStatus = 'expired';
      return;
    }
    const { result, error } = await callBackendWithError<OIDCServerCredentialInfo>(SERVICE, 'PollServerDeviceLogin', deviceRef);
    if (!showDevice) {
      return;
    }
    if (error || !result) {
      deviceError = error ?? 'Polling the device login failed.';
      return;
    }
    deviceStatus = result.status;
    if (result.status === 'active' && !result.device_login) {
      showDevice = false;
      addNotification('success', `Server credential "${result.name}" logged in`);
      await load();
      return;
    }
    if (result.status === 'expired') {
      deviceError = 'The device login was not approved in time.';
      return;
    }
    if (result.device_login) {
      deviceLogin = result.device_login;
    }
    schedulePoll(deviceLogin?.interval_seconds ?? DEFAULT_INTERVAL_SECONDS);
  }

  // --- Row actions ---

  async function refreshCredential(c: OIDCServerCredentialInfo): Promise<void> {
    busy = `refresh:${keyOf(c)}`;
    const { result, error } = await callBackendWithError<OIDCServerCredentialInfo>(SERVICE, 'RefreshServerCredential', refOf(c));
    busy = '';
    if (error || !result) {
      addNotification('error', error ?? `Failed to refresh "${c.name}"`);
      return;
    }
    addNotification('success', `Server credential "${c.name}" refreshed`);
    await load();
  }

  async function copyToken(c: OIDCServerCredentialInfo): Promise<void> {
    busy = `copy:${keyOf(c)}`;
    const { ok, error } = await callBackendVoidWithError(SERVICE, 'CopyServerAccessToken', refOf(c));
    busy = '';
    if (!ok) {
      addNotification('error', error ?? `Failed to copy the access token of "${c.name}"`);
      return;
    }
    addNotification('success', `Access token of "${c.name}" copied; the clipboard clears itself`);
  }

  function openDelete(c: OIDCServerCredentialInfo): void {
    deleteTarget = c;
    showDelete = true;
  }

  async function submitDelete(): Promise<void> {
    if (!deleteTarget) return;
    const target = deleteTarget;
    busy = 'delete';
    const { ok, error } = await callBackendVoidWithError(SERVICE, 'DeleteServerCredential', refOf(target));
    busy = '';
    if (!ok) {
      addNotification('error', error ?? `Failed to delete "${target.name}"`);
      return;
    }
    showDelete = false;
    deleteTarget = null;
    addNotification('success', `Server credential "${target.name}" deleted`);
    await load();
  }
</script>

{#if connected}
<div class="server-section">
  <Card variant="elevated">
    <div class="section" data-testid="oidc-server-credentials">
      <div class="section-heading-row">
        <h2 class="text-title-medium section-heading">
          <Icon path={mdiServerNetwork} size={20} />
          Server credentials
        </h2>
        <div class="heading-actions">
          <Button variant="text" icon={mdiRefresh} on:click={load}>Reload</Button>
          <Button variant="outline" icon={mdiImport} on:click={() => openImport(null)}>Import login</Button>
          <Button variant="primary" icon={mdiPlus} on:click={openCreate}>Add server credential</Button>
        </div>
      </div>

      <p class="text-body-small description">
        Logins held and refreshed by the connected server. Shared credentials serve the whole tenant;
        personal ones only you. Local providers below stay on this device.
      </p>

      {#if loading}
        <div class="loading-row"><LoadingSpinner size={28} /></div>
      {:else if loadError}
        <p class="text-body-medium error-text" role="alert">{loadError}</p>
      {:else if credentials.length === 0}
        <p class="text-body-medium description">No server credentials yet.</p>
      {:else}
        <table class="cred-table" aria-label="Server OIDC credentials">
          <thead>
            <tr>
              <th class="text-label-small" scope="col">Name</th>
              <th class="text-label-small" scope="col">Scope</th>
              <th class="text-label-small" scope="col">Provider</th>
              <th class="text-label-small" scope="col">Status</th>
              <th class="text-label-small" scope="col">Expires</th>
              <th class="text-label-small" scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each credentials as c (keyOf(c))}
              <tr data-testid="server-cred-{c.name}" class:attention={needsAttention(c)}>
                <td class="text-body-medium">{c.name}</td>
                <td class="text-body-small">{scopeLabel(c)}</td>
                <td class="text-body-small">{c.template || c.issuer || ''}</td>
                <td class="text-body-small">
                  <StatusBadge status={badge(c.status).status} text={badge(c.status).text} />
                  {#if c.status_reason}<div class="reason">{c.status_reason}</div>{/if}
                  {#if c.last_error}<div class="reason error-text">{c.last_error}</div>{/if}
                </td>
                <td class="text-body-small">{c.expires_at ?? ''}</td>
                <td>
                  <div class="row-actions">
                    {#if c.supports_device}
                      <Button variant="text" size="sm" icon={mdiCellphone}
                        loading={busy === `device:${keyOf(c)}`} on:click={() => startDeviceLogin(c)}>Device login</Button>
                    {/if}
                    <Button variant="text" size="sm" icon={mdiImport} on:click={() => openImport(c)}>Import</Button>
                    {#if c.refreshable}
                      <Button variant="text" size="sm" icon={mdiRefresh}
                        loading={busy === `refresh:${keyOf(c)}`} on:click={() => refreshCredential(c)}>Refresh</Button>
                    {/if}
                    {#if c.status === 'active'}
                      <Button variant="text" size="sm" icon={mdiContentCopy}
                        loading={busy === `copy:${keyOf(c)}`} on:click={() => copyToken(c)}>Copy token</Button>
                    {/if}
                    <Button variant="text" size="sm" icon={mdiDelete} on:click={() => openDelete(c)}>Delete</Button>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>
  </Card>
</div>
{/if}

<Modal bind:open={showCreate} title="Add server credential" maxWidth="560px">
  <div class="form">
    <Input id="server-cred-name" label="Name" bind:value={createName} placeholder="codex" />
    <div class="form-field">
      <label class="text-label-medium" for="server-cred-scope">Scope</label>
      <select id="server-cred-scope" class="form-select" bind:value={createScope}>
        <option value="user">Personal (only you)</option>
        <option value="tenant">Shared with the tenant</option>
      </select>
    </div>
    <div class="form-field">
      <label class="text-label-medium" for="server-cred-template">Provider</label>
      <select id="server-cred-template" class="form-select" bind:value={createTemplate}>
        {#each templates as t (t.name)}
          <option value={t.name}>{t.name} - {t.description}</option>
        {/each}
        <option value="">Custom provider</option>
      </select>
    </div>
    {#if createNeedsIssuer}
      <Input id="server-cred-issuer" label="Issuer URL" bind:value={createIssuer} placeholder="https://idp.example.com" />
    {/if}
    {#if createTemplate === ''}
      <Input id="server-cred-client-id" label="Client ID" bind:value={createClientID} />
      <Input id="server-cred-scopes" label="Scopes (comma-separated)" bind:value={createScopes} placeholder="openid, offline_access" />
      <Input id="server-cred-device-endpoint" label="Device authorization endpoint" bind:value={createDeviceEndpoint} />
    {/if}
    {#if createError}<p class="text-body-small error-text" role="alert">{createError}</p>{/if}
  </div>
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (showCreate = false)}>Cancel</Button>
    <Button variant="primary" loading={busy === 'create'} on:click={submitCreate}>Create</Button>
  </svelte:fragment>
</Modal>

<Modal bind:open={showImport} title="Import a login" maxWidth="560px">
  <div class="form">
    <div class="mode-tabs" role="tablist">
      <button class="mode-tab" class:active={importSource === 'tokens'} role="tab"
        aria-selected={importSource === 'tokens'} on:click={() => (importSource = 'tokens')}>Tokens</button>
      <button class="mode-tab" class:active={importSource === 'codex'} role="tab"
        aria-selected={importSource === 'codex'} on:click={() => (importSource = 'codex')}>codex auth.json</button>
    </div>
    <Input id="server-import-name" label="Name" bind:value={importName} placeholder="codex" />
    <div class="form-field">
      <label class="text-label-medium" for="server-import-scope">Scope</label>
      <select id="server-import-scope" class="form-select" bind:value={importScope}>
        <option value="user">Personal (only you)</option>
        <option value="tenant">Shared with the tenant</option>
      </select>
    </div>
    <label class="checkbox text-body-medium">
      <input type="checkbox" bind:checked={importCreate} />
      Create the credential
    </label>
    {#if importSource === 'codex'}
      <div class="form-field">
        <label class="text-label-medium" for="server-import-codex">codex auth.json</label>
        <textarea id="server-import-codex" class="form-textarea" rows="6" bind:value={importCodexJSON}
          placeholder="Paste the content of ~/.codex/auth.json" spellcheck="false" autocomplete="off"></textarea>
        <span class="text-body-small description">Imported as an openai credential; the server refreshes it from now on.</span>
      </div>
    {:else}
      {#if importCreate}
        <div class="form-field">
          <label class="text-label-medium" for="server-import-template">Provider</label>
          <select id="server-import-template" class="form-select" bind:value={importTemplate}>
            {#each importTemplates as t (t.name)}
              <option value={t.name}>{t.name} - {t.description}</option>
            {/each}
          </select>
        </div>
      {/if}
      <Input id="server-import-access" type="password" label="Access token" bind:value={importAccessToken} />
      <Input id="server-import-refresh" type="password" label="Refresh token (optional)" bind:value={importRefreshToken} />
      <Input id="server-import-expires" label="Expires at (RFC 3339, optional)" bind:value={importExpiresAt}
        placeholder="2027-01-01T00:00:00Z" />
    {/if}
    {#if importError}<p class="text-body-small error-text" role="alert">{importError}</p>{/if}
  </div>
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => { clearImportSecrets(); showImport = false; }}>Cancel</Button>
    <Button variant="primary" loading={busy === 'import'} on:click={submitImport}>Import</Button>
  </svelte:fragment>
</Modal>

<Modal bind:open={showDevice} title="Device login{deviceRef ? ` - ${deviceRef.name}` : ''}" maxWidth="480px">
  {#if deviceLogin}
    <div class="form" data-testid="device-login">
      <p class="text-body-medium">Open the verification page on any device and enter the code:</p>
      <a class="text-body-medium verify-link" href={deviceLogin.verification_uri_complete || deviceLogin.verification_uri}
        target="_blank" rel="noopener noreferrer">{deviceLogin.verification_uri_complete || deviceLogin.verification_uri}</a>
      <p class="user-code font-mono" data-testid="device-user-code">{deviceLogin.user_code}</p>
      {#if deviceError}
        <p class="text-body-small error-text" role="alert">{deviceError}</p>
      {:else}
        <p class="text-body-small description" data-testid="device-status">
          Waiting for approval ({deviceStatus || 'pending'})...
        </p>
      {/if}
    </div>
  {/if}
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (showDevice = false)}>Close</Button>
  </svelte:fragment>
</Modal>

<Modal bind:open={showDelete} title="Delete server credential?" maxWidth="440px">
  <p class="text-body-medium">
    Delete "{deleteTarget?.name ?? ''}" from the server? Every workload using it loses access.
  </p>
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (showDelete = false)}>Cancel</Button>
    <Button variant="danger" loading={busy === 'delete'} on:click={submitDelete}>Delete</Button>
  </svelte:fragment>
</Modal>

<style>
  .server-section {
    padding: 16px 24px 0;
  }

  .section {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .section-heading-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
  }

  .section-heading {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0;
  }

  .heading-actions,
  .row-actions {
    display: flex;
    align-items: center;
    gap: 4px;
    flex-wrap: wrap;
  }

  .description,
  .reason {
    color: var(--color-on-surface-variant);
  }

  .loading-row {
    display: flex;
    justify-content: center;
    padding: 24px;
  }

  .error-text {
    color: var(--color-error);
  }

  .cred-table {
    width: 100%;
    border-collapse: collapse;
  }

  .cred-table th,
  .cred-table td {
    text-align: left;
    padding: 8px;
    border-bottom: 1px solid var(--color-outline-variant);
    vertical-align: top;
  }

  tr.attention td:first-child {
    border-left: 3px solid var(--color-error);
  }

  .form {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .form-select,
  .form-textarea {
    padding: 8px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--color-outline);
    background-color: var(--color-surface);
    color: var(--color-on-surface);
  }

  .form-textarea {
    font-family: var(--font-mono, monospace);
    resize: vertical;
  }

  .checkbox {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .mode-tabs {
    display: flex;
    gap: 4px;
  }

  .mode-tab {
    padding: 6px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: none;
    color: var(--color-on-surface);
    cursor: pointer;
  }

  .mode-tab.active {
    background-color: var(--color-secondary-container);
    color: var(--color-on-secondary-container);
  }

  .verify-link {
    color: var(--color-primary);
    word-break: break-all;
  }

  .user-code {
    font-size: 1.75rem;
    letter-spacing: 0.15em;
    text-align: center;
    margin: 8px 0;
  }
</style>
