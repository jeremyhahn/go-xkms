<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import ViewToolbar from '$lib/components/ViewToolbar.svelte';
  import SearchBar from '$lib/components/SearchBar.svelte';
  import Button from '$lib/components/Button.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import Tabs from '$lib/components/Tabs.svelte';
  import Card from '$lib/components/Card.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import JSONViewer from '$lib/components/JSONViewer.svelte';
  import OIDCProviderCard from '$lib/components/OIDCProviderCard.svelte';
  import OIDCProviderDialog from '$lib/components/OIDCProviderDialog.svelte';
  import OIDCScriptDialog from '$lib/components/OIDCScriptDialog.svelte';
  import {
    mdiPlus, mdiOpenInApp, mdiRefresh, mdiContentCopy, mdiPlay, mdiCodeBraces
  } from '$lib/utils/icons';
  import { callBackend, callBackendVoid, callBackendWithError } from '$lib/api/backend';
  import type {
    OIDCProviderEntry, OIDCTokenInfo, OIDCLoginResult,
    OIDCRefreshStatus, OIDCExecResult, OIDCProviderTemplateInfo
  } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';
  import {
    oidcState, oidcProviders, setProviders, addProvider, updateProvider, removeProvider,
    setOIDCLoading, setOIDCSearch, setToken, removeToken, setAllTokens,
    setRefreshStatus, setAllRefreshStatus, startStatusPolling, stopStatusPolling
  } from '$lib/stores/oidc';

  const tabs = [
    { id: 'providers', label: 'Providers' },
    { id: 'tokens', label: 'Tokens' },
    { id: 'scripts', label: 'Scripts' },
  ];

  let activeTab = 'providers';
  let showProviderDialog = false;
  let providerDialogMode: 'add' | 'edit' = 'add';
  let editProvider: OIDCProviderEntry | null = null;
  let savingProvider = false;
  let showDeleteConfirm = false;
  let deleteTargetName = '';
  let deleting = false;
  let loginLoadingMap: Record<string, boolean> = {};
  let refreshLoadingMap: Record<string, boolean> = {};
  let showScriptDialog = false;
  let providerTemplates: OIDCProviderTemplateInfo[] = [];
  let showTokenViewer = false;
  let tokenViewerJSON = '';
  let tokenViewerProvider = '';
  let showExecDialog = false;
  let execProvider: OIDCProviderEntry | null = null;
  let execRunning = false;
  let execResult: OIDCExecResult | null = null;

  $: state = $oidcState;
  $: providers = $oidcProviders;
  $: tokenList = Object.values(state.tokens);

  onMount(async () => {
    await loadTemplates();
    await loadProviders();
    await loadAllTokens();
    startStatusPolling(pollRefreshStatuses);
  });

  onDestroy(() => {
    stopStatusPolling();
  });

  async function loadTemplates(): Promise<void> {
    const result = await callBackend<OIDCProviderTemplateInfo[]>('OIDCService', 'GetTemplates');
    if (result) {
      providerTemplates = result;
    }
  }

  async function loadProviders(): Promise<void> {
    setOIDCLoading(true);
    const result = await callBackend<OIDCProviderEntry[]>('OIDCService', 'GetProviders');
    if (result) {
      setProviders(result);
    }
    setOIDCLoading(false);
  }

  async function loadAllTokens(): Promise<void> {
    const tokens = await callBackend<OIDCTokenInfo[]>('OIDCService', 'GetAllTokens');
    if (tokens) {
      setAllTokens(tokens);
    }
  }

  async function pollRefreshStatuses(): Promise<void> {
    const statuses = await callBackend<OIDCRefreshStatus[]>('OIDCService', 'GetAllRefreshStatus');
    if (statuses) {
      setAllRefreshStatus(statuses);
    }
  }

  async function handleAddProvider(entry: OIDCProviderEntry): Promise<void> {
    savingProvider = true;
    if (providerDialogMode === 'add') {
      const ok = await callBackendVoid('OIDCService', 'AddProvider', entry);
      if (ok) {
        addProvider(entry);
        addNotification('success', `Provider "${entry.name}" added`);
        showProviderDialog = false;
      } else {
        addNotification('error', 'Failed to add provider');
      }
    } else {
      const ok = await callBackendVoid('OIDCService', 'UpdateProvider', entry.name, entry);
      if (ok) {
        updateProvider(entry.name, entry);
        addNotification('success', `Provider "${entry.name}" updated`);
        showProviderDialog = false;
      } else {
        addNotification('error', 'Failed to update provider');
      }
    }
    savingProvider = false;
  }

  async function handleDiscover(issuer: string): Promise<void> {
    if (!issuer.trim()) return;
    const result = await callBackend<unknown>('OIDCService', 'DiscoverProvider', issuer.trim());
    if (result) {
      addNotification('success', 'Provider discovered successfully');
    } else {
      addNotification('error', 'Failed to discover provider at this issuer URL');
    }
  }

  function openEditDialog(p: OIDCProviderEntry): void {
    editProvider = p;
    providerDialogMode = 'edit';
    showProviderDialog = true;
  }

  function openDeleteConfirm(name: string): void {
    deleteTargetName = name;
    showDeleteConfirm = true;
  }

  async function handleDelete(): Promise<void> {
    deleting = true;
    const ok = await callBackendVoid('OIDCService', 'DeleteProvider', deleteTargetName);
    deleting = false;
    if (ok) {
      removeProvider(deleteTargetName);
      addNotification('success', `Provider "${deleteTargetName}" deleted`);
      showDeleteConfirm = false;
    } else {
      addNotification('error', 'Failed to delete provider');
    }
  }

  async function handleLogin(name: string): Promise<void> {
    loginLoadingMap = { ...loginLoadingMap, [name]: true };
    const { result, error } = await callBackendWithError<OIDCLoginResult>('OIDCService', 'Login', name);
    loginLoadingMap = { ...loginLoadingMap, [name]: false };
    if (result?.success && result.token) {
      setToken(name, result.token);
      addNotification('success', `Logged in to "${name}"`);
    } else {
      addNotification('error', result?.error ?? error ?? `Login failed for "${name}"`);
    }
  }

  async function handleLogout(name: string): Promise<void> {
    const ok = await callBackendVoid('OIDCService', 'Logout', name);
    if (ok) {
      removeToken(name);
      addNotification('info', `Logged out of "${name}"`);
    } else {
      addNotification('error', 'Logout failed');
    }
  }

  async function handleRefresh(name: string): Promise<void> {
    refreshLoadingMap = { ...refreshLoadingMap, [name]: true };
    const { result: token, error } = await callBackendWithError<OIDCTokenInfo>('OIDCService', 'RefreshToken', name);
    refreshLoadingMap = { ...refreshLoadingMap, [name]: false };
    if (token) {
      setToken(name, token);
      addNotification('success', `Token refreshed for "${name}"`);
    } else {
      addNotification('error', error ?? 'Token refresh failed');
    }
  }

  async function handleStartAutoRefresh(name: string): Promise<void> {
    const ok = await callBackendVoid('OIDCService', 'StartAutoRefresh', name);
    if (ok) {
      addNotification('success', `Auto-refresh started for "${name}"`);
      pollRefreshStatuses();
    } else {
      addNotification('error', 'Failed to start auto-refresh');
    }
  }

  async function handleStopAutoRefresh(name: string): Promise<void> {
    const ok = await callBackendVoid('OIDCService', 'StopAutoRefresh', name);
    if (ok) {
      addNotification('info', `Auto-refresh stopped for "${name}"`);
      pollRefreshStatuses();
    } else {
      addNotification('error', 'Failed to stop auto-refresh');
    }
  }

  async function handleExecuteScript(providerName: string, script: string): Promise<OIDCExecResult | null> {
    return await callBackend<OIDCExecResult>('OIDCService', 'ExecuteScript', providerName, script);
  }

  async function handleViewToken(name: string): Promise<void> {
    const raw = await callBackend<string>('OIDCService', 'GetRawTokenResponse', name);
    if (raw) {
      tokenViewerJSON = raw;
      tokenViewerProvider = name;
      showTokenViewer = true;
    } else {
      addNotification('error', 'Failed to retrieve token response');
    }
  }

  function handleRunExec(provider: OIDCProviderEntry): void {
    execProvider = provider;
    execResult = null;
    showExecDialog = true;
  }

  async function handleExecConfirm(): Promise<void> {
    if (!execProvider?.exec) return;
    execRunning = true;
    execResult = null;
    const result = await callBackend<OIDCExecResult>('OIDCService', 'ExecuteScript', execProvider.name, execProvider.exec);
    execResult = result;
    execRunning = false;
  }

  function formatExpiry(expiresIn: number): string {
    if (expiresIn <= 0) return 'Expired';
    if (expiresIn < 60) return `${expiresIn}s`;
    if (expiresIn < 3600) return `${Math.floor(expiresIn / 60)}m`;
    return `${Math.floor(expiresIn / 3600)}h ${Math.floor((expiresIn % 3600) / 60)}m`;
  }
</script>

<div class="oidc-view">
  <GradientHeader title="OIDC" subtitle="OpenID Connect identity providers and tokens" />

  <div class="oidc-content">
    <ViewToolbar>
      <Tabs {tabs} {activeTab} onChange={(id) => (activeTab = id)} />
      {#if activeTab === 'providers'}
        <SearchBar placeholder="Search providers..." value={state.searchQuery} onChange={setOIDCSearch} />
      {/if}
      <div class="toolbar-spacer" />
      <Button variant="outline" size="sm" icon={mdiPlay} on:click={() => (showScriptDialog = true)}>
        Run Script
      </Button>
      <Button variant="primary" size="sm" icon={mdiPlus} on:click={() => { providerDialogMode = 'add'; editProvider = null; showProviderDialog = true; }}>
        Add Provider
      </Button>
    </ViewToolbar>

    {#if state.loading}
      <div class="loading-container">
        <LoadingSpinner size={40} />
      </div>
    {:else if activeTab === 'providers'}
      {#if providers.length === 0}
        <EmptyState
          icon={mdiOpenInApp}
          title="No OIDC Providers"
          description={state.searchQuery ? 'No providers match your search.' : 'Add an OIDC provider to get started with identity authentication.'}
          actionLabel={state.searchQuery ? '' : 'Add Provider'}
          onAction={state.searchQuery ? null : () => { providerDialogMode = 'add'; editProvider = null; showProviderDialog = true; }}
        />
      {:else}
        <div class="provider-grid">
          {#each providers as p (p.name)}
            <OIDCProviderCard
              provider={p}
              token={state.tokens[p.name]}
              refreshStatus={state.refreshStatus[p.name]}
              loginLoading={loginLoadingMap[p.name] ?? false}
              refreshLoading={refreshLoadingMap[p.name] ?? false}
              onLogin={handleLogin}
              onLogout={handleLogout}
              onRefresh={handleRefresh}
              onEdit={openEditDialog}
              onDelete={openDeleteConfirm}
              onStartAutoRefresh={handleStartAutoRefresh}
              onStopAutoRefresh={handleStopAutoRefresh}
              onViewToken={handleViewToken}
              onRunExec={handleRunExec}
            />
          {/each}
        </div>
      {/if}

    {:else if activeTab === 'tokens'}
      {#if tokenList.length === 0}
        <EmptyState
          icon={mdiOpenInApp}
          title="No Active Tokens"
          description="Log in to a provider to see token information here."
        />
      {:else}
        <div class="tokens-list">
          {#each tokenList as token (token.provider)}
            <Card variant="outlined">
              <div class="token-card">
                <div class="token-header">
                  <h3 class="text-title-medium token-provider">{token.provider}</h3>
                  <StatusBadge status={token.is_expired ? 'warning' : 'connected'} />
                </div>
                <div class="token-details">
                  {#if token.subject}
                    <div class="token-field">
                      <span class="text-label-small field-label">Subject</span>
                      <span class="text-body-small">{token.subject}</span>
                    </div>
                  {/if}
                  {#if token.email}
                    <div class="token-field">
                      <span class="text-label-small field-label">Email</span>
                      <span class="text-body-small">{token.email}</span>
                    </div>
                  {/if}
                  {#if token.name}
                    <div class="token-field">
                      <span class="text-label-small field-label">Name</span>
                      <span class="text-body-small">{token.name}</span>
                    </div>
                  {/if}
                  <div class="token-field">
                    <span class="text-label-small field-label">Issuer</span>
                    <span class="text-body-small">{token.issuer}</span>
                  </div>
                  <div class="token-field">
                    <span class="text-label-small field-label">Expires In</span>
                    <span class="text-body-small" class:expired-text={token.is_expired}>
                      {formatExpiry(token.expires_in)}
                    </span>
                  </div>
                  <div class="token-field">
                    <span class="text-label-small field-label">Expires At</span>
                    <span class="text-body-small">{token.expires_at}</span>
                  </div>
                  {#if token.scopes.length > 0}
                    <div class="token-field">
                      <span class="text-label-small field-label">Scopes</span>
                      <div class="scope-tags">
                        {#each token.scopes as scope}
                          <span class="scope-tag text-label-small">{scope}</span>
                        {/each}
                      </div>
                    </div>
                  {/if}
                  <div class="token-field">
                    <span class="text-label-small field-label">Has Refresh Token</span>
                    <span class="text-body-small">{token.has_refresh ? 'Yes' : 'No'}</span>
                  </div>
                </div>
                <div class="token-actions">
                  <Button variant="outline" size="sm" icon={mdiRefresh} loading={refreshLoadingMap[token.provider] ?? false} on:click={() => handleRefresh(token.provider)}>
                    Refresh
                  </Button>
                  <Button variant="outline" size="sm" icon={mdiCodeBraces} on:click={() => handleViewToken(token.provider)}>
                    View JSON
                  </Button>
                  <Button variant="outline" size="sm" on:click={() => handleLogout(token.provider)}>
                    Logout
                  </Button>
                </div>
              </div>
            </Card>
          {/each}
        </div>
      {/if}

    {:else if activeTab === 'scripts'}
      <div class="scripts-tab">
        <Card variant="elevated">
          <div class="scripts-info">
            <Icon path={mdiPlay} size={24} />
            <div>
              <h3 class="text-title-small">Script Execution</h3>
              <p class="text-body-medium">
                Execute scripts with OIDC token environment variables injected.
                The script runs with the selected provider's access token, refresh token,
                and identity claims available as environment variables.
              </p>
            </div>
          </div>
          <div class="scripts-action">
            <Button
              variant="primary"
              icon={mdiPlay}
              disabled={state.providers.length === 0}
              on:click={() => (showScriptDialog = true)}
            >
              Open Script Runner
            </Button>
          </div>
        </Card>
      </div>
    {/if}
  </div>

  <OIDCProviderDialog
    bind:open={showProviderDialog}
    mode={providerDialogMode}
    provider={editProvider}
    templates={providerTemplates}
    saving={savingProvider}
    onSave={handleAddProvider}
    onDiscover={handleDiscover}
  />

  <OIDCScriptDialog
    bind:open={showScriptDialog}
    providers={state.providers}
    onExecute={handleExecuteScript}
  />

  <Modal bind:open={showDeleteConfirm} title="Delete Provider?" maxWidth="440px">
    <p class="text-body-medium">
      Are you sure you want to delete provider "{deleteTargetName}"? This will also remove any stored tokens and stop auto-refresh.
    </p>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showDeleteConfirm = false)} disabled={deleting}>Cancel</Button>
      <Button variant="danger" loading={deleting} on:click={handleDelete}>Delete</Button>
    </svelte:fragment>
  </Modal>

  <!-- Token Response Viewer -->
  <Modal bind:open={showTokenViewer} title="Token Response - {tokenViewerProvider}" maxWidth="680px">
    <JSONViewer json={tokenViewerJSON} filename="oidc-token-{tokenViewerProvider}" />
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showTokenViewer = false)}>Close</Button>
    </svelte:fragment>
  </Modal>

  <!-- Exec Script Test -->
  <Modal bind:open={showExecDialog} title="Test Exec Script" maxWidth="680px">
    {#if execProvider}
      <div class="exec-dialog-content">
        <div class="exec-script-info">
          <span class="text-label-small field-label">Provider</span>
          <span class="text-body-medium">{execProvider.name}</span>
        </div>
        <div class="exec-script-info">
          <span class="text-label-small field-label">Script</span>
          <pre class="exec-script-pre">{execProvider.exec}</pre>
        </div>
        {#if execResult}
          <div class="exec-result" class:exec-success={execResult.success} class:exec-failure={!execResult.success}>
            <div class="exec-result-header">
              <span class="text-label-medium">Exit Code: {execResult.exit_code}</span>
              <StatusBadge status={execResult.success ? 'connected' : 'error'} />
            </div>
            {#if execResult.stdout}
              <div class="exec-output">
                <span class="text-label-small field-label">Stdout</span>
                <pre class="exec-output-pre">{execResult.stdout}</pre>
              </div>
            {/if}
            {#if execResult.stderr}
              <div class="exec-output">
                <span class="text-label-small field-label">Stderr</span>
                <pre class="exec-output-pre exec-stderr">{execResult.stderr}</pre>
              </div>
            {/if}
            {#if execResult.error}
              <div class="exec-output">
                <span class="text-label-small field-label">Error</span>
                <span class="text-body-small exec-error-text">{execResult.error}</span>
              </div>
            {/if}
          </div>
        {/if}
      </div>
    {/if}
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showExecDialog = false)}>Close</Button>
      <Button variant="primary" loading={execRunning} on:click={handleExecConfirm}>Run</Button>
    </svelte:fragment>
  </Modal>
</div>

<style>
  .oidc-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .oidc-content {
    flex: 1;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
  }

  .loading-container {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 48px;
  }

  .provider-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
    gap: 16px;
    padding: 16px 24px 24px;
  }

  .tokens-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding: 16px 24px 24px;
    max-width: 700px;
  }

  .token-card {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .token-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }

  .token-provider {
    margin: 0;
    color: var(--color-on-surface);
  }

  .token-details {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 8px;
  }

  .token-field {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .field-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .expired-text {
    color: var(--color-error);
    font-weight: 500;
  }

  .scope-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }

  .scope-tag {
    padding: 2px 8px;
    background-color: var(--color-primary-95);
    color: var(--color-primary);
    border-radius: var(--radius-full);
    font-weight: 500;
  }

  :global([data-theme="dark"]) .scope-tag {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .token-actions {
    display: flex;
    gap: 8px;
    padding-top: 8px;
    border-top: 1px solid var(--color-outline-variant);
  }

  .scripts-tab {
    padding: 16px 24px 24px;
    max-width: 700px;
  }

  .scripts-info {
    display: flex;
    align-items: flex-start;
    gap: 16px;
    color: var(--color-on-surface-variant);
  }

  .scripts-info h3 {
    margin: 0;
    color: var(--color-on-surface);
  }

  .scripts-info p {
    margin: 4px 0 0;
    line-height: 1.5;
  }

  .scripts-action {
    padding-top: 16px;
  }

  /* Exec Dialog */
  .exec-dialog-content {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .exec-script-info {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .exec-script-pre {
    margin: 0;
    padding: 8px 12px;
    font-family: var(--font-mono);
    font-size: 13px;
    background-color: var(--color-surface-container-lowest);
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    white-space: pre-wrap;
    word-break: break-all;
    color: var(--color-on-surface);
  }

  .exec-result {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 12px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--color-outline-variant);
  }

  .exec-result.exec-success {
    background-color: var(--color-security-verified-container, #e8f5e9);
  }

  .exec-result.exec-failure {
    background-color: var(--color-error-container, #fbe9e7);
  }

  .exec-result-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .exec-output {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .exec-output-pre {
    margin: 0;
    padding: 8px;
    font-family: var(--font-mono);
    font-size: 12px;
    background-color: var(--color-surface-container-lowest);
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 200px;
    overflow-y: auto;
    color: var(--color-on-surface);
  }

  .exec-stderr {
    color: var(--color-error);
  }

  .exec-error-text {
    color: var(--color-error);
  }
</style>
