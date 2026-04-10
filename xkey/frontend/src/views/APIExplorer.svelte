<script lang="ts">
  import { onMount } from 'svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import {
    mdiConsoleLine, mdiPlus, mdiDelete, mdiRefresh, mdiDeleteSweep,
    mdiClockOutline, mdiShieldKeyOutline, mdiChevronDown, mdiAlertCircle
  } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { isWailsAvailable, callBackend, callBackendWithError, callBackendVoid } from '$lib/api/backend';
  import type { AvailableToken, GUIConfig } from '$lib/api/backend';
  import { isEnterpriseMode, enterprisePolicy } from '$lib/stores/auth';

  /** Request shape matching Go ExplorerRequest. */
  interface ExplorerRequest {
    method: string;
    url: string;
    headers: Record<string, string>;
    body: string;
  }

  /** Response shape matching Go ExplorerResponse. */
  interface ExplorerResponse {
    status_code: number;
    status: string;
    headers: Record<string, string>;
    body: string;
    duration_ms: number;
    error: string;
  }

  /** History entry shape matching Go HistoryEntry. */
  interface HistoryEntry {
    id: string;
    timestamp: string;
    request: ExplorerRequest;
    response: ExplorerResponse;
  }

  const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
  const METHODS_WITH_BODY = ['POST', 'PUT', 'PATCH'];

  let selectedMethod = 'GET';
  let requestUrl = '';
  let requestBody = '';
  let headers: Array<{ key: string; value: string }> = [];
  let sending = false;

  // Response state
  let response: ExplorerResponse | null = null;
  let responseTab: 'headers' | 'raw' | 'preview' = 'headers';

  // History state
  let history: HistoryEntry[] = [];
  let historyLoading = false;

  // Token picker state
  let availableTokens: AvailableToken[] = [];
  let showTokenPicker = false;
  let tokenPickerLoading = false;

  // Sandbox policy (loaded from config, may be overridden by enterprise policy)
  let sandboxPolicy = 'allow-same-origin allow-scripts allow-forms allow-popups';

  $: showBodyInput = METHODS_WITH_BODY.includes(selectedMethod);

  $: if (response) {
    const ct = response.headers?.['Content-Type'] || response.headers?.['content-type'] || '';
    responseTab = ct.includes('text/html') ? 'preview' : 'raw';
  }

  onMount(async () => {
    loadHistory();
    // Load sandbox policy from user config, respecting enterprise override.
    const cfg = await callBackend<GUIConfig>('AppService', 'GetConfig');
    if (cfg?.api_explorer_sandbox_policy) {
      sandboxPolicy = cfg.api_explorer_sandbox_policy;
    }
    // Enterprise policy override takes precedence.
    if ($isEnterpriseMode && $enterprisePolicy?.api_explorer_sandbox_policy) {
      sandboxPolicy = $enterprisePolicy.api_explorer_sandbox_policy as string;
    }
  });

  async function loadHistory(): Promise<void> {
    if (!isWailsAvailable()) return;
    historyLoading = true;
    const entries = await callBackend<HistoryEntry[]>('APIExplorerService', 'GetHistory');
    if (entries) {
      history = entries;
    }
    historyLoading = false;
  }

  function buildHeaderMap(): Record<string, string> {
    const map: Record<string, string> = {};
    for (const h of headers) {
      if (h.key.trim()) {
        map[h.key.trim()] = h.value;
      }
    }
    return map;
  }

  function normalizeUrl(raw: string): string {
    const trimmed = raw.trim();
    if (!/^https?:\/\//i.test(trimmed)) {
      return 'https://' + trimmed;
    }
    return trimmed;
  }

  async function handleSend(): Promise<void> {
    if (!requestUrl.trim()) {
      addNotification('error', 'URL is required');
      return;
    }
    const url = normalizeUrl(requestUrl);
    requestUrl = url;
    sending = true;
    response = null;

    if (isWailsAvailable()) {
      const { result, error } = await callBackendWithError<ExplorerResponse>('APIExplorerService', 'Execute', {
        method: selectedMethod,
        url,
        headers: buildHeaderMap(),
        body: showBodyInput ? requestBody : '',
      });
      if (result) {
        response = result;
        if (result.error) {
          addNotification('error', result.error);
        }
      } else if (error) {
        response = {
          status_code: 0,
          status: 'Error',
          headers: {},
          body: '',
          duration_ms: 0,
          error,
        };
        addNotification('error', error);
      }
      await loadHistory();
    } else {
      // Standalone mode: show a placeholder response
      response = {
        status_code: 0,
        status: 'Unavailable',
        headers: {},
        body: 'Backend not available in standalone mode',
        duration_ms: 0,
        error: 'Not running in Wails mode',
      };
    }
    sending = false;
  }

  async function handleClearHistory(): Promise<void> {
    if (isWailsAvailable()) {
      await callBackendVoid('APIExplorerService', 'ClearHistory');
      history = [];
      addNotification('info', 'History cleared');
    }
  }

  async function handleDeleteHistoryEntry(id: string): Promise<void> {
    if (isWailsAvailable()) {
      await callBackendVoid('APIExplorerService', 'DeleteHistoryEntry', id);
      history = history.filter(e => e.id !== id);
    }
  }

  function handleReplayEntry(entry: HistoryEntry): void {
    selectedMethod = entry.request.method;
    requestUrl = entry.request.url;
    requestBody = entry.request.body || '';
    headers = Object.entries(entry.request.headers || {}).map(([key, value]) => ({ key, value }));
    response = entry.response;
  }

  async function toggleTokenPicker(): Promise<void> {
    if (showTokenPicker) {
      showTokenPicker = false;
      return;
    }
    tokenPickerLoading = true;
    showTokenPicker = true;
    const tokens = await callBackend<AvailableToken[]>('APIExplorerService', 'ListAvailableTokens');
    availableTokens = tokens ?? [];
    tokenPickerLoading = false;
  }

  function extractAccessToken(raw: string): string {
    // If the value looks like a JSON object, extract the access_token field.
    const trimmed = raw.trim();
    if (trimmed.startsWith('{')) {
      try {
        const parsed = JSON.parse(trimmed);
        if (typeof parsed.access_token === 'string' && parsed.access_token) {
          return parsed.access_token;
        }
      } catch { /* not JSON, use as-is */ }
    }
    return raw;
  }

  function selectToken(token: AvailableToken): void {
    const bearerToken = extractAccessToken(token.token);
    // Find existing Authorization header or add one.
    const authIdx = headers.findIndex(h => h.key.toLowerCase() === 'authorization');
    if (authIdx >= 0) {
      headers[authIdx].value = 'Bearer ' + bearerToken;
      headers = [...headers];
    } else {
      headers = [...headers, { key: 'Authorization', value: 'Bearer ' + bearerToken }];
    }
    showTokenPicker = false;
    addNotification('info', `Token applied: ${token.label}`);
  }

  function addHeader(): void {
    headers = [...headers, { key: '', value: '' }];
  }

  function removeHeader(index: number): void {
    headers = headers.filter((_, i) => i !== index);
  }

  function statusColorClass(code: number): string {
    if (code >= 200 && code < 300) return 'status-success';
    if (code >= 300 && code < 400) return 'status-redirect';
    if (code >= 400 && code < 500) return 'status-client-error';
    if (code >= 500) return 'status-server-error';
    return 'status-unknown';
  }

  function formatResponseBody(body: string): string {
    if (!body) return '';
    try {
      const parsed = JSON.parse(body);
      return JSON.stringify(parsed, null, 2);
    } catch {
      return body;
    }
  }

  function formatTimestamp(ts: string): string {
    if (!ts) return '';
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString();
    } catch {
      return ts;
    }
  }

  function methodColorClass(method: string): string {
    const colors: Record<string, string> = {
      GET: 'method-get',
      POST: 'method-post',
      PUT: 'method-put',
      DELETE: 'method-delete',
      PATCH: 'method-patch',
    };
    return colors[method] || 'method-default';
  }
</script>

<div class="api-explorer-view" data-testid="api-explorer-view">
  <GradientHeader title="API Explorer" subtitle="Send HTTP requests and inspect responses" />

  <div class="explorer-layout">
    <!-- Main Panel -->
    <div class="explorer-main">

      <!-- Request Panel -->
      <Card variant="elevated">
        <div class="request-section">
          <h2 class="text-title-medium section-heading">Request</h2>

          <div class="request-line">
            <select
              class="method-select"
              bind:value={selectedMethod}
              data-testid="method-select"
            >
              {#each HTTP_METHODS as method}
                <option value={method}>{method}</option>
              {/each}
            </select>
            <input
              type="text"
              class="url-input"
              placeholder="https://api.example.com/v1/resource"
              bind:value={requestUrl}
              data-testid="url-input"
              on:keydown={(e) => { if (e.key === 'Enter') handleSend(); }}
            />
            <div data-testid="send-button">
              <Button
                variant="primary"
                loading={sending}
                on:click={handleSend}
              >
                Send
              </Button>
            </div>
          </div>

          <!-- Headers -->
          <div class="headers-section">
            <div class="headers-header">
              <span class="text-label-large">Headers</span>
              <div class="headers-actions">
                <div class="token-picker-wrapper">
                  <button
                    class="token-picker-btn"
                    on:click={toggleTokenPicker}
                    data-testid="token-picker-button"
                    title="Insert auth token"
                  >
                    <Icon path={mdiShieldKeyOutline} size={16} />
                    <span class="text-label-small">Auth Token</span>
                    <Icon path={mdiChevronDown} size={14} />
                  </button>
                  {#if showTokenPicker}
                    <div class="token-picker-dropdown" data-testid="token-picker-dropdown">
                      {#if tokenPickerLoading}
                        <div class="token-picker-loading">
                          <span class="text-body-small">Loading tokens...</span>
                        </div>
                      {:else if availableTokens.length === 0}
                        <div class="token-picker-empty">
                          <span class="text-body-small">No tokens available</span>
                        </div>
                      {:else}
                        {#each availableTokens as token}
                          <button
                            class="token-picker-item"
                            on:click={() => selectToken(token)}
                            title={token.label}
                          >
                            <div class="token-item-top">
                              <span class="token-source-badge {token.source}">{token.source}</span>
                              {#if token.is_expired}
                                <span class="token-expired-badge" title="Token expired">
                                  <Icon path={mdiAlertCircle} size={12} />
                                  expired
                                </span>
                              {/if}
                            </div>
                            <span class="token-label text-body-small">{token.label}</span>
                            {#if token.expires_at}
                              <span class="token-expiry text-label-small">{token.expires_at}</span>
                            {/if}
                          </button>
                        {/each}
                      {/if}
                    </div>
                  {/if}
                </div>
                <button
                  class="add-header-btn"
                  on:click={addHeader}
                  data-testid="add-header-button"
                  title="Add header"
                >
                  <Icon path={mdiPlus} size={16} />
                  <span class="text-label-small">Add</span>
                </button>
              </div>
            </div>
            {#each headers as header, i}
              <div class="header-row" data-testid="header-row-{i}">
                <input
                  type="text"
                  class="header-key-input"
                  placeholder="Header name"
                  bind:value={header.key}
                />
                <input
                  type="text"
                  class="header-value-input"
                  placeholder="Value"
                  bind:value={header.value}
                />
                <button class="remove-header-btn" on:click={() => removeHeader(i)} title="Remove header">
                  <Icon path={mdiDelete} size={16} />
                </button>
              </div>
            {/each}
          </div>

          <!-- Body (only for methods with body) -->
          {#if showBodyInput}
            <div class="body-section">
              <span class="text-label-large">Body</span>
              <textarea
                class="body-textarea"
                placeholder={'{"key": "value"}'}
                bind:value={requestBody}
                data-testid="request-body-input"
                rows="6"
              ></textarea>
            </div>
          {/if}
        </div>
      </Card>

      <!-- Response Panel -->
      <Card variant="outlined">
        <div class="response-section">
          <h2 class="text-title-medium section-heading">Response</h2>

          {#if response}
            <div class="response-meta">
              {#if response.status_code > 0}
                <span class="status-badge {statusColorClass(response.status_code)}" data-testid="response-status">
                  {response.status_code} {response.status}
                </span>
              {:else if response.error}
                <span class="status-badge status-error" data-testid="response-status">
                  Error
                </span>
              {/if}
              <span class="duration-badge" data-testid="response-duration">
                <Icon path={mdiClockOutline} size={14} />
                {response.duration_ms} ms
              </span>
            </div>

            <!-- Response Tabs -->
            <div class="response-tabs">
              <button
                class="response-tab"
                class:active={responseTab === 'headers'}
                on:click={() => responseTab = 'headers'}
              >
                Headers
                {#if response.headers && Object.keys(response.headers).length > 0}
                  <span class="tab-count">{Object.keys(response.headers).length}</span>
                {/if}
              </button>
              <button
                class="response-tab"
                class:active={responseTab === 'raw'}
                on:click={() => responseTab = 'raw'}
              >
                Raw
              </button>
              <button
                class="response-tab"
                class:active={responseTab === 'preview'}
                on:click={() => responseTab = 'preview'}
              >
                Preview
              </button>
            </div>

            <div class="response-tab-content">
              {#if responseTab === 'headers'}
                {#if response.headers && Object.keys(response.headers).length > 0}
                  <div class="response-headers-table">
                    <div class="headers-table-header">
                      <span class="headers-col-name text-label-small">Name</span>
                      <span class="headers-col-value text-label-small">Value</span>
                    </div>
                    {#each Object.entries(response.headers) as [key, value]}
                      <div class="headers-table-row">
                        <span class="headers-col-name header-name">{key}</span>
                        <span class="headers-col-value header-value">{value}</span>
                      </div>
                    {/each}
                  </div>
                {:else}
                  <div class="tab-empty-msg">
                    <span class="text-body-small">No response headers</span>
                  </div>
                {/if}
              {:else if responseTab === 'preview'}
                {#if response.body}
                  <iframe
                    class="response-preview-iframe"
                    sandbox={sandboxPolicy}
                    srcdoc={response.body}
                    title="Response Preview"
                  ></iframe>
                {:else}
                  <div class="tab-empty-msg">
                    <span class="text-body-small">No response body</span>
                  </div>
                {/if}
              {:else}
                {#if response.body}
                  <pre class="response-body" data-testid="response-body">{formatResponseBody(response.body)}</pre>
                {:else}
                  <div class="tab-empty-msg" data-testid="response-body">
                    <span class="text-body-small">No response body</span>
                  </div>
                {/if}
              {/if}
            </div>
          {:else}
            <div class="response-placeholder" data-testid="response-body">
              <Icon path={mdiConsoleLine} size={32} />
              <span class="text-body-medium">Send a request to see the response here</span>
            </div>
          {/if}
        </div>
      </Card>
    </div>

    <!-- History Sidebar -->
    <div class="explorer-history">
      <div class="history-header">
        <span class="text-title-small">History</span>
        <button
          class="clear-history-btn"
          on:click={handleClearHistory}
          data-testid="clear-history-button"
          title="Clear history"
        >
          <Icon path={mdiDeleteSweep} size={16} />
        </button>
      </div>
      <div class="history-list" data-testid="history-list">
        {#if history.length === 0}
          <div class="history-empty">
            <span class="text-body-small">No requests yet</span>
          </div>
        {:else}
          {#each history as entry}
            <button
              class="history-entry"
              on:click={() => handleReplayEntry(entry)}
              title="{entry.request.method} {entry.request.url}"
            >
              <div class="history-entry-top">
                <span class="history-method {methodColorClass(entry.request.method)}">
                  {entry.request.method}
                </span>
                {#if entry.response && entry.response.status_code > 0}
                  <span class="history-status {statusColorClass(entry.response.status_code)}">
                    {entry.response.status_code}
                  </span>
                {/if}
              </div>
              <span class="history-url text-body-small">{entry.request.url}</span>
              <span class="history-time text-label-small">{formatTimestamp(entry.timestamp)}</span>
            </button>
          {/each}
        {/if}
      </div>
    </div>
  </div>
</div>

<style>
  .api-explorer-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .explorer-layout {
    flex: 1;
    display: flex;
    overflow: hidden;
  }

  .explorer-main {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .explorer-history {
    width: 280px;
    min-width: 280px;
    border-left: 1px solid var(--color-outline-variant);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  /* Request Section */
  .request-section {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .section-heading {
    margin: 0;
    color: var(--color-on-surface);
    padding-bottom: 8px;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .request-line {
    display: flex;
    gap: 8px;
    align-items: stretch;
  }

  .method-select {
    height: 40px;
    padding: 0 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-mono);
    font-size: 14px;
    font-weight: 600;
    outline: none;
    cursor: pointer;
    min-width: 110px;
  }

  .method-select:focus {
    border-color: var(--color-primary);
  }

  .url-input {
    flex: 1;
    height: 40px;
    padding: 0 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-mono);
    font-size: 14px;
    outline: none;
  }

  .url-input:focus {
    border-color: var(--color-primary);
  }

  .url-input::placeholder {
    color: var(--color-on-surface-variant);
    opacity: 0.6;
  }

  /* Headers */
  .headers-section {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .headers-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .headers-header span {
    color: var(--color-on-surface);
  }

  .add-header-btn {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 4px 10px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--color-primary);
    cursor: pointer;
    font-family: var(--font-sans);
    transition: background-color var(--transition-fast);
  }

  .add-header-btn:hover {
    background-color: var(--color-primary-95);
  }

  .header-row {
    display: flex;
    gap: 8px;
    align-items: center;
  }

  .header-key-input,
  .header-value-input {
    flex: 1;
    height: 36px;
    padding: 0 10px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-mono);
    font-size: 13px;
    outline: none;
  }

  .header-key-input:focus,
  .header-value-input:focus {
    border-color: var(--color-primary);
  }

  .header-key-input::placeholder,
  .header-value-input::placeholder {
    color: var(--color-on-surface-variant);
    opacity: 0.6;
  }

  .remove-header-btn {
    width: 32px;
    height: 32px;
    display: flex;
    align-items: center;
    justify-content: center;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    flex-shrink: 0;
    transition: background-color var(--transition-fast), color var(--transition-fast);
  }

  .remove-header-btn:hover {
    background-color: var(--color-error-container);
    color: var(--color-error);
  }

  /* Body */
  .body-section {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .body-section span {
    color: var(--color-on-surface);
  }

  .body-textarea {
    width: 100%;
    padding: 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-mono);
    font-size: 13px;
    outline: none;
    resize: vertical;
    min-height: 80px;
    box-sizing: border-box;
  }

  .body-textarea:focus {
    border-color: var(--color-primary);
  }

  .body-textarea::placeholder {
    color: var(--color-on-surface-variant);
    opacity: 0.6;
  }

  /* Response Section */
  .response-section {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .response-meta {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .status-badge {
    display: inline-flex;
    align-items: center;
    padding: 4px 12px;
    border-radius: var(--radius-full);
    font-size: 13px;
    font-weight: 600;
    font-family: var(--font-mono);
  }

  .status-success {
    background-color: var(--color-security-verified-container, #e8f5e9);
    color: var(--color-security-verified, #2e7d32);
  }

  .status-redirect {
    background-color: var(--color-tertiary-container, #e3f2fd);
    color: var(--color-tertiary, #1565c0);
  }

  .status-client-error {
    background-color: var(--color-security-warning-container, #fff3e0);
    color: var(--color-security-warning, #e65100);
  }

  .status-server-error {
    background-color: var(--color-error-container, #fbe9e7);
    color: var(--color-error, #c62828);
  }

  .status-error {
    background-color: var(--color-error-container, #fbe9e7);
    color: var(--color-error, #c62828);
  }

  .status-unknown {
    background-color: var(--color-surface-container);
    color: var(--color-on-surface-variant);
  }

  .duration-badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 4px 10px;
    border-radius: var(--radius-full);
    background-color: var(--color-surface-container);
    color: var(--color-on-surface-variant);
    font-size: 12px;
    font-family: var(--font-mono);
  }

  /* Response Tabs */
  .response-tabs {
    display: flex;
    gap: 0;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .response-tab {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 8px 16px;
    border: none;
    border-bottom: 2px solid transparent;
    background: transparent;
    color: var(--color-on-surface-variant);
    font-size: 13px;
    font-weight: 600;
    font-family: var(--font-sans);
    cursor: pointer;
    transition: color var(--transition-fast), border-color var(--transition-fast);
  }

  .response-tab:hover:not(.active) {
    color: var(--color-on-surface);
    background-color: var(--color-surface-container);
  }

  .response-tab.active {
    color: var(--color-primary);
    border-bottom-color: var(--color-primary);
  }

  .tab-count {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 18px;
    height: 18px;
    padding: 0 5px;
    border-radius: var(--radius-full);
    background-color: var(--color-surface-container);
    font-size: 11px;
    font-weight: 600;
    font-family: var(--font-mono);
    color: var(--color-on-surface-variant);
  }

  .response-tab.active .tab-count {
    background-color: var(--color-primary-95);
    color: var(--color-primary);
  }

  .response-tab-content {
    overflow: auto;
    max-height: 450px;
  }

  .tab-empty-msg {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 32px;
    color: var(--color-on-surface-variant);
    opacity: 0.6;
  }

  /* Headers Table */
  .response-headers-table {
    display: flex;
    flex-direction: column;
    font-family: var(--font-mono);
    font-size: 12px;
  }

  .headers-table-header {
    display: flex;
    gap: 12px;
    padding: 8px 12px;
    background-color: var(--color-surface-container);
    border-bottom: 1px solid var(--color-outline-variant);
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    position: sticky;
    top: 0;
    z-index: 1;
  }

  .headers-table-row {
    display: flex;
    gap: 12px;
    padding: 6px 12px;
    border-bottom: 1px solid var(--color-surface-variant);
    transition: background-color var(--transition-fast);
  }

  .headers-table-row:hover {
    background-color: var(--color-surface-container-low);
  }

  .headers-col-name {
    width: 220px;
    min-width: 160px;
    flex-shrink: 0;
  }

  .headers-col-value {
    flex: 1;
    min-width: 0;
  }

  .header-name {
    color: var(--color-primary);
    font-weight: 600;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .header-value {
    color: var(--color-on-surface);
    word-break: break-all;
  }

  /* Response Body */
  .response-body {
    padding: 12px;
    background-color: var(--color-surface-container-lowest);
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--color-on-surface);
    white-space: pre-wrap;
    word-break: break-all;
    margin: 0;
    min-height: 40px;
  }

  .response-preview-iframe {
    width: 100%;
    min-height: 300px;
    max-height: 500px;
    border: none;
    background-color: white;
  }

  .response-placeholder {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
    padding: 40px 24px;
    color: var(--color-on-surface-variant);
    opacity: 0.6;
  }

  /* History Sidebar */
  .history-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px;
    border-bottom: 1px solid var(--color-outline-variant);
    flex-shrink: 0;
  }

  .history-header span {
    color: var(--color-on-surface);
  }

  .clear-history-btn {
    width: 32px;
    height: 32px;
    display: flex;
    align-items: center;
    justify-content: center;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    transition: background-color var(--transition-fast), color var(--transition-fast);
  }

  .clear-history-btn:hover {
    background-color: var(--color-error-container);
    color: var(--color-error);
  }

  .history-list {
    flex: 1;
    overflow-y: auto;
    padding: 8px;
  }

  .history-empty {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    color: var(--color-on-surface-variant);
    opacity: 0.6;
  }

  .history-entry {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 10px 12px;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    cursor: pointer;
    text-align: left;
    width: 100%;
    font-family: var(--font-sans);
    transition: background-color var(--transition-fast);
  }

  .history-entry:hover {
    background-color: var(--color-surface-container);
  }

  .history-entry + .history-entry {
    border-top: 1px solid var(--color-surface-variant);
  }

  .history-entry-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }

  .history-method {
    font-size: 11px;
    font-weight: 700;
    font-family: var(--font-mono);
    padding: 2px 6px;
    border-radius: 3px;
  }

  .method-get { color: #2e7d32; background-color: rgba(46, 125, 50, 0.1); }
  .method-post { color: #1565c0; background-color: rgba(21, 101, 192, 0.1); }
  .method-put { color: #e65100; background-color: rgba(230, 81, 0, 0.1); }
  .method-delete { color: #c62828; background-color: rgba(198, 40, 40, 0.1); }
  .method-patch { color: #6a1b9a; background-color: rgba(106, 27, 154, 0.1); }
  .method-default { color: var(--color-on-surface-variant); background-color: var(--color-surface-container); }

  .history-status {
    font-size: 11px;
    font-weight: 600;
    font-family: var(--font-mono);
    padding: 1px 6px;
    border-radius: 3px;
  }

  .history-url {
    color: var(--color-on-surface);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .history-time {
    color: var(--color-on-surface-variant);
    opacity: 0.7;
  }

  /* Token Picker */
  .headers-actions {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .token-picker-wrapper {
    position: relative;
  }

  .token-picker-btn {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 4px 10px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--color-tertiary);
    cursor: pointer;
    font-family: var(--font-sans);
    transition: background-color var(--transition-fast);
  }

  .token-picker-btn:hover {
    background-color: var(--color-tertiary-container);
  }

  .token-picker-dropdown {
    position: absolute;
    top: 100%;
    right: 0;
    z-index: 20;
    min-width: 300px;
    max-height: 280px;
    overflow-y: auto;
    margin-top: 4px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-lowest);
    box-shadow: var(--shadow-md, 0 4px 12px rgba(0,0,0,0.15));
  }

  .token-picker-loading,
  .token-picker-empty {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    color: var(--color-on-surface-variant);
    opacity: 0.6;
  }

  .token-picker-item {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 10px 12px;
    border: none;
    background: transparent;
    cursor: pointer;
    text-align: left;
    width: 100%;
    font-family: var(--font-sans);
    transition: background-color var(--transition-fast);
  }

  .token-picker-item:hover {
    background-color: var(--color-surface-container);
  }

  .token-picker-item + .token-picker-item {
    border-top: 1px solid var(--color-surface-variant);
  }

  .token-item-top {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .token-source-badge {
    font-size: 10px;
    font-weight: 700;
    font-family: var(--font-mono);
    padding: 1px 6px;
    border-radius: 3px;
    text-transform: uppercase;
  }

  .token-source-badge.oidc { color: #1565c0; background-color: rgba(21, 101, 192, 0.1); }
  .token-source-badge.fido2 { color: #2e7d32; background-color: rgba(46, 125, 50, 0.1); }
  .token-source-badge.bootstrap { color: #6a1b9a; background-color: rgba(106, 27, 154, 0.1); }

  .token-expired-badge {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    font-size: 10px;
    font-weight: 600;
    color: var(--color-error);
    background-color: var(--color-error-container);
    padding: 1px 5px;
    border-radius: 3px;
  }

  .token-label {
    color: var(--color-on-surface);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .token-expiry {
    color: var(--color-on-surface-variant);
    opacity: 0.7;
  }
</style>
