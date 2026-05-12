<script lang="ts">
  import { onMount } from 'svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import {
    mdiWeb,
    mdiShieldCheck,
    mdiOpenInNew,
    mdiPlus,
    mdiClose,
    mdiRefresh,
    mdiAlert,
  } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import {
    callBackend,
    callBackendWithError,
    isWailsAvailable,
  } from '$lib/api/backend';
  import { extensionPairingChanged } from '$lib/stores/events';

  interface BrowserInfo {
    name: string;
    path: string;
  }

  interface BrowserConfig {
    default_browser: string;
    custom_command: string;
    include_trust_bundle: boolean;
    chrome_profile_mode: string;
    firefox_profile_mode: string;
  }

  interface LaunchResult {
    browser: string;
    family: string;
    mode: string;
    cert_count: number;
    pid: number;
  }

  interface ManifestInfo {
    browser: string;
    name: string;
    installed: boolean;
    path: string;
  }

  interface ExtensionPairingStatus {
    paired: boolean;
    origin: string;
    paired_at: string;
  }

  interface ExtensionFullStatus {
    ipc_running: boolean;
    ipc_socket_path: string;
    paired_extensions: ExtensionPairingStatus[];
    manifests: ManifestInfo[];
  }

  type Family = 'chrome' | 'firefox';

  interface BrowserEntry {
    info: BrowserInfo;
    family: Family;
    manifestInstalled: boolean;
    launchURL: string;
  }

  let loading = false;
  let browsers: BrowserEntry[] = [];
  let certCount = 0;
  let browserConfig: BrowserConfig = {
    default_browser: 'system',
    custom_command: '',
    include_trust_bundle: false,
    chrome_profile_mode: 'isolated',
    firefox_profile_mode: 'isolated',
  };
  let launching: string | null = null;
  let manifestBusy: string | null = null;

  function classify(path: string): Family | '' {
    const base = (path.split('/').pop() ?? path).toLowerCase();
    if (/chrome|chromium|brave|edge|opera|vivaldi/.test(base)) return 'chrome';
    if (/firefox|librewolf|waterfox/.test(base)) return 'firefox';
    return '';
  }

  async function load(): Promise<void> {
    if (!isWailsAvailable()) return;
    loading = true;
    try {
      const detected =
        (await callBackend<BrowserInfo[]>('SecureBrowserService', 'DetectBrowsers')) || [];
      const config = await callBackend<BrowserConfig>('BrowserService', 'GetConfig');
      if (config) {
        browserConfig = {
          ...config,
          chrome_profile_mode: config.chrome_profile_mode || 'isolated',
          firefox_profile_mode: config.firefox_profile_mode || 'isolated',
        };
      }
      const count = await callBackend<number>('TrustService', 'CertificateCount');
      if (count !== null) certCount = count;

      const extStatus = await callBackend<ExtensionFullStatus>(
        'PairingService',
        'GetExtensionFullStatus',
      );
      const manifestMap = new Map<string, boolean>();
      if (extStatus?.manifests) {
        for (const m of extStatus.manifests) {
          manifestMap.set(m.browser, m.installed);
        }
      }

      const entries: BrowserEntry[] = [];
      for (const info of detected) {
        const fam = classify(info.path);
        if (!fam) continue;
        entries.push({
          info,
          family: fam,
          manifestInstalled: manifestMap.get(fam) ?? false,
          launchURL: 'about:blank',
        });
      }
      browsers = entries;
    } finally {
      loading = false;
    }
  }

  async function saveProfileMode(family: Family, mode: string): Promise<void> {
    const next: BrowserConfig = { ...browserConfig };
    if (family === 'chrome') next.chrome_profile_mode = mode;
    else next.firefox_profile_mode = mode;
    const { error } = await callBackendWithError<void>(
      'BrowserService',
      'SetConfig',
      next,
    );
    if (error) {
      addNotification('error', `Failed to save profile mode: ${error}`);
      return;
    }
    browserConfig = next;
  }

  async function launch(entry: BrowserEntry): Promise<void> {
    const url = entry.launchURL.trim() || 'about:blank';
    launching = entry.info.path;
    const { result, error } = await callBackendWithError<LaunchResult>(
      'SecureBrowserService',
      'LaunchBrowser',
      entry.info.path,
      url,
    );
    launching = null;
    if (error) {
      addNotification('error', `Launch failed: ${error}`);
      return;
    }
    if (result) {
      addNotification(
        'success',
        `Launched ${result.family} (${result.mode}) with ${result.cert_count} cert${result.cert_count !== 1 ? 's' : ''}`,
      );
    }
  }

  async function installManifest(family: Family): Promise<void> {
    manifestBusy = family;
    const { error } = await callBackendWithError<void>(
      'PairingService',
      'InstallManifest',
      family,
    );
    manifestBusy = null;
    if (error) {
      addNotification('error', `Failed to install ${family} manifest: ${error}`);
      return;
    }
    addNotification('success', `Native messaging manifest installed for ${family}`);
    await load();
  }

  async function uninstallManifest(family: Family): Promise<void> {
    manifestBusy = family;
    const { error } = await callBackendWithError<void>(
      'PairingService',
      'UninstallManifest',
      family,
    );
    manifestBusy = null;
    if (error) {
      addNotification('error', `Failed to uninstall ${family} manifest: ${error}`);
      return;
    }
    addNotification('success', `Native messaging manifest uninstalled for ${family}`);
    await load();
  }

  $: if ($extensionPairingChanged > 0 && isWailsAvailable() && !loading) {
    extensionPairingChanged.set(0);
    load();
  }

  onMount(load);
</script>

<div class="browser-view">
  <GradientHeader
    title="Browser"
    subtitle="Launch Chrome and Firefox family browsers with xkey trust store and extension integration"
  />

  {#if loading}
    <div class="loading">
      <LoadingSpinner size={32} />
      <span class="text-body-medium">Detecting browsers…</span>
    </div>
  {:else}
    <div class="summary-card">
      <Card variant="elevated">
        <div class="summary-row">
          <div class="summary-item">
            <Icon path={mdiShieldCheck} size={22} />
            <div class="summary-info">
              <span class="text-label-small field-label">Trust store</span>
              <span class="text-body-medium">{certCount} certificate{certCount !== 1 ? 's' : ''}</span>
            </div>
          </div>
          <div class="summary-item">
            <Icon path={mdiWeb} size={22} />
            <div class="summary-info">
              <span class="text-label-small field-label">Detected browsers</span>
              <span class="text-body-medium">{browsers.length}</span>
            </div>
          </div>
          <Button variant="outline" icon={mdiRefresh} on:click={load}>Refresh</Button>
        </div>
      </Card>
    </div>

    {#if browsers.length === 0}
      <Card variant="outlined">
        <div class="empty-state" data-testid="browser-empty">
          <Icon path={mdiAlert} size={32} color="var(--color-security-warning)" />
          <span class="text-title-medium">No supported browsers detected</span>
          <span class="text-body-small">
            Install a Chrome or Firefox family browser to use trust store integration.
          </span>
        </div>
      </Card>
    {:else}
      {#each browsers as entry (entry.info.path)}
        <Card variant="outlined">
          <div class="browser-card" data-testid={`browser-card-${entry.family}`}>
            <div class="browser-header">
              <div class="browser-identity">
                <Icon path={mdiWeb} size={24} />
                <div>
                  <span class="text-title-medium">{entry.info.name}</span>
                  <span class="text-body-small mono path">{entry.info.path}</span>
                </div>
              </div>
              <StatusBadge status="verified" label={entry.family} />
            </div>

            <div class="browser-grid">
              <!-- Launch -->
              <div class="pane">
                <h3 class="text-title-small pane-heading">
                  <Icon path={mdiOpenInNew} size={18} /> Launch with trust store
                </h3>
                <label class="field">
                  <span class="text-label-small">URL</span>
                  <input
                    class="field-input"
                    type="text"
                    placeholder="https://example.com"
                    bind:value={entry.launchURL}
                  />
                </label>
                <label class="field">
                  <span class="text-label-small">Profile mode</span>
                  <select
                    class="field-input"
                    value={entry.family === 'chrome'
                      ? browserConfig.chrome_profile_mode
                      : browserConfig.firefox_profile_mode}
                    on:change={(e) => saveProfileMode(entry.family, e.currentTarget.value)}
                  >
                    <option value="isolated">Isolated (clean profile)</option>
                    <option value="shared">Shared (your default profile)</option>
                  </select>
                </label>
                <Button
                  variant="primary"
                  icon={mdiShieldCheck}
                  loading={launching === entry.info.path}
                  disabled={certCount === 0}
                  on:click={() => launch(entry)}
                >
                  Launch secure browser
                </Button>
                {#if certCount === 0}
                  <span class="text-body-small hint">
                    Trust store is empty — add a CA certificate first.
                  </span>
                {/if}
              </div>

              <!-- Extension -->
              <div class="pane">
                <h3 class="text-title-small pane-heading">
                  <Icon path={mdiShieldCheck} size={18} /> xkey extension
                </h3>
                <div class="extension-status">
                  <span class="text-body-small">Native messaging manifest</span>
                  {#if entry.manifestInstalled}
                    <StatusBadge status="verified" label="Installed" />
                  {:else}
                    <StatusBadge status="warning" label="Not installed" />
                  {/if}
                </div>
                {#if entry.manifestInstalled}
                  <Button
                    variant="outline"
                    icon={mdiClose}
                    loading={manifestBusy === entry.family}
                    on:click={() => uninstallManifest(entry.family)}
                  >
                    Uninstall manifest
                  </Button>
                {:else}
                  <Button
                    variant="primary"
                    icon={mdiPlus}
                    loading={manifestBusy === entry.family}
                    on:click={() => installManifest(entry.family)}
                  >
                    Install manifest
                  </Button>
                {/if}
                <span class="text-body-small hint">
                  Installs the native messaging host so the xkey browser extension can
                  autofill credentials.
                </span>
              </div>
            </div>
          </div>
        </Card>
      {/each}
    {/if}
  {/if}
</div>

<style>
  .browser-view {
    display: flex;
    flex-direction: column;
    gap: 16px;
    padding: 16px 24px 32px;
  }

  .loading {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 24px;
    color: var(--color-on-surface-variant);
  }

  .summary-card :global(.card) {
    padding: 16px;
  }

  .summary-row {
    display: flex;
    align-items: center;
    gap: 32px;
    flex-wrap: wrap;
  }

  .summary-item {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .summary-info {
    display: flex;
    flex-direction: column;
  }

  .field-label {
    color: var(--color-on-surface-variant);
  }

  .browser-card {
    display: flex;
    flex-direction: column;
    gap: 20px;
    padding: 8px 4px;
  }

  .browser-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }

  .browser-identity {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .browser-identity > div {
    display: flex;
    flex-direction: column;
  }

  .mono {
    font-family: var(--font-mono, monospace);
  }

  .path {
    color: var(--color-on-surface-variant);
    word-break: break-all;
  }

  .browser-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
  }

  .pane {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding: 16px;
    border: 1px solid var(--color-outline-variant, rgba(0, 0, 0, 0.08));
    border-radius: 8px;
    background: var(--color-surface-container-low, transparent);
  }

  .pane-heading {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .field-input {
    padding: 8px 10px;
    border: 1px solid var(--color-outline, rgba(0, 0, 0, 0.2));
    border-radius: 6px;
    font: inherit;
    color: inherit;
    background: var(--color-surface, transparent);
  }

  .field-input:focus {
    outline: 2px solid var(--color-primary, #0057b7);
    outline-offset: 1px;
  }

  .extension-status {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }

  .hint {
    color: var(--color-on-surface-variant);
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
    padding: 32px 16px;
    text-align: center;
  }
</style>
