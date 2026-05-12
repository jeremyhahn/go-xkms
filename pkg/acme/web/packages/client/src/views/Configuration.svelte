<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import FormField from '@trustedca/shared/components/FormField.svelte';
  import Button from '@trustedca/shared/components/Button.svelte';
  import LoadingSpinner from '@trustedca/shared/components/LoadingSpinner.svelte';
  import { notifySuccess, notifyError } from '@trustedca/shared/stores/notifications';
  import { clientConfig, configLoading, fetchConfig, saveConfig } from '../lib/stores/config';

  let directoryURL = '';
  let accountEmail = '';
  let challengePort = '80';
  let challengeWebRoot = '';
  let logLevel = 'info';
  let logFormat = 'json';
  let fileInput: HTMLInputElement;

  function loadFromStore() {
    if ($clientConfig) {
      directoryURL = $clientConfig.directoryURL;
      accountEmail = $clientConfig.accountEmail;
      challengePort = $clientConfig.challengePort;
      challengeWebRoot = $clientConfig.challengeWebRoot;
      logLevel = $clientConfig.logLevel;
      logFormat = $clientConfig.logFormat;
    }
  }

  function getCurrentFormUpdate() {
    return {
      directoryURL,
      accountEmail,
      challengePort,
      challengeWebRoot,
      logLevel,
      logFormat,
    };
  }

  async function handleSave() {
    await saveConfig(getCurrentFormUpdate());
  }

  function exportConfig() {
    const config = getCurrentFormUpdate();
    const json = JSON.stringify(config, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'trustedca-config.json';
    a.click();
    URL.revokeObjectURL(url);
    notifySuccess('Configuration exported');
  }

  function importConfig(event: Event) {
    const target = event.target as HTMLInputElement;
    const file = target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const text = e.target?.result as string;
        const parsed = JSON.parse(text);

        if (typeof parsed.directoryURL === 'string') {
          directoryURL = parsed.directoryURL;
        }
        if (typeof parsed.accountEmail === 'string') {
          accountEmail = parsed.accountEmail;
        }
        if (typeof parsed.challengePort === 'string') {
          challengePort = parsed.challengePort;
        }
        if (typeof parsed.challengeWebRoot === 'string') {
          challengeWebRoot = parsed.challengeWebRoot;
        }
        if (typeof parsed.logLevel === 'string') {
          logLevel = parsed.logLevel;
        }
        if (typeof parsed.logFormat === 'string') {
          logFormat = parsed.logFormat;
        }

        notifySuccess('Configuration imported. Review and save to apply.');
      } catch {
        notifyError('Failed to parse configuration file. Please use a valid JSON file.');
      }
    };
    reader.readAsText(file);

    // Reset file input so the same file can be re-imported.
    target.value = '';
  }

  onMount(async () => {
    await fetchConfig();
    loadFromStore();
  });
</script>

<div class="p-6">
  <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100 mb-6">
    Configuration
  </h1>

  {#if $configLoading}
    <div class="flex items-center justify-center py-20">
      <LoadingSpinner size="lg" />
    </div>
  {:else}
    <div class="max-w-xl">
      <!-- Import / Export -->
      <div class="flex gap-2 mb-4">
        <Button variant="secondary" on:click={exportConfig}>
          <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
          </svg>
          Export Config
        </Button>
        <label class="inline-flex">
          <Button variant="secondary" on:click={() => fileInput.click()}>
            <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
            </svg>
            Import Config
          </Button>
          <input
            bind:this={fileInput}
            type="file"
            accept=".json,.yaml,.yml"
            class="hidden"
            on:change={importConfig}
          />
        </label>
      </div>

      <Card title="Client Configuration" subtitle="Default settings for certificate operations">
        <form class="space-y-4" on:submit|preventDefault={handleSave}>
          <FormField label="ACME Server URL" required id="server-url">
            <input
              id="server-url"
              class="input"
              type="url"
              bind:value={directoryURL}
              placeholder="https://ca.example.com/acme/directory"
              required
            />
          </FormField>

          <FormField label="Account Email" id="cfg-account-email">
            <input
              id="cfg-account-email"
              class="input"
              type="email"
              bind:value={accountEmail}
              placeholder="admin@example.com"
            />
          </FormField>

          <div class="grid grid-cols-2 gap-4">
            <FormField label="Challenge Port" id="cfg-challenge-port">
              <input
                id="cfg-challenge-port"
                class="input"
                type="text"
                bind:value={challengePort}
                placeholder="80"
              />
            </FormField>

            <FormField label="Challenge Web Root" id="cfg-challenge-webroot">
              <input
                id="cfg-challenge-webroot"
                class="input"
                type="text"
                bind:value={challengeWebRoot}
                placeholder="/var/www/html"
              />
            </FormField>
          </div>

          <div class="grid grid-cols-2 gap-4">
            <FormField label="Log Level" id="cfg-log-level">
              <select id="cfg-log-level" class="select" bind:value={logLevel}>
                <option value="debug">debug</option>
                <option value="info">info</option>
                <option value="warn">warn</option>
                <option value="error">error</option>
              </select>
            </FormField>

            <FormField label="Log Format" id="cfg-log-format">
              <select id="cfg-log-format" class="select" bind:value={logFormat}>
                <option value="json">json</option>
                <option value="text">text</option>
              </select>
            </FormField>
          </div>

          <Button type="submit" variant="primary" loading={$configLoading}>
            Save Configuration
          </Button>
        </form>
      </Card>
    </div>
  {/if}
</div>
