<script lang="ts">
  import Modal from './Modal.svelte';
  import Input from './Input.svelte';
  import Button from './Button.svelte';
  import Toggle from './Toggle.svelte';
  import type { OIDCProviderEntry, OIDCProviderType, OIDCProviderTemplateInfo } from '$lib/api/backend';

  export let open: boolean = false;
  export let mode: 'add' | 'edit' = 'add';
  export let provider: OIDCProviderEntry | null = null;
  export let templates: OIDCProviderTemplateInfo[] = [];
  export let onSave: (entry: OIDCProviderEntry) => void = () => {};
  export let onDiscover: (issuer: string) => void = () => {};
  export let saving: boolean = false;

  // Phase tracking for add mode: 'template' (pick) or 'form' (configure).
  let phase: 'template' | 'form' = 'template';
  let selectedTemplate: OIDCProviderTemplateInfo | null = null;

  // Form fields.
  let name = '';
  let providerType: OIDCProviderType = 'oidc';
  let templateName = '';
  let issuer = '';
  let clientId = '';
  let clientSecret = '';
  let redirectUrl = 'http://localhost:8085/callback';
  let scopes = 'openid profile email offline_access';
  let execScript = '';
  let autoRefresh = 0;
  let background = false;
  let logFile = '';
  let awsRegion = '';
  let awsProfile = '';
  let awsCredentialsFile = '';
  let awsOutput = '';
  let awsCrossDevice = false;
  let awsSessionStore = '';
  let dpop = false;
  let advancedOpen = false;
  let dialogSessionId = '';

  $: if (open) {
    const newSessionId = `${mode}-${provider?.name ?? 'new'}`;
    if (newSessionId !== dialogSessionId) {
      dialogSessionId = newSessionId;
      if (mode === 'edit' && provider) {
        phase = 'form';
        selectedTemplate = null;
        templateName = provider.template ?? '';
        name = provider.name;
        providerType = provider.type;
        issuer = provider.issuer;
        clientId = provider.client_id;
        clientSecret = provider.client_secret ?? '';
        redirectUrl = provider.redirect_url;
        scopes = provider.scopes.join(' ');
        execScript = provider.exec ?? '';
        autoRefresh = provider.auto_refresh;
        background = provider.background;
        logFile = provider.log_file ?? '';
        awsRegion = provider.aws_region ?? '';
        awsProfile = provider.aws_profile ?? '';
        awsCredentialsFile = provider.aws_credentials_file ?? '';
        awsOutput = provider.aws_output ?? '';
        awsCrossDevice = provider.aws_cross_device ?? false;
        awsSessionStore = provider.aws_session_store ?? '';
        dpop = provider.dpop ?? false;
        advancedOpen = false;
      } else if (mode === 'add') {
        phase = 'template';
        selectedTemplate = null;
        templateName = '';
        name = '';
        providerType = 'oidc';
        issuer = '';
        clientId = '';
        clientSecret = '';
        redirectUrl = 'http://localhost:8085/callback';
        scopes = 'openid profile email offline_access';
        execScript = '';
        autoRefresh = 0;
        background = false;
        logFile = '';
        awsRegion = '';
        awsProfile = '';
        awsCredentialsFile = '';
        awsOutput = '';
        awsCrossDevice = false;
        awsSessionStore = '';
        dpop = false;
        advancedOpen = false;
      }
    }
  } else {
    dialogSessionId = '';
  }

  // Template display order and labels.
  // Only show templates that provide meaningful pre-configuration.
  // Okta, Auth0, Keycloak were removed — they had no pre-filled fields and were
  // identical to Custom. Users who need them can use Custom with their issuer URL.
  const templateOrder = ['aws', 'google', 'microsoft', 'custom'];
  const templateLabels: Record<string, string> = {
    aws: 'AWS',
    'aws-exec': 'AWS (Exec)',
    google: 'Google',
    microsoft: 'Microsoft',
    custom: 'Custom',
  };

  $: sortedTemplates = templateOrder
    .map(n => templates.find(t => t.name === n))
    .filter((t): t is OIDCProviderTemplateInfo => t !== undefined);

  // Determine which template is active (for conditional fields).
  $: isAWS = selectedTemplate?.type === 'aws' || providerType === 'aws';
  $: isCustom = templateName === 'custom' || templateName === '';

  // Validation logic varies by template.
  $: {
    if (isAWS) {
      isValid = name.trim() !== '' && awsRegion.trim() !== '';
    } else if (isCustom) {
      // Custom: user must provide issuer + client ID.
      isValid = name.trim() !== '' && issuer.trim() !== '' && clientId.trim() !== '';
    } else {
      // Google, Microsoft — issuer is pre-filled, just need name + client ID.
      isValid = name.trim() !== '' && clientId.trim() !== '';
    }
  }
  let isValid = false;

  function selectTemplate(tmpl: OIDCProviderTemplateInfo): void {
    selectedTemplate = tmpl;
    templateName = tmpl.name;
    providerType = tmpl.type;

    // Pre-fill issuer from template if available.
    if (tmpl.issuer) {
      issuer = tmpl.issuer;
    } else {
      issuer = '';
    }

    // Pre-fill scopes from template.
    if (tmpl.scopes && tmpl.scopes.length > 0) {
      scopes = tmpl.scopes.join(' ');
    } else {
      scopes = 'openid profile email offline_access';
    }

    // Pre-fill DPoP from template.
    dpop = tmpl.dpop ?? false;

    phase = 'form';
  }

  function goBackToTemplates(): void {
    phase = 'template';
    selectedTemplate = null;
  }

  function handleSave(): void {
    const entry: OIDCProviderEntry = {
      name: name.trim(),
      type: providerType,
      issuer: issuer.trim(),
      client_id: clientId.trim(),
      redirect_url: redirectUrl.trim(),
      scopes: scopes.trim().split(/\s+/).filter(Boolean),
      auto_refresh: Math.max(0, autoRefresh),
      background,
    };
    if (templateName && templateName !== 'custom') entry.template = templateName;
    if (dpop) entry.dpop = dpop;
    if (clientSecret) entry.client_secret = clientSecret;
    if (execScript) entry.exec = execScript;
    if (logFile) entry.log_file = logFile;
    if (isAWS) {
      if (awsRegion) entry.aws_region = awsRegion;
      if (awsProfile) entry.aws_profile = awsProfile;
      if (awsCredentialsFile) entry.aws_credentials_file = awsCredentialsFile;
      if (awsOutput) entry.aws_output = awsOutput;
      entry.aws_cross_device = awsCrossDevice;
      if (awsSessionStore) entry.aws_session_store = awsSessionStore;
    }
    onSave(entry);
  }

  $: dialogTitle = mode === 'edit'
    ? 'Edit OIDC Provider'
    : phase === 'template'
      ? 'Choose Provider Type'
      : selectedTemplate
        ? `Add ${templateLabels[selectedTemplate.name] ?? selectedTemplate.name} Provider`
        : 'Add OIDC Provider';
</script>

<Modal bind:open title={dialogTitle} maxWidth="560px">
  {#if mode === 'add' && phase === 'template'}
    <!-- Phase 1: Template Selector -->
    <div class="template-grid">
      {#each sortedTemplates as tmpl (tmpl.name)}
        <button class="template-card" on:click={() => selectTemplate(tmpl)}>
          <span class="template-name text-title-small">{templateLabels[tmpl.name] ?? tmpl.name}</span>
          <span class="template-desc text-body-small">{tmpl.description || 'Custom configuration'}</span>
        </button>
      {:else}
        <div class="template-empty" data-testid="oidc-templates-unavailable">
          <h3 class="text-title-medium">Provider Templates Unavailable</h3>
          <p class="text-body-medium">
            The OIDC service is not available. Please ensure xKey is running.
          </p>
        </div>
      {/each}
    </div>
  {:else}
    <!-- Phase 2: Contextual Form -->
    <div class="dialog-form">
      {#if mode === 'add' && selectedTemplate}
        <button class="back-link text-label-medium" on:click={goBackToTemplates}>
          &larr; Back to provider types
        </button>
      {/if}

      <Input label="Name" placeholder="my-provider" bind:value={name} disabled={mode === 'edit'} />

      {#if isAWS}
        <!-- AWS: Region is the primary required field -->
        <Input label="AWS Region" placeholder="us-east-1" bind:value={awsRegion} />
        <Input label="AWS Profile" placeholder="default" bind:value={awsProfile} />
        <div class="toggle-row">
          <span class="text-body-medium">Cross-device flow</span>
          <Toggle bind:checked={awsCrossDevice} />
        </div>
      {:else if isCustom}
        <!-- Custom: show Type selector + all core fields -->
        <div class="form-field">
          <label class="text-label-medium form-label" for="provider-type">Type</label>
          <select id="provider-type" class="form-select" bind:value={providerType}>
            <option value="oidc">Standard OIDC</option>
            <option value="aws">AWS</option>
          </select>
        </div>
        <div class="issuer-row">
          <div class="issuer-input">
            <Input label="Issuer URL" placeholder="https://accounts.google.com" bind:value={issuer} />
          </div>
          <div class="discover-btn">
            <Button variant="outline" size="sm" on:click={() => onDiscover(issuer)} disabled={!issuer.trim()}>
              Discover
            </Button>
          </div>
        </div>
        <Input label="Client ID" placeholder="your-client-id" bind:value={clientId} />
        <Input label="Client Secret" placeholder="your-client-secret" bind:value={clientSecret} type="password" />
        <Input label="Redirect URL" placeholder="http://localhost:8085/callback" bind:value={redirectUrl} />
      {:else}
        <!-- Google, Microsoft: Issuer is pre-filled, need Client ID + secret + redirect -->
        <Input label="Client ID" placeholder="your-client-id" bind:value={clientId} />
        <Input label="Client Secret" placeholder="your-client-secret" bind:value={clientSecret} type="password" />
        <Input label="Redirect URL" placeholder="http://localhost:8085/callback" bind:value={redirectUrl} />
      {/if}

      <!-- Collapsible Advanced Section -->
      <button class="advanced-toggle" on:click={() => (advancedOpen = !advancedOpen)}>
        <span class="advanced-chevron" class:advanced-chevron-open={advancedOpen}>&#9654;</span>
        <span class="text-label-medium">Advanced Settings</span>
      </button>
      {#if advancedOpen}
        <div class="advanced-content">
          {#if !isCustom && !isAWS}
            <!-- Show issuer read-only for template providers that have it pre-filled -->
            {#if selectedTemplate?.issuer}
              <Input label="Issuer URL" bind:value={issuer} disabled={true} />
            {/if}
          {/if}
          <Input label="Scopes" placeholder="openid profile email offline_access" bind:value={scopes} helperText="Space-separated list of scopes" />
          <div class="toggle-row">
            <div class="toggle-label-group">
              <span class="text-body-medium">DPoP token binding (RFC 9449)</span>
              <span class="text-body-small helper-text">Binds tokens to a cryptographic key to prevent replay</span>
            </div>
            <Toggle bind:checked={dpop} />
          </div>
          <Input label="Exec Script" placeholder="/path/to/script.sh" bind:value={execScript} helperText="Script executed with token environment" />
          <div class="inline-field">
            <Input label="Auto-Refresh (seconds)" placeholder="0" type="number" bind:value={autoRefresh} on:change={() => { if (Number(autoRefresh) < 0) autoRefresh = 0; }} />
          </div>
          <div class="toggle-row">
            <span class="text-body-medium">Background mode</span>
            <Toggle bind:checked={background} />
          </div>
          <Input label="Log File" placeholder="(optional)" bind:value={logFile} />

          {#if isAWS}
            <div class="section-divider">
              <span class="text-label-medium">AWS Advanced</span>
            </div>
            <Input label="Credentials File" placeholder="~/.aws/credentials" bind:value={awsCredentialsFile} />
            <div class="form-field">
              <label class="text-label-medium form-label" for="aws-output">Output Format</label>
              <select id="aws-output" class="form-select" bind:value={awsOutput}>
                <option value="">Default</option>
                <option value="json">JSON</option>
                <option value="yaml">YAML</option>
                <option value="text">Text</option>
                <option value="table">Table</option>
              </select>
            </div>
            <Input label="Session Store" placeholder="(optional)" bind:value={awsSessionStore} />
          {/if}
        </div>
      {/if}
    </div>
  {/if}

  <svelte:fragment slot="actions">
    {#if mode === 'add' && phase === 'template'}
      <Button variant="text" on:click={() => (open = false)}>Cancel</Button>
    {:else}
      <Button variant="text" on:click={() => (open = false)} disabled={saving}>Cancel</Button>
      <Button variant="primary" loading={saving} disabled={!isValid} on:click={handleSave}>
        {mode === 'add' ? 'Add Provider' : 'Save Changes'}
      </Button>
    {/if}
  </svelte:fragment>
</Modal>

<style>
  /* Template selector grid */
  .template-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: 12px;
    padding: 4px 0;
  }

  .template-card {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
    padding: 20px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-lowest);
    cursor: pointer;
    transition: border-color 0.15s, background-color 0.15s;
    text-align: center;
  }

  .template-card:hover {
    border-color: var(--color-primary);
    background-color: var(--color-primary-95, rgba(var(--color-primary-rgb, 103, 80, 164), 0.05));
  }

  :global([data-theme="dark"]) .template-card:hover {
    background-color: var(--color-primary-container, rgba(255, 255, 255, 0.06));
  }

  .template-name {
    color: var(--color-on-surface);
    font-weight: 600;
  }

  .template-desc {
    color: var(--color-on-surface-variant);
    line-height: 1.3;
  }

  .template-empty {
    grid-column: 1 / -1;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    padding: 32px 16px;
    text-align: center;
    color: var(--color-on-surface-variant);
  }

  .template-empty h3 {
    color: var(--color-on-surface);
    margin: 0;
  }

  .template-empty p {
    margin: 0;
    max-width: 320px;
  }

  /* Form */
  .dialog-form {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .back-link {
    background: none;
    border: none;
    color: var(--color-primary);
    cursor: pointer;
    padding: 0;
    text-align: left;
    font-family: var(--font-sans);
  }

  .back-link:hover {
    text-decoration: underline;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .form-label {
    color: var(--color-on-surface-variant);
    padding-left: 4px;
  }

  .form-select {
    height: 48px;
    padding: 0 16px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
    outline: none;
    cursor: pointer;
  }

  .form-select:focus {
    border-color: var(--color-primary);
  }

  .issuer-row {
    display: flex;
    align-items: flex-end;
    gap: 8px;
  }

  .issuer-input {
    flex: 1;
  }

  .discover-btn {
    padding-bottom: 2px;
  }

  /* Collapsible Advanced Section */
  .advanced-toggle {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 0 4px;
    border: none;
    border-bottom: 1px solid var(--color-outline-variant);
    background: none;
    color: var(--color-on-surface);
    cursor: pointer;
    font-family: var(--font-sans);
    width: 100%;
    text-align: left;
  }

  .advanced-toggle:hover {
    color: var(--color-primary);
  }

  .advanced-chevron {
    display: inline-block;
    font-size: 10px;
    transition: transform 0.2s ease;
    color: var(--color-on-surface-variant);
  }

  .advanced-chevron-open {
    transform: rotate(90deg);
  }

  .advanced-content {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding-top: 12px;
  }

  .section-divider {
    padding: 8px 0 4px;
    border-bottom: 1px solid var(--color-outline-variant);
    color: var(--color-on-surface);
  }

  .toggle-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 4px 0;
  }

  .toggle-row span {
    color: var(--color-on-surface);
  }

  .inline-field {
    max-width: 200px;
  }

  .toggle-label-group {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .helper-text {
    color: var(--color-on-surface-variant);
    font-size: 12px;
  }
</style>
