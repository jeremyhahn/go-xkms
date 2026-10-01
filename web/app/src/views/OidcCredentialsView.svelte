<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import {
    PROVIDER_TEMPLATES,
    fmtTime,
    needsAttention,
    parseCodexAuthJson,
    parseScopes,
    providerLabel,
    refKey,
    refOf,
    statusView,
    templateFor,
    type LoginMethod,
    type ProviderTemplate,
  } from "$lib/oidcCredential.ts";
  import type { OIDCCredential, OIDCCredentialScope, OIDCCredentialTokens } from "@go-xkms/sdk";

  let credentials = $state<OIDCCredential[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);

  const shared = $derived(credentials.filter((c) => c.scope === "tenant"));
  const personal = $derived(credentials.filter((c) => c.scope === "user"));

  // Token fields, shared by the create dialog's import method and the import
  // dialog. They hold secrets only while a dialog is open: clearTokens runs
  // on every close and submit.
  let tAccess = $state("");
  let tRefresh = $state("");
  let tId = $state("");
  let tAuthJson = $state("");
  let tParseErr = $state<string | null>(null);

  // The create dialog.
  let showCreate = $state(false);
  let cName = $state("");
  let cScope = $state<OIDCCredentialScope>("tenant");
  let cTemplate = $state("openai");
  let cIssuer = $state("");
  let cClientId = $state("");
  let cClientSecret = $state("");
  let cScopes = $state("");
  let cMethod = $state<LoginMethod>("device");
  let cErr = $state<string | null>(null);
  let cBusy = $state(false);

  const cTpl = $derived(templateFor(cTemplate));
  const cInvalid = $derived(
    cName.trim() === "" ||
      (cTpl.needsIssuer && cIssuer.trim() === "") ||
      (cTpl.needsClientId && cClientId.trim() === "") ||
      (cMethod === "import" && tAccess === ""),
  );

  // The import dialog.
  let importTarget = $state<OIDCCredential | null>(null);
  let importErr = $state<string | null>(null);
  let importBusy = $state(false);

  // The device login dialog: the credential whose device_login is shown, and
  // the controller that stops its polling when the dialog closes.
  let device = $state<OIDCCredential | null>(null);
  let deviceErr = $state<string | null>(null);
  let deviceAbort: AbortController | null = null;

  let deleteTarget = $state<OIDCCredential | null>(null);
  let deleteBusy = $state(false);

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      const resp = await getSDKClient().oidcCredentials.list();
      credentials = resp.credentials;
    } catch (e) {
      error = message(e);
    } finally {
      loading = false;
    }
  }

  function clearTokens(): void {
    tAccess = "";
    tRefresh = "";
    tId = "";
    tAuthJson = "";
    tParseErr = null;
  }

  /** tokens returns the entered tokens, omitting the empty optional ones. */
  function tokens(): OIDCCredentialTokens {
    const t: OIDCCredentialTokens = { access_token: tAccess };
    if (tRefresh !== "") t.refresh_token = tRefresh;
    if (tId !== "") t.id_token = tId;
    return t;
  }

  /** fillFromAuthJson parses the pasted codex auth.json into the token fields, then drops the paste. */
  function fillFromAuthJson(): void {
    try {
      const parsed = parseCodexAuthJson(tAuthJson);
      tAccess = parsed.access_token;
      tRefresh = parsed.refresh_token ?? "";
      tId = parsed.id_token ?? "";
      tAuthJson = "";
      tParseErr = null;
    } catch (e) {
      tParseErr = message(e);
    }
  }

  function openCreate(): void {
    cName = "";
    cScope = "tenant";
    selectTemplate("openai");
    cIssuer = "";
    cClientId = "";
    cClientSecret = "";
    cScopes = "";
    cErr = null;
    clearTokens();
    showCreate = true;
  }

  function closeCreate(): void {
    showCreate = false;
    cClientSecret = "";
    clearTokens();
  }

  function selectTemplate(id: string): void {
    cTemplate = id;
    const tpl = templateFor(id);
    if (!tpl.methods.includes(cMethod)) cMethod = tpl.methods[0]!;
  }

  async function create(): Promise<void> {
    cBusy = true;
    cErr = null;
    try {
      const scopes = parseScopes(cScopes);
      const created = await getSDKClient().oidcCredentials.create({
        scope: cScope,
        name: cName.trim(),
        config: {
          ...(cTemplate !== "" ? { template: cTemplate } : {}),
          ...(cIssuer.trim() !== "" ? { issuer: cIssuer.trim() } : {}),
          ...(cClientId.trim() !== "" ? { client_id: cClientId.trim() } : {}),
          ...(cClientSecret !== "" ? { client_secret: cClientSecret } : {}),
          ...(scopes.length > 0 ? { scopes } : {}),
        },
        ...(cMethod === "import" ? { tokens: tokens() } : {}),
      });
      const method = cMethod;
      closeCreate();
      await load();
      if (method === "device") {
        void startDevice(created);
      } else {
        showToast("success", `OIDC credential "${created.name}" created.`);
      }
    } catch (e) {
      cErr = message(e);
    } finally {
      cBusy = false;
    }
  }

  function openImport(c: OIDCCredential): void {
    clearTokens();
    importErr = null;
    importTarget = c;
  }

  function closeImport(): void {
    importTarget = null;
    clearTokens();
  }

  async function importTokens(): Promise<void> {
    if (importTarget === null) return;
    const target = importTarget;
    importBusy = true;
    importErr = null;
    try {
      await getSDKClient().oidcCredentials.importTokens(refOf(target), tokens());
      showToast("success", `Tokens imported into "${target.name}".`);
      closeImport();
      await load();
    } catch (e) {
      importErr = message(e);
    } finally {
      importBusy = false;
    }
  }

  /** startDevice starts a device login for c and polls it until it settles. */
  async function startDevice(c: OIDCCredential): Promise<void> {
    let started: OIDCCredential;
    try {
      started = await getSDKClient().oidcCredentials.startDeviceLogin(refOf(c));
    } catch (e) {
      showToast("error", message(e));
      return;
    }
    deviceErr = null;
    device = started;
    const ctl = new AbortController();
    deviceAbort = ctl;
    try {
      const done = await getSDKClient().oidcCredentials.waitForDeviceLogin(started, {
        signal: ctl.signal,
        onPending: (p) => {
          if (p.device_login !== undefined) device = p;
        },
      });
      if (ctl.signal.aborted) return;
      if (done.status === "active") {
        showToast("success", `"${done.name}" is logged in.`);
        closeDevice();
        await load();
        return;
      }
      const reason = done.status_reason ? `: ${done.status_reason}` : "";
      deviceErr = `The login ended ${statusView(done.status).label}${reason}.`;
    } catch (e) {
      if (ctl.signal.aborted) return;
      deviceErr = message(e);
    }
  }

  function closeDevice(): void {
    deviceAbort?.abort();
    deviceAbort = null;
    device = null;
    deviceErr = null;
  }

  async function copyCode(code: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(code);
      showToast("success", "Code copied.");
    } catch (e) {
      showToast("error", message(e));
    }
  }

  async function refresh(c: OIDCCredential): Promise<void> {
    try {
      const updated = await getSDKClient().oidcCredentials.refresh(refOf(c));
      showToast("success", `"${updated.name}" refreshed.`);
      await load();
    } catch (e) {
      showToast("error", message(e));
    }
  }

  /**
   * copyToken fetches a current access token on demand and puts it on the
   * clipboard. The token lives only in this call's scope: it is never
   * assigned to component state, logged, or shown.
   */
  async function copyToken(c: OIDCCredential): Promise<void> {
    try {
      const token = await getSDKClient().oidcCredentials.getAccessToken(refOf(c));
      await navigator.clipboard.writeText(token.access_token);
      showToast("success", `Access token of "${c.name}" copied.`);
    } catch (e) {
      showToast("error", message(e));
    }
  }

  async function confirmDelete(): Promise<void> {
    if (deleteTarget === null) return;
    const target = deleteTarget;
    deleteBusy = true;
    try {
      await getSDKClient().oidcCredentials.delete(refOf(target));
      showToast("success", `OIDC credential "${target.name}" deleted.`);
      deleteTarget = null;
      await load();
    } catch (e) {
      showToast("error", message(e));
    } finally {
      deleteBusy = false;
    }
  }

  onMount(() => {
    void load();
  });

  onDestroy(() => {
    deviceAbort?.abort();
  });
</script>

{#snippet credentialTable(list: OIDCCredential[], caption: string, empty: string)}
  <div class="overflow-x-auto">
    <table class="table table-sm">
      <caption class="text-left font-semibold py-2">{caption}</caption>
      <thead>
        <tr>
          <th scope="col">Name</th>
          <th scope="col">Provider</th>
          <th scope="col">Status</th>
          <th scope="col">Expires</th>
          <th scope="col">Last refresh</th>
          <th scope="col"><span class="sr-only">Actions</span></th>
        </tr>
      </thead>
      <tbody>
        {#each list as c (refKey(c))}
          {@const status = statusView(c.status)}
          {@const detail = c.status_reason || c.last_error}
          <tr>
            <td>{c.name}</td>
            <td class="text-sm">{providerLabel(c)}</td>
            <td>
              <StatusBadge label={status.label} kind={status.kind} />
              {#if detail}
                <p class="text-xs mt-1" class:text-error={needsAttention(c.status)}>{detail}</p>
              {/if}
            </td>
            <td class="text-sm">{fmtTime(c.expires_at)}</td>
            <td class="text-sm">{fmtTime(c.last_refresh)}</td>
            <td class="text-right whitespace-nowrap">
              {#if c.status === "active"}
                <button class="btn btn-ghost btn-xs" aria-label={`Copy access token of ${c.name}`} onclick={() => copyToken(c)}>
                  Copy token
                </button>
              {/if}
              {#if c.refreshable}
                <button class="btn btn-ghost btn-xs" aria-label={`Refresh ${c.name}`} onclick={() => refresh(c)}>Refresh</button>
              {/if}
              {#if templateFor(c.config.template).methods.includes("device")}
                <button class="btn btn-ghost btn-xs" aria-label={`Device login for ${c.name}`} onclick={() => startDevice(c)}>
                  Log in
                </button>
              {/if}
              <button class="btn btn-ghost btn-xs" aria-label={`Import tokens into ${c.name}`} onclick={() => openImport(c)}>
                Import
              </button>
              <button
                class="btn btn-ghost btn-xs text-error"
                aria-label={`Delete ${c.name}`}
                onclick={() => (deleteTarget = c)}
              >
                Delete
              </button>
            </td>
          </tr>
        {/each}
        {#if list.length === 0}
          <tr><td colspan="6" class="text-center text-base-content/60 py-6">{empty}</td></tr>
        {/if}
      </tbody>
    </table>
  </div>
{/snippet}

{#snippet tokenForm(tpl: ProviderTemplate)}
  {#if tpl.codexAuthJson}
    <label class="block text-sm" for="oidc-auth-json">Paste a codex auth.json (read in this browser only)</label>
    <textarea
      id="oidc-auth-json"
      class="textarea textarea-bordered w-full font-mono text-xs"
      rows="3"
      autocomplete="off"
      spellcheck="false"
      bind:value={tAuthJson}
    ></textarea>
    {#if tParseErr}<p class="text-xs text-error" role="alert">{tParseErr}</p>{/if}
    <button class="btn btn-sm" onclick={fillFromAuthJson} disabled={tAuthJson.trim() === ""}>Fill from auth.json</button>
  {/if}
  <input
    type="password"
    class="input input-bordered w-full"
    aria-label={tpl.id === "anthropic" ? "Token" : "Access token"}
    placeholder={tpl.id === "anthropic" ? "Token (claude setup-token)" : "Access token"}
    autocomplete="off"
    bind:value={tAccess}
  />
  {#if tpl.id !== "anthropic"}
    <input
      type="password"
      class="input input-bordered w-full"
      aria-label="Refresh token"
      placeholder="Refresh token (optional)"
      autocomplete="off"
      bind:value={tRefresh}
    />
    <input
      type="password"
      class="input input-bordered w-full"
      aria-label="ID token"
      placeholder="ID token (optional)"
      autocomplete="off"
      bind:value={tId}
    />
  {/if}
{/snippet}

<PageHeader title="OIDC Credentials" subtitle="OAuth/OIDC logins the server holds and refreshes; consumers fetch an access token by name">
  {#snippet actions()}
    <button class="btn btn-primary btn-sm" onclick={openCreate}>+ Create</button>
  {/snippet}
</PageHeader>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <div class="space-y-6">
    {@render credentialTable(shared, "Shared with the tenant", "No shared credentials.")}
    {@render credentialTable(personal, "Personal (only you)", "No personal credentials.")}
  </div>
{/if}

{#if showCreate}
  <Modal open={showCreate} onClose={closeCreate} labelledby="create-oidc-credential-title">
    <h3 id="create-oidc-credential-title" class="text-lg font-semibold mb-4">Create OIDC credential</h3>
    {#if cErr}<Alert kind="error" class="mb-3"><span>{cErr}</span></Alert>{/if}
    <div class="space-y-3">
      <input class="input input-bordered w-full" aria-label="Name" placeholder="Name" bind:value={cName} />
      <select class="select select-bordered w-full" aria-label="Visibility" bind:value={cScope}>
        <option value="tenant">Shared with the tenant</option>
        <option value="user">Personal (only me)</option>
      </select>
      <select
        class="select select-bordered w-full"
        aria-label="Provider"
        value={cTemplate}
        onchange={(e) => selectTemplate(e.currentTarget.value)}
      >
        {#each PROVIDER_TEMPLATES as t (t.id)}<option value={t.id}>{t.label}</option>{/each}
      </select>
      <p class="text-sm text-base-content/70">{cTpl.hint}</p>
      {#if cTpl.needsIssuer}
        <input class="input input-bordered w-full" aria-label="Issuer URL" placeholder="https://issuer.example.com" bind:value={cIssuer} />
      {/if}
      {#if cTpl.needsClientId}
        <input class="input input-bordered w-full" aria-label="Client ID" placeholder="Client ID" bind:value={cClientId} />
        <input
          type="password"
          class="input input-bordered w-full"
          aria-label="Client secret"
          placeholder="Client secret (optional)"
          autocomplete="off"
          bind:value={cClientSecret}
        />
        <input
          class="input input-bordered w-full"
          aria-label="Scopes"
          placeholder="Scopes (optional; the template's when empty)"
          bind:value={cScopes}
        />
      {/if}
      {#if cTpl.methods.length > 1}
        <div role="tablist" class="tabs tabs-boxed">
          {#each cTpl.methods as m (m)}
            <button role="tab" class="tab" class:tab-active={cMethod === m} aria-selected={cMethod === m} onclick={() => (cMethod = m)}>
              {m === "device" ? "Device login" : "Import tokens"}
            </button>
          {/each}
        </div>
      {/if}
      {#if cMethod === "device"}
        <p class="text-sm text-base-content/70">After creating, approve the login with the code shown on another device.</p>
      {:else}
        {@render tokenForm(cTpl)}
      {/if}
    </div>
    <div class="modal-action">
      <button class="btn btn-ghost" onclick={closeCreate} disabled={cBusy}>Cancel</button>
      <button class="btn btn-primary" onclick={create} disabled={cBusy || cInvalid}>
        {#if cBusy}<span class="loading loading-spinner loading-xs"></span>{/if}
        Create
      </button>
    </div>
  </Modal>
{/if}

{#if importTarget}
  <Modal open={importTarget !== null} onClose={closeImport} labelledby="import-oidc-tokens-title">
    <h3 id="import-oidc-tokens-title" class="text-lg font-semibold mb-4">Import tokens into "{importTarget.name}"</h3>
    {#if importErr}<Alert kind="error" class="mb-3"><span>{importErr}</span></Alert>{/if}
    <div class="space-y-3">
      <p class="text-sm text-base-content/70">The tokens replace the credential's current login.</p>
      {@render tokenForm(templateFor(importTarget.config.template))}
    </div>
    <div class="modal-action">
      <button class="btn btn-ghost" onclick={closeImport} disabled={importBusy}>Cancel</button>
      <button class="btn btn-primary" onclick={importTokens} disabled={importBusy || tAccess === ""}>
        {#if importBusy}<span class="loading loading-spinner loading-xs"></span>{/if}
        Import
      </button>
    </div>
  </Modal>
{/if}

{#if device}
  {@const login = device.device_login}
  <Modal open={device !== null} onClose={closeDevice} labelledby="oidc-device-login-title">
    <h3 id="oidc-device-login-title" class="text-lg font-semibold mb-4">Log in "{device.name}"</h3>
    {#if deviceErr}
      <Alert kind="error" class="mb-3"><span>{deviceErr}</span></Alert>
    {:else if login}
      <div class="space-y-3">
        <p class="text-sm">
          Open
          <a class="link link-primary" href={login.verification_uri_complete || login.verification_uri} target="_blank" rel="noopener noreferrer">
            {login.verification_uri}
          </a>
          and enter this code:
        </p>
        <div class="flex items-center gap-3">
          <span class="font-mono text-2xl tracking-widest" aria-label="User code">{login.user_code}</span>
          <button class="btn btn-ghost btn-xs" onclick={() => copyCode(login.user_code)}>Copy code</button>
        </div>
        <p class="text-sm text-base-content/70" role="status">
          <span class="loading loading-spinner loading-xs"></span>
          Waiting for approval (the code expires {fmtTime(login.expires_at)}).
        </p>
      </div>
    {/if}
    <div class="modal-action">
      <button class="btn btn-ghost" onclick={closeDevice}>{deviceErr ? "Close" : "Cancel"}</button>
    </div>
  </Modal>
{/if}

{#if deleteTarget}
  <Modal open={deleteTarget !== null} onClose={() => (deleteTarget = null)} labelledby="delete-oidc-credential-title">
    <h3 id="delete-oidc-credential-title" class="text-lg font-semibold mb-4">Delete "{deleteTarget.name}"?</h3>
    <p class="text-sm text-base-content/70">
      The login and its tokens are discarded. Consumers referencing this credential stop getting access tokens.
    </p>
    <div class="modal-action">
      <button class="btn btn-ghost" onclick={() => (deleteTarget = null)} disabled={deleteBusy}>Cancel</button>
      <button class="btn btn-error" onclick={confirmDelete} disabled={deleteBusy}>
        {#if deleteBusy}<span class="loading loading-spinner loading-xs"></span>{/if}
        Delete
      </button>
    </div>
  </Modal>
{/if}
