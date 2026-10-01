<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import VaultFactors from "$components/VaultFactors.svelte";
  import { MIN_PASSPHRASE_LENGTH, enrollPasskey, hasKeyFactor, hasPasskey, unlockPasskey, unlockWithKeyFactor } from "$lib/vault.ts";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import type { PasswordInfo, PasswordStoreStatusResponse, PasswordVaultCredential, PasswordVaultStatusResponse } from "@go-xkms/sdk";

  let status = $state<PasswordStoreStatusResponse | null>(null);
  let entries = $state<PasswordInfo[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  // The vault is per user: personal entries open with the caller's own
  // passphrase or passkey, never a deployment PIN. vault is the caller's
  // vault status while locked: whether a first factor exists (enrolling it
  // issues a one-time recovery code), its factors, and the relying party a
  // passkey is created for (absent when the server offers no passkeys).
  let vault = $state<PasswordVaultStatusResponse | null>(null);
  const vaultInitialized = $derived(vault?.initialized ?? true);
  const passkeysOffered = $derived(!!vault?.passkey_rp_id);
  let passphrase = $state("");
  let passphraseConfirm = $state("");
  let recoveryCode = $state<string | null>(null);
  let showAdd = $state(false);
  let showFactors = $state(false);

  // Recovery: the one-time code plus a new passphrase replaces the lost
  // factors and opens the session; the server answers with a new code.
  let recovering = $state(false);
  let rCode = $state("");
  let rPassphrase = $state("");
  let rConfirm = $state("");
  let rErr = $state<string | null>(null);

  let aName = $state("");
  let aUsername = $state("");
  let aPassword = $state("");
  let aErr = $state<string | null>(null);

  async function refreshStatus(): Promise<void> {
    status = await getSDKClient().passwords.status();
    vault = status.is_locked ? await getSDKClient().passwords.vaultStatus() : null;
  }

  /**
   * withPasskey runs a passkey action and reports its failure -- including
   * the SDK's typed errors for a browser or key without the PRF extension --
   * in place, never falling back to another factor.
   */
  async function withPasskey(action: () => Promise<void>): Promise<void> {
    busy = true;
    try {
      await action();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    } finally {
      busy = false;
    }
  }

  function createVaultWithPasskey(): Promise<void> {
    return withPasskey(async () => {
      const cred = await enrollPasskey(vault!, "web console");
      const resp = await getSDKClient().passwords.vaultEnroll(cred);
      recoveryCode = resp.recovery_code ?? null;
      showToast("success", "Vault created and unlocked.");
      await load();
    });
  }

  function unlockWithPasskey(): Promise<void> {
    return withPasskey(async () => {
      const cred = await unlockPasskey(vault!.factors);
      await getSDKClient().passwords.unlock(cred);
      showToast("success", "Vault unlocked.");
      await load();
    });
  }

  // A PIV card, certificate or TPM key never comes into the browser: xKey,
  // through its extension, unlocks the vault after the user approves there.
  function unlockWithXkey(): Promise<void> {
    return withPasskey(async () => {
      await unlockWithKeyFactor(vault!);
      showToast("success", "Vault unlocked by xKey.");
      await load();
    });
  }

  async function recoverWith(cred: PasswordVaultCredential): Promise<void> {
    const resp = await getSDKClient().passwords.vaultRecover({ recovery_code: rCode, ...cred });
    rCode = ""; rPassphrase = ""; rConfirm = "";
    recovering = false;
    recoveryCode = resp.recovery_code ?? null;
    showToast("success", "Vault recovered and unlocked.");
    await load();
  }

  function recoverWithPasskey(): Promise<void> {
    rErr = null;
    return withPasskey(async () => {
      try {
        await recoverWith(await enrollPasskey(vault!, "web console"));
      } catch (e) {
        rErr = e instanceof Error ? e.message : String(e);
        throw e;
      }
    });
  }

  async function createVault(): Promise<void> {
    busy = true;
    try {
      const resp = await getSDKClient().passwords.vaultEnroll({ factor: "passphrase", passphrase, label: "web console" });
      passphrase = "";
      passphraseConfirm = "";
      recoveryCode = resp.recovery_code ?? null;
      showToast("success", "Vault created and unlocked.");
      await load();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    } finally {
      busy = false;
    }
  }

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      await refreshStatus();
      if (status && !status.is_locked) {
        const resp = await getSDKClient().passwords.list();
        entries = resp.passwords;
      } else {
        entries = [];
      }
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function unlock(): Promise<void> {
    busy = true;
    try {
      await getSDKClient().passwords.unlock({ factor: "passphrase", passphrase });
      passphrase = "";
      showToast("success", "Vault unlocked.");
      await load();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    } finally {
      busy = false;
    }
  }

  async function recover(): Promise<void> {
    busy = true;
    rErr = null;
    try {
      await recoverWith({ factor: "passphrase", passphrase: rPassphrase, label: "web console" });
    } catch (e) {
      rErr = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function lock(): Promise<void> {
    busy = true;
    try {
      await getSDKClient().passwords.lock();
      showToast("success", "Vault locked.");
      await load();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    } finally {
      busy = false;
    }
  }

  async function add(): Promise<void> {
    busy = true;
    aErr = null;
    try {
      await getSDKClient().passwords.add({ name: aName, username: aUsername, password: aPassword });
      showToast("success", `Entry "${aName}" added.`);
      showAdd = false;
      aName = ""; aUsername = ""; aPassword = "";
      await load();
    } catch (e) {
      aErr = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function del(id: string): Promise<void> {
    try {
      await getSDKClient().passwords.delete(id);
      showToast("success", "Entry deleted.");
      await load();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  // Mount-time load: the view has no reactive inputs, so onMount is both
  // correct and immune to an $effect re-running on unrelated state.
  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Passwords" subtitle="Encrypted credential vault">
  {#snippet actions()}
    {#if status && !status.is_locked}
      <button class="btn btn-primary btn-sm" onclick={() => (showAdd = true)}>+ Add</button>
      <button class="btn btn-sm" onclick={() => (showFactors = true)}>Vault factors</button>
      <button class="btn btn-sm" onclick={lock} disabled={busy}>Lock</button>
    {/if}
  {/snippet}
</PageHeader>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else if status}
  <div class="flex flex-wrap gap-2 mb-4">
    <StatusBadge label={status.is_locked ? "locked" : "unlocked"} ok={!status.is_locked} />
    <StatusBadge label={`${status.password_count} entries`} kind="neutral" />
  </div>

  {#if status.is_locked && !vaultInitialized}
    <div class="card bg-base-200 max-w-sm">
      <div class="card-body">
        <h2 class="card-title text-base">Create your vault</h2>
        <p class="text-sm">Your personal entries are sealed with your own passphrase. Nobody else can open them.</p>
        <input type="password" class="input input-bordered" aria-label="Passphrase" placeholder={`Passphrase (${MIN_PASSPHRASE_LENGTH}+ characters)`} bind:value={passphrase} />
        <input type="password" class="input input-bordered" aria-label="Confirm passphrase" placeholder="Confirm passphrase" bind:value={passphraseConfirm} />
        <button class="btn btn-primary btn-sm w-fit" onclick={createVault} disabled={busy || passphrase.length < MIN_PASSPHRASE_LENGTH || passphrase !== passphraseConfirm}>Create vault</button>
        {#if passkeysOffered}
          <div class="divider my-1 text-xs">or</div>
          <button class="btn btn-sm w-fit" onclick={createVaultWithPasskey} disabled={busy}>Create with a passkey</button>
        {/if}
      </div>
    </div>
  {:else if status.is_locked && recovering}
    <div class="card bg-base-200 max-w-sm">
      <div class="card-body">
        <h2 class="card-title text-base">Recover your vault</h2>
        <p class="text-sm">Enter your recovery code and choose a new passphrase. The code works once; you will get a new one.</p>
        {#if rErr}<Alert kind="error"><span>{rErr}</span></Alert>{/if}
        <input class="input input-bordered font-mono" aria-label="Recovery code" placeholder="ABCD-EFGH-…" autocomplete="off" bind:value={rCode} />
        <input type="password" class="input input-bordered" aria-label="New passphrase" placeholder={`New passphrase (${MIN_PASSPHRASE_LENGTH}+ characters)`} bind:value={rPassphrase} />
        <input type="password" class="input input-bordered" aria-label="Confirm new passphrase" placeholder="Confirm new passphrase" bind:value={rConfirm} />
        <div class="flex flex-wrap gap-2">
          <button class="btn btn-primary btn-sm" onclick={recover} disabled={busy || rCode.trim() === "" || rPassphrase.length < MIN_PASSPHRASE_LENGTH || rPassphrase !== rConfirm}>Recover vault</button>
          {#if passkeysOffered}
            <button class="btn btn-sm" onclick={recoverWithPasskey} disabled={busy || rCode.trim() === ""}>Recover with a new passkey</button>
          {/if}
          <button class="btn btn-ghost btn-sm" onclick={() => { recovering = false; rErr = null; }} disabled={busy}>Back to unlock</button>
        </div>
      </div>
    </div>
  {:else if status.is_locked}
    <div class="card bg-base-200 max-w-sm">
      <div class="card-body">
        <h2 class="card-title text-base">Unlock vault</h2>
        <input type="password" class="input input-bordered" aria-label="Passphrase" placeholder="Passphrase" bind:value={passphrase} />
        <div class="flex flex-wrap gap-2">
          <button class="btn btn-primary btn-sm" onclick={unlock} disabled={busy || passphrase === ""}>Unlock</button>
          {#if hasPasskey(vault)}
            <button class="btn btn-sm" onclick={unlockWithPasskey} disabled={busy}>Unlock with passkey</button>
          {/if}
          {#if hasKeyFactor(vault)}
            <button class="btn btn-sm" onclick={unlockWithXkey} disabled={busy}>Unlock with xKey</button>
          {/if}
          <button class="btn btn-ghost btn-sm" onclick={() => (recovering = true)} disabled={busy}>Use recovery code</button>
        </div>
      </div>
    </div>
  {:else}
    <div class="overflow-x-auto">
      <table class="table table-sm">
        <caption class="sr-only">Password vault entries</caption>
        <thead><tr><th scope="col">Name</th><th scope="col">Username</th><th scope="col">URL</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
        <tbody>
          {#each entries as e (e.id)}
            <tr>
              <td>{e.name}</td>
              <td>{e.username ?? "—"}</td>
              <td>{e.url ?? "—"}</td>
              <td class="text-right"><button class="btn btn-ghost btn-xs text-error" onclick={() => del(e.id)}>Delete</button></td>
            </tr>
          {/each}
          {#if entries.length === 0}
            <tr><td colspan="4" class="text-center text-base-content/60 py-6">No entries.</td></tr>
          {/if}
        </tbody>
      </table>
    </div>
  {/if}
{/if}

{#if recoveryCode}
  <Modal open={recoveryCode !== null} onClose={() => {}} labelledby="recovery-code-title">
      <h3 id="recovery-code-title" class="text-lg font-semibold mb-4">Your recovery code</h3>
      <Alert kind="warning" class="mb-3"><span>Store this now. It will not be shown again, and any earlier code no longer works. It is the only way back into your personal entries if you lose your other factors.</span></Alert>
      <code class="block font-mono text-lg break-all select-all p-3 bg-base-200 rounded">{recoveryCode}</code>
      <div class="modal-action">
        <button class="btn btn-primary" onclick={() => (recoveryCode = null)}>I have stored it</button>
      </div>
  </Modal>
{/if}

{#if showFactors}
  <VaultFactors onClose={() => { showFactors = false; void load(); }} />
{/if}

{#if showAdd}
  <Modal open={showAdd} onClose={() => (showAdd = false)} labelledby="add-password-title">
      <h3 id="add-password-title" class="text-lg font-semibold mb-4">Add entry</h3>
      {#if aErr}<Alert kind="error" class="mb-3"><span>{aErr}</span></Alert>{/if}
      <div class="space-y-3">
        <input class="input input-bordered w-full" aria-label="Name" placeholder="Name" bind:value={aName} />
        <input class="input input-bordered w-full" aria-label="Username" placeholder="Username" bind:value={aUsername} />
        <input type="password" class="input input-bordered w-full" aria-label="Password" placeholder="Password" bind:value={aPassword} />
      </div>
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (showAdd = false)} disabled={busy}>Cancel</button>
        <button class="btn btn-primary" onclick={add} disabled={busy || aName === "" || aPassword === ""}>Add</button>
      </div>
  </Modal>
{/if}
