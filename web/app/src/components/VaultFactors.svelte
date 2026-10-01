<script lang="ts">
  // The caller's own password-vault factors, managed while the session is
  // open: list them, add a passphrase, change a passphrase in place, remove
  // a factor. The server refuses removing the last passphrase or passkey and
  // never removes the recovery code; its refusal is shown here verbatim.
  import { onMount } from "svelte";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import type { PasswordVaultFactor, PasswordVaultStatusResponse } from "@go-xkms/sdk";
  import { MIN_PASSPHRASE_LENGTH, enrollPasskey, factorTypeLabel } from "$lib/vault.ts";

  interface Props {
    onClose: () => void;
  }
  let { onClose }: Props = $props();

  let vault = $state<PasswordVaultStatusResponse | null>(null);
  const factors = $derived(vault?.factors ?? []);
  let error = $state<string | null>(null);
  let busy = $state(false);

  // One passphrase form serves both adding and changing: changing names the
  // factor it replaces.
  let changing = $state<PasswordVaultFactor | null>(null);
  let passphrase = $state("");
  let confirm = $state("");
  let label = $state("");

  const passphraseOK = $derived(passphrase.length >= MIN_PASSPHRASE_LENGTH && passphrase === confirm);

  function resetForm(): void {
    changing = null;
    passphrase = "";
    confirm = "";
    label = "";
  }

  async function load(): Promise<void> {
    try {
      vault = await getSDKClient().passwords.vaultStatus();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  async function run(action: () => Promise<unknown>, done: string): Promise<void> {
    busy = true;
    error = null;
    try {
      await action();
      showToast("success", done);
      resetForm();
      await load();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  function submitPassphrase(): Promise<void> {
    const target = changing;
    if (target) {
      return run(
        () => getSDKClient().passwords.vaultRotate(target.id, { factor: "passphrase", passphrase, label: target.label }),
        "Passphrase changed.",
      );
    }
    return run(
      () => getSDKClient().passwords.vaultEnroll({ factor: "passphrase", passphrase, label: label || "web console" }),
      "Passphrase added.",
    );
  }

  // A passkey is created in this browser for the server's relying party;
  // a browser or key without the PRF extension is reported, never replaced.
  function addPasskey(): Promise<void> {
    const status = vault!;
    return run(async () => {
      const cred = await enrollPasskey(status, label || "passkey");
      await getSDKClient().passwords.vaultEnroll(cred);
    }, "Passkey added.");
  }

  function remove(f: PasswordVaultFactor): Promise<void> {
    return run(() => getSDKClient().passwords.vaultRemoveFactor(f.id), "Factor removed.");
  }

  function name(f: PasswordVaultFactor): string {
    return f.label || factorTypeLabel(f.factor);
  }

  onMount(() => {
    void load();
  });
</script>

<Modal open={true} {onClose} labelledby="vault-factors-title">
  <h3 id="vault-factors-title" class="text-lg font-semibold mb-4">Vault factors</h3>
  {#if error}<Alert kind="error" class="mb-3"><span>{error}</span></Alert>{/if}

  <table class="table table-sm mb-4">
    <caption class="sr-only">Factors that open your vault</caption>
    <thead><tr><th scope="col">Factor</th><th scope="col">Type</th><th scope="col">Added</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
    <tbody>
      {#each factors as f (f.id)}
        <tr>
          <td>{f.factor === "recovery" ? "—" : name(f)}</td>
          <td>{factorTypeLabel(f.factor)}</td>
          <td>{new Date(f.created_at).toLocaleDateString()}</td>
          <td class="text-right whitespace-nowrap">
            {#if f.factor === "passphrase"}
              <button class="btn btn-ghost btn-xs" aria-label={`Change ${name(f)}`} onclick={() => { resetForm(); changing = f; }} disabled={busy}>Change</button>
            {/if}
            {#if f.factor !== "recovery"}
              <button class="btn btn-ghost btn-xs text-error" aria-label={`Remove ${name(f)}`} onclick={() => remove(f)} disabled={busy}>Remove</button>
            {/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>

  <div class="space-y-2">
    <h4 class="font-medium text-sm">{changing ? `Change "${name(changing)}"` : "Add a passphrase"}</h4>
    <input type="password" class="input input-bordered w-full" aria-label="New passphrase" placeholder={`New passphrase (${MIN_PASSPHRASE_LENGTH}+ characters)`} bind:value={passphrase} />
    <input type="password" class="input input-bordered w-full" aria-label="Confirm new passphrase" placeholder="Confirm new passphrase" bind:value={confirm} />
    {#if !changing}
      <input class="input input-bordered w-full" aria-label="Label" placeholder="Label (e.g. laptop)" bind:value={label} />
    {/if}
  </div>

  <div class="modal-action">
    {#if changing}
      <button class="btn btn-ghost" onclick={resetForm} disabled={busy}>Cancel change</button>
      <button class="btn btn-primary" onclick={submitPassphrase} disabled={busy || !passphraseOK}>Change passphrase</button>
    {:else}
      <button class="btn btn-ghost" onclick={onClose} disabled={busy}>Close</button>
      {#if vault?.passkey_rp_id}
        <button class="btn" onclick={addPasskey} disabled={busy}>Add passkey</button>
      {/if}
      <button class="btn btn-primary" onclick={submitPassphrase} disabled={busy || !passphraseOK}>Add passphrase</button>
    {/if}
  </div>
</Modal>
