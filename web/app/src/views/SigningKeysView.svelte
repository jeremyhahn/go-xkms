<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import type { SetSigningKeyBindingRequest, SigningKeyBinding, SigningKeyResolution } from "@go-xkms/sdk";

  let bindings = $state<SigningKeyBinding[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);

  // The set dialog.
  let showSet = $state(false);
  let sRepository = $state("");
  let sKeyId = $state("");
  let sBackend = $state("");
  let sBusy = $state(false);
  const sInvalid = $derived(sRepository.trim() === "" || sKeyId.trim() === "");

  let deleteTarget = $state<SigningKeyBinding | null>(null);
  let deleteBusy = $state(false);

  // The resolve lookup.
  let rRepository = $state("");
  let rBusy = $state(false);
  let resolution = $state<SigningKeyResolution | null>(null);

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  function fmtTime(iso: string): string {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
  }

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      const resp = await getSDKClient().signingKeys.list();
      bindings = resp.bindings;
    } catch (e) {
      error = message(e);
    } finally {
      loading = false;
    }
  }

  function openSet(): void {
    sRepository = "";
    sKeyId = "";
    sBackend = "";
    showSet = true;
  }

  async function save(): Promise<void> {
    sBusy = true;
    try {
      const req: SetSigningKeyBindingRequest = { repository: sRepository.trim(), key_id: sKeyId.trim() };
      if (sBackend.trim() !== "") req.backend = sBackend.trim();
      const b = await getSDKClient().signingKeys.set(req);
      showSet = false;
      showToast("success", `Signing key "${b.key_id}" bound to ${b.repository}.`);
      await load();
    } catch (e) {
      showToast("error", message(e));
    } finally {
      sBusy = false;
    }
  }

  async function confirmDelete(): Promise<void> {
    if (deleteTarget === null) return;
    const repository = deleteTarget.repository;
    deleteBusy = true;
    try {
      await getSDKClient().signingKeys.delete(repository);
      showToast("success", `Binding for ${repository} deleted; the release key signs it.`);
      deleteTarget = null;
      await load();
    } catch (e) {
      showToast("error", message(e));
    } finally {
      deleteBusy = false;
    }
  }

  async function lookUp(): Promise<void> {
    rBusy = true;
    resolution = null;
    try {
      resolution = await getSDKClient().signingKeys.resolve(rRepository.trim());
    } catch (e) {
      showToast("error", message(e));
    } finally {
      rBusy = false;
    }
  }

  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Signing Keys" subtitle="The key that signs each repository's releases; the release key signs every repository not named here">
  {#snippet actions()}
    <button class="btn btn-primary btn-sm" onclick={openSet}>Set binding</button>
  {/snippet}
</PageHeader>

{#if loading}
  <div class="flex justify-center py-8"><span class="loading loading-spinner"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else if bindings.length === 0}
  <p class="text-sm text-base-content/70">No bindings: the tenant release key signs every repository.</p>
{:else}
  <table class="table table-sm">
    <thead>
      <tr>
        <th scope="col">Repository</th>
        <th scope="col">Key ID</th>
        <th scope="col">Backend</th>
        <th scope="col">Updated</th>
        <th scope="col"><span class="sr-only">Actions</span></th>
      </tr>
    </thead>
    <tbody>
      {#each bindings as b (b.repository)}
        <tr>
          <td class="font-mono">{b.repository}</td>
          <td class="font-mono">{b.key_id}</td>
          <td>{b.backend ?? ""}</td>
          <td><time datetime={b.updated_at}>{fmtTime(b.updated_at)}</time></td>
          <td class="text-right">
            <button
              class="btn btn-ghost btn-xs text-error"
              aria-label={`Delete binding for ${b.repository}`}
              onclick={() => (deleteTarget = b)}>Delete</button
            >
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}

<section class="mt-8 space-y-3">
  <h2 class="text-lg font-semibold">Resolve</h2>
  <form
    class="flex gap-2"
    onsubmit={(e) => {
      e.preventDefault();
      void lookUp();
    }}
  >
    <input
      class="input input-bordered input-sm w-full max-w-md"
      aria-label="Repository to resolve"
      placeholder="owner/repository"
      bind:value={rRepository}
    />
    <button class="btn btn-sm" type="submit" disabled={rBusy || rRepository.trim() === ""}>Resolve</button>
  </form>
  {#if resolution}
    <p class="text-sm" data-testid="resolve-result">
      {#if resolution.default}
        No binding: the tenant release key signs {resolution.repository}.
      {:else}
        {resolution.repository} is signed by <span class="font-mono">{resolution.key_id}</span>{#if resolution.backend}
          on backend {resolution.backend}{/if}.
      {/if}
    </p>
  {/if}
</section>

{#if showSet}
  <Modal open={showSet} onClose={() => (showSet = false)} labelledby="set-signing-key-title">
    <h3 id="set-signing-key-title" class="text-lg font-semibold mb-4">Set signing key binding</h3>
    <div class="space-y-3">
      <input class="input input-bordered w-full" aria-label="Repository" placeholder="owner/repository" bind:value={sRepository} />
      <input class="input input-bordered w-full" aria-label="Key ID" placeholder="Key ID" bind:value={sKeyId} />
      <input class="input input-bordered w-full" aria-label="Backend" placeholder="Backend (optional)" bind:value={sBackend} />
    </div>
    <div class="modal-action">
      <button class="btn btn-ghost" onclick={() => (showSet = false)} disabled={sBusy}>Close</button>
      <button class="btn btn-primary" onclick={save} disabled={sBusy || sInvalid}>
        {#if sBusy}<span class="loading loading-spinner loading-xs"></span>{/if}
        Save
      </button>
    </div>
  </Modal>
{/if}

{#if deleteTarget}
  <Modal open={deleteTarget !== null} onClose={() => (deleteTarget = null)} labelledby="delete-signing-key-title">
    <h3 id="delete-signing-key-title" class="text-lg font-semibold mb-4">Delete the binding for "{deleteTarget.repository}"?</h3>
    <p class="text-sm text-base-content/70">The tenant release key signs this repository from then on.</p>
    <div class="modal-action">
      <button class="btn btn-ghost" onclick={() => (deleteTarget = null)} disabled={deleteBusy}>Cancel</button>
      <button class="btn btn-error" onclick={confirmDelete} disabled={deleteBusy}>
        {#if deleteBusy}<span class="loading loading-spinner loading-xs"></span>{/if}
        Delete
      </button>
    </div>
  </Modal>
{/if}
