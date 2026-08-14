<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import { can } from "$stores/session.svelte.ts";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import type { FrostKeyInfo, FrostKeyPackage } from "@go-xkms/sdk";

  let keys = $state<FrostKeyInfo[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);

  let showGenerate = $state(false);
  let gKeyID = $state("");
  let gAlgorithm = $state("ed25519");
  let gThreshold = $state(2);
  let gTotal = $state(3);
  let gDealer = $state(true);
  let gParticipants = $state("");
  let gErr = $state<string | null>(null);

  // Dealer-mode generation returns one key package per participant, each
  // holding that participant's SECRET share. The shares stay masked until the
  // operator explicitly reveals them, matching how Key detail gates raw key
  // material export.
  let packages = $state<FrostKeyPackage[]>([]);
  let revealed = $state<Record<number, boolean>>({});

  let showVerify = $state(false);
  let vKeyID = $state("");
  let vMessage = $state("");
  let vSignature = $state("");
  let vErr = $state<string | null>(null);

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      const resp = await getSDKClient().frost.listKeys();
      keys = resp.keys ?? [];
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function generate(): Promise<void> {
    busy = true;
    gErr = null;
    try {
      const participants = gParticipants
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s !== "");
      const resp = await getSDKClient().frost.generateKey({
        key_id: gKeyID === "" ? undefined : gKeyID,
        algorithm: gAlgorithm,
        threshold: gThreshold,
        total: gTotal,
        dealer_mode: gDealer,
        participants: participants.length > 0 ? participants : undefined,
      });
      packages = resp.packages ?? [];
      revealed = {};
      showToast("success", `FROST key "${resp.key_id}" generated (${resp.threshold}-of-${resp.total}).`);
      showGenerate = false;
      gKeyID = "";
      await load();
    } catch (e) {
      gErr = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function del(id: string): Promise<void> {
    try {
      await getSDKClient().frost.deleteKey(id);
      showToast("success", `FROST key "${id}" deleted.`);
      await load();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  async function verify(): Promise<void> {
    busy = true;
    vErr = null;
    try {
      const resp = await getSDKClient().frost.verify({
        key_id: vKeyID,
        message: vMessage,
        signature: vSignature,
      });
      showToast(resp.valid ? "success" : "warning", `${resp.valid ? "Valid" : "INVALID"} — ${resp.message}`);
      showVerify = false;
    } catch (e) {
      vErr = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  function copy(text: string): void {
    void navigator.clipboard.writeText(text);
    showToast("success", "Copied to clipboard.");
  }

  function shortHex(hex: string): string {
    return hex.length > 24 ? `${hex.slice(0, 12)}…${hex.slice(-8)}` : hex;
  }

  onMount(() => {
    void load();
  });
</script>

<PageHeader title="FROST" subtitle="Flexible Round-Optimized Schnorr Threshold signatures">
  {#snippet actions()}
    {#if can("keys", "verify")}
      <button class="btn btn-ghost btn-sm" onclick={() => (showVerify = true)}>Verify</button>
    {/if}
    {#if can("keys", "create")}
      <button class="btn btn-primary btn-sm" onclick={() => (showGenerate = true)}>+ Generate</button>
    {/if}
  {/snippet}
</PageHeader>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <div class="overflow-x-auto">
    <table class="table table-sm">
      <caption class="sr-only">FROST threshold keys</caption>
      <thead>
        <tr>
          <th scope="col">Key ID</th><th scope="col">Algorithm</th><th scope="col">Threshold</th>
          <th scope="col">Participant</th><th scope="col">Group public key</th><th scope="col"><span class="sr-only">Actions</span></th>
        </tr>
      </thead>
      <tbody>
        {#each keys as k (k.key_id)}
          <tr>
            <td class="font-mono">{k.key_id}</td>
            <td>{k.algorithm}</td>
            <td>{k.threshold}-of-{k.total}</td>
            <td>{k.participant_id}</td>
            <td class="font-mono text-xs">{shortHex(k.group_public_key)}</td>
            <td class="text-right">
              <button class="btn btn-ghost btn-xs" onclick={() => copy(k.group_public_key)}>Copy key</button>
              {#if can("keys", "delete")}
                <button class="btn btn-ghost btn-xs text-error" onclick={() => del(k.key_id)}>Delete</button>
              {/if}
            </td>
          </tr>
        {/each}
        {#if keys.length === 0}
          <tr><td colspan="6" class="text-center text-base-content/60 py-6">No FROST keys.</td></tr>
        {/if}
      </tbody>
    </table>
  </div>

  <Alert kind="info" class="mt-6">
    <span>
      Signing runs over three rounds (commit, sign, aggregate) across separate
      participants and is coordinated with <code>xkmsctl frost</code>. This
      screen manages the threshold keys and verifies finished signatures.
    </span>
  </Alert>
{/if}

{#if packages.length > 0}
  <div class="card bg-base-200 mt-6">
    <div class="card-body">
      <h3 class="card-title text-base">Dealer packages</h3>
      <Alert kind="warning">
        <span>
          Each package holds one participant's <strong>secret share</strong>.
          Distribute them over separate confidential channels and do not retain
          a copy here — reloading this screen discards them.
        </span>
      </Alert>
      <div class="overflow-x-auto">
        <table class="table table-sm">
          <caption class="sr-only">Dealer package shares by participant</caption>
          <thead><tr><th scope="col">Participant</th><th scope="col">Secret share</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {#each packages as p (p.participant_id)}
              <tr>
                <td>{p.participant_id}{p.participant_name ? ` (${p.participant_name})` : ""}</td>
                <td class="font-mono text-xs">
                  {#if revealed[p.participant_id]}
                    {p.secret_share}
                  {:else}
                    ••••••••••••••••
                  {/if}
                </td>
                <td class="text-right">
                  <button
                    class="btn btn-ghost btn-xs"
                    onclick={() => (revealed = { ...revealed, [p.participant_id]: !revealed[p.participant_id] })}
                  >
                    {revealed[p.participant_id] ? "Hide" : "Reveal"}
                  </button>
                  <button class="btn btn-ghost btn-xs" onclick={() => copy(p.secret_share)}>Copy</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <div class="card-actions justify-end">
        <button class="btn btn-sm" onclick={() => { packages = []; revealed = {}; }}>Discard</button>
      </div>
    </div>
  </div>
{/if}

{#if showGenerate}
  <Modal open={showGenerate} onClose={() => (showGenerate = false)} labelledby="generate-frost-title">
      <h3 id="generate-frost-title" class="text-lg font-semibold mb-4">Generate FROST key</h3>
      {#if gErr}<Alert kind="error" class="mb-3"><span>{gErr}</span></Alert>{/if}
      <div class="space-y-3">
        <input class="input input-bordered w-full" aria-label="Key ID" placeholder="Key ID (optional)" bind:value={gKeyID} />
        <select class="select select-bordered w-full" aria-label="Algorithm" bind:value={gAlgorithm}>
          <option>ed25519</option><option>secp256k1</option><option>p256</option>
        </select>
        <div class="flex gap-3">
          <label class="form-control w-full">
            <span class="label-text">Threshold</span>
            <input class="input input-bordered w-full" type="number" min="1" bind:value={gThreshold} />
          </label>
          <label class="form-control w-full">
            <span class="label-text">Total</span>
            <input class="input input-bordered w-full" type="number" min="1" bind:value={gTotal} />
          </label>
        </div>
        <input
          class="input input-bordered w-full"
          aria-label="Participants"
          placeholder="Participants (comma-separated names, optional)"
          bind:value={gParticipants}
        />
        <label class="label cursor-pointer justify-start gap-3">
          <input type="checkbox" class="checkbox" bind:checked={gDealer} />
          <span class="label-text">Dealer mode (this server generates every share)</span>
        </label>
      </div>
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (showGenerate = false)} disabled={busy}>Cancel</button>
        <button class="btn btn-primary" onclick={generate} disabled={busy || gThreshold > gTotal || gThreshold < 1}>
          Generate
        </button>
      </div>
  </Modal>
{/if}

{#if showVerify}
  <Modal open={showVerify} onClose={() => (showVerify = false)} labelledby="verify-frost-title">
      <h3 id="verify-frost-title" class="text-lg font-semibold mb-4">Verify FROST signature</h3>
      {#if vErr}<Alert kind="error" class="mb-3"><span>{vErr}</span></Alert>{/if}
      <div class="space-y-3">
        <input class="input input-bordered w-full" aria-label="Key ID" placeholder="Key ID" bind:value={vKeyID} />
        <input class="input input-bordered w-full font-mono" aria-label="Message (hex)" placeholder="Message (hex)" bind:value={vMessage} />
        <input class="input input-bordered w-full font-mono" aria-label="Signature (hex)" placeholder="Signature (hex)" bind:value={vSignature} />
      </div>
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (showVerify = false)} disabled={busy}>Cancel</button>
        <button
          class="btn btn-primary"
          onclick={verify}
          disabled={busy || vKeyID === "" || vMessage === "" || vSignature === ""}
        >
          Verify
        </button>
      </div>
  </Modal>
{/if}
