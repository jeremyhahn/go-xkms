<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import type { FrostAggregateResponse, FrostCommitment, FrostSignatureShare } from "@go-xkms/sdk";

  // This node's round state. The two secret nonces live only here: they are
  // never rendered, toasted or logged, and are dropped after the sign round.
  interface Round {
    participantId: number;
    sessionId: string;
    hidingNonce: string;
    bindingNonce: string;
    commitment: FrostCommitment;
  }

  let keyId = $state("");
  let message = $state("");
  let round = $state<Round | null>(null);
  let ownCommitment = $state<FrostCommitment | null>(null);
  let sessionId = $state("");
  let commitmentsJson = $state("");
  let commitments = $state<FrostCommitment[]>([]);
  let ownShare = $state<FrostSignatureShare | null>(null);
  let sharesJson = $state("");
  let verify = $state(true);
  let result = $state<FrostAggregateResponse | null>(null);

  let busy = $state(false);
  let error = $state<string | null>(null);
  let commitmentsErr = $state<string | null>(null);
  let sharesErr = $state<string | null>(null);

  function toHex(s: string): string {
    return Array.from(new TextEncoder().encode(s), (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function parseArray<T>(text: string): T[] | null {
    if (text.trim() === "") return [];
    try {
      const v: unknown = JSON.parse(text);
      return Array.isArray(v) ? (v as T[]) : null;
    } catch {
      return null;
    }
  }

  function errText(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  async function generate(): Promise<void> {
    busy = true;
    error = null;
    try {
      const r = await getSDKClient().frost.generateNonces(keyId);
      const c = { participant_id: r.participant_id, hiding_commitment: r.hiding_commitment, binding_commitment: r.binding_commitment };
      round = { participantId: r.participant_id, sessionId: r.session_id, hidingNonce: r.hiding_nonce, bindingNonce: r.binding_nonce, commitment: c };
      ownCommitment = c;
      sessionId = r.session_id;
      ownShare = null;
      result = null;
    } catch (e) {
      error = errText(e);
    } finally {
      busy = false;
    }
  }

  async function sign(): Promise<void> {
    if (!round) return;
    commitmentsErr = null;
    const others = parseArray<FrostCommitment>(commitmentsJson);
    if (others === null) {
      commitmentsErr = "Commitments must be a JSON array.";
      return;
    }
    const r = round;
    // Single use: the nonces leave component state before the call returns.
    round = null;
    busy = true;
    error = null;
    const all = [...others, r.commitment];
    try {
      const resp = await getSDKClient().frost.signRound(keyId, {
        key_id: keyId,
        message: toHex(message),
        session_id: r.sessionId,
        hiding_nonce: r.hidingNonce,
        binding_nonce: r.bindingNonce,
        hiding_commitment: r.commitment.hiding_commitment,
        binding_commitment: r.commitment.binding_commitment,
        commitments: all,
      });
      commitments = all;
      ownShare = { participant_id: resp.participant_id, session_id: resp.session_id, share: resp.signature_share };
    } catch (e) {
      error = errText(e);
    } finally {
      busy = false;
    }
  }

  async function aggregate(): Promise<void> {
    if (!ownShare) return;
    sharesErr = null;
    const others = parseArray<FrostSignatureShare>(sharesJson);
    if (others === null) {
      sharesErr = "Shares must be a JSON array.";
      return;
    }
    busy = true;
    error = null;
    try {
      result = await getSDKClient().frost.aggregate({
        key_id: keyId,
        message: toHex(message),
        commitments,
        shares: [...others, ownShare],
        verify,
      });
    } catch (e) {
      error = errText(e);
    } finally {
      busy = false;
    }
  }
</script>

<PageHeader title="FROST Signing" subtitle="This node's part of a FROST threshold signature" />

{#if error}<Alert kind="error" class="mb-4"><span>{error}</span></Alert>{/if}

<div class="grid gap-3 max-w-2xl mb-6">
  <label class="form-control">
    <span class="label-text">Key ID</span>
    <input class="input input-bordered w-full" aria-label="Key ID" bind:value={keyId} />
  </label>
  <label class="form-control">
    <span class="label-text">Message</span>
    <input class="input input-bordered w-full" aria-label="Message" bind:value={message} />
  </label>
</div>

<section class="mb-6">
  <h2 class="text-lg font-semibold mb-2">1. Generate nonces</h2>
  <button class="btn btn-primary btn-sm" onclick={generate} disabled={busy || keyId === ""}>Generate nonces</button>
  {#if ownCommitment}
    <div class="mt-3 space-y-1">
      <div class="flex gap-2"><span>Participant {ownCommitment.participant_id}</span></div>
      <div>Session: <code>{sessionId}</code></div>
      <div class="text-sm text-base-content/70">Share this commitment with the other participants:</div>
      <pre class="bg-base-200 p-2 rounded text-xs overflow-x-auto">{JSON.stringify(ownCommitment)}</pre>
    </div>
  {/if}
</section>

<section class="mb-6">
  <h2 class="text-lg font-semibold mb-2">2. Sign</h2>
  <textarea
    class="textarea textarea-bordered w-full font-mono text-xs"
    aria-label="Other commitments (JSON)"
    placeholder="[&#123;&quot;participant_id&quot;: 1, &quot;hiding_commitment&quot;: &quot;...&quot;, &quot;binding_commitment&quot;: &quot;...&quot;&#125;]"
    rows="3"
    bind:value={commitmentsJson}
  ></textarea>
  {#if commitmentsErr}<p class="text-error text-sm">{commitmentsErr}</p>{/if}
  <button class="btn btn-primary btn-sm mt-2" onclick={sign} disabled={busy || round === null}>Sign</button>
  {#if ownShare}
    <div class="mt-3 space-y-1">
      <div class="text-sm text-base-content/70">Share this signature share with the aggregator:</div>
      <pre class="bg-base-200 p-2 rounded text-xs overflow-x-auto">{JSON.stringify(ownShare)}</pre>
    </div>
  {/if}
</section>

<section class="mb-6">
  <h2 class="text-lg font-semibold mb-2">3. Aggregate</h2>
  <textarea
    class="textarea textarea-bordered w-full font-mono text-xs"
    aria-label="Other shares (JSON)"
    placeholder="[&#123;&quot;participant_id&quot;: 1, &quot;session_id&quot;: &quot;...&quot;, &quot;share&quot;: &quot;...&quot;&#125;]"
    rows="3"
    bind:value={sharesJson}
  ></textarea>
  {#if sharesErr}<p class="text-error text-sm">{sharesErr}</p>{/if}
  <label class="label cursor-pointer justify-start gap-2">
    <input type="checkbox" class="checkbox checkbox-sm" aria-label="Verify signature" bind:checked={verify} />
    <span class="label-text">Verify signature</span>
  </label>
  <button class="btn btn-primary btn-sm" onclick={aggregate} disabled={busy || ownShare === null}>Aggregate</button>
  {#if result}
    <div class="mt-3 space-y-1">
      <div class="flex gap-2">
        <StatusBadge label={result.verified ? "verified" : "not verified"} ok={result.verified} />
      </div>
      <pre class="bg-base-200 p-2 rounded text-xs overflow-x-auto">{result.signature}</pre>
    </div>
  {/if}
</section>
