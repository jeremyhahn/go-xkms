<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import { can } from "$stores/session.svelte.ts";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import type { AuthFactorRecord, UserInfo } from "@go-xkms/sdk";

  // Factors are listed per user — the server requires a user_id and has no
  // "all factors" route, so the screen starts from a user selection.
  let users = $state<UserInfo[]>([]);
  let selectedUserID = $state<number | null>(null);
  let factors = $state<AuthFactorRecord[]>([]);

  let error = $state<string | null>(null);
  let loading = $state(true);
  let loadingFactors = $state(false);
  let busy = $state(false);

  let showAdd = $state(false);
  let aType = $state("fido2");
  let aLabel = $state("");
  let aCredential = $state("");
  let aSPKI = $state("");
  let aErr = $state<string | null>(null);

  let relabelTarget = $state<AuthFactorRecord | null>(null);
  let rLabel = $state("");
  let rErr = $state<string | null>(null);

  const canManage = $derived(can("users", "update"));

  async function loadUsers(): Promise<void> {
    loading = true;
    error = null;
    try {
      const resp = await getSDKClient().users.list();
      users = resp.users ?? [];
      const first = users[0];
      if (first !== undefined && selectedUserID === null) {
        selectedUserID = Number(first.id);
        await loadFactors();
      }
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function loadFactors(): Promise<void> {
    if (selectedUserID === null) {
      factors = [];
      return;
    }
    loadingFactors = true;
    error = null;
    try {
      const resp = await getSDKClient().factors.list(selectedUserID);
      factors = resp.factors ?? [];
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loadingFactors = false;
    }
  }

  async function add(): Promise<void> {
    if (selectedUserID === null) {
      return;
    }
    busy = true;
    aErr = null;
    try {
      await getSDKClient().factors.add({
        user_id: selectedUserID,
        type: aType,
        label: aLabel,
        credential: aCredential,
        spki_credential: aSPKI === "" ? undefined : aSPKI,
        created_by: "admin",
      });
      showToast("success", `Factor "${aLabel}" enrolled.`);
      showAdd = false;
      aLabel = "";
      aCredential = "";
      aSPKI = "";
      await loadFactors();
    } catch (e) {
      aErr = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  // force is offered only after an unforced revoke fails, so the operator has
  // to see the last-active-factor refusal before overriding it — removing a
  // user's final factor also deactivates the account.
  async function remove(f: AuthFactorRecord, force: boolean): Promise<void> {
    try {
      await getSDKClient().factors.remove(f.id, force);
      showToast("success", `Factor "${f.label ?? f.id}" revoked.`);
      await loadFactors();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  async function relabel(): Promise<void> {
    if (relabelTarget === null) {
      return;
    }
    busy = true;
    rErr = null;
    try {
      await getSDKClient().factors.relabel(relabelTarget.id, { label: rLabel });
      showToast("success", "Factor relabelled.");
      relabelTarget = null;
      await loadFactors();
    } catch (e) {
      rErr = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  function onUserChange(): void {
    void loadFactors();
  }

  function fmt(ts: string | undefined): string {
    return ts === undefined || ts === "" ? "—" : new Date(ts).toLocaleString();
  }

  onMount(() => {
    void loadUsers();
  });
</script>

<PageHeader title="Auth Factors" subtitle="Per-user N-factor enrolment (mTLS, FIDO2, PIV)">
  {#snippet actions()}
    {#if canManage}
      <button
        class="btn btn-primary btn-sm"
        onclick={() => (showAdd = true)}
        disabled={selectedUserID === null}
      >
        + Enroll factor
      </button>
    {/if}
  {/snippet}
</PageHeader>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <div class="mb-4 max-w-sm">
    <label class="form-control">
      <span class="label-text">User</span>
      <select class="select select-bordered w-full" bind:value={selectedUserID} onchange={onUserChange}>
        {#each users as u (u.id)}
          <option value={Number(u.id)}>{u.username}</option>
        {/each}
      </select>
    </label>
  </div>

  {#if loadingFactors}
    <div class="flex justify-center py-8"><span class="loading loading-spinner"></span></div>
  {:else}
    <div class="overflow-x-auto">
      <table class="table table-sm">
        <caption class="sr-only">Auth factors for the selected user</caption>
        <thead>
          <tr>
            <th scope="col">Label</th><th scope="col">Type</th><th scope="col">Registered</th>
            <th scope="col">Last used</th><th scope="col">Status</th><th scope="col"><span class="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {#each factors as f (f.id)}
            <tr class={f.revoked_at ? "opacity-50" : ""}>
              <td>{f.label ?? f.id}</td>
              <td><span class="badge badge-ghost">{f.type}</span></td>
              <td class="text-xs">{fmt(f.registered_at)}</td>
              <td class="text-xs">{fmt(f.last_used_at)}</td>
              <td>
                {#if f.revoked_at}
                  <span class="badge badge-error badge-sm">revoked</span>
                {:else}
                  <span class="badge badge-success badge-sm">active</span>
                {/if}
              </td>
              <td class="text-right">
                {#if canManage && !f.revoked_at}
                  <button
                    class="btn btn-ghost btn-xs"
                    onclick={() => { relabelTarget = f; rLabel = f.label ?? ""; rErr = null; }}
                  >
                    Relabel
                  </button>
                  <button class="btn btn-ghost btn-xs text-error" onclick={() => remove(f, false)}>Revoke</button>
                  <button class="btn btn-ghost btn-xs text-error" onclick={() => remove(f, true)}>Force revoke</button>
                {/if}
              </td>
            </tr>
          {/each}
          {#if factors.length === 0}
            <tr><td colspan="6" class="text-center text-base-content/60 py-6">No factors enrolled.</td></tr>
          {/if}
        </tbody>
      </table>
    </div>

    <Alert kind="info" class="mt-6">
      <span>
        Revoking a user's last active factor is refused unless forced, and a
        forced revoke deactivates the account. Enrolling a passkey from the
        holder's own browser is done from the Register screen; this screen
        enrolls a credential an administrator already holds.
      </span>
    </Alert>
  {/if}
{/if}

{#if showAdd}
  <Modal open={showAdd} onClose={() => (showAdd = false)} labelledby="enroll-factor-title">
      <h3 id="enroll-factor-title" class="text-lg font-semibold mb-4">Enroll auth factor</h3>
      {#if aErr}<Alert kind="error" class="mb-3"><span>{aErr}</span></Alert>{/if}
      <div class="space-y-3">
        <select class="select select-bordered w-full" aria-label="Factor type" bind:value={aType}>
          <option value="fido2">fido2</option>
          <option value="mtls">mtls</option>
          <option value="piv">piv</option>
        </select>
        <input class="input input-bordered w-full" aria-label="Label" placeholder="Label" bind:value={aLabel} />
        <label class="form-control">
          <span class="label-text">
            Credential (base64) —
            {aType === "fido2" ? "WebAuthn credential ID" : "SHA-256 of the certificate"}
          </span>
          <input class="input input-bordered w-full font-mono" bind:value={aCredential} />
        </label>
        {#if aType !== "fido2"}
          <label class="form-control">
            <span class="label-text">SPKI credential (base64, optional — renewal-stable)</span>
            <input class="input input-bordered w-full font-mono" bind:value={aSPKI} />
          </label>
        {/if}
      </div>
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (showAdd = false)} disabled={busy}>Cancel</button>
        <button class="btn btn-primary" onclick={add} disabled={busy || aLabel === "" || aCredential === ""}>
          Enroll
        </button>
      </div>
  </Modal>
{/if}

{#if relabelTarget}
  <Modal open={relabelTarget !== null} onClose={() => (relabelTarget = null)} labelledby="relabel-factor-title">
      <h3 id="relabel-factor-title" class="text-lg font-semibold mb-4">Relabel factor</h3>
      {#if rErr}<Alert kind="error" class="mb-3"><span>{rErr}</span></Alert>{/if}
      <input class="input input-bordered w-full" aria-label="Label" placeholder="Label" bind:value={rLabel} />
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (relabelTarget = null)} disabled={busy}>Cancel</button>
        <button class="btn btn-primary" onclick={relabel} disabled={busy || rLabel === ""}>Save</button>
      </div>
  </Modal>
{/if}
