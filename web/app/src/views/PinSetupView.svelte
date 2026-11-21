<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";

  // PINs are secrets: they live only in these inputs, are cleared after every
  // call, and never reach a toast, an alert or any rendered text.
  const MISMATCH = "The new PIN and its confirmation differ.";

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  let soCurrent = $state("");
  let soNew = $state("");
  let soConfirm = $state("");
  let soErr = $state<string | null>(null);
  let soBusy = $state(false);

  async function setSO(): Promise<void> {
    soErr = null;
    if (soNew !== soConfirm) {
      soErr = MISMATCH;
      return;
    }
    soBusy = true;
    try {
      await getSDKClient().pin.setSO({ current_so_pin: soCurrent, new_so_pin: soNew });
      showToast("success", "SO PIN set.");
    } catch (e) {
      soErr = message(e);
    } finally {
      soCurrent = ""; soNew = ""; soConfirm = "";
      soBusy = false;
    }
  }

  let userSO = $state("");
  let userNew = $state("");
  let userConfirm = $state("");
  let userErr = $state<string | null>(null);
  let userBusy = $state(false);

  async function setUser(): Promise<void> {
    userErr = null;
    if (userNew !== userConfirm) {
      userErr = MISMATCH;
      return;
    }
    userBusy = true;
    try {
      await getSDKClient().pin.setUser({ so_pin: userSO, new_user_pin: userNew });
      showToast("success", "User PIN set.");
    } catch (e) {
      userErr = message(e);
    } finally {
      userSO = ""; userNew = ""; userConfirm = "";
      userBusy = false;
    }
  }

  let verifyRole = $state<"so" | "user">("user");
  let verifyPin = $state("");
  let verified = $state<boolean | null>(null);
  let verifyBusy = $state(false);

  async function verify(): Promise<void> {
    verified = null;
    verifyBusy = true;
    const pin = verifyPin;
    try {
      const client = getSDKClient().pin;
      await (verifyRole === "so" ? client.verifySO({ pin }) : client.verifyUser({ pin }));
      verified = true;
    } catch {
      verified = false;
    } finally {
      verifyPin = "";
      verifyBusy = false;
    }
  }
</script>

<PageHeader title="PIN Setup" subtitle="Set the initial SO and user PINs, and verify a PIN" />

<p class="mb-4 text-sm text-base-content/70">
  To change a PIN, see the lockout status or reset a lockout:
  <a class="link link-primary" href="#/pin">Open PIN management</a>
</p>

<div class="grid gap-4 lg:grid-cols-3">
  <section class="card bg-base-100 shadow-sm">
    <div class="card-body space-y-3">
      <h2 class="card-title text-base">Set SO PIN</h2>
      {#if soErr}<Alert kind="error"><span>{soErr}</span></Alert>{/if}
      <input class="input input-bordered w-full" type="password" autocomplete="off" aria-label="Current SO PIN" placeholder="Current (default) SO PIN" bind:value={soCurrent} />
      <input class="input input-bordered w-full" type="password" autocomplete="off" aria-label="New SO PIN" placeholder="New SO PIN" bind:value={soNew} />
      <input class="input input-bordered w-full" type="password" autocomplete="off" aria-label="Confirm new SO PIN" placeholder="Confirm new SO PIN" bind:value={soConfirm} />
      <div class="card-actions justify-end">
        <button class="btn btn-primary btn-sm" onclick={setSO} disabled={soBusy || soCurrent === "" || soNew === "" || soConfirm === ""}>Set SO PIN</button>
      </div>
    </div>
  </section>

  <section class="card bg-base-100 shadow-sm">
    <div class="card-body space-y-3">
      <h2 class="card-title text-base">Set user PIN</h2>
      {#if userErr}<Alert kind="error"><span>{userErr}</span></Alert>{/if}
      <input class="input input-bordered w-full" type="password" autocomplete="off" aria-label="SO PIN" placeholder="SO PIN" bind:value={userSO} />
      <input class="input input-bordered w-full" type="password" autocomplete="off" aria-label="New user PIN" placeholder="New user PIN" bind:value={userNew} />
      <input class="input input-bordered w-full" type="password" autocomplete="off" aria-label="Confirm new user PIN" placeholder="Confirm new user PIN" bind:value={userConfirm} />
      <div class="card-actions justify-end">
        <button class="btn btn-primary btn-sm" onclick={setUser} disabled={userBusy || userSO === "" || userNew === "" || userConfirm === ""}>Set user PIN</button>
      </div>
    </div>
  </section>

  <section class="card bg-base-100 shadow-sm">
    <div class="card-body space-y-3">
      <h2 class="card-title text-base">Verify PIN</h2>
      {#if verified === true}
        <Alert kind="success"><span>PIN verified</span></Alert>
      {:else if verified === false}
        <Alert kind="error">
          <span>PIN not verified</span>
          <span>Each failed attempt counts toward the PIN lockout.</span>
        </Alert>
      {/if}
      <div class="flex gap-4" role="radiogroup" aria-label="PIN to verify against">
        <label class="label cursor-pointer gap-2">
          <input type="radio" class="radio radio-sm" name="verify-role" value="so" bind:group={verifyRole} />
          <span>SO</span>
        </label>
        <label class="label cursor-pointer gap-2">
          <input type="radio" class="radio radio-sm" name="verify-role" value="user" bind:group={verifyRole} />
          <span>User</span>
        </label>
      </div>
      <input class="input input-bordered w-full" type="password" autocomplete="off" aria-label="PIN to verify" placeholder="PIN" bind:value={verifyPin} />
      <div class="card-actions justify-end">
        <button class="btn btn-primary btn-sm" onclick={verify} disabled={verifyBusy || verifyPin === ""}>Verify</button>
      </div>
    </div>
  </section>
</div>
