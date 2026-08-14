<script lang="ts">
  import { toastStore, dismissToast } from "$stores/toast.svelte.ts";
  import Alert from "./Alert.svelte";

  type Kind = "info" | "success" | "warning" | "error";

  function normalize(kind: string): Kind {
    return kind === "success" || kind === "warning" || kind === "error" ? kind : "info";
  }
</script>

<div class="toast toast-end z-50">
  {#each toastStore.toasts as toast (toast.id)}
    <Alert kind={normalize(toast.kind)}>
      <span>{toast.message}</span>
      <button
        class="btn btn-ghost btn-xs"
        aria-label="Dismiss"
        onclick={() => dismissToast(toast.id)}>✕</button
      >
    </Alert>
  {/each}
</div>
