<script lang="ts">
  // Shared alert/status banner. Every call site already wraps its message in
  // its own inner <span> (daisyUI's alert layout expects a flex child), so
  // this only supplies the outer chrome plus the announcement semantics: an
  // error/warning is `role="alert"` (implicit assertive live region) so
  // screen readers interrupt with it immediately, success/info is
  // `role="status"` (polite) so it is announced without stealing focus.
  import type { Snippet } from "svelte";

  interface Props {
    kind?: "error" | "warning" | "success" | "info";
    class?: string;
    children: Snippet;
  }
  let { kind = "info", class: extra = "", children }: Props = $props();

  const cls: Record<string, string> = {
    error: "alert-error",
    warning: "alert-warning",
    success: "alert-success",
    info: "alert-info",
  };
  const assertive = $derived(kind === "error" || kind === "warning");
</script>

<div
  class="alert {cls[kind]} {extra}"
  role={assertive ? "alert" : "status"}
  aria-live={assertive ? "assertive" : "polite"}
>
  {@render children()}
</div>
