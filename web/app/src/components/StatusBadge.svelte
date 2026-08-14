<script lang="ts">
  interface Props {
    label: string;
    ok?: boolean;
    kind?: "success" | "warning" | "error" | "info" | "neutral";
  }
  let { label, ok, kind }: Props = $props();

  const resolved = $derived(
    kind ?? (ok === undefined ? "neutral" : ok ? "success" : "error"),
  );
  const cls: Record<string, string> = {
    success: "badge-success",
    warning: "badge-warning",
    error: "badge-error",
    info: "badge-info",
    neutral: "badge-neutral",
  };
</script>

<span class="badge {cls[resolved]}">{label}</span>
