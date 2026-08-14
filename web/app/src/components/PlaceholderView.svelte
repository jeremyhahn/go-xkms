<script lang="ts">
  import PageHeader from "./PageHeader.svelte";
  import Alert from "./Alert.svelte";

  interface Props {
    title: string;
    phase?: string;
  }
  let { title, phase }: Props = $props();
</script>

<PageHeader {title} subtitle="Server-managed capability" />

<Alert kind="info">
  <span>
    This screen is planned for a later delivery phase{phase ? ` (${phase})` : ""}.
    The underlying capability is available today through
    <code class="font-mono">xkmsctl</code>.
  </span>
</Alert>
