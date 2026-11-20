package buildgates

import (
	"strings"
	"testing"
)

// registryMasks are the add-mask registrations a job that reads the
// CI_IMAGE_REGISTRY secret makes, in this order, before its first
// ci-registry.sh call: the registry, its host:port and its bare host. A
// producer job's masks do not carry into a consumer job (Codex on #2302).
var registryMasks = []string{
	`host=${reg%%/*}`,
	`echo "::add-mask::$reg"`,
	`echo "::add-mask::$host"`,
	`echo "::add-mask::${host%%:*}"`,
}

func hasRegistryMasks(s string) bool {
	at := 0
	for _, m := range registryMasks {
		i := strings.Index(s[at:], m)
		if i < 0 {
			return false
		}
		at += i + len(m)
	}
	return true
}

// registryMaskProblems reports a job that reads CI_IMAGE_REGISTRY and reaches
// a ci-registry.sh call before it masks the registry, host:port and bare host.
func registryMaskProblems(name, job string) []string {
	if !strings.Contains(job, poolSecretEnv) {
		return nil
	}
	masked := false
	for _, s := range jobSteps(job) {
		reads := strings.Contains(s, poolSecretEnv)
		call := strings.Index(s, poolRegistrySh)
		if call >= 0 && !masked && !(reads && hasRegistryMasks(s[:call])) {
			return []string{name + ": step " + stepTitle(s) + " calls " + poolRegistrySh +
				" before the job masks the registry, host:port and bare host"}
		}
		if reads && hasRegistryMasks(s) {
			masked = true
		}
	}
	return nil
}

func TestPoolRegistryMaskedInEveryJobBeforeUse(t *testing.T) {
	src := readWorkflow(t)
	readers := 0
	for _, name := range workflowJobs(src) {
		job := jobBlock(src, name)
		if strings.Contains(job, poolSecretEnv) {
			readers++
		}
		for _, p := range registryMaskProblems(name, job) {
			t.Error(p)
		}
	}
	if readers < 6 {
		t.Fatalf("found %d jobs reading CI_IMAGE_REGISTRY; the walk missed some", readers)
	}
}

func TestRegistryMaskCheckCatchesARegression(t *testing.T) {
	unmasked := "  build:\n    steps:\n" +
		"      - name: Take the toolchain image\n        env:\n          " + poolSecretEnv + "\n" +
		"        run: " + poolRegistrySh + " use toolchain x\n"
	if len(registryMaskProblems("build", unmasked)) != 1 {
		t.Errorf("an unmasked consumer passed")
	}
	partial := strings.Replace(unmasked, "        run: ", "        run: |\n          reg=${CI_IMAGE_REGISTRY%/}\n          "+
		registryMasks[0]+"\n          "+registryMasks[1]+"\n          ", 1)
	if len(registryMaskProblems("build", partial)) != 1 {
		t.Errorf("a consumer masking only the registry passed")
	}
	var full strings.Builder
	full.WriteString("        run: |\n          reg=${CI_IMAGE_REGISTRY%/}\n")
	for _, m := range registryMasks {
		full.WriteString("          " + m + "\n")
	}
	full.WriteString("          ")
	ok := strings.Replace(unmasked, "        run: ", full.String(), 1)
	if p := registryMaskProblems("build", ok); len(p) != 0 {
		t.Errorf("a fully masked consumer failed: %q", p)
	}
}
