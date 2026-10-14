// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build frost

// frost_ceremony_test.go drives the frost verbs end to end, the way three
// operators on three machines would: each participant creates a recipient
// key, the dealer encrypts a package to each, every participant imports its
// package into its own key directory, two of them sign, and anyone holding
// the public half aggregates and verifies the signature.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const frostCeremonyPassphrase = "correct horse battery staple"

// frostCeremony is a 2-of-3 key dealt to three participant key directories.
type frostCeremony struct {
	dir          string
	keyID        string
	participants []*Config
	groupKey     string
}

// dealFrostKey runs recipient on every participant, keygen on a dealer, and
// import on every participant.
func dealFrostKey(t *testing.T) *frostCeremony {
	t.Helper()
	setFrostPassphraseEnv(t, frostCeremonyPassphrase)
	c := &frostCeremony{dir: t.TempDir(), keyID: "treasury"}

	keygenFlags := []verbFlag{
		{"key-id", c.keyID}, {"threshold", "2"}, {"total", "3"},
		{"participants", "alice, bob, carol"}, {"export-dir", filepath.Join(c.dir, "packages")},
	}
	for id := 1; id <= 3; id++ {
		cfg := newFrostTestConfig(t)
		c.participants = append(c.participants, cfg)
		pem := filepath.Join(c.dir, fmt.Sprintf("recipient-%d.pem", id))
		got := runVerbJSON(t, cfg, frostRecipientCmd, nil, verbFlag{"public-key-file", pem})
		require.NotEmpty(t, got)
		require.FileExists(t, pem)
		keygenFlags = append(keygenFlags, verbFlag{"recipient", fmt.Sprintf("%d=%s", id, pem)})
	}

	dealt := runVerbJSON(t, newFrostTestConfig(t), frostKeygenCmd, nil, keygenFlags...)
	require.Equal(t, "dealer", dealt["mode"])
	c.groupKey = dealt["group_public_key"].(string)
	files := dealt["exported_files"].([]any)
	require.Len(t, files, 3)

	for i, name := range []string{"alice", "bob", "carol"} {
		pkg := filepath.Join(c.dir, "packages", fmt.Sprintf("%s_participant_%d.json", name, i+1))
		assert.Equal(t, pkg, files[i])
		imported := runVerbJSON(t, c.participants[i], frostImportCmd, nil, verbFlag{"package", pkg})
		assert.Equal(t, c.groupKey, imported["group_public_key"])
		assert.Equal(t, name, imported["participant_name"])
		assert.EqualValues(t, i+1, imported["participant_id"])
	}
	return c
}

// sign runs both signing rounds for the given participants (0-based) and
// returns the commitment and share file lists.
func (c *frostCeremony) sign(t *testing.T, message string, signers ...int) (string, string) {
	t.Helper()
	var commitments, shares []string
	for _, i := range signers {
		path := filepath.Join(c.dir, fmt.Sprintf("commitment-%d.json", i+1))
		got := runVerbJSON(t, c.participants[i], frostRound1Cmd, nil, verbFlag{"key-id", c.keyID}, verbFlag{"output", path})
		assert.EqualValues(t, i+1, got["participant_id"], "a commitment carries its signer's participant ID")
		commitments = append(commitments, path)
	}
	list := commitments[0]
	for _, path := range commitments[1:] {
		list += "," + path
	}
	for n, i := range signers {
		share := filepath.Join(c.dir, fmt.Sprintf("share-%d.json", i+1))
		runVerbJSON(t, c.participants[i], frostRound2Cmd, nil,
			verbFlag{"key-id", c.keyID}, verbFlag{"nonces", commitments[n]},
			verbFlag{"commitments", list}, verbFlag{"message", message}, verbFlag{"output", share})
		shares = append(shares, share)
	}
	shareList := shares[0]
	for _, path := range shares[1:] {
		shareList += "," + path
	}
	return list, shareList
}

// TestFrostCeremony deals one 2-of-3 key and drives every verb against it;
// each store open runs the PKCS#8 passphrase KDF, so the key is dealt once.
func TestFrostCeremony(t *testing.T) {
	c := dealFrostKey(t)
	alice := c.participants[0]
	commitments, shares := c.sign(t, "pay 100 to bob", 0, 2)
	sigPath := filepath.Join(c.dir, "signature.hex")

	t.Run("aggregate and verify", func(t *testing.T) {
		aggregated := runVerbJSON(t, c.participants[1], frostAggregateCmd, nil,
			verbFlag{"key-id", c.keyID}, verbFlag{"commitments", commitments}, verbFlag{"shares", shares},
			verbFlag{"message", "pay 100 to bob"}, verbFlag{"output", sigPath}, verbFlag{"format", "hex"})
		assert.Equal(t, true, aggregated["verified"])
		sigHex, err := os.ReadFile(sigPath)
		require.NoError(t, err)

		verified := runVerbJSON(t, alice, frostVerifyCmd, nil,
			verbFlag{"key-id", c.keyID}, verbFlag{"message", "pay 100 to bob"}, verbFlag{"signature", sigPath})
		assert.Equal(t, "PASSED", verified["status"])

		verified = runVerbJSON(t, c.participants[2], frostVerifyCmd, nil,
			verbFlag{"key-id", c.keyID}, verbFlag{"message", "pay 100 to bob"}, verbFlag{"signature-hex", "0x" + string(sigHex)})
		assert.Equal(t, "PASSED", verified["status"])

		_, code, stderr := runVerb(t, alice, frostVerifyCmd, nil,
			verbFlag{"key-id", c.keyID}, verbFlag{"message", "pay 900 to bob"}, verbFlag{"signature", sigPath})
		assert.Equal(t, 1, code, "a signature over another message must not verify")
		assert.Contains(t, stderr, ErrFROSTVerifyFailed.Error())
	})

	for _, format := range []string{"raw", "base64"} {
		t.Run("aggregate "+format, func(t *testing.T) {
			path := filepath.Join(c.dir, "signature."+format)
			got := runVerbJSON(t, alice, frostAggregateCmd, nil,
				verbFlag{"key-id", c.keyID}, verbFlag{"commitments", commitments}, verbFlag{"shares", shares},
				verbFlag{"message", "pay 100 to bob"}, verbFlag{"output", path}, verbFlag{"format", format})
			assert.Equal(t, format, got["format"])

			verified := runVerbJSON(t, c.participants[2], frostVerifyCmd, nil,
				verbFlag{"key-id", c.keyID}, verbFlag{"message", "pay 100 to bob"}, verbFlag{"signature", path})
			assert.Equal(t, "PASSED", verified["status"])
		})
	}

	t.Run("aggregate refuses a foreign message", func(t *testing.T) {
		path := filepath.Join(c.dir, "forged")
		stdout, code, _ := runVerb(t, alice, frostAggregateCmd, nil,
			verbFlag{"key-id", c.keyID}, verbFlag{"commitments", commitments}, verbFlag{"shares", shares},
			verbFlag{"message", "pay 900 to bob"}, verbFlag{"output", path})
		assert.Equal(t, 1, code, "shares over one message must not aggregate into a signature over another")
		assert.Empty(t, stdout)
		assert.NoFileExists(t, path)
	})

	t.Run("import refusals", func(t *testing.T) {
		bobsPackage := filepath.Join(c.dir, "packages", "bob_participant_2.json")
		_, code, _ := runVerb(t, newFrostTestConfig(t), frostImportCmd, nil, verbFlag{"package", bobsPackage})
		assert.Equal(t, 1, code, "a package encrypted to bob must not import into another key directory")

		_, code, _ = runVerb(t, alice, frostImportCmd, nil, verbFlag{"package", filepath.Join(c.dir, "absent.json")})
		assert.Equal(t, 1, code)

		testFrostImportRefusals(t, c)
	})

	t.Run("signing refusals", func(t *testing.T) {
		testFrostSigningRefusals(t, c, commitments, shares)
	})

	t.Run("list info delete", func(t *testing.T) {
		table, code, _ := runVerb(t, alice, frostListCmd, nil)
		assert.Equal(t, -1, code)
		assert.Regexp(t, `treasury\s+FROST-Ed25519-SHA512\s+2/3`, table)

		listed, code, _ := runVerb(t, alice, frostListCmd, nil, verbFlag{"format", "json"})
		assert.Equal(t, -1, code)
		var keys []map[string]any
		require.NoError(t, json.Unmarshal([]byte(listed), &keys), listed)
		require.Len(t, keys, 1)

		info := runVerbJSON(t, alice, frostInfoCmd, []string{c.keyID}, verbFlag{"show-public-key", "true"})
		assert.Equal(t, c.groupKey, info["group_public_key"])
		assert.EqualValues(t, 1, info["participant_id"])
		info = runVerbJSON(t, alice, frostInfoCmd, []string{c.keyID})
		assert.NotContains(t, info, "group_public_key")

		withStdinLine(t, "n\n")
		out, code, _ := runVerb(t, alice, frostDeleteCmd, []string{c.keyID})
		assert.Equal(t, -1, code)
		assert.Contains(t, out, "Aborted")
		runVerbJSON(t, alice, frostInfoCmd, []string{c.keyID})

		out, code, _ = runVerb(t, alice, frostDeleteCmd, []string{c.keyID}, verbFlag{"force", "true"})
		assert.Equal(t, -1, code)
		assert.Contains(t, out, "Successfully deleted key: treasury")

		_, code, stderr := runVerb(t, alice, frostInfoCmd, []string{c.keyID})
		assert.Equal(t, 1, code)
		assert.Contains(t, stderr, ErrGetKeyFailed.Error())

		out, code, _ = runVerb(t, alice, frostListCmd, nil)
		assert.Equal(t, -1, code)
		assert.Contains(t, out, "No FROST keys found")
	})
}

// testFrostImportRefusals feeds alice packages that are sealed to her but
// unusable, and checks each is refused with the error naming the bad field.
func testFrostImportRefusals(t *testing.T, c *frostCeremony) {
	alice := c.participants[0]
	recipients, err := parseFrostRecipients([]string{"1=" + filepath.Join(c.dir, "recipient-1.pem")}, 1)
	require.NoError(t, err)
	sealToAlice := func(name string, export *KeyPackageExport) string {
		encrypted, err := encryptKeyPackageExport(export, recipients[1])
		require.NoError(t, err)
		data, err := json.Marshal(encrypted)
		require.NoError(t, err)
		path := filepath.Join(c.dir, name+".json")
		require.NoError(t, os.WriteFile(path, data, 0600))
		return path
	}
	valid := func() *KeyPackageExport {
		return &KeyPackageExport{
			KeyID: "crafted", Algorithm: "FROST-Ed25519-SHA512", Threshold: 2, Total: 3, ParticipantID: 1,
			SecretShare: "00", GroupPublicKey: "00", VerificationShares: map[uint32]string{1: "00"},
		}
	}
	notJSON := filepath.Join(c.dir, "not-a-package.json")
	require.NoError(t, os.WriteFile(notJSON, []byte("{not json"), 0600))

	badShare, badGroup, badVS := valid(), valid(), valid()
	badShare.SecretShare = "zz"
	badGroup.GroupPublicKey = "zz"
	badVS.VerificationShares = map[uint32]string{2: "zz"}

	cases := []struct {
		name     string
		pkg      string
		sentinel string
	}{
		{"not JSON", notJSON, ErrParsePackageFileFailed.Error()},
		{"secret share not hex", sealToAlice("bad-share", badShare), ErrDecodeSecretShareFailed.Error()},
		{"group key not hex", sealToAlice("bad-group", badGroup), ErrDecodeGroupPublicKeyFailed.Error()},
		{"verification share not hex", sealToAlice("bad-vs", badVS), "failed to decode verification share 2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code, stderr := runVerb(t, alice, frostImportCmd, nil, verbFlag{"package", tc.pkg})
			assert.Equal(t, 1, code)
			assert.Empty(t, out)
			assert.Contains(t, stderr, tc.sentinel)
		})
	}
}

// withStdinLine replaces os.Stdin with a pipe holding line.
func withStdinLine(t *testing.T, line string) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_, err = w.WriteString(line)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	original := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = original
		assert.NoError(t, r.Close())
	})
}

func TestFrostKeygen_ParticipantModeStoresOneShare(t *testing.T) {
	setFrostPassphraseEnv(t, frostCeremonyPassphrase)
	cfg := newFrostTestConfig(t)

	got := runVerbJSON(t, cfg, frostKeygenCmd, nil,
		verbFlag{"key-id", "solo"}, verbFlag{"participant-id", "2"}, verbFlag{"participants", "a,b,c"})
	assert.Equal(t, "participant", got["mode"])
	assert.EqualValues(t, 2, got["participant_id"])
	assert.Equal(t, []any{"a", "b", "c"}, got["participants"])

	info := runVerbJSON(t, cfg, frostInfoCmd, []string{"solo"}, verbFlag{"show-public-key", "true"})
	assert.Equal(t, got["group_public_key"], info["group_public_key"])
}

func TestFrostKeygen_Refusals(t *testing.T) {
	setFrostPassphraseEnv(t, frostCeremonyPassphrase)
	dir := t.TempDir()
	cases := []struct {
		name  string
		flags []verbFlag
		check func(t *testing.T, stderr string)
	}{
		{"dealer mode without export dir", nil, func(t *testing.T, stderr string) {
			assert.Contains(t, stderr, ErrDealerModeExportDirRequired.Error())
		}},
		{"recipient in participant mode", []verbFlag{{"participant-id", "1"}, {"recipient", "1=x.pem"}}, func(t *testing.T, stderr string) {
			assert.Contains(t, stderr, ErrFrostRecipientParticipantMode.Error())
		}},
		{"participant names do not match total", []verbFlag{{"participants", "a,b"}, {"export-dir", dir}}, func(t *testing.T, stderr string) {
			assert.Contains(t, stderr, (&ParticipantCountError{Count: 2, Total: 3}).Error())
		}},
		{"participant ID beyond total", []verbFlag{{"participant-id", "4"}}, func(t *testing.T, stderr string) {
			assert.Contains(t, stderr, (&ParticipantIDRangeError{Total: 3}).Error())
		}},
		{"dealer mode missing a recipient", []verbFlag{{"export-dir", dir}}, func(t *testing.T, stderr string) {
			assert.NotEmpty(t, stderr)
		}},
		{"invalid threshold", []verbFlag{{"threshold", "5"}, {"participant-id", "1"}}, func(t *testing.T, stderr string) {
			assert.Contains(t, stderr, ErrGenerateFROSTPackagesFailed.Error())
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code, stderr := runVerb(t, newFrostTestConfig(t), frostKeygenCmd, nil, tc.flags...)
			assert.Equal(t, 1, code)
			assert.Empty(t, out)
			tc.check(t, stderr)
		})
	}
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "a refused keygen writes no package")
}

func TestFrostKeygen_StorageRefusals(t *testing.T) {
	setFrostPassphraseEnv(t, frostCeremonyPassphrase)
	dir := t.TempDir()
	notDir := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(notDir, []byte("x"), 0600))

	dealer := []verbFlag{{"key-id", "dealt"}}
	for id := 1; id <= 3; id++ {
		pem := filepath.Join(dir, fmt.Sprintf("recipient-%d.pem", id))
		runVerbJSON(t, newFrostTestConfig(t), frostRecipientCmd, nil, verbFlag{"public-key-file", pem})
		dealer = append(dealer, verbFlag{"recipient", fmt.Sprintf("%d=%s", id, pem)})
	}
	blockedDir := filepath.Join(dir, "blocked")
	require.NoError(t, os.MkdirAll(filepath.Join(blockedDir, "participant_1.json"), 0700))

	unopenable := newFrostTestConfig(t)
	unopenable.KeyDir = filepath.Join(notDir, "keys")
	held := newFrostTestConfig(t)
	runVerbJSON(t, held, frostKeygenCmd, nil, verbFlag{"key-id", "solo"}, verbFlag{"participant-id", "1"})

	cases := []struct {
		name     string
		cfg      *Config
		flags    []verbFlag
		sentinel error
	}{
		{"export dir under a file", newFrostTestConfig(t), append([]verbFlag{{"export-dir", filepath.Join(notDir, "packages")}}, dealer...), ErrCreateExportDirectoryFailed},
		{"package path is a directory", newFrostTestConfig(t), append([]verbFlag{{"export-dir", blockedDir}}, dealer...), ErrWritePackageFileFailed},
		{"store cannot open", unopenable, []verbFlag{{"key-id", "solo"}, {"participant-id", "1"}}, ErrCreateFROSTBackendFailed},
		{"key already held", held, []verbFlag{{"key-id", "solo"}, {"participant-id", "1"}}, ErrGenerateFROSTKeyFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code, stderr := runVerb(t, tc.cfg, frostKeygenCmd, nil, tc.flags...)
			assert.Equal(t, 1, code)
			assert.Empty(t, out)
			assert.Contains(t, stderr, tc.sentinel.Error())
		})
	}
}

// TestFrostVerbs_RefuseUnopenableStore proves every verb that opens the
// local store reports ErrCreateFROSTBackendFailed when it cannot be created.
func TestFrostVerbs_RefuseUnopenableStore(t *testing.T) {
	setFrostPassphraseEnv(t, "correct horse battery staple")
	notDir := filepath.Join(t.TempDir(), "plain.txt")
	require.NoError(t, os.WriteFile(notDir, []byte("x"), 0600))
	message := verbFlag{"message", "hello"}
	keyID := verbFlag{"key-id", "group-key"}

	cases := []struct {
		cmd   *cobra.Command
		args  []string
		flags []verbFlag
	}{
		{frostListCmd, nil, nil},
		{frostInfoCmd, []string{"group-key"}, nil},
		{frostDeleteCmd, []string{"group-key"}, []verbFlag{{"force", "true"}}},
		{frostImportCmd, nil, []verbFlag{{"package", notDir}}},
		{frostRound1Cmd, nil, []verbFlag{keyID}},
		{frostRound2Cmd, nil, []verbFlag{keyID, message}},
		{frostAggregateCmd, nil, []verbFlag{keyID, message}},
		{frostVerifyCmd, nil, []verbFlag{keyID, message, {"signature-hex", "00"}}},
	}
	for _, tc := range cases {
		t.Run(tc.cmd.Name(), func(t *testing.T) {
			cfg := NewConfig()
			cfg.OutputFormat = "text"
			cfg.KeyDir = filepath.Join(notDir, "keys")

			out, code, stderr := runVerb(t, cfg, tc.cmd, tc.args, tc.flags...)
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, ErrCreateFROSTBackendFailed.Error())
			assert.Empty(t, out)
		})
	}
}

// testFrostSigningRefusals checks the signing verbs reject missing and
// malformed inputs without writing output.
func testFrostSigningRefusals(t *testing.T, c *frostCeremony, commitments, shares string) {
	alice := c.participants[0]
	missing := filepath.Join(c.dir, "absent.json")
	garbage := filepath.Join(c.dir, "garbage.json")
	require.NoError(t, os.WriteFile(garbage, []byte("{not json"), 0600))
	badShare := filepath.Join(c.dir, "bad-share.json")
	require.NoError(t, os.WriteFile(badShare, []byte(`{"participant_id":1,"signature_share":"zz"}`), 0600))
	nonces, err := os.ReadFile(filepath.Join(c.dir, "commitment-1.json.nonces"))
	require.NoError(t, err)
	// Each pair below is a commitment path and its .nonces sibling, with one
	// half missing or unparsable.
	garbageNonces := filepath.Join(c.dir, "garbage-nonces.json")
	require.NoError(t, os.WriteFile(garbageNonces+".nonces", []byte("{not json"), 0600))
	orphanNonces := filepath.Join(c.dir, "orphan.json")
	require.NoError(t, os.WriteFile(orphanNonces+".nonces", nonces, 0600))
	garbageCommitment := filepath.Join(c.dir, "garbage-commitment.json")
	require.NoError(t, os.WriteFile(garbageCommitment, []byte("{not json"), 0600))
	require.NoError(t, os.WriteFile(garbageCommitment+".nonces", nonces, 0600))
	ownNonces := filepath.Join(c.dir, "commitment-1.json")
	blockedNonces := filepath.Join(c.dir, "blocked.json")
	require.NoError(t, os.Mkdir(blockedNonces+".nonces", 0700))
	round2 := func(nonces, commitmentList string) []verbFlag {
		return []verbFlag{{"key-id", c.keyID}, {"nonces", nonces}, {"commitments", commitmentList}, {"message", "m"}, {"output", missing}}
	}

	cases := []struct {
		name     string
		cmd      *cobra.Command
		flags    []verbFlag
		sentinel string
	}{
		{"round1 unknown key", frostRound1Cmd, []verbFlag{{"key-id", "nope"}, {"output", filepath.Join(c.dir, "c.json")}}, ErrGenerateNoncesFailed.Error()},
		{"round1 unwritable output", frostRound1Cmd, []verbFlag{{"key-id", c.keyID}, {"output", filepath.Join(missing, "c.json")}}, ErrWriteCommitmentFileFailed.Error()},
		{"round2 no message", frostRound2Cmd, []verbFlag{{"key-id", c.keyID}, {"nonces", missing}, {"commitments", commitments}, {"output", missing}}, ErrMessageInputRequired.Error()},
		{"round2 missing nonces", frostRound2Cmd, []verbFlag{{"key-id", c.keyID}, {"nonces", missing}, {"commitments", commitments}, {"message", "m"}, {"output", missing}}, ErrReadNonceFileFailed.Error()},
		{"round2 unreadable commitment", frostRound2Cmd, []verbFlag{{"key-id", c.keyID}, {"nonces", filepath.Join(c.dir, "commitment-1.json")}, {"commitments", missing}, {"message", "m"}, {"output", missing}}, missing},
		{"round1 unwritable nonces", frostRound1Cmd, []verbFlag{{"key-id", c.keyID}, {"output", blockedNonces}}, ErrWriteNonceFileFailed.Error()},
		{"round2 unparsable nonces", frostRound2Cmd, round2(garbageNonces, commitments), ErrParseNonceFileFailed.Error()},
		{"round2 nonces without their commitment", frostRound2Cmd, round2(orphanNonces, commitments), ErrReadCommitmentFileFailed.Error()},
		{"round2 unparsable own commitment", frostRound2Cmd, round2(garbageCommitment, commitments), ErrParseCommitmentFileFailed.Error()},
		{"round2 unparsable peer commitment", frostRound2Cmd, round2(ownNonces, garbage), garbage},
		{"round2 unknown key", frostRound2Cmd, append(round2(ownNonces, commitments), verbFlag{"key-id", "nope"}), ErrGenerateSignatureShareFailed.Error()},
		{"aggregate unknown key", frostAggregateCmd, []verbFlag{{"key-id", "nope"}, {"commitments", commitments}, {"shares", shares}, {"message", "pay 100 to bob"}, {"output", missing}}, ErrAggregateSignaturesFailed.Error()},
		{"aggregate unwritable output", frostAggregateCmd, []verbFlag{{"key-id", c.keyID}, {"commitments", commitments}, {"shares", shares}, {"message", "pay 100 to bob"}, {"output", filepath.Join(missing, "sig")}}, ErrWriteSignatureFileFailed.Error()},
		{"aggregate unreadable commitment", frostAggregateCmd, []verbFlag{{"key-id", c.keyID}, {"commitments", missing}, {"shares", shares}, {"message", "pay 100 to bob"}, {"output", missing}}, missing},
		{"aggregate unparsable commitment", frostAggregateCmd, []verbFlag{{"key-id", c.keyID}, {"commitments", garbage}, {"shares", shares}, {"message", "pay 100 to bob"}, {"output", missing}}, garbage},
		{"aggregate unreadable share", frostAggregateCmd, []verbFlag{{"key-id", c.keyID}, {"commitments", commitments}, {"shares", missing}, {"message", "pay 100 to bob"}, {"output", missing}}, missing},
		{"aggregate unparsable share", frostAggregateCmd, []verbFlag{{"key-id", c.keyID}, {"commitments", commitments}, {"shares", garbage}, {"message", "pay 100 to bob"}, {"output", missing}}, garbage},
		{"aggregate share not hex", frostAggregateCmd, []verbFlag{{"key-id", c.keyID}, {"commitments", commitments}, {"shares", badShare}, {"message", "pay 100 to bob"}, {"output", missing}}, badShare},
		{"verify no signature", frostVerifyCmd, []verbFlag{{"key-id", c.keyID}, {"message", "pay 100 to bob"}}, ErrSignatureInputRequired.Error()},
		{"verify signature not hex", frostVerifyCmd, []verbFlag{{"key-id", c.keyID}, {"message", "pay 100 to bob"}, {"signature-hex", "xyz"}}, ErrInvalidSignatureHex.Error()},
		{"verify unreadable signature", frostVerifyCmd, []verbFlag{{"key-id", c.keyID}, {"message", "pay 100 to bob"}, {"signature", missing}}, ErrReadSignatureFileFailed.Error()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code, stderr := runVerb(t, alice, tc.cmd, nil, tc.flags...)
			assert.Equal(t, 1, code)
			assert.Empty(t, out)
			assert.Contains(t, stderr, tc.sentinel)
		})
	}
	assert.NoFileExists(t, missing)
}
