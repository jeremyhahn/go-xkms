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

package kdf

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"testing"
)

// x963Vector is one record from the NIST CAVP ANS X9.63-2001 KDF response
// file.
//
// Provenance: official CAVP component test vectors,
// components/800-135testvectors/ansx963_2001.zip -> ansx963_2001.rsp. The
// SHA-1 and SHA-224 groups in that file are omitted; this package does not
// offer them as KDF pseudorandom functions.
type x963Vector struct {
	name       string
	hash       crypto.Hash
	keyLen     int
	z          string
	sharedInfo string
	keyData    string
}

var cavpX963Vectors = []x963Vector{
	{
		name:       "SHA-256/keydatalen=128/sharedinfolen=0/COUNT=0",
		hash:       crypto.SHA256,
		keyLen:     16,
		z:          "96c05619d56c328ab95fe84b18264b08725b85e33fd34f08",
		sharedInfo: "",
		keyData:    "443024c3dae66b95e6f5670601558f71",
	},
	{
		name:       "SHA-256/keydatalen=128/sharedinfolen=0/COUNT=1",
		hash:       crypto.SHA256,
		keyLen:     16,
		z:          "96f600b73ad6ac5629577eced51743dd2c24c21b1ac83ee4",
		sharedInfo: "",
		keyData:    "b6295162a7804f5667ba9070f82fa522",
	},
	{
		name:       "SHA-256/keydatalen=1024/sharedinfolen=128/COUNT=0",
		hash:       crypto.SHA256,
		keyLen:     128,
		z:          "22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d",
		sharedInfo: "75eef81aa3041e33b80971203d2c0c52",
		keyData:    "c498af77161cc59f2962b9a713e2b215152d139766ce34a776df11866a69bf2e52a13d9c7c6fc878c50c5ea0bc7b00e0da2447cfd874f6cf92f30d0097111485500c90c3af8b487872d04685d14c8d1dc8d7fa08beb0ce0ababc11f0bd496269142d43525a78e5bc79a17f59676a5706dc54d54d4d1f0bd7e386128ec26afc21",
	},
	{
		name:       "SHA-256/keydatalen=1024/sharedinfolen=128/COUNT=1",
		hash:       crypto.SHA256,
		keyLen:     128,
		z:          "7e335afa4b31d772c0635c7b0e06f26fcd781df947d2990a",
		sharedInfo: "d65a4812733f8cdbcdfb4b2f4c191d87",
		keyData:    "c0bd9e38a8f9de14c2acd35b2f3410c6988cf02400543631e0d6a4c1d030365acbf398115e51aaddebdc9590664210f9aa9fed770d4c57edeafa0b8c14f93300865251218c262d63dadc47dfa0e0284826793985137e0a544ec80abf2fdf5ab90bdaea66204012efe34971dc431d625cd9a329b8217cc8fd0d9f02b13f2f6b0b",
	},
	{
		name:       "SHA-384/keydatalen=128/sharedinfolen=0/COUNT=0",
		hash:       crypto.SHA384,
		keyLen:     16,
		z:          "d8554db1b392cd55c3fe957bed76af09c13ac2a9392f88f6",
		sharedInfo: "",
		keyData:    "671a46aada145162f8ddf1ca586a1cda",
	},
	{
		name:       "SHA-384/keydatalen=128/sharedinfolen=0/COUNT=1",
		hash:       crypto.SHA384,
		keyLen:     16,
		z:          "070265bd04222fc1dcb67182fa797166eaa18a2a1e1a6c0f",
		sharedInfo: "",
		keyData:    "522d79f65430350cec5c59c014e1a2cd",
	},
	{
		name:       "SHA-384/keydatalen=1024/sharedinfolen=128/COUNT=0",
		hash:       crypto.SHA384,
		keyLen:     128,
		z:          "c051fd22539c9de791d6c43a854b8f80a6bf70190050854a",
		sharedInfo: "1317504aa34759bb4c931e3b78201945",
		keyData:    "cf6a84434734ac6949e1d7976743277be789906908ad3ca3a8923da7f476abbeb574306d7243031a85566914bfd247d2519c479953d9d55b6b831e56260806c39af21b74e3ecf470e3bd8332791c8a23c13352514fdef00c2d1a408ba31b2d3f9fdcb373895484649a645d1845eec91b5bfdc5ad28c7824984482002dd4a8677",
	},
	{
		name:       "SHA-384/keydatalen=1024/sharedinfolen=128/COUNT=1",
		hash:       crypto.SHA384,
		keyLen:     128,
		z:          "2c9436cd85df982911df60d54f2d41d81660cdb37e457daf",
		sharedInfo: "6b5910575296437a75c04371c8623cf6",
		keyData:    "6efb45067e00024beaa9fa763ef2c701527cd9eb5697f7f77475f2d36495058e3558893006ab0169e9a9f78481f6f06e9b005413856af89cd764beba0fff6ed4a077ffd36f966b633e058793320febf52b937554539096838873171933c2b7f864000be1b3a01ad6c4e66c3190bbfc90d7deb31e8857cf272cdd2caea730839e",
	},
	{
		name:       "SHA-512/keydatalen=128/sharedinfolen=0/COUNT=0",
		hash:       crypto.SHA512,
		keyLen:     16,
		z:          "87fc0d8c4477485bb574f5fcea264b30885dc8d90ad82782",
		sharedInfo: "",
		keyData:    "947665fbb9152153ef460238506a0245",
	},
	{
		name:       "SHA-512/keydatalen=128/sharedinfolen=0/COUNT=1",
		hash:       crypto.SHA512,
		keyLen:     16,
		z:          "293e901c8f43178794a9792f98861732faa4677e72b8ce1e",
		sharedInfo: "",
		keyData:    "883e84f877b05a092ada456571c58cb9",
	},
	{
		name:       "SHA-512/keydatalen=1024/sharedinfolen=128/COUNT=0",
		hash:       crypto.SHA512,
		keyLen:     128,
		z:          "00aa5bb79b33e389fa58ceadc047197f14e73712f452caa9fc4c9adb369348b81507392f1a86ddfdb7c4ff8231c4bd0f44e44a1b55b1404747a9e2e753f55ef05a2d",
		sharedInfo: "e3b5b4c1b0d5cf1d2b3a2f9937895d31",
		keyData:    "4463f869f3cc18769b52264b0112b5858f7ad32a5a2d96d8cffabf7fa733633d6e4dd2a599acceb3ea54a6217ce0b50eef4f6b40a5c30250a5a8eeee208002267089dbf351f3f5022aa9638bf1ee419dea9c4ff745a25ac27bda33ca08bd56dd1a59b4106cf2dbbc0ab2aa8e2efa7b17902d34276951ceccab87f9661c3e8816",
	},
	{
		name:       "SHA-512/keydatalen=1024/sharedinfolen=128/COUNT=1",
		hash:       crypto.SHA512,
		keyLen:     128,
		z:          "009dcd6ba5c8c803ca21f9996ca5dd86047d4ddc150fddace1b1ebe996c2007e3ee907c8ff03b9ef766e8ceb4dedf7489e5162e2278c0185e4be381bec17dd992cf8",
		sharedInfo: "1e60e51c11a538b0ea8990d69a4c6358",
		keyData:    "4e55036a32f32fc965046fdfbf686c108e43a69f8fc1a64ff1bd77763f2eedc8bf277d78b4ce31243e1adbe2c2d5dd59b47503b5b90b54f9d7a9a5aea49c7f0283cb64c3849a1d157000fd41ef6c1d1a5b62734e7c9a20dcfb57f2da974933f57ee619d72898d0e93d9a4254aaddf73941d6269298b4d49c0ac64a33802fe8f2",
	},
}

// TestConcat_CAVP_X963 validates the ANS X9.63 KDF against the published NIST
// CAVP vectors.
func TestConcat_CAVP_X963(t *testing.T) {
	adapter := NewX963Adapter()
	if len(cavpX963Vectors) == 0 {
		t.Fatal("no X9.63 vectors loaded")
	}

	for _, v := range cavpX963Vectors {
		t.Run(v.name, func(t *testing.T) {
			got, err := adapter.DeriveKey(mustHex(t, v.z), &KDFParams{
				Algorithm: AlgorithmX963,
				Hash:      v.hash,
				KeyLength: v.keyLen,
				Info:      mustHex(t, v.sharedInfo),
			})
			if err != nil {
				t.Fatalf("DeriveKey: %v", err)
			}
			if want := mustHex(t, v.keyData); !bytes.Equal(got, want) {
				t.Errorf("key data mismatch\n got: %x\nwant: %x", got, want)
			}
		})
	}
}

// TestConcat_SP80056A_Construction validates the SP 800-56A concatenation KDF
// against the construction spelled out in the standard,
// K(i) = H([i]_32 || Z || OtherInfo), computed independently here.
//
// Provenance: self-derived from NIST SP 800-56A Rev. 3 Section 5.8.2.1, not
// CAVP. NIST does not publish a standalone .rsp response file for the
// one-step concatenation KDF; its coverage lives in the ACVP KAS suites,
// where the KDF output is not exposed as a separate value.
func TestConcat_SP80056A_Construction(t *testing.T) {
	z := []byte("shared-secret-from-ecdh-p256!!!!")
	otherInfo := []byte("AlgorithmID||PartyUInfo||PartyVInfo")

	// Two SHA-256 blocks: the requested 48 bytes spans a block boundary.
	counter := make([]byte, 4)

	var want []byte
	for i := uint32(1); i <= 2; i++ {
		binary.BigEndian.PutUint32(counter, i)
		h := crypto.SHA256.New()
		h.Write(counter)
		h.Write(z)
		h.Write(otherInfo)
		want = h.Sum(want)
	}
	want = want[:48]

	got, err := NewSP80056AAdapter().DeriveKey(z, &KDFParams{
		Algorithm: AlgorithmSP80056A,
		Hash:      crypto.SHA256,
		KeyLength: 48,
		Info:      otherInfo,
	})
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("SP 800-56A construction mismatch\n got: %x\nwant: %x", got, want)
	}
}

// TestConcat_X963_Construction validates the X9.63 construction,
// K(i) = H(Z || [i]_32 || SharedInfo), independently of the CAVP table so a
// failure points at the byte ordering rather than at the vector file.
func TestConcat_X963_Construction(t *testing.T) {
	z := []byte("shared-secret-from-ecdh-p384!!!!")
	sharedInfo := []byte("x963-shared-info")

	counter := make([]byte, 4)
	var want []byte
	for i := uint32(1); i <= 2; i++ {
		binary.BigEndian.PutUint32(counter, i)
		h := crypto.SHA256.New()
		h.Write(z)
		h.Write(counter)
		h.Write(sharedInfo)
		want = h.Sum(want)
	}
	want = want[:40]

	got, err := NewX963Adapter().DeriveKey(z, &KDFParams{
		Algorithm: AlgorithmX963,
		Hash:      crypto.SHA256,
		KeyLength: 40,
		Info:      sharedInfo,
	})
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("X9.63 construction mismatch\n got: %x\nwant: %x", got, want)
	}
}

// TestConcat_ModesDiffer confirms the two concatenation KDFs are distinct
// constructions: they differ only in where the counter sits, and that
// difference must show in the output.
func TestConcat_ModesDiffer(t *testing.T) {
	z := []byte("shared-secret-from-ecdh-p521!!!!")
	params := func(algorithm KDFAlgorithm) *KDFParams {
		return &KDFParams{
			Algorithm: algorithm,
			Hash:      crypto.SHA256,
			KeyLength: 32,
			Info:      []byte("info"),
		}
	}

	x963, err := NewX963Adapter().DeriveKey(z, params(AlgorithmX963))
	if err != nil {
		t.Fatalf("X9.63 DeriveKey: %v", err)
	}
	concat, err := NewSP80056AAdapter().DeriveKey(z, params(AlgorithmSP80056A))
	if err != nil {
		t.Fatalf("SP 800-56A DeriveKey: %v", err)
	}
	if bytes.Equal(x963, concat) {
		t.Error("X9.63 and SP 800-56A produced identical output")
	}
}

// TestConcat_InfoChangesOutput proves the caller's shared info reaches the
// hash.
func TestConcat_InfoChangesOutput(t *testing.T) {
	z := []byte("shared-secret-from-ecdh-x25519!!")

	for _, adapter := range []*ConcatAdapter{NewX963Adapter(), NewSP80056AAdapter()} {
		t.Run(string(adapter.Algorithm()), func(t *testing.T) {
			base := &KDFParams{
				Algorithm: adapter.Algorithm(),
				Hash:      crypto.SHA256,
				KeyLength: 32,
				Info:      []byte("info-1"),
			}
			first, err := adapter.DeriveKey(z, base)
			if err != nil {
				t.Fatalf("DeriveKey: %v", err)
			}

			base.Info = []byte("info-2")
			second, err := adapter.DeriveKey(z, base)
			if err != nil {
				t.Fatalf("DeriveKey: %v", err)
			}
			if bytes.Equal(first, second) {
				t.Error("changing Info did not change the derived key")
			}
		})
	}
}

// TestConcat_OutputLengths exercises requested lengths on both sides of the
// hash block boundary.
func TestConcat_OutputLengths(t *testing.T) {
	z := []byte("shared-secret-from-ecdh-lengths!")

	for _, adapter := range []*ConcatAdapter{NewX963Adapter(), NewSP80056AAdapter()} {
		t.Run(string(adapter.Algorithm()), func(t *testing.T) {
			for _, length := range []int{1, 31, 32, 33, 64, 65, 100} {
				key, err := adapter.DeriveKey(z, &KDFParams{
					Algorithm: adapter.Algorithm(),
					Hash:      crypto.SHA256,
					KeyLength: length,
					Info:      []byte("info"),
				})
				if err != nil {
					t.Fatalf("DeriveKey(%d): %v", length, err)
				}
				if len(key) != length {
					t.Errorf("requested %d bytes, got %d", length, len(key))
				}
			}
		})
	}
}

// TestConcat_RejectedParameters covers the invalid parameter space.
func TestConcat_RejectedParameters(t *testing.T) {
	tests := []struct {
		name    string
		params  *KDFParams
		wantErr error
	}{
		{"nil params", nil, ErrInvalidIKM},
		{"zero key length", &KDFParams{Hash: crypto.SHA256}, ErrInvalidKeyLength},
		{"negative key length", &KDFParams{Hash: crypto.SHA256, KeyLength: -1}, ErrInvalidKeyLength},
		{"unavailable hash", &KDFParams{Hash: crypto.Hash(0), KeyLength: 32}, ErrInvalidHash},
	}

	for _, adapter := range []*ConcatAdapter{NewX963Adapter(), NewSP80056AAdapter()} {
		for _, tt := range tests {
			t.Run(string(adapter.Algorithm())+"/"+tt.name, func(t *testing.T) {
				if err := adapter.ValidateParams(tt.params); !errors.Is(err, tt.wantErr) {
					t.Errorf("ValidateParams = %v, want %v", err, tt.wantErr)
				}
				if _, err := adapter.DeriveKey([]byte("shared-secret"), tt.params); !errors.Is(err, tt.wantErr) {
					t.Errorf("DeriveKey = %v, want %v", err, tt.wantErr)
				}
			})
		}

		t.Run(string(adapter.Algorithm())+"/empty shared secret", func(t *testing.T) {
			_, err := adapter.DeriveKey(nil, &KDFParams{Hash: crypto.SHA256, KeyLength: 32})
			if !errors.Is(err, ErrInvalidIKM) {
				t.Errorf("got %v, want ErrInvalidIKM", err)
			}
		})
	}
}

// TestNewAdapter covers the canonical dispatch table.
func TestNewAdapter(t *testing.T) {
	supported := []KDFAlgorithm{
		AlgorithmHKDF,
		AlgorithmSP800108Counter,
		AlgorithmSP800108Feedback,
		AlgorithmSP800108DoublePipeline,
		AlgorithmX963,
		AlgorithmSP80056A,
	}
	for _, algorithm := range supported {
		adapter, err := NewAdapter(algorithm)
		if err != nil {
			t.Fatalf("NewAdapter(%s): %v", algorithm, err)
		}
		if adapter.Algorithm() != algorithm {
			t.Errorf("NewAdapter(%s) reported %s", algorithm, adapter.Algorithm())
		}
	}

	for _, algorithm := range []KDFAlgorithm{AlgorithmPBKDF2, AlgorithmArgon2id, "", "NOPE"} {
		if _, err := NewAdapter(algorithm); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("NewAdapter(%q) = %v, want ErrUnsupportedAlgorithm", algorithm, err)
		}
	}
}
