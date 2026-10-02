package transport

import (
	"encoding/json"
	"testing"
)

// TestSecretFields_WireUnchanged proves the PIN and password fields, now
// wipeable byte slices, read the JSON they always did and write it back
// byte for byte.
func TestSecretFields_WireUnchanged(t *testing.T) {
	cases := []struct {
		name string
		json string
		new  func() any
		get  func(any) []byte
	}{
		{
			name: "seal password",
			json: `{"backend":"tpm2","key_id":"k","data":"ZA==","password":"p\"w\\d\n"}`,
			new:  func() any { return &SealRequest{} },
			get:  func(v any) []byte { return v.(*SealRequest).Password },
		},
		{
			name: "unseal password",
			json: `{"backend":"tpm2","key_id":"","ciphertext":null,"password":"s3cret"}`,
			new:  func() any { return &UnsealRequest{} },
			get:  func(v any) []byte { return v.(*UnsealRequest).Password },
		},
		{
			name: "piv pin",
			json: `{"backend":"b","slot":"9a","payload":"AQ==","pin":"123456"}`,
			new:  func() any { return &PIVSignRequest{} },
			get:  func(v any) []byte { return v.(*PIVSignRequest).PIN },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := tc.new()
			if err := json.Unmarshal([]byte(tc.json), v); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(tc.get(v)) == 0 {
				t.Fatal("secret not decoded")
			}
			// Compare through a string-typed twin: what the old struct wrote.
			out, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var oldForm, newForm map[string]json.RawMessage
			if err := json.Unmarshal(out, &newForm); err != nil {
				t.Fatalf("remarshal output: %v", err)
			}
			if err := json.Unmarshal([]byte(tc.json), &oldForm); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"password", "pin"} {
				if string(oldForm[key]) != string(newForm[key]) {
					t.Errorf("%s: wrote %s, old wire form %s", key, newForm[key], oldForm[key])
				}
			}
		})
	}
}

// TestSecretFields_StringTwin proves a string-typed peer and the new type
// interoperate in both directions for every secret field.
func TestSecretFields_StringTwin(t *testing.T) {
	type twin struct {
		Password string `json:"password,omitempty"`
	}
	old, err := json.Marshal(twin{Password: "a\"b<c>&é"})
	if err != nil {
		t.Fatal(err)
	}
	var req SealRequest
	if err := json.Unmarshal(old, &req); err != nil {
		t.Fatal(err)
	}
	written, err := json.Marshal(&req)
	if err != nil {
		t.Fatal(err)
	}
	var back twin
	if err := json.Unmarshal(written, &back); err != nil {
		t.Fatal(err)
	}
	if back.Password != "a\"b<c>&é" {
		t.Errorf("round trip = %q", back.Password)
	}
	req.Password.Wipe()
	if req.Password != nil {
		t.Error("Wipe left a reference")
	}
}
