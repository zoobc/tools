// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEncryptAndDecryptThroughCLI(t *testing.T) {
	clearEnv(t)
	var d struct {
		Keys []struct {
			Seed string `json:"seed"`
		} `json:"keys"`
		Samples []struct {
			Name             string `json:"name"`
			RecipientSeed    string `json:"recipient_seed"`
			RecipientAddress string `json:"recipient_address"`
			Plaintext        string `json:"plaintext"`
			PlaintextHex     string `json:"plaintext_hex"`
			MessageField     string `json:"message_field"`
		} `json:"samples"`
		Invalid []struct {
			Case          string `json:"case"`
			RecipientSeed string `json:"recipient_seed"`
			MessageField  string `json:"message_field"`
			ExitCode      int    `json:"exit_code"`
			ErrorClass    string `json:"error_class"`
		} `json:"invalid"`
	}
	load(t, "encryption.json", &d)
	s := d.Samples[0]
	code, out, errs := run(t, "", "send-zbc", d.Keys[0].Seed, s.RecipientAddress, "1", "--message", s.Plaintext, "--encrypt", "--genesis", "v1", "--offline")
	if code != 0 {
		t.Fatalf("send-zbc --encrypt: %d %s%s", code, out, errs)
	}
	var j struct {
		Message string `json:"message"`
		Payload struct {
			MessageHex string `json:"message_hex"`
		} `json:"payload"`
	}
	if err := json.Unmarshal([]byte(out), &j); err != nil || j.Message != s.Plaintext {
		t.Fatalf("output: %v %s", err, out)
	}
	if !strings.HasPrefix(j.Payload.MessageHex, "5a424531") || len(j.Payload.MessageHex) != 2*(len(s.Plaintext)+52) {
		t.Fatalf("sealed field: %s", j.Payload.MessageHex)
	}
	code, out, errs = run(t, "", "decrypt-message", s.RecipientSeed, j.Payload.MessageHex)
	var dm struct {
		Message    string `json:"message"`
		MessageHex string `json:"message_hex"`
		ErrorClass string `json:"error_class"`
	}
	_ = json.Unmarshal([]byte(out), &dm)
	if code != 0 || dm.Message != s.Plaintext {
		t.Fatalf("decrypt-message: %d %s%s", code, out, errs)
	}
	for _, smp := range d.Samples {
		code, out, _ = run(t, "", "decrypt-message", smp.RecipientSeed, smp.MessageField)
		_ = json.Unmarshal([]byte(out), &dm)
		if code != 0 || dm.MessageHex != smp.PlaintextHex {
			t.Fatalf("%s: %d %s", smp.Name, code, out)
		}
	}
	for _, i := range d.Invalid {
		code, out, _ = run(t, "", "decrypt-message", i.RecipientSeed, i.MessageField)
		_ = json.Unmarshal([]byte(out), &dm)
		if code != i.ExitCode || dm.ErrorClass != i.ErrorClass {
			t.Fatalf("%s: %d %s", i.Case, code, out)
		}
	}
	if code, _, _ = run(t, "", "send-zbc", d.Keys[0].Seed, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "1", "--message", "x", "--encrypt", "--genesis", "v1", "--offline"); code != 2 {
		t.Fatalf("--encrypt to a non-ZBC recipient: %d", code)
	}
}
