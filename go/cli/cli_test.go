// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/zoobc/tools/go/zbc"
)

func load(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "spec", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func clearEnv(t *testing.T) {
	for _, k := range []string{"ZBC_KEY", "ZBC_API", "ZBC_TIMEOUT", "ZOOBC_GENESIS_HASH"} {
		t.Setenv(k, "")
	}
}

type vec struct {
	Name, Command, Key, Genesis string
	Params                      map[string]string
	Fee, Timestamp              int64
	Message                     *string
	Escrow                      *struct {
		Approver            string
		Commission, Timeout int64
		Instruction         string
	}
	Expected struct {
		TransactionHash string `json:"transaction_hash"`
		UnsignedBytes   string `json:"unsigned_bytes"`
		Payload         map[string]any
	}
}

func TestOfflineReproducesEveryVector(t *testing.T) {
	clearEnv(t)
	var core, all struct{ Vectors []vec }
	load(t, "transactions.json", &core)
	load(t, "transactions-all.json", &all)
	for _, v := range append(core.Vectors, all.Vectors...) {
		def := zbc.CommandByName[v.Command]
		if def.NeedsNode {
			continue
		}
		skip := false
		for _, p := range def.Params {
			if p.Kind == "file" {
				skip = true
			}
		}
		if skip {
			continue
		}
		args := []string{v.Command, v.Key}
		for _, p := range def.Params[1:] {
			if v.Command == "liquid-payment" && p.Name == "token_id" {
				continue
			}
			val, ok := v.Params[p.Name]
			if !ok {
				val = p.Default
			}
			args = append(args, val)
		}
		args = append(args, "--fee", strconv.FormatInt(v.Fee, 10), "--timestamp", strconv.FormatInt(v.Timestamp, 10), "--genesis", v.Genesis, "--offline")
		if v.Message != nil {
			args = append(args, "--message", *v.Message)
		}
		if v.Escrow != nil {
			args = append(args, "--escrow-approver", v.Escrow.Approver, "--escrow-commission", strconv.FormatInt(v.Escrow.Commission, 10), "--escrow-timeout", strconv.FormatInt(v.Escrow.Timeout, 10))
			if v.Escrow.Instruction != "" {
				args = append(args, "--escrow-instruction", v.Escrow.Instruction)
			}
		}
		if v.Command == "liquid-payment" && v.Params["token_id"] != "" && v.Params["token_id"] != "0" {
			args = append(args, "--token", v.Params["token_id"])
		}
		code, out, errs := run(t, "", args...)
		if code != 0 {
			t.Errorf("%s: exit %d %s %s", v.Name, code, out, errs)
			continue
		}
		var j map[string]any
		if err := json.Unmarshal([]byte(out), &j); err != nil {
			t.Fatal(err)
		}
		if j["transaction_hash"] != v.Expected.TransactionHash || j["unsigned_bytes"] != v.Expected.UnsignedBytes {
			t.Errorf("%s: hash %v", v.Name, j["transaction_hash"])
		}
		if !reflect.DeepEqual(j["payload"], v.Expected.Payload) {
			t.Errorf("%s: payload %v != %v", v.Name, j["payload"], v.Expected.Payload)
		}
	}
}

func TestExitCodes(t *testing.T) {
	clearEnv(t)
	var d struct {
		Vectors []struct {
			Case, ErrorClass string `json:",omitempty"`
			Args             []string
			Stdin            *string
			ExitCode         int    `json:"exit_code"`
			Class            string `json:"error_class"`
		}
	}
	load(t, "cli.json", &d)
	for _, c := range d.Vectors {
		stdin := ""
		if c.Stdin != nil {
			stdin = *c.Stdin
		}
		code, out, errs := run(t, stdin, c.Args...)
		if code != c.ExitCode {
			t.Errorf("%s: exit %d, want %d: %s %s", c.Case, code, c.ExitCode, out, errs)
			continue
		}
		if c.Class != "" {
			var j map[string]any
			_ = json.Unmarshal([]byte(out), &j)
			if j["error_class"] != c.Class {
				t.Errorf("%s: error_class %v, want %s", c.Case, j["error_class"], c.Class)
			}
		}
	}
}

func TestMessagesThroughCLI(t *testing.T) {
	clearEnv(t)
	var d struct {
		Vectors []struct {
			Seed       string `json:"seed"`
			Message    string `json:"message"`
			MessageHex string `json:"message_hex"`
			Address    string `json:"address"`
			Signature  string `json:"signature"`
			HexInput   bool   `json:"hex_input"`
		}
		Invalid []struct {
			Case, Address, Message, Signature string
			ExitCode                          int `json:"exit_code"`
		}
	}
	load(t, "messages.json", &d)
	for _, v := range d.Vectors {
		msg := v.Message
		var flag []string
		if v.HexInput {
			msg = v.MessageHex
			flag = []string{"--hex"}
		}
		code, out, _ := run(t, "", append([]string{"sign-message", v.Seed, msg}, flag...)...)
		var j map[string]any
		_ = json.Unmarshal([]byte(out), &j)
		if code != 0 || j["signature"] != v.Signature {
			t.Errorf("sign-message %s: %d %v", v.Seed, code, j["signature"])
		}
		code, out, _ = run(t, "", append([]string{"verify-message", v.Address, msg, v.Signature}, flag...)...)
		_ = json.Unmarshal([]byte(out), &j)
		if code != 0 || j["valid"] != true {
			t.Errorf("verify-message %s: %d", v.Seed, code)
		}
	}
	for _, n := range d.Invalid {
		if code, _, _ := run(t, "", "verify-message", n.Address, n.Message, n.Signature); code != n.ExitCode {
			t.Errorf("%s: exit %d, want %d", n.Case, code, n.ExitCode)
		}
	}
}

func TestJSONInputAndEnvKey(t *testing.T) {
	clearEnv(t)
	var d struct{ Vectors []vec }
	load(t, "transactions.json", &d)
	v := d.Vectors[0]
	stdin, _ := json.Marshal(map[string]any{"sender_privkey": v.Key, "recipient": v.Params["recipient"], "amount": v.Params["amount"], "fee": v.Fee, "timestamp": v.Timestamp, "offline": true})
	code, out, errs := run(t, string(stdin), "send-zbc", "--json-input", "--genesis", v.Genesis)
	var j map[string]any
	_ = json.Unmarshal([]byte(out), &j)
	if code != 0 || j["transaction_hash"] != v.Expected.TransactionHash {
		t.Errorf("json-input: %d %s %s", code, out, errs)
	}
	t.Setenv("ZBC_KEY", v.Key)
	for _, args := range [][]string{{v.Params["recipient"], v.Params["amount"]}, {"-", v.Params["recipient"], v.Params["amount"]}} {
		code, out, errs := run(t, "", append(append([]string{"send-zbc"}, args...), "--timestamp", strconv.FormatInt(v.Timestamp, 10), "--genesis", v.Genesis, "--offline")...)
		_ = json.Unmarshal([]byte(out), &j)
		if code != 0 || j["transaction_hash"] != v.Expected.TransactionHash {
			t.Errorf("ZBC_KEY %v: %d %s %s", args, code, out, errs)
		}
	}
}

func TestUnreachableNode(t *testing.T) {
	clearEnv(t)
	var d struct{ Vectors []vec }
	load(t, "transactions.json", &d)
	v := d.Vectors[0]
	code, out, _ := run(t, "", "send-zbc", v.Key, v.Params["recipient"], "1", "--api", "http://127.0.0.1:9", "--genesis", "v1", "--timeout", "2")
	var j map[string]any
	_ = json.Unmarshal([]byte(out), &j)
	if code != 3 || j["error_class"] != "node_unreachable" {
		t.Errorf("unreachable: %d %s", code, out)
	}
}
