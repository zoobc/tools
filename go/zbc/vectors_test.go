// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

package zbc

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func loadVectors(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "spec", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatal(err)
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestKeys(t *testing.T) {
	var d struct {
		Seeds []struct {
			Seed        string `json:"seed"`
			PublicKey   string `json:"public_key"`
			Address     string `json:"address"`
			NodeAddress string `json:"node_address"`
		}
		Wallets []struct {
			Mnemonic, Passphrase string
			Accounts             []struct {
				Index       int    `json:"index"`
				Path        string `json:"path"`
				Seed        string `json:"seed"`
				Address     string `json:"address"`
				NodeAddress string `json:"node_address"`
			}
		}
	}
	loadVectors(t, "keys.json", &d)
	for _, s := range d.Seeds {
		kp, err := KeyPairFromHex(s.Seed)
		if err != nil || hex.EncodeToString(kp.PublicKey) != s.PublicKey || kp.Address() != s.Address || kp.NodeAddress() != s.NodeAddress {
			t.Errorf("seed %s: %v %s %s", s.Seed, err, kp.Address(), kp.NodeAddress())
		}
	}
	for _, w := range d.Wallets {
		if !ValidateMnemonic(w.Mnemonic) {
			t.Errorf("mnemonic rejected")
		}
		for _, a := range w.Accounts {
			kp, path, err := WalletAccount(w.Mnemonic, a.Index, w.Passphrase)
			if err != nil || path != a.Path || hex.EncodeToString(kp.Seed) != a.Seed || kp.Address() != a.Address || kp.NodeAddress() != a.NodeAddress {
				t.Errorf("account %d: %v %s %s", a.Index, err, path, kp.Address())
			}
		}
	}
}

func TestAddresses(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("..", "..", "spec", "vectors", "addresses.json"))
	var generic struct {
		Vectors []map[string]any
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	for _, v := range generic.Vectors {
		input, _ := v["input"].(string)
		chain, _ := v["chain"].(string)
		p, err := ParseAddress(input, chain)
		if valid, _ := v["valid"].(bool); valid {
			want, _ := v["address_bytes"].(string)
			typ, _ := v["account_type"].(float64)
			if err != nil || p.Type != int(typ) || hex.EncodeToString(p.Bytes()) != want {
				t.Errorf("%q: got type %d %s err %v", input, p.Type, hex.EncodeToString(p.Bytes()), err)
			}
		} else if err == nil {
			t.Errorf("%q: accepted, reference refuses it", input)
		}
	}
}

func TestMessages(t *testing.T) {
	var d struct {
		Vectors []struct {
			Seed       string `json:"seed"`
			MessageHex string `json:"message_hex"`
			Address    string `json:"address"`
			PublicKey  string `json:"public_key"`
			Digest     string `json:"digest"`
			Signature  string `json:"signature"`
		}
		Invalid []struct{ Case, Address, Message, Signature string }
	}
	loadVectors(t, "messages.json", &d)
	for _, v := range d.Vectors {
		kp, _ := KeyPairFromHex(v.Seed)
		s := SignMessage(kp, unhex(t, v.MessageHex))
		if s.Address != v.Address || s.PublicKey != v.PublicKey || s.Digest != v.Digest || s.Signature != v.Signature {
			t.Errorf("sign %s: %+v", v.Seed, s)
		}
		if !VerifyMessage(v.Address, unhex(t, v.MessageHex), unhex(t, v.Signature)) {
			t.Errorf("verify %s failed", v.Seed)
		}
	}
	for _, n := range d.Invalid {
		sig, _ := hex.DecodeString(n.Signature)
		if VerifyMessage(n.Address, []byte(n.Message), sig) {
			t.Errorf("%s: verified, must not", n.Case)
		}
	}
}

type txVector struct {
	Name, Command, Key, Genesis string
	Type                        uint32
	Params                      map[string]string
	Fee, Timestamp              int64
	Message                     *string
	Escrow                      *struct {
		Approver            string
		Commission, Timeout int64
		Instruction         string
	}
	ReferenceBlock *struct {
		BlockHash string `json:"block_hash"`
		Height    uint32
	} `json:"reference_block"`
	Files    map[string]string
	Expected struct {
		Body             string          `json:"body"`
		UnsignedBytes    string          `json:"unsigned_bytes"`
		Digest           string          `json:"digest"`
		Signature        string          `json:"signature"`
		TransactionBytes string          `json:"transaction_bytes"`
		TransactionHash  string          `json:"transaction_hash"`
		Payload          json.RawMessage `json:"payload"`
	}
}

func checkSigned(t *testing.T, v txVector, body []byte) {
	t.Helper()
	if hex.EncodeToString(body) != v.Expected.Body {
		t.Errorf("%s body: %s != %s", v.Name, hex.EncodeToString(body), v.Expected.Body)
		return
	}
	def := CommandByName[v.Command]
	kp, _ := KeyPairFromHex(v.Key)
	var recipient []byte
	if def.Recipient == "required" {
		r, err := ParseAddress(v.Params["recipient"], "")
		if err != nil {
			t.Fatal(err)
		}
		recipient = r.Bytes()
	}
	var escrow *Escrow
	if v.Escrow != nil {
		escrow = &Escrow{v.Escrow.Approver, v.Escrow.Commission, v.Escrow.Timeout, v.Escrow.Instruction}
	}
	var msg []byte
	if v.Message != nil {
		msg = []byte(*v.Message)
	}
	ctx, _ := SigningContextOf(v.Genesis)
	s, err := SignTransaction(Unsigned{Type: v.Type, Timestamp: v.Timestamp, Sender: kp.AccountBytes(), Recipient: recipient, Fee: v.Fee, Body: body, Escrow: escrow, Message: msg}, kp, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(s.Unsigned) != v.Expected.UnsignedBytes || hex.EncodeToString(s.Digest) != v.Expected.Digest || hex.EncodeToString(s.Signature) != v.Expected.Signature ||
		hex.EncodeToString(s.Bytes) != v.Expected.TransactionBytes || hex.EncodeToString(s.Hash) != v.Expected.TransactionHash {
		t.Errorf("%s: envelope differs\n got %x\nwant %s", v.Name, s.Unsigned, v.Expected.UnsignedBytes)
	}
	var got, want map[string]any
	b, _ := json.Marshal(s.Payload)
	_ = json.Unmarshal(b, &got)
	_ = json.Unmarshal(v.Expected.Payload, &want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s payload: %v != %v", v.Name, got, want)
	}
}

func TestCoreTransactions(t *testing.T) {
	var d struct{ Vectors []txVector }
	loadVectors(t, "transactions.json", &d)
	for _, v := range d.Vectors {
		var body []byte
		if v.Command == "send-zbc" {
			n, _ := ParseInteger(v.Params["amount"], "int64", "amount")
			body = SendZBCBody(n)
		} else {
			n, _ := ParseInteger(v.Params["approval"], "uint32", "approval")
			body, _ = ApprovalEscrowBody(uint32(n), unhex(t, v.Params["transaction_hash"]))
		}
		checkSigned(t, v, body)
	}
}

func TestAllTransactionTypes(t *testing.T) {
	var d struct{ Vectors []txVector }
	loadVectors(t, "transactions-all.json", &d)
	for _, v := range d.Vectors {
		def := CommandByName[v.Command]
		kp, _ := KeyPairFromHex(v.Key)
		ctx, _ := SigningContextOf(v.Genesis)
		in := CustomInput{Def: def, Params: v.Params, Sender: kp, Ctx: ctx, Timestamp: v.Timestamp}
		if v.ReferenceBlock != nil {
			in.Block = &ReferenceBlock{unhex(t, v.ReferenceBlock.BlockHash), v.ReferenceBlock.Height}
		}
		var body []byte
		var err error
		if def.Custom == "multisig" || def.Custom == "settle" {
			body, _, err = CustomBody(in)
		} else {
			bc := &BodyContext{Sender: kp, Files: map[string][]byte{}, Computed: map[string][]byte{}}
			for k, h := range v.Files {
				bc.Files[k] = unhex(t, h)
			}
			if _, err = ComputeFields(in, bc); err == nil {
				body, err = BuildBody(def, v.Params, bc)
			}
		}
		if err != nil {
			t.Errorf("%s: %v", v.Name, err)
			continue
		}
		checkSigned(t, v, body)
	}
}

func TestTransactionID(t *testing.T) {
	if TransactionID(unhex(t, "4ac2d11be8fe534bf2b2776fa7c1a3ece08e17f3b71e8d796545f5edde8b86fa")) != 5427962248764179018 {
		t.Error("transaction id")
	}
}
