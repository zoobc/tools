// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

package zbc

import (
	"bytes"
	"encoding/hex"
	"regexp"
	"testing"
)

type encryptionKey struct {
	Seed            string `json:"seed"`
	PublicKey       string `json:"public_key"`
	X25519PublicKey string `json:"x25519_public_key"`
	X25519SecretKey string `json:"x25519_secret_key"`
}

type encryptionSealed struct {
	Name               string `json:"name"`
	RecipientSeed      string `json:"recipient_seed"`
	RecipientPublicKey string `json:"recipient_public_key"`
	PlaintextHex       string `json:"plaintext_hex"`
	EphemeralSecretKey string `json:"ephemeral_secret_key"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Nonce              string `json:"nonce"`
	MessageField       string `json:"message_field"`
}

type encryptionSample struct {
	Name          string `json:"name"`
	RecipientSeed string `json:"recipient_seed"`
	PlaintextHex  string `json:"plaintext_hex"`
	MessageField  string `json:"message_field"`
}

type encryptionInvalid struct {
	Case          string `json:"case"`
	RecipientSeed string `json:"recipient_seed"`
	MessageField  string `json:"message_field"`
	ExitCode      int    `json:"exit_code"`
	ErrorClass    string `json:"error_class"`
}

type encryptionVectors struct {
	Keys    []encryptionKey     `json:"keys"`
	Sealed  []encryptionSealed  `json:"sealed"`
	Samples []encryptionSample  `json:"samples"`
	Invalid []encryptionInvalid `json:"invalid"`
}

func TestEncryption(t *testing.T) {
	var d encryptionVectors
	loadVectors(t, "encryption.json", &d)
	if len(d.Keys) == 0 || len(d.Sealed) == 0 || len(d.Samples) == 0 {
		t.Fatal("encryption.json is empty")
	}
	for _, k := range d.Keys {
		pk, err := Ed25519PublicKeyToX25519(unhex(t, k.PublicKey))
		if err != nil || hex.EncodeToString(pk) != k.X25519PublicKey {
			t.Fatalf("pk conversion of %s: %x %v", k.PublicKey, pk, err)
		}
		if hex.EncodeToString(Ed25519SeedToX25519(unhex(t, k.Seed))) != k.X25519SecretKey {
			t.Fatalf("sk conversion of %s", k.Seed)
		}
		base, _ := X25519Base(unhex(t, k.X25519SecretKey))
		if hex.EncodeToString(base) != k.X25519PublicKey {
			t.Fatalf("X25519 base of %s", k.X25519SecretKey)
		}
	}
	for _, s := range d.Sealed {
		f, err := Seal(unhex(t, s.PlaintextHex), unhex(t, s.RecipientPublicKey), unhex(t, s.EphemeralSecretKey))
		if err != nil || hex.EncodeToString(f) != s.MessageField {
			t.Fatalf("%s: sealed %x %v", s.Name, f, err)
		}
		pt, ok := OpenSealed(f, unhex(t, s.RecipientSeed))
		if !ok || hex.EncodeToString(pt) != s.PlaintextHex {
			t.Fatalf("%s: open", s.Name)
		}
	}
	for _, s := range d.Samples {
		pt, ok := OpenSealed(unhex(t, s.MessageField), unhex(t, s.RecipientSeed))
		if !ok || hex.EncodeToString(pt) != s.PlaintextHex {
			t.Fatalf("%s: the C++ tool's field does not open", s.Name)
		}
	}
	isHex := regexp.MustCompile(`^[0-9a-f]*$`)
	for _, i := range d.Invalid {
		if !isHex.MatchString(i.MessageField) {
			continue
		}
		if _, ok := OpenSealed(unhex(t, i.MessageField), unhex(t, i.RecipientSeed)); ok {
			t.Fatalf("%s: opened", i.Case)
		}
	}
	kp, _ := KeyPairFromHex(d.Keys[0].Seed)
	f, err := Seal([]byte("round trip"), kp.PublicKey, nil)
	if err != nil || len(f) != 10+SealedOverhead {
		t.Fatalf("random seal: %v", err)
	}
	if pt, ok := OpenSealed(f, kp.Seed); !ok || !bytes.Equal(pt, []byte("round trip")) {
		t.Fatal("random round trip")
	}
}
