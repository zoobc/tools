// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

package zbc

import (
	"bytes"
	"encoding/hex"
	"regexp"
	"testing"
)

type encryptionVectors struct {
	Keys []struct {
		Seed, PublicKey, X25519PublicKey, X25519SecretKey string
	} `json:"keys"`
	Sealed []struct {
		Name, RecipientSeed, RecipientPublicKey, PlaintextHex, EphemeralSecretKey, EphemeralPublicKey, Nonce, MessageField string
	} `json:"sealed"`
	Samples []struct {
		Name, RecipientSeed, PlaintextHex, MessageField string
	} `json:"samples"`
	Invalid []struct {
		Case, RecipientSeed, MessageField string
		ExitCode                          int    `json:"exit_code"`
		ErrorClass                        string `json:"error_class"`
	} `json:"invalid"`
}

func TestEncryption(t *testing.T) {
	var d encryptionVectors
	loadVectors(t, "encryption.json", &d)
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
