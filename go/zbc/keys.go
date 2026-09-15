// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

package zbc

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ZooBCCoinType is the SLIP-44 coin type of the m/44'/883'/i' wallet path.
const ZooBCCoinType = 883

// KeyPair is a 32-byte seed with its public key.
type KeyPair struct {
	Seed      []byte
	PublicKey []byte
}

// KeyPairFromSeed derives the key pair of a 32-byte seed.
func KeyPairFromSeed(seed []byte) (KeyPair, error) {
	if len(seed) != 32 {
		return KeyPair{}, errors.New("Private key must be 64 hex characters (32 bytes)")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return KeyPair{Seed: append([]byte{}, seed...), PublicKey: []byte(priv.Public().(ed25519.PublicKey))}, nil
}

// KeyPairFromHex derives the key pair of a 64-hex seed.
func KeyPairFromHex(seedHex string) (KeyPair, error) {
	if !IsHex(seedHex, 64) {
		return KeyPair{}, errors.New("Private key must be 64 hex characters (32 bytes)")
	}
	seed, _ := hex.DecodeString(seedHex)
	return KeyPairFromSeed(seed)
}

// Address is the ZBC_ form of the public key.
func (k KeyPair) Address() string { return MustEncodeZbcAddress(k.PublicKey, "ZBC") }

// NodeAddress is the ZNK_ form of the same key.
func (k KeyPair) NodeAddress() string { return MustEncodeZbcAddress(k.PublicKey, "ZNK") }

// AccountBytes is the 36-byte typed account address: 00000000 || public key.
func (k KeyPair) AccountBytes() []byte { return TypedAddress(TypeZooBC, k.PublicKey) }

// Sign is a detached Ed25519 signature with the seed.
func (k KeyPair) Sign(msg []byte) []byte { return ed25519.Sign(ed25519.NewKeyFromSeed(k.Seed), msg) }

// RandomSeed is a fresh 32-byte seed from crypto/rand.
func RandomSeed() []byte {
	s := make([]byte, 32)
	if _, err := rand.Read(s); err != nil {
		panic(err)
	}
	return s
}

// ValidateMnemonic is true for 12, 15, 18, 21 or 24 English words with a valid checksum.
func ValidateMnemonic(mnemonic string) bool {
	words := strings.Fields(mnemonic)
	switch len(words) {
	case 12, 15, 18, 21, 24:
	default:
		return false
	}
	var bits strings.Builder
	for _, w := range words {
		idx := -1
		for i, x := range BIP39Words {
			if x == w {
				idx = i
				break
			}
		}
		if idx < 0 {
			return false
		}
		bits.WriteString(fmt.Sprintf("%011b", idx))
	}
	s := bits.String()
	cs := len(words) / 3
	entropy := make([]byte, (len(s)-cs)/8)
	for i := range entropy {
		var v byte
		for j := 0; j < 8; j++ {
			v = v<<1 | (s[8*i+j] - '0')
		}
		entropy[i] = v
	}
	sum := sha256.Sum256(entropy)
	return s[len(s)-cs:] == fmt.Sprintf("%08b", sum[0])[:cs]
}

// MnemonicFromEntropy builds a mnemonic from 16–32 bytes of entropy (a multiple of 4).
func MnemonicFromEntropy(entropy []byte) (string, error) {
	if len(entropy) < 16 || len(entropy) > 32 || len(entropy)%4 != 0 {
		return "", errors.New("entropy must be 16-32 bytes, a multiple of 4")
	}
	var bits strings.Builder
	for _, b := range entropy {
		bits.WriteString(fmt.Sprintf("%08b", b))
	}
	sum := sha256.Sum256(entropy)
	bits.WriteString(fmt.Sprintf("%08b", sum[0])[:len(entropy)/4])
	s := bits.String()
	words := make([]string, 0, len(s)/11)
	for i := 0; i+11 <= len(s); i += 11 {
		idx := 0
		for j := 0; j < 11; j++ {
			idx = idx<<1 | int(s[i+j]-'0')
		}
		words = append(words, BIP39Words[idx])
	}
	return strings.Join(words, " "), nil
}

// GenerateMnemonic makes a random mnemonic of 12, 15, 18, 21 or 24 words.
func GenerateMnemonic(words int) (string, error) {
	entropy := make([]byte, (words*11-words/3)/8)
	if _, err := rand.Read(entropy); err != nil {
		return "", err
	}
	return MnemonicFromEntropy(entropy)
}

// MnemonicToSeed is PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048, 64).
func MnemonicToSeed(mnemonic, passphrase string) []byte {
	seed, err := pbkdf2.Key(sha512.New, strings.Join(strings.Fields(mnemonic), " "), []byte("mnemonic"+passphrase), 2048, 64)
	if err != nil {
		panic(err)
	}
	return seed
}

var pathRe = regexp.MustCompile(`^m(/[0-9]+')+$`)

// SLIP10Derive follows a hardened-only Ed25519 path such as m/44'/883'/0' and returns the 32-byte key.
func SLIP10Derive(path string, seed []byte) ([]byte, error) {
	if !pathRe.MatchString(path) {
		return nil, errors.New("invalid derivation path: " + path)
	}
	mac := hmac.New(sha512.New, []byte("ed25519 seed"))
	mac.Write(seed)
	digest := mac.Sum(nil)
	key, chain := digest[:32], digest[32:]
	for _, seg := range strings.Split(path, "/")[1:] {
		var index uint64
		if _, err := fmt.Sscanf(seg[:len(seg)-1], "%d", &index); err != nil || index >= 0x80000000 {
			return nil, errors.New("path index too large")
		}
		data := make([]byte, 37)
		copy(data[1:], key)
		binary.BigEndian.PutUint32(data[33:], uint32(index)+0x80000000)
		mac = hmac.New(sha512.New, chain)
		mac.Write(data)
		digest = mac.Sum(nil)
		key, chain = digest[:32], digest[32:]
	}
	return key, nil
}

// WalletAccount is account index of a mnemonic wallet: m/44'/883'/index'.
func WalletAccount(mnemonic string, index int, passphrase string) (KeyPair, string, error) {
	path := fmt.Sprintf("m/44'/%d'/%d'", ZooBCCoinType, index)
	key, err := SLIP10Derive(path, MnemonicToSeed(mnemonic, passphrase))
	if err != nil {
		return KeyPair{}, "", err
	}
	kp, err := KeyPairFromSeed(key)
	return kp, path, err
}
