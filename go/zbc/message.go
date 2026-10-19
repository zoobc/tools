// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

package zbc

import (
	"crypto/ed25519"
	"crypto/sha3"
	"encoding/hex"
)

// MessageSigningScheme names the off-chain message signature the tools produce: chain-bound (signing.md 5a).
const MessageSigningScheme = "ZBC-MSG-v2"

// MessageSigningSchemeV1 is the legacy unbound scheme (signing.md 5); verified until MessageSigningV1Sunset, never produced.
const MessageSigningSchemeV1 = "ZBC-MSG-v1"

// MessageSigningV1Sunset is 2026-12-01T00:00:00Z: from then on a v1 signature is invalid.
const MessageSigningV1Sunset int64 = 1796083200

// MessageSigningV1Accepted is the scheme verify-message reports for a v1 signature that still verifies.
const MessageSigningV1Accepted = MessageSigningSchemeV1 + " (accepted until 2026-12-01)"

// MessageDigest is SHA3-256("ZBC-MSG-v2" || genesis_hash (32) || message).
func MessageDigest(message, genesisHash []byte) []byte {
	buf := append([]byte("ZBC-MSG-v2"), genesisHash...)
	sum := sha3.Sum256(append(buf, message...))
	return sum[:]
}

// MessageDigestV1 is SHA3-256("ZBC-MSG" || message), the legacy digest.
func MessageDigestV1(message []byte) []byte {
	sum := sha3.Sum256(append([]byte("ZBC-MSG"), message...))
	return sum[:]
}

// SignedMessage is the sign-message result.
type SignedMessage struct {
	Scheme      string `json:"scheme"`
	GenesisHash string `json:"genesis_hash"`
	Address     string `json:"address"`
	PublicKey   string `json:"public_key"`
	MessageHex  string `json:"message_hex"`
	Digest      string `json:"digest"`
	Signature   string `json:"signature"`
}

// SignMessage signs a message under ZBC-MSG-v2 for the chain whose genesis block hash is genesisHash (32 bytes).
func SignMessage(kp KeyPair, message, genesisHash []byte) (SignedMessage, error) {
	if len(genesisHash) != 32 {
		return SignedMessage{}, Usage("ZBC-MSG-v2 binds the signature to one chain: it needs the chain's genesis (a node, or --genesis <hex>)")
	}
	digest := MessageDigest(message, genesisHash)
	return SignedMessage{MessageSigningScheme, hex.EncodeToString(genesisHash), kp.Address(), hex.EncodeToString(kp.PublicKey),
		hex.EncodeToString(message), hex.EncodeToString(digest), hex.EncodeToString(kp.Sign(digest))}, nil
}

// PublicKeyOfAddress is the key behind a ZBC_ address or 64 hex, or nil.
func PublicKeyOfAddress(address string) []byte {
	if IsHex(address, 64) {
		b, _ := hex.DecodeString(address)
		return b
	}
	if prefix, payload, ok := DecodeZbcAddress(address); ok && prefix == "ZBC" {
		return payload
	}
	return nil
}

func verifyDigest(address string, digest, signature []byte) bool {
	pub := PublicKeyOfAddress(address)
	if pub == nil || len(signature) != 64 {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), digest, signature)
}

// VerifyMessage checks a ZBC-MSG-v2 signature for the chain genesisHash; false for anything that does not verify, never panics.
func VerifyMessage(address string, message, signature, genesisHash []byte) bool {
	return len(genesisHash) == 32 && verifyDigest(address, MessageDigest(message, genesisHash), signature)
}

// VerifyMessageV1 checks a legacy ZBC-MSG-v1 signature, regardless of the sunset.
func VerifyMessageV1(address string, message, signature []byte) bool {
	return verifyDigest(address, MessageDigestV1(message), signature)
}

// MessageVerification is what verify-message reports.
type MessageVerification struct {
	Valid  bool
	Scheme string // MessageSigningScheme, or MessageSigningV1Accepted when a v1 signature was accepted
	Digest []byte // the digest that verified; otherwise the v2 digest when the genesis is known, else the v1 digest
}

// VerifyMessageAny tries v2 (when genesisHash is 32 bytes), then v1 while now is before MessageSigningV1Sunset.
func VerifyMessageAny(address string, message, signature, genesisHash []byte, now int64) MessageVerification {
	r := MessageVerification{Scheme: MessageSigningScheme}
	if len(genesisHash) == 32 {
		r.Digest = MessageDigest(message, genesisHash)
		if verifyDigest(address, r.Digest, signature) {
			r.Valid = true
			return r
		}
	}
	if now < MessageSigningV1Sunset && VerifyMessageV1(address, message, signature) {
		return MessageVerification{Valid: true, Scheme: MessageSigningV1Accepted, Digest: MessageDigestV1(message)}
	}
	if r.Digest == nil {
		r.Digest = MessageDigestV1(message)
	}
	return r
}
