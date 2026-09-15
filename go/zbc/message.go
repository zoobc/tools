// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

package zbc

import (
	"crypto/ed25519"
	"crypto/sha3"
	"encoding/hex"
)

// MessageSigningScheme names the off-chain message signature.
const MessageSigningScheme = "ZBC-MSG-v1"

// MessageDigest is SHA3-256("ZBC-MSG" || message).
func MessageDigest(message []byte) []byte {
	sum := sha3.Sum256(append([]byte("ZBC-MSG"), message...))
	return sum[:]
}

// SignedMessage is the sign-message result.
type SignedMessage struct {
	Scheme     string `json:"scheme"`
	Address    string `json:"address"`
	PublicKey  string `json:"public_key"`
	MessageHex string `json:"message_hex"`
	Digest     string `json:"digest"`
	Signature  string `json:"signature"`
}

// SignMessage signs a message under ZBC-MSG-v1.
func SignMessage(kp KeyPair, message []byte) SignedMessage {
	digest := MessageDigest(message)
	return SignedMessage{MessageSigningScheme, kp.Address(), hex.EncodeToString(kp.PublicKey), hex.EncodeToString(message),
		hex.EncodeToString(digest), hex.EncodeToString(kp.Sign(digest))}
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

// VerifyMessage is false for anything that does not verify; it never panics.
func VerifyMessage(address string, message, signature []byte) bool {
	pub := PublicKeyOfAddress(address)
	if pub == nil || len(signature) != 64 {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), MessageDigest(message), signature)
}
