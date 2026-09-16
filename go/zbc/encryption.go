// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

package zbc

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"
)

// Sealed transaction messages (spec/signing.md section 8): "ZBE1" || libsodium sealed box to the
// recipient's Ed25519 key converted to X25519. X25519 comes from crypto/ecdh; HSalsa20, XSalsa20
// and Poly1305 are here, since the standard library has neither Salsa20 nor Poly1305.

// SealedMagic is the 4-byte marker in front of a sealed message field.
var SealedMagic = []byte("ZBE1")

// SealedOverhead is how much longer a sealed field is than its plaintext: marker 4 + ephemeral key 32 + tag 16.
const SealedOverhead = 52

var curveP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

func leToBig(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

func bigToLe(v *big.Int, n int) []byte {
	out := make([]byte, n)
	b := v.Bytes()
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

// Ed25519PublicKeyToX25519 converts an Ed25519 public key to the X25519 public key of the same
// point: u = (1 + y) / (1 - y) mod p.
func Ed25519PublicKeyToX25519(pk []byte) ([]byte, error) {
	if len(pk) != 32 {
		return nil, errors.New("public key must be 32 bytes")
	}
	y := leToBig(pk)
	y.SetBit(y, 255, 0)
	one := big.NewInt(1)
	num := new(big.Int).Add(one, y)
	den := new(big.Int).Sub(one, y)
	den.Mod(den, curveP)
	if den.Sign() == 0 {
		return nil, errors.New("public key has no X25519 form")
	}
	u := num.Mul(num, den.ModInverse(den, curveP))
	return bigToLe(u.Mod(u, curveP), 32), nil
}

// Ed25519SeedToX25519 is the X25519 secret key of an Ed25519 seed: the clamped first half of SHA-512(seed).
func Ed25519SeedToX25519(seed []byte) []byte {
	h := sha512.Sum512(seed)
	sk := h[:32]
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64
	return sk
}

// X25519Base is the X25519 public key of a scalar: X25519(scalar, 9).
func X25519Base(scalar []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

func x25519(scalar, u []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		return nil, err
	}
	p, err := ecdh.X25519().NewPublicKey(u)
	if err != nil {
		return nil, err
	}
	return k.ECDH(p)
}

var salsaSigma = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574} // "expand 32-byte k"

func rotl(v uint32, c uint) uint32 { return v<<c | v>>(32-c) }

func salsaRounds(x *[16]uint32) {
	for i := 0; i < 10; i++ {
		for _, q := range [8][4]int{{0, 4, 8, 12}, {5, 9, 13, 1}, {10, 14, 2, 6}, {15, 3, 7, 11}, {0, 1, 2, 3}, {5, 6, 7, 4}, {10, 11, 8, 9}, {15, 12, 13, 14}} {
			a, b, c, d := q[0], q[1], q[2], q[3]
			x[b] ^= rotl(x[a]+x[d], 7)
			x[c] ^= rotl(x[b]+x[a], 9)
			x[d] ^= rotl(x[c]+x[b], 13)
			x[a] ^= rotl(x[d]+x[c], 18)
		}
	}
}

func salsaState(key []byte, x *[16]uint32) {
	x[0], x[5], x[10], x[15] = salsaSigma[0], salsaSigma[1], salsaSigma[2], salsaSigma[3]
	for i := 0; i < 4; i++ {
		x[1+i] = binary.LittleEndian.Uint32(key[4*i:])
		x[11+i] = binary.LittleEndian.Uint32(key[16+4*i:])
	}
}

// HSalsa20 is HSalsa20(key 32, input 16) -> 32 bytes.
func HSalsa20(key, input []byte) []byte {
	var x [16]uint32
	salsaState(key, &x)
	for i := 0; i < 4; i++ {
		x[6+i] = binary.LittleEndian.Uint32(input[4*i:])
	}
	salsaRounds(&x)
	out := make([]byte, 32)
	for i, w := range [8]int{0, 5, 10, 15, 6, 7, 8, 9} {
		binary.LittleEndian.PutUint32(out[4*i:], x[w])
	}
	return out
}

func salsa20Block(key, nonce8 []byte, counter uint64) [64]byte {
	var x0 [16]uint32
	salsaState(key, &x0)
	x0[6] = binary.LittleEndian.Uint32(nonce8)
	x0[7] = binary.LittleEndian.Uint32(nonce8[4:])
	x0[8] = uint32(counter)
	x0[9] = uint32(counter >> 32)
	x := x0
	salsaRounds(&x)
	var out [64]byte
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(out[4*i:], x[i]+x0[i])
	}
	return out
}

// XSalsa20Stream is the XSalsa20 keystream of a 32-byte key and a 24-byte nonce.
func XSalsa20Stream(key, nonce24 []byte, length int) []byte {
	sub := HSalsa20(key, nonce24[:16])
	out := make([]byte, 0, length+64)
	for c := uint64(0); len(out) < length; c++ {
		blk := salsa20Block(sub, nonce24[16:24], c)
		out = append(out, blk[:]...)
	}
	return out[:length]
}

// Poly1305 is the one-time authenticator of RFC 8439 section 2.5.
func Poly1305(key32, msg []byte) []byte {
	r := leToBig(key32[:16])
	r.And(r, leToBig([]byte{0xff, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f}))
	s := leToBig(key32[16:32])
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 130), big.NewInt(5))
	acc := new(big.Int)
	for i := 0; i < len(msg); i += 16 {
		end := i + 16
		if end > len(msg) {
			end = len(msg)
		}
		n := leToBig(msg[i:end])
		n.SetBit(n, 8*(end-i), 1)
		acc.Add(acc, n)
		acc.Mul(acc, r)
		acc.Mod(acc, p)
	}
	acc.Add(acc, s)
	acc.And(acc, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)))
	return bigToLe(acc, 16)
}

// Secretbox is crypto_secretbox_easy: tag (16) || ciphertext.
func Secretbox(key, nonce, plaintext []byte) []byte {
	stream := XSalsa20Stream(key, nonce, 32+len(plaintext))
	c := make([]byte, len(plaintext))
	for i := range plaintext {
		c[i] = plaintext[i] ^ stream[32+i]
	}
	return append(Poly1305(stream[:32], c), c...)
}

// SecretboxOpen is crypto_secretbox_open_easy: the plaintext, or false when the tag does not verify.
func SecretboxOpen(key, nonce, boxed []byte) ([]byte, bool) {
	if len(boxed) < 16 {
		return nil, false
	}
	c := boxed[16:]
	stream := XSalsa20Stream(key, nonce, 32+len(c))
	if !bytes.Equal(Poly1305(stream[:32], c), boxed[:16]) {
		return nil, false
	}
	out := make([]byte, len(c))
	for i := range c {
		out[i] = c[i] ^ stream[32+i]
	}
	return out, true
}

func boxKey(sk, pk []byte) ([]byte, error) {
	shared, err := x25519(sk, pk)
	if err != nil {
		return nil, err
	}
	return HSalsa20(shared, make([]byte, 16)), nil
}

func sealedNonce(ephemeralPk, recipientPkX []byte) []byte {
	return blake2b(append(append([]byte{}, ephemeralPk...), recipientPkX...), 24)
}

// IsSealed is true when the field starts with the marker (it may still fail to open).
func IsSealed(field []byte) bool { return len(field) >= 4 && bytes.Equal(field[:4], SealedMagic) }

// Seal seals plaintext to the recipient's 32-byte Ed25519 public key. The ephemeral secret key is
// drawn at random unless one is given (tests).
func Seal(plaintext, recipientPublicKey, ephemeralSecretKey []byte) ([]byte, error) {
	rpk, err := Ed25519PublicKeyToX25519(recipientPublicKey)
	if err != nil {
		return nil, err
	}
	esk := ephemeralSecretKey
	if esk == nil {
		esk = make([]byte, 32)
		if _, err := rand.Read(esk); err != nil {
			return nil, err
		}
	}
	epk, err := X25519Base(esk)
	if err != nil {
		return nil, err
	}
	key, err := boxKey(esk, rpk)
	if err != nil {
		return nil, err
	}
	out := append(append([]byte{}, SealedMagic...), epk...)
	return append(out, Secretbox(key, sealedNonce(epk, rpk), plaintext)...), nil
}

// OpenSealed opens a sealed field with the recipient's 32-byte Ed25519 seed: the plaintext, or
// false when it is not a sealed message or the key does not open it.
func OpenSealed(field, recipientSeed []byte) ([]byte, bool) {
	if !IsSealed(field) || len(field) < SealedOverhead || len(recipientSeed) != 32 {
		return nil, false
	}
	sk := Ed25519SeedToX25519(recipientSeed)
	pk, err := X25519Base(sk)
	if err != nil {
		return nil, false
	}
	epk := field[4:36]
	key, err := boxKey(sk, epk)
	if err != nil {
		return nil, false
	}
	return SecretboxOpen(key, sealedNonce(epk, pk), field[36:])
}
