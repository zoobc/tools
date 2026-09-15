// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

package zbc

import (
	"crypto/sha256"
	"math/big"
	"strings"
)

// Base58 alphabets.
const (
	BitcoinAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	RippleAlphabet  = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
)

// Base58Decode decodes with the given alphabet; ok is false on a foreign character.
func Base58Decode(s, alphabet string) (out []byte, ok bool) {
	n := new(big.Int)
	for _, c := range s {
		v := strings.IndexRune(alphabet, c)
		if v < 0 {
			return nil, false
		}
		n.Mul(n, big.NewInt(58))
		n.Add(n, big.NewInt(int64(v)))
	}
	body := n.Bytes()
	zeros := 0
	for _, c := range s {
		if byte(c) != alphabet[0] {
			break
		}
		zeros++
	}
	return append(make([]byte, zeros), body...), true
}

// Base58Encode encodes with the given alphabet.
func Base58Encode(b []byte, alphabet string) string {
	n := new(big.Int).SetBytes(b)
	var sb []byte
	mod := new(big.Int)
	for n.Sign() > 0 {
		n.DivMod(n, big.NewInt(58), mod)
		sb = append([]byte{alphabet[mod.Int64()]}, sb...)
	}
	for _, x := range b {
		if x != 0 {
			break
		}
		sb = append([]byte{alphabet[0]}, sb...)
	}
	return string(sb)
}

// Base58CheckDecode returns the payload without its 4-byte SHA-256d checksum, or nil.
func Base58CheckDecode(s, alphabet string) []byte {
	raw, ok := Base58Decode(s, alphabet)
	if !ok || len(raw) < 5 {
		return nil
	}
	body := raw[:len(raw)-4]
	h1 := sha256.Sum256(body)
	h2 := sha256.Sum256(h1[:])
	for i := 0; i < 4; i++ {
		if h2[i] != raw[len(raw)-4+i] {
			return nil
		}
	}
	return body
}

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []int) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		b := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (b>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HrpExpand(hrp string) []int {
	out := make([]int, 0, 2*len(hrp)+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, int(hrp[i])>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, int(hrp[i])&31)
	}
	return out
}

// bech32DecodeRaw returns the hrp, the 5-bit data without checksum and "bech32" or "bech32m".
func bech32DecodeRaw(s string) (hrp string, data []int, encoding string, ok bool) {
	if len(s) > 1023 || (strings.ToLower(s) != s && strings.ToUpper(s) != s) {
		return "", nil, "", false
	}
	low := strings.ToLower(s)
	pos := strings.LastIndex(low, "1")
	if pos < 1 || pos+7 > len(low) {
		return "", nil, "", false
	}
	hrp = low[:pos]
	for i := pos + 1; i < len(low); i++ {
		v := strings.IndexByte(bech32Charset, low[i])
		if v < 0 {
			return "", nil, "", false
		}
		data = append(data, v)
	}
	switch bech32Polymod(append(bech32HrpExpand(hrp), data...)) {
	case 1:
		encoding = "bech32"
	case 0x2bc830a3:
		encoding = "bech32m"
	default:
		return "", nil, "", false
	}
	return hrp, data[:len(data)-6], encoding, true
}

func convertBits(data []int, from, to uint, pad bool) ([]int, bool) {
	acc, bits := 0, uint(0)
	maxv := (1 << to) - 1
	var out []int
	for _, v := range data {
		if v < 0 || v>>from != 0 {
			return nil, false
		}
		acc = (acc << from) | v
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, (acc>>bits)&maxv)
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, (acc<<(to-bits))&maxv)
		}
	} else if bits >= from || ((acc<<(to-bits))&maxv) != 0 {
		return nil, false
	}
	return out, true
}

// SegwitDecode returns the witness version and program of a bech32/bech32m segwit address.
func SegwitDecode(s string) (hrp string, version int, program []byte, ok bool) {
	hrp, data, enc, ok := bech32DecodeRaw(s)
	if !ok || len(data) < 1 {
		return "", 0, nil, false
	}
	version = data[0]
	prog, ok := convertBits(data[1:], 5, 8, false)
	if !ok || len(prog) < 2 || len(prog) > 40 || version > 16 {
		return "", 0, nil, false
	}
	if version == 0 && len(prog) != 20 && len(prog) != 32 {
		return "", 0, nil, false
	}
	if (version == 0) != (enc == "bech32") {
		return "", 0, nil, false
	}
	program = make([]byte, len(prog))
	for i, v := range prog {
		program[i] = byte(v)
	}
	return hrp, version, program, true
}

// Bech32DecodePlain decodes plain bech32 with an 8-bit payload (Cardano addresses).
func Bech32DecodePlain(s string) (hrp string, payload []byte, ok bool) {
	hrp, data, enc, ok := bech32DecodeRaw(s)
	if !ok || enc != "bech32" {
		return "", nil, false
	}
	b, ok := convertBits(data, 5, 8, false)
	if !ok {
		return "", nil, false
	}
	payload = make([]byte, len(b))
	for i, v := range b {
		payload[i] = byte(v)
	}
	return hrp, payload, true
}

// SS58Decode returns the prefix and 32-byte account id of an SS58 (Polkadot) address.
func SS58Decode(s string) (prefix int, accountID []byte, ok bool) {
	raw, ok := Base58Decode(s, BitcoinAlphabet)
	if !ok {
		return 0, nil, false
	}
	var plen int
	switch {
	case len(raw) >= 35 && raw[0] < 64:
		plen, prefix = 1, int(raw[0])
	case len(raw) >= 36 && raw[0] >= 64 && raw[0] < 128:
		plen, prefix = 2, ((int(raw[0])&0x3f)<<2)|(int(raw[1])>>6)|((int(raw[1])&0x3f)<<8)
	default:
		return 0, nil, false
	}
	body := raw[:len(raw)-2]
	if len(body)-plen != 32 {
		return 0, nil, false
	}
	sum := blake2b512(append([]byte("SS58PRE"), body...))
	if sum[0] != raw[len(raw)-2] || sum[1] != raw[len(raw)-1] {
		return 0, nil, false
	}
	return prefix, body[plen:], true
}
