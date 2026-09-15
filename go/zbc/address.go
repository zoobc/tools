// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

package zbc

import (
	"crypto/sha3"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Account types (spec/addresses.md section 1).
const (
	TypeZooBC          = 0
	TypeBitcoin        = 1
	TypeEmpty          = 2
	TypeEstoniaEID     = 3
	TypeEthereum       = 4
	TypeBitcoinP2PKH   = 5
	TypeBitcoinP2SH    = 6
	TypeBitcoinP2WPKH  = 7
	TypeBitcoinP2WSH   = 8
	TypeBitcoinTaproot = 9
	TypeDataSet        = 10
	TypeSolana         = 11
	TypePolkadot       = 12
	TypeCardano        = 13
	TypeRipple         = 14
	TypeTron           = 15
	TypeTezos          = 16
)

var typeNames = map[int]string{0: "ZooBC", 1: "Bitcoin", 3: "Estonia eID", 4: "Ethereum", 5: "Bitcoin P2PKH", 6: "Bitcoin P2SH",
	7: "Bitcoin P2WPKH", 8: "Bitcoin P2WSH", 9: "Bitcoin Taproot", 10: "DataSet", 11: "Solana", 12: "Polkadot", 13: "Cardano",
	14: "Ripple", 15: "Tron", 16: "Tezos"}

var chains = map[string]string{"zbc": "zbc", "zoobc": "zbc", "btc": "btc", "bitcoin": "btc", "eth": "eth", "ethereum": "eth", "evm": "eth",
	"sol": "sol", "solana": "sol", "dot": "dot", "polkadot": "dot", "substrate": "dot", "ada": "ada", "cardano": "ada", "xrp": "xrp",
	"ripple": "xrp", "trx": "trx", "tron": "trx", "xtz": "xtz", "tezos": "xtz", "zbs": "zbs", "dataset": "zbs"}

var hexRe = regexp.MustCompile(`^[0-9a-fA-F]*$`)

// IsHex reports whether s is even-length hex, of exactly n characters when n > 0.
func IsHex(s string, n int) bool {
	return hexRe.MatchString(s) && len(s)%2 == 0 && (n <= 0 || len(s) == n)
}

// AccountTypeName names an account type.
func AccountTypeName(t int) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("type %d", t)
}

// TypedAddress is the 4-byte little-endian type followed by the payload.
func TypedAddress(t int, payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(out, uint32(int32(t)))
	copy(out[4:], payload)
	return out
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// EncodeZbcAddress is PREFIX_ + base32(payload || SHA3-256(payload || prefix)[:3]) in seven groups of eight.
func EncodeZbcAddress(payload []byte, prefix string) (string, error) {
	if len(payload) != 32 || len(prefix) != 3 {
		return "", errors.New("address payload must be 32 bytes and the prefix 3 characters")
	}
	sum := sha3.Sum256(append(append([]byte{}, payload...), prefix...))
	s := b32.EncodeToString(append(append([]byte{}, payload...), sum[:3]...))
	var sb strings.Builder
	sb.WriteString(prefix)
	for i := 0; i < 7; i++ {
		sb.WriteString("_" + s[8*i:8*i+8])
	}
	return sb.String(), nil
}

// MustEncodeZbcAddress is EncodeZbcAddress for a 32-byte payload known to be valid.
func MustEncodeZbcAddress(payload []byte, prefix string) string {
	s, err := EncodeZbcAddress(payload, prefix)
	if err != nil {
		panic(err)
	}
	return s
}

// DecodeZbcAddress reads PREFIX_... (separators _ or -, any case); returns the upper-case prefix and the 32-byte payload.
func DecodeZbcAddress(text string) (prefix string, payload []byte, ok bool) {
	norm := strings.ToUpper(text)
	if len(norm) < 4 || (norm[3] != '_' && norm[3] != '-') {
		return "", nil, false
	}
	prefix = norm[:3]
	body := strings.NewReplacer("_", "", "-", "").Replace(norm[4:])
	if len(body) != 56 {
		return "", nil, false
	}
	raw, err := b32.DecodeString(body)
	if err != nil || len(raw) != 35 {
		return "", nil, false
	}
	sum := sha3.Sum256(append(append([]byte{}, raw[:32]...), prefix...))
	if sum[0] != raw[32] || sum[1] != raw[33] || sum[2] != raw[34] {
		return "", nil, false
	}
	return prefix, raw[:32], true
}

// ParsedAddress is a recipient as the envelope carries it.
type ParsedAddress struct {
	Type    int
	Payload []byte
	Display string
}

// Bytes is the typed address: 4-byte type LE then the payload (36 bytes for a ZooBC account).
func (p ParsedAddress) Bytes() []byte { return TypedAddress(p.Type, p.Payload) }

// TypeName names the account type.
func (p ParsedAddress) TypeName() string { return AccountTypeName(p.Type) }

func zbcForm(a string) (ParsedAddress, error) {
	prefix, payload, ok := DecodeZbcAddress(a)
	if !ok {
		return ParsedAddress{}, errors.New("invalid ZooBC address checksum")
	}
	if prefix == "ZBS" {
		return ParsedAddress{TypeDataSet, payload, a}, nil
	}
	return ParsedAddress{TypeZooBC, payload, a}, nil
}

func parseHinted(a, hint string) (ParsedAddress, error) {
	switch hint {
	case "eth":
		h := strings.TrimPrefix(strings.TrimPrefix(a, "0x"), "0X")
		if !IsHex(h, 40) {
			return ParsedAddress{}, errors.New("not a 20-byte Ethereum address")
		}
		b, _ := hex.DecodeString(h)
		return ParsedAddress{TypeEthereum, b, a}, nil
	case "sol":
		d, ok := Base58Decode(a, BitcoinAlphabet)
		if !ok || len(d) != 32 {
			return ParsedAddress{}, errors.New("not a 32-byte Solana address")
		}
		return ParsedAddress{TypeSolana, d, a}, nil
	case "dot":
		_, id, ok := SS58Decode(a)
		if !ok {
			return ParsedAddress{}, errors.New("not a valid SS58 address")
		}
		return ParsedAddress{TypePolkadot, id, a}, nil
	case "zbc", "zbs":
		return zbcForm(a)
	}
	return parseAuto(a)
}

func parseAuto(a string) (ParsedAddress, error) {
	if len(a) == 42 && (strings.HasPrefix(a, "0x") || strings.HasPrefix(a, "0X")) && IsHex(a[2:], 40) {
		b, _ := hex.DecodeString(a[2:])
		return ParsedAddress{TypeEthereum, b, a}, nil
	}
	if len(a) > 4 && (a[3] == '_' || a[3] == '-') {
		return zbcForm(a)
	}
	low5 := strings.ToLower(a)
	if len(low5) > 5 {
		low5 = low5[:5]
	}
	if strings.HasPrefix(low5, "bc1") || strings.HasPrefix(low5, "tb1") || strings.HasPrefix(low5, "bcrt1") {
		_, version, prog, ok := SegwitDecode(a)
		if !ok {
			return ParsedAddress{}, errors.New("invalid Bitcoin bech32 address")
		}
		switch {
		case version == 0 && len(prog) == 20:
			return ParsedAddress{TypeBitcoinP2WPKH, prog, a}, nil
		case version == 0 && len(prog) == 32:
			return ParsedAddress{TypeBitcoinP2WSH, prog, a}, nil
		case version == 1 && len(prog) == 32:
			return ParsedAddress{TypeBitcoinTaproot, prog, a}, nil
		}
		return ParsedAddress{}, errors.New("unsupported Bitcoin witness program")
	}
	if (a[0] == '1' || a[0] == '3') && len(a) >= 26 && len(a) <= 35 {
		if raw, ok := Base58Decode(a, BitcoinAlphabet); ok && len(raw) == 25 {
			if body := Base58CheckDecode(a, BitcoinAlphabet); len(body) == 21 {
				if body[0] == 0x00 {
					return ParsedAddress{TypeBitcoinP2PKH, body[1:], a}, nil
				}
				if body[0] == 0x05 {
					return ParsedAddress{TypeBitcoinP2SH, body[1:], a}, nil
				}
			}
		}
	}
	if len(a) > 5 && strings.ToLower(a[:5]) == "addr1" {
		if hrp, b, ok := Bech32DecodePlain(a); ok && hrp == "addr" && len(b) == 29 && b[0] == 0x61 {
			return ParsedAddress{TypeCardano, b[1:], a}, nil
		}
		return ParsedAddress{}, errors.New("invalid Cardano address (expected a mainnet enterprise addr1… address)")
	}
	if a[0] == 'T' && len(a) == 34 {
		if body := Base58CheckDecode(a, BitcoinAlphabet); len(body) == 21 && body[0] == 0x41 {
			return ParsedAddress{TypeTron, body[1:], a}, nil
		}
		return ParsedAddress{}, errors.New("invalid Tron address")
	}
	if a[0] == 'r' && len(a) >= 25 && len(a) <= 35 {
		if body := Base58CheckDecode(a, RippleAlphabet); len(body) == 21 && body[0] == 0x00 {
			return ParsedAddress{TypeRipple, body[1:], a}, nil
		}
		return ParsedAddress{}, errors.New("invalid Ripple address")
	}
	if strings.HasPrefix(a, "tz1") {
		if body := Base58CheckDecode(a, BitcoinAlphabet); len(body) == 23 && body[0] == 0x06 && body[1] == 0xa1 && body[2] == 0x9f {
			return ParsedAddress{TypeTezos, body[3:], a}, nil
		}
		return ParsedAddress{}, errors.New("invalid Tezos address")
	}
	if _, id, ok := SS58Decode(a); ok && len(id) == 32 {
		return ParsedAddress{TypePolkadot, id, a}, nil
	}
	if len(a) >= 32 && len(a) <= 44 {
		if d, ok := Base58Decode(a, BitcoinAlphabet); ok && len(d) == 32 {
			return ParsedAddress{TypeSolana, d, a}, nil
		}
	}
	if IsHex(a, 64) {
		key, _ := hex.DecodeString(a)
		return ParsedAddress{TypeZooBC, key, MustEncodeZbcAddress(key, "ZBC")}, nil
	}
	return ParsedAddress{}, errors.New("unrecognised address. Supported: ZooBC (ZBC_/ZBS_), Bitcoin, Ethereum, Solana, Polkadot, Cardano, Ripple, Tron, Tezos")
}

// ParseAddress reads a recipient in the order of spec/addresses.md section 3; chain forces one reading (--chain).
func ParseAddress(text, chain string) (ParsedAddress, error) {
	a := strings.TrimSpace(text)
	if a == "" {
		return ParsedAddress{}, errors.New("empty address")
	}
	if chain != "" {
		hint, ok := chains[strings.ToLower(chain)]
		if !ok {
			return ParsedAddress{}, fmt.Errorf("unknown chain %s", chain)
		}
		p, err := parseHinted(a, hint)
		if err == nil {
			return p, nil
		}
		up := strings.ToUpper(a)
		low := strings.ToLower(a)
		plain := (len(a) == 42 && (strings.HasPrefix(a, "0x") || strings.HasPrefix(a, "0X"))) || strings.HasPrefix(up, "ZBC") ||
			strings.HasPrefix(up, "ZNK") || strings.HasPrefix(up, "ZBS") || a[0] == '1' || a[0] == '3' ||
			strings.HasPrefix(low, "bc1") || strings.HasPrefix(low, "tb1") || strings.HasPrefix(low, "bcrt1") || len(a) == 64
		if !plain {
			return ParsedAddress{}, err
		}
		return parseAuto(a)
	}
	return parseAuto(a)
}

// ParseKey32 reads a registry key parameter: 64 hex (optionally 0x) or a ZNK_/ZBG_/ZBR_/ZBC_ text address.
func ParseKey32(text string) ([]byte, error) {
	if len(text) == 66 && text[3] == '_' {
		_, payload, ok := DecodeZbcAddress(text)
		if !ok {
			return nil, errors.New("invalid address checksum")
		}
		return payload, nil
	}
	h := strings.TrimPrefix(strings.TrimPrefix(text, "0x"), "0X")
	if !IsHex(h, 64) {
		return nil, errors.New("key must be a 64-hex string or a ZNK_/ZBG_/ZBR_ address")
	}
	b, _ := hex.DecodeString(h)
	return b, nil
}
