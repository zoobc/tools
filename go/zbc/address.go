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
	"unicode"
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

// btcLabels: the reference's fallback reading names a Bitcoin account by its script (tx_common.h get_btc_recipient_label).
var btcLabels = map[int]string{1: "BTC (legacy)", 5: "BTC P2PKH", 6: "BTC P2SH", 7: "BTC P2WPKH", 8: "BTC P2WSH", 9: "BTC P2TR"}

// chainOfType: the chain each account type is written in; a --chain btc/ada/xrp/trx/xtz reading must agree with it.
var chainOfType = map[int]string{0: "zbc", 10: "zbs", 1: "btc", 5: "btc", 6: "btc", 7: "btc", 8: "btc", 9: "btc", 4: "eth", 11: "sol",
	12: "dot", 13: "ada", 14: "xrp", 15: "trx", 16: "xtz"}

var chainNames = map[string]string{"btc": "Bitcoin", "ada": "Cardano", "xrp": "Ripple", "trx": "Tron", "xtz": "Tezos"}

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

// ZbcSignificant is the 59 significant characters of a ZooBC address: separators (_ -) and whitespace dropped, upper case (addresses.md 2).
func ZbcSignificant(text string) string {
	var b strings.Builder
	for _, r := range text {
		if r == '_' || r == '-' || unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(r)
	}
	return strings.ToUpper(b.String())
}

// DecodeZbcAddress reads a ZooBC address in any spelling; returns the upper-case prefix and the 32-byte payload.
func DecodeZbcAddress(text string) (prefix string, payload []byte, ok bool) {
	norm := ZbcSignificant(text)
	if len(norm) < 3 {
		return "", nil, false
	}
	prefix = norm[:3]
	body := norm[3:]
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
	Label   string // set by the fallback reading, which names the type its own way
}

// Bytes is the typed address: 4-byte type LE then the payload (36 bytes for a ZooBC account).
func (p ParsedAddress) Bytes() []byte { return TypedAddress(p.Type, p.Payload) }

// TypeName is the recipient_type the tools print: the account type's name, or the fallback reading's label.
func (p ParsedAddress) TypeName() string {
	if p.Label != "" {
		return p.Label
	}
	return AccountTypeName(p.Type)
}

func bech32Prefixed(a string) bool {
	low5 := strings.ToLower(a)
	if len(low5) > 5 {
		low5 = low5[:5]
	}
	return strings.HasPrefix(low5, "bc1") || strings.HasPrefix(low5, "tb1") || strings.HasPrefix(low5, "bcrt1")
}

func bech32Bitcoin(a string) (ParsedAddress, error) {
	_, version, prog, ok := SegwitDecode(a)
	if !ok {
		return ParsedAddress{}, errors.New("invalid Bitcoin bech32 address")
	}
	switch {
	case version == 0 && len(prog) == 20:
		return ParsedAddress{TypeBitcoinP2WPKH, prog, a, ""}, nil
	case version == 0 && len(prog) == 32:
		return ParsedAddress{TypeBitcoinP2WSH, prog, a, ""}, nil
	case version == 1 && len(prog) == 32:
		return ParsedAddress{TypeBitcoinTaproot, prog, a, ""}, nil
	}
	return ParsedAddress{}, errors.New("unsupported Bitcoin witness program")
}

func base58Bitcoin(a string) (ParsedAddress, bool) {
	if raw, ok := Base58Decode(a, BitcoinAlphabet); ok && len(raw) == 25 {
		if body := Base58CheckDecode(a, BitcoinAlphabet); len(body) == 21 {
			if body[0] == 0x00 {
				return ParsedAddress{TypeBitcoinP2PKH, body[1:], a, ""}, true
			}
			if body[0] == 0x05 {
				return ParsedAddress{TypeBitcoinP2SH, body[1:], a, ""}, true
			}
		}
	}
	return ParsedAddress{}, false
}

// fallback is the reference's second reading (parse_address in tx_common.h), on the string as given, when the first one
// fails: applies is false when no form of it applies; err is set when one applies and the string is not that form.
func fallback(s string) (p ParsedAddress, applies bool, err error) {
	if len(s) == 42 && (strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X")) {
		if !IsHex(s[2:], 40) {
			return p, true, errors.New("invalid hex character in ETH address")
		}
		b, _ := hex.DecodeString(s[2:])
		return ParsedAddress{TypeEthereum, b, s, "ETH (compact)"}, true, nil
	}
	if strings.HasPrefix(s, "1") || strings.HasPrefix(s, "3") {
		q, found := base58Bitcoin(s)
		if !found {
			return p, true, errors.New("failed to decode BTC address")
		}
		q.Label = btcLabels[q.Type]
		return q, true, nil
	}
	if bech32Prefixed(s) {
		q, err := bech32Bitcoin(s)
		if err != nil {
			return p, true, err
		}
		q.Label = btcLabels[q.Type]
		return q, true, nil
	}
	up := strings.ToUpper(s)
	if strings.HasPrefix(up, "ZBC") || strings.HasPrefix(up, "ZNK") || strings.HasPrefix(up, "ZBS") {
		_, payload, found := DecodeZbcAddress(s)
		if !found {
			return p, true, errors.New("address checksum validation failed")
		}
		if strings.HasPrefix(up, "ZBS") {
			return ParsedAddress{TypeDataSet, payload, s, "DATASET"}, true, nil
		}
		return ParsedAddress{TypeZooBC, payload, s, "ZBC"}, true, nil
	}
	if IsHex(s, 64) {
		key, _ := hex.DecodeString(s)
		return ParsedAddress{TypeZooBC, key, MustEncodeZbcAddress(key, "ZBC"), "ZBC"}, true, nil
	}
	return p, false, nil
}

func zbcForm(a string) (ParsedAddress, error) {
	prefix, payload, ok := DecodeZbcAddress(a)
	if !ok {
		return ParsedAddress{}, errors.New("invalid ZooBC address checksum")
	}
	if prefix == "ZBS" {
		return ParsedAddress{TypeDataSet, payload, a, ""}, nil
	}
	return ParsedAddress{TypeZooBC, payload, a, ""}, nil
}

func parseHinted(a, hint string) (ParsedAddress, error) {
	switch hint {
	case "eth":
		h := strings.TrimPrefix(strings.TrimPrefix(a, "0x"), "0X")
		if !IsHex(h, 40) {
			return ParsedAddress{}, errors.New("not a 20-byte Ethereum address")
		}
		b, _ := hex.DecodeString(h)
		return ParsedAddress{TypeEthereum, b, a, ""}, nil
	case "sol":
		d, ok := Base58Decode(a, BitcoinAlphabet)
		if !ok || len(d) != 32 {
			return ParsedAddress{}, errors.New("not a 32-byte Solana address")
		}
		return ParsedAddress{TypeSolana, d, a, ""}, nil
	case "dot":
		_, id, ok := SS58Decode(a)
		if !ok {
			return ParsedAddress{}, errors.New("not a valid SS58 address")
		}
		return ParsedAddress{TypePolkadot, id, a, ""}, nil
	case "zbc", "zbs":
		return zbcForm(a)
	}
	// btc, ada, xrp, trx, xtz: detection reads the address; the hint is a check, never a reading
	p, err := parseAuto(a)
	if err != nil {
		return p, err
	}
	if chainOfType[p.Type] != hint {
		return ParsedAddress{}, fmt.Errorf("not a %s address: it reads as %s", chainNames[hint], AccountTypeName(p.Type))
	}
	return p, nil
}

// looksZbc is shape only: PREFIX then a separator, or the bare form: 59 significant characters, ZBC/ZBS prefix, base32 body.
func looksZbc(a string) bool {
	if len(a) > 4 && (a[3] == '_' || a[3] == '-') {
		return true
	}
	n := ZbcSignificant(a)
	if len(n) != 59 || !(strings.HasPrefix(n, "ZBC") || strings.HasPrefix(n, "ZBS")) {
		return false
	}
	for _, c := range n[3:] {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", c) {
			return false
		}
	}
	return true
}

func parseAuto(a string) (ParsedAddress, error) {
	if len(a) == 42 && (strings.HasPrefix(a, "0x") || strings.HasPrefix(a, "0X")) && IsHex(a[2:], 40) {
		b, _ := hex.DecodeString(a[2:])
		return ParsedAddress{TypeEthereum, b, a, ""}, nil
	}
	if looksZbc(a) {
		return zbcForm(a)
	}
	if bech32Prefixed(a) {
		return bech32Bitcoin(a)
	}
	if (a[0] == '1' || a[0] == '3') && len(a) >= 26 && len(a) <= 35 {
		if p, ok := base58Bitcoin(a); ok {
			return p, nil
		}
	}
	if len(a) > 5 && strings.ToLower(a[:5]) == "addr1" {
		if hrp, b, ok := Bech32DecodePlain(a); ok && hrp == "addr" && len(b) == 29 && b[0] == 0x61 {
			return ParsedAddress{TypeCardano, b[1:], a, ""}, nil
		}
		return ParsedAddress{}, errors.New("invalid Cardano address (expected a mainnet enterprise addr1… address)")
	}
	if a[0] == 'T' && len(a) == 34 {
		if body := Base58CheckDecode(a, BitcoinAlphabet); len(body) == 21 && body[0] == 0x41 {
			return ParsedAddress{TypeTron, body[1:], a, ""}, nil
		}
		return ParsedAddress{}, errors.New("invalid Tron address")
	}
	if a[0] == 'r' && len(a) >= 25 && len(a) <= 35 {
		if body := Base58CheckDecode(a, RippleAlphabet); len(body) == 21 && body[0] == 0x00 {
			return ParsedAddress{TypeRipple, body[1:], a, ""}, nil
		}
		return ParsedAddress{}, errors.New("invalid Ripple address")
	}
	if strings.HasPrefix(a, "tz1") {
		if body := Base58CheckDecode(a, BitcoinAlphabet); len(body) == 23 && body[0] == 0x06 && body[1] == 0xa1 && body[2] == 0x9f {
			return ParsedAddress{TypeTezos, body[3:], a, ""}, nil
		}
		return ParsedAddress{}, errors.New("invalid Tezos address")
	}
	if _, id, ok := SS58Decode(a); ok && len(id) == 32 {
		return ParsedAddress{TypePolkadot, id, a, ""}, nil
	}
	if len(a) >= 32 && len(a) <= 44 {
		if d, ok := Base58Decode(a, BitcoinAlphabet); ok && len(d) == 32 {
			return ParsedAddress{TypeSolana, d, a, ""}, nil
		}
	}
	if IsHex(a, 64) {
		key, _ := hex.DecodeString(a)
		return ParsedAddress{TypeZooBC, key, MustEncodeZbcAddress(key, "ZBC"), ""}, nil
	}
	return ParsedAddress{}, errors.New("unrecognised address. Supported: ZooBC (ZBC_/ZBS_), Bitcoin, Ethereum, Solana, Polkadot, Cardano, Ripple, Tron, Tezos")
}

// ParseAddress reads a recipient as spec/addresses.md section 3 says; chain forces one reading (--chain). When the reading
// fails, the fallback the reference keeps still takes 0x+40 hex, a Bitcoin address, ZBC/ZNK/ZBS text and 64 hex, and
// TypeName is then its label ("ETH (compact)", "BTC P2PKH", "ZBC", "DATASET").
func ParseAddress(text, chain string) (ParsedAddress, error) {
	a := strings.TrimSpace(text)
	if a == "" {
		return ParsedAddress{}, errors.New("empty address")
	}
	var p ParsedAddress
	var err error
	if chain != "" {
		hint, ok := chains[strings.ToLower(chain)]
		if !ok {
			return ParsedAddress{}, fmt.Errorf("unknown chain %s", chain)
		}
		p, err = parseHinted(a, hint)
	} else {
		p, err = parseAuto(a)
	}
	if err == nil {
		return p, nil
	}
	q, applies, ferr := fallback(text)
	if !applies {
		return ParsedAddress{}, err
	}
	if ferr != nil {
		return ParsedAddress{}, ferr
	}
	return q, nil
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
