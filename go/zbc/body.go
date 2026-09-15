// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

package zbc

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var intRe = regexp.MustCompile(`^-?\d+$`)

// ParseInteger reads a decimal parameter of the given kind (int64, uint64, uint32, uint8).
func ParseInteger(value, kind, name string) (int64, error) {
	v := strings.TrimSpace(value)
	if !intRe.MatchString(v) {
		return 0, Usage("%s must be a whole number, got \"%s\"", name, value)
	}
	switch kind {
	case "uint64":
		u, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, Usage("%s is out of range for %s", name, kind)
		}
		return int64(u), nil
	case "uint32", "uint8":
		u, err := strconv.ParseUint(v, 10, map[string]int{"uint32": 32, "uint8": 8}[kind])
		if err != nil {
			return 0, Usage("%s is out of range for %s", name, kind)
		}
		return int64(u), nil
	default:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, Usage("%s is out of range for %s", name, kind)
		}
		return n, nil
	}
}

// SplitList splits a comma-separated parameter, dropping blanks.
func SplitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if t := strings.TrimSpace(x); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// ValidateParam checks one value against its parameter kind; returns the value to keep.
func ValidateParam(p ParamDef, value string) (string, error) {
	switch p.Kind {
	case "privkey":
		if !IsHex(value, 64) {
			return "", Usage("%s must be 64 hex characters (a 32-byte private key)", p.Name)
		}
	case "address":
		if _, err := ParseAddress(value, ""); err != nil {
			return "", Usage("invalid %s: %v", p.Name, err)
		}
	case "address_list":
		for _, a := range SplitList(value) {
			if _, err := ParseAddress(a, ""); err != nil {
				return "", Usage("invalid %s entry %s: %v", p.Name, a, err)
			}
		}
	case "key":
		if _, err := ParseKey32(value); err != nil {
			return "", Usage("invalid %s: %v", p.Name, err)
		}
	case "int64", "uint64", "uint32", "uint8":
		n, err := ParseInteger(value, p.Kind, p.Name)
		if err != nil {
			return "", err
		}
		if (p.Min != nil && n < *p.Min) || (p.Max != nil && n > *p.Max) {
			lo, hi := "-inf", "inf"
			if p.Min != nil {
				lo = strconv.FormatInt(*p.Min, 10)
			}
			if p.Max != nil {
				hi = strconv.FormatInt(*p.Max, 10)
			}
			return "", Usage("%s must be between %s and %s", p.Name, lo, hi)
		}
		return strings.TrimSpace(value), nil
	case "hex32":
		if !IsHex(value, 64) {
			return "", Usage("%s must be 64 hex characters (32 bytes)", p.Name)
		}
	case "hexbytes":
		if !IsHex(value, 0) {
			return "", Usage("%s must be hex", p.Name)
		}
	}
	return value, nil
}

// BodyContext carries what the generic serialiser cannot read from the parameters.
type BodyContext struct {
	Sender   KeyPair
	Files    map[string][]byte // bytes of `file` parameters, by parameter name
	Computed map[string][]byte // values produced by custom hooks, by field name
}

var whenRe = regexp.MustCompile(`^(\w+) != (0|'')$`)

func conditionHolds(when string, params map[string]string) (bool, error) {
	m := whenRe.FindStringSubmatch(when)
	if m == nil {
		return false, fmt.Errorf("unsupported condition %s", when)
	}
	v := params[m[1]]
	if m[2] == "0" {
		if v == "" {
			return false, nil
		}
		n, err := strconv.ParseInt(v, 10, 64)
		return err == nil && n != 0, nil
	}
	return v != "", nil
}

// EncodeField serialises one body field.
func EncodeField(f FieldDef, params map[string]string, ctx *BodyContext) ([]byte, error) {
	if ctx.Computed != nil {
		if v, ok := ctx.Computed[f.Name]; ok {
			return v, nil
		}
	}
	value := params[f.From]
	if f.WhenZero != "" {
		if n, err := strconv.ParseInt(value, 10, 64); value == "" || (err == nil && n <= 0) {
			value = params[f.WhenZero]
			if value == "" {
				value = "0"
			}
		}
	}
	w := NewWriter()
	switch f.Encoding {
	case "u8":
		n, err := ParseInteger(value, "uint8", f.Name)
		if err != nil {
			return nil, err
		}
		return w.U8(byte(n)).Finish(), nil
	case "u16le":
		n, err := ParseInteger(value, "uint32", f.Name)
		if err != nil {
			return nil, err
		}
		return w.U16(uint16(n)).Finish(), nil
	case "u32le":
		n, err := ParseInteger(value, "uint32", f.Name)
		if err != nil {
			return nil, err
		}
		return w.U32(uint32(n)).Finish(), nil
	case "u64le":
		n, err := ParseInteger(value, "int64", f.Name)
		if err != nil {
			return nil, err
		}
		return w.I64(n).Finish(), nil
	case "hex":
		b, err := hex.DecodeString(value)
		if err != nil {
			return nil, Usage("%s must be hex", f.From)
		}
		if f.Size > 0 && len(b) != f.Size {
			return nil, Usage("%s must be %d bytes (%d hex)", f.From, f.Size, 2*f.Size)
		}
		return b, nil
	case "hex16":
		b, err := hex.DecodeString(value)
		if err != nil {
			return nil, Usage("%s must be hex", f.From)
		}
		return w.U16(uint16(len(b))).Bytes(b).Finish(), nil
	case "bytes32":
		b, ok := ctx.Files[f.From]
		if !ok {
			var err error
			if b, err = hex.DecodeString(value); err != nil {
				return nil, Usage("%s must be hex", f.From)
			}
		}
		return w.U32(uint32(len(b))).Bytes(b).Finish(), nil
	case "str16":
		return w.U16(uint16(len(value))).Bytes([]byte(value)).Finish(), nil
	case "str32":
		return w.U32(uint32(len(value))).Bytes([]byte(value)).Finish(), nil
	case "address":
		a, err := ParseAddress(value, "")
		if err != nil {
			return nil, Usage("invalid %s: %v", f.From, err)
		}
		return a.Bytes(), nil
	case "address_list", "address_list8":
		items := SplitList(value)
		if f.Encoding == "address_list8" {
			if len(items) > 255 {
				return nil, Usage("%s: at most 255 entries", f.From)
			}
			w.U8(byte(len(items)))
		}
		for _, x := range items {
			a, err := ParseAddress(x, "")
			if err != nil {
				return nil, Usage("invalid %s entry %s: %v", f.From, x, err)
			}
			w.Bytes(a.Bytes())
		}
		return w.Finish(), nil
	case "sender_address":
		return ctx.Sender.AccountBytes(), nil
	case "pubkey_of_key":
		kp, err := KeyPairFromHex(value)
		if err != nil {
			return nil, Usage("%s must be 64 hex characters (a 32-byte private key)", f.From)
		}
		return kp.PublicKey, nil
	case "key32":
		b, err := ParseKey32(value)
		if err != nil {
			return nil, Usage("invalid %s: %v", f.From, err)
		}
		return b, nil
	case "literal":
		b, err := hex.DecodeString(f.Value)
		return b, err
	case "custom":
		return nil, fmt.Errorf("field %s needs a custom hook", f.Name)
	}
	return nil, fmt.Errorf("unknown encoding %s", f.Encoding)
}

// BuildBody serialises the whole body of a non-custom transaction.
func BuildBody(def *TxDef, params map[string]string, ctx *BodyContext) ([]byte, error) {
	w := NewWriter()
	for _, f := range def.Body {
		if f.When != "" {
			ok, err := conditionHolds(f.When, params)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
		}
		b, err := EncodeField(f, params, ctx)
		if err != nil {
			return nil, err
		}
		w.Bytes(b)
	}
	return w.Finish(), nil
}
