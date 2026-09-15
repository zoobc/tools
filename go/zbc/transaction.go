// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

package zbc

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

// Transaction types the core knows by name; the rest come from the command table.
const (
	TypeSendZBC        = 1
	TypeApprovalEscrow = 4
)

// Escrow approvals.
const (
	Approve = 0
	Reject  = 1
	Expire  = 2
)

var txSigningTag = []byte("ZBC-TX")

// EmptyAccount is the 4-byte marker for "no recipient" and "no escrow".
var EmptyAccount = TypedAddress(TypeEmpty, nil)

// Escrow terms of a transfer (the --escrow-* options); Timeout is an absolute Unix time in seconds.
type Escrow struct {
	Approver    string
	Commission  int64
	Timeout     int64
	Instruction string
}

// Bytes is the escrow block of the envelope (spec/signing.md section 3).
func (e Escrow) Bytes() ([]byte, error) {
	approver, err := ParseAddress(e.Approver, "")
	if err != nil {
		return nil, err
	}
	w := NewWriter()
	w.Bytes(approver.Bytes()).I64(e.Commission).I64(e.Timeout).U32(uint32(len(e.Instruction))).Bytes([]byte(e.Instruction)).U8(0)
	return w.Finish(), nil
}

// SigningContext is the chain a signature is for: Version 2 with GenesisHash, or 1 (legacy).
type SigningContext struct {
	Version     int
	GenesisHash []byte
}

// SigningContextOf reads --genesis: 64 hex, or "v1"/"legacy".
func SigningContextOf(genesis string) (SigningContext, error) {
	if genesis == "v1" || genesis == "legacy" {
		return SigningContext{Version: 1}, nil
	}
	if !IsHex(genesis, 64) {
		return SigningContext{}, errors.New("--genesis must be the 64-hex genesis block hash (or 'v1' for the legacy digest)")
	}
	g, _ := hex.DecodeString(genesis)
	return SigningContext{Version: 2, GenesisHash: g}, nil
}

// Writer builds little-endian byte strings.
type Writer struct{ buf bytes.Buffer }

// NewWriter is an empty Writer.
func NewWriter() *Writer { return &Writer{} }

// Bytes appends raw bytes.
func (w *Writer) Bytes(b []byte) *Writer { w.buf.Write(b); return w }

// U8 appends one byte.
func (w *Writer) U8(v byte) *Writer { w.buf.WriteByte(v); return w }

// U16 appends a uint16 LE.
func (w *Writer) U16(v uint16) *Writer { return w.Bytes(binary.LittleEndian.AppendUint16(nil, v)) }

// U32 appends a uint32 LE.
func (w *Writer) U32(v uint32) *Writer { return w.Bytes(binary.LittleEndian.AppendUint32(nil, v)) }

// I64 appends an int64 as 8 bytes LE (two's complement).
func (w *Writer) I64(v int64) *Writer {
	return w.Bytes(binary.LittleEndian.AppendUint64(nil, uint64(v)))
}

// Finish returns the bytes.
func (w *Writer) Finish() []byte { return w.buf.Bytes() }

// Unsigned describes a transaction before signing.
type Unsigned struct {
	Type      uint32
	Timestamp int64
	Sender    []byte // 36-byte typed account
	Recipient []byte // typed bytes, or nil for none
	Fee       int64
	Body      []byte
	Escrow    *Escrow
	Message   []byte
	Version   byte // 0 means 1
}

// UnsignedBytes are fields 1–11 of the envelope: what the digest covers.
func UnsignedBytes(tx Unsigned) ([]byte, error) {
	v := tx.Version
	if v == 0 {
		v = 1
	}
	w := NewWriter().U32(tx.Type).U8(v).I64(tx.Timestamp).Bytes(tx.Sender)
	if len(tx.Recipient) == 0 || bytes.Equal(tx.Recipient, make([]byte, len(tx.Recipient))) {
		w.Bytes(EmptyAccount)
	} else {
		w.Bytes(tx.Recipient)
	}
	w.I64(tx.Fee).U32(uint32(len(tx.Body))).Bytes(tx.Body)
	if tx.Escrow != nil {
		eb, err := tx.Escrow.Bytes()
		if err != nil {
			return nil, err
		}
		w.Bytes(eb)
	} else {
		w.Bytes(EmptyAccount)
	}
	w.U32(uint32(len(tx.Message))).Bytes(tx.Message)
	return w.Finish(), nil
}

// SigningDigest is SHA3-256("ZBC-TX" || genesis || unsigned) for version 2, SHA3-256(unsigned) for version 1.
func SigningDigest(unsigned []byte, ctx SigningContext) []byte {
	var sum [32]byte
	if ctx.Version == 2 {
		sum = sha3.Sum256(append(append(append([]byte{}, txSigningTag...), ctx.GenesisHash...), unsigned...))
	} else {
		sum = sha3.Sum256(unsigned)
	}
	return sum[:]
}

// TransactionHash is SHA3-256(unsigned || signature).
func TransactionHash(unsigned, signature []byte) []byte {
	sum := sha3.Sum256(append(append([]byte{}, unsigned...), signature...))
	return sum[:]
}

// TransactionID is the first 8 bytes of the hash as a signed int64 LE.
func TransactionID(hash []byte) int64 { return int64(binary.LittleEndian.Uint64(hash[:8])) }

// EscrowPayload is the escrow object of the submit payload.
type EscrowPayload struct {
	ApproverAddress string `json:"approver_address"`
	Commission      int64  `json:"commission"`
	Timeout         int64  `json:"timeout"`
	Instruction     string `json:"instruction,omitempty"`
}

// Payload is the JSON object POST /api/v1/transactions takes (spec/api.md section 2).
type Payload struct {
	Version                 int            `json:"version"`
	Timestamp               int64          `json:"timestamp"`
	SenderAccountAddress    string         `json:"sender_account_address"`
	RecipientAccountAddress string         `json:"recipient_account_address"`
	TransactionType         uint32         `json:"transaction_type"`
	Fee                     int64          `json:"fee"`
	TransactionBodyBytes    string         `json:"transaction_body_bytes"`
	Signature               string         `json:"signature"`
	MessageHex              string         `json:"message_hex,omitempty"`
	Escrow                  *EscrowPayload `json:"escrow,omitempty"`
}

// Signed is a built, signed and hashed transaction.
type Signed struct {
	Unsigned       []byte
	Digest         []byte
	Signature      []byte
	Bytes          []byte
	Hash           []byte
	Payload        Payload
	SigningVersion int
	GenesisHash    []byte
}

// SignTransaction builds, signs and hashes a transaction for the chain of ctx.
func SignTransaction(tx Unsigned, kp KeyPair, ctx SigningContext) (Signed, error) {
	unsigned, err := UnsignedBytes(tx)
	if err != nil {
		return Signed{}, err
	}
	digest := SigningDigest(unsigned, ctx)
	sig := kp.Sign(digest)
	full := append(append([]byte{}, unsigned...), sig...)
	recipient := ""
	if len(tx.Recipient) == 36 && bytes.Equal(tx.Recipient[:4], []byte{0, 0, 0, 0}) {
		recipient = hex.EncodeToString(tx.Recipient[4:])
	} else if len(tx.Recipient) > 0 {
		recipient = hex.EncodeToString(tx.Recipient)
	}
	v := int(tx.Version)
	if v == 0 {
		v = 1
	}
	p := Payload{Version: v, Timestamp: tx.Timestamp, SenderAccountAddress: hex.EncodeToString(tx.Sender[4:]), RecipientAccountAddress: recipient,
		TransactionType: tx.Type, Fee: tx.Fee, TransactionBodyBytes: hex.EncodeToString(tx.Body), Signature: hex.EncodeToString(sig)}
	if len(tx.Message) > 0 {
		p.MessageHex = hex.EncodeToString(tx.Message)
	}
	if tx.Escrow != nil {
		approver, _ := ParseAddress(tx.Escrow.Approver, "")
		p.Escrow = &EscrowPayload{hex.EncodeToString(approver.Bytes()), tx.Escrow.Commission, tx.Escrow.Timeout, tx.Escrow.Instruction}
	}
	sum := sha3.Sum256(full)
	return Signed{unsigned, digest, sig, full, sum[:], p, ctx.Version, ctx.GenesisHash}, nil
}

// SendZBCBody is the 8-byte amount.
func SendZBCBody(amount int64) []byte { return NewWriter().I64(amount).Finish() }

// ApprovalEscrowBody is approval u32le then the 32-byte escrowed transaction hash.
func ApprovalEscrowBody(approval uint32, escrowedHash []byte) ([]byte, error) {
	if len(escrowedHash) != 32 {
		return nil, errors.New("Transaction hash must be 64 hex characters (the escrowed transaction's SHA3-256 hash)")
	}
	return NewWriter().U32(approval).Bytes(escrowedHash).Finish(), nil
}
