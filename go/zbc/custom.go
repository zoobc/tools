// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

package zbc

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"sort"
)

// ReferenceBlock is the block a proof of ownership refers to.
type ReferenceBlock struct {
	Hash   []byte
	Height uint32
}

// ProofOfOwnership is owner (36) || block hash (32) || height u32le, then the owner's signature over it.
func ProofOfOwnership(owner KeyPair, block ReferenceBlock) []byte {
	msg := NewWriter().Bytes(owner.AccountBytes()).Bytes(block.Hash).U32(block.Height).Finish()
	return append(msg, owner.Sign(msg)...)
}

// CustomInput is what the hand-written parts need.
type CustomInput struct {
	Def       *TxDef
	Params    map[string]string
	Sender    KeyPair
	Ctx       SigningContext
	Timestamp int64
	Block     *ReferenceBlock
}

// ComputeFields fills ctx.Computed for the fields the generic serialiser cannot produce; returns extra output fields.
func ComputeFields(in CustomInput, ctx *BodyContext) (map[string]any, error) {
	if ctx.Computed == nil {
		ctx.Computed = map[string][]byte{}
	}
	extra := map[string]any{}
	p := in.Params
	switch in.Def.Command {
	case "store-file":
		pieces, err := hex.DecodeString(p["piece_ids"])
		if err != nil || len(pieces) == 0 || len(pieces)%32 != 0 {
			return nil, Usage("piece_ids must be a nonzero multiple of 32 bytes")
		}
		ctx.Computed["piece_count"] = NewWriter().U32(uint32(len(pieces) / 32)).Finish()
		extra["piece_count"] = len(pieces) / 32
	case "register-node", "update-node", "claim-node":
		if in.Block == nil {
			return nil, Internal("proof of ownership needs the latest block")
		}
		ctx.Computed["proof_of_ownership"] = ProofOfOwnership(in.Sender, *in.Block)
		node, err := KeyPairFromHex(p["node_privkey"])
		if err != nil {
			return nil, Usage("%v", err)
		}
		extra["node_znk"] = node.NodeAddress()
		extra["owner_zbc"] = in.Sender.Address()
	case "fee-vote-reveal":
		h, err := hex.DecodeString(p["recent_block_hash"])
		if err != nil {
			return nil, Usage("recent_block_hash must be hex")
		}
		height, err := ParseInteger(p["recent_block_height"], "uint32", "recent_block_height")
		if err != nil {
			return nil, err
		}
		vote, err := ParseInteger(p["fee_vote"], "int64", "fee_vote")
		if err != nil {
			return nil, err
		}
		sig := in.Sender.Sign(NewWriter().Bytes(h).U32(uint32(height)).I64(vote).Finish())
		ctx.Computed["voter_signature"] = NewWriter().U32(uint32(len(sig))).Bytes(sig).Finish()
	case "gateway-heartbeat":
		gw, err := KeyPairFromHex(p["gateway_privkey"])
		if err != nil {
			return nil, Usage("gateway_privkey is not a valid key")
		}
		height, err := ParseInteger(p["reference_height"], "uint32", "reference_height")
		if err != nil {
			return nil, err
		}
		h, err := hex.DecodeString(p["reference_block_hash"])
		if err != nil || len(h) != 32 {
			return nil, Usage("reference_block_hash must be 32 bytes (64 hex)")
		}
		ctx.Computed["signature"] = gw.Sign(NewWriter().Bytes(gw.PublicKey).U32(uint32(height)).Bytes(h).Finish())
		extra["gateway_key"] = hex.EncodeToString(gw.PublicKey)
		extra["reference_height"] = height
		extra["reference_block_hash"] = p["reference_block_hash"]
	}
	return extra, nil
}

// MultisigAddress is SHA3-256(min u32le || nonce u64le || count u32le || sorted participant addresses).
func MultisigAddress(participants [][]byte, nonce int64, minSignatures uint32) []byte {
	sorted := make([][]byte, len(participants))
	copy(sorted, participants)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i], sorted[j]) < 0 })
	w := NewWriter().U32(minSignatures).I64(nonce).U32(uint32(len(sorted)))
	for _, a := range sorted {
		w.Bytes(a)
	}
	sum := sha3.Sum256(w.Finish())
	return sum[:]
}

// CustomBody builds the two fully custom bodies: multisig and app-settle.
func CustomBody(in CustomInput) ([]byte, map[string]any, error) {
	switch in.Def.Command {
	case "multisig":
		return multisigBody(in)
	case "app-settle":
		return settleBody(in)
	}
	return nil, nil, Internal("no custom body for %s", in.Def.Command)
}

func multisigBody(in CustomInput) ([]byte, map[string]any, error) {
	p := in.Params
	var participants [][]byte
	for _, a := range SplitList(p["participants"]) {
		pa, err := ParseAddress(a, "")
		if err != nil {
			return nil, nil, Usage("Invalid participant address: %s", a)
		}
		participants = append(participants, pa.Bytes())
	}
	if len(participants) == 0 {
		return nil, nil, Usage("Need at least one participant")
	}
	minSigs, err := ParseInteger(p["min_signatures"], "uint32", "min_signatures")
	if err != nil {
		return nil, nil, err
	}
	nonceStr := p["nonce"]
	if nonceStr == "" {
		nonceStr = "0"
	}
	nonce, err := ParseInteger(nonceStr, "int64", "nonce")
	if err != nil {
		return nil, nil, err
	}
	signers := SplitList(p["signer_privkeys"])
	if len(signers) == 0 {
		return nil, nil, Usage("Need at least one signer key")
	}
	recipient, err := ParseAddress(p["recipient"], "")
	if err != nil {
		return nil, nil, Usage("Invalid recipient: %v", err)
	}
	amount, err := ParseInteger(p["amount"], "int64", "amount")
	if err != nil {
		return nil, nil, err
	}
	feeStr := p["inner_fee"]
	if feeStr == "" {
		feeStr = "10000000"
	}
	innerFee, err := ParseInteger(feeStr, "int64", "inner_fee")
	if err != nil {
		return nil, nil, err
	}
	msAddr := MultisigAddress(participants, nonce, uint32(minSigs))
	inner, _ := UnsignedBytes(Unsigned{Type: TypeSendZBC, Timestamp: in.Timestamp, Sender: TypedAddress(TypeZooBC, msAddr),
		Recipient: recipient.Bytes(), Fee: innerFee, Body: SendZBCBody(amount)})
	innerHashArr := sha3.Sum256(inner)
	innerDigest := SigningDigest(inner, in.Ctx)
	type sigEntry struct {
		addrHex string
		sig     []byte
	}
	var sigs []sigEntry
	for _, sk := range signers {
		kp, err := KeyPairFromHex(sk)
		if err != nil {
			return nil, nil, Usage("Invalid signer key")
		}
		sigs = append(sigs, sigEntry{hex.EncodeToString(kp.AccountBytes()), kp.Sign(innerDigest)})
	}
	sort.Slice(sigs, func(i, j int) bool { return sigs[i].addrHex < sigs[j].addrHex })
	w := NewWriter().U32(1).U32(uint32(minSigs)).I64(nonce).U32(uint32(len(participants)))
	for _, a := range participants {
		w.Bytes(a)
	}
	w.U32(uint32(len(inner))).Bytes(inner).U32(1).Bytes(innerHashArr[:]).U32(uint32(len(sigs)))
	for _, s := range sigs {
		a, _ := hex.DecodeString(s.addrHex)
		w.Bytes(a).U32(uint32(len(s.sig))).Bytes(s.sig)
	}
	extra := map[string]any{"multisig_address": hex.EncodeToString(msAddr), "multisig_zbc_address": MustEncodeZbcAddress(msAddr, "ZBC"),
		"min_signatures": minSigs, "inner_tx_hash": hex.EncodeToString(innerHashArr[:]),
		"fund_hint": "send ZBC to multisig_zbc_address before the signatures complete, else the inner tx stays in mempool"}
	return w.Finish(), extra, nil
}

func settleBody(in CustomInput) ([]byte, map[string]any, error) {
	p := in.Params
	appID, err := ParseInteger(p["app_id"], "int64", "app_id")
	if err != nil {
		return nil, nil, err
	}
	p0, err0 := KeyPairFromHex(p["p0_privkey"])
	p1, err1 := KeyPairFromHex(p["p1_privkey"])
	if err0 != nil || err1 != nil {
		return nil, nil, Usage("seat keys must be 64 hex")
	}
	seats := []KeyPair{p0, p1}
	turnStr := p["opening_turn"]
	if turnStr == "" {
		turnStr = "0"
	}
	turn, err := ParseInteger(turnStr, "uint8", "opening_turn")
	if err != nil {
		return nil, nil, err
	}
	if turn != 0 && turn != 1 {
		return nil, nil, Usage("opening_turn must be 0 or 1")
	}
	var cells []int64
	for _, c := range SplitList(p["moves"]) {
		n, err := ParseInteger(c, "uint8", "move")
		if err != nil {
			return nil, nil, err
		}
		cells = append(cells, n)
	}
	if len(cells) == 0 {
		return nil, nil, Usage("no moves given")
	}
	state := make([]byte, 9)
	entries := NewWriter()
	for k, cell := range cells {
		seat := (int(turn) + k) % 2
		if cell > 8 || state[cell] != 0 {
			return nil, nil, Usage("illegal move at seq %d", k+1)
		}
		move := []byte{byte(cell)}
		stateHash := sha3.Sum256(state)
		digest := sha3.Sum256(NewWriter().I64(appID).U32(uint32(k + 1)).Bytes(stateHash[:]).Bytes(move).Finish())
		entries.U8(byte(seat)).U16(uint16(len(move))).Bytes(move).Bytes(seats[seat].Sign(digest[:]))
		state[cell] = byte(seat + 1)
	}
	body := NewWriter().I64(appID).U32(uint32(len(cells))).U32(uint32(len(cells))).Bytes(entries.Finish()).Finish()
	return body, map[string]any{"app_id": appID, "opening_turn": turn, "final_seq": len(cells)}, nil
}
