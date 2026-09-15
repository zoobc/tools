# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
"""The hand-written parts the descriptions mark computed or custom (spec/transactions/README.md)."""
import hashlib
import struct
from typing import Dict, List, Optional, Tuple

from . import ed25519
from .address import is_hex, parse_address
from .body import parse_integer, split_list
from .errors import usage
from .keys import KeyPair, key_pair
from .transaction import SEND_ZBC, SigningContext, signing_digest, u64, unsigned_bytes


def proof_of_ownership(owner: KeyPair, block_hash: bytes, height: int) -> bytes:
    """owner address (36) || block hash (32) || height u32le, then the owner's signature over those 72 bytes."""
    msg = owner.account_bytes + block_hash + struct.pack("<I", height)
    return msg + ed25519.sign(msg, owner.seed)


def compute_fields(spec: dict, params: Dict[str, str], sender: KeyPair, computed: Dict[str, bytes],
                   reference_block: Optional[Tuple[bytes, int]] = None) -> dict:
    """Fill `computed` for the fields the generic serialiser cannot produce; returns extra output fields."""
    cmd, extra = spec["command"], {}
    if cmd == "store-file":
        pieces = bytes.fromhex(params.get("piece_ids", ""))
        if not pieces or len(pieces) % 32:
            raise usage("piece_ids must be a nonzero multiple of 32 bytes")
        computed["piece_count"] = struct.pack("<I", len(pieces) // 32)
        extra["piece_count"] = len(pieces) // 32
    elif cmd in ("register-node", "update-node", "claim-node"):
        if reference_block is None:
            raise ValueError("proof of ownership needs the latest block")
        computed["proof_of_ownership"] = proof_of_ownership(sender, reference_block[0], reference_block[1])
        extra["node_znk"] = key_pair(params["node_privkey"]).node_address
        extra["owner_zbc"] = sender.address
    elif cmd == "fee-vote-reveal":
        info = (bytes.fromhex(params["recent_block_hash"]) + struct.pack("<I", parse_integer(params["recent_block_height"], "uint32", "recent_block_height"))
                + u64(parse_integer(params["fee_vote"], "int64", "fee_vote")))
        sig = ed25519.sign(info, sender.seed)
        computed["voter_signature"] = struct.pack("<I", len(sig)) + sig
    elif cmd == "gateway-heartbeat":
        if not is_hex(params["gateway_privkey"], 64):
            raise usage("gateway_privkey is not a valid key")
        gw = key_pair(params["gateway_privkey"])
        h = parse_integer(params["reference_height"], "uint32", "reference_height")
        block_hash = bytes.fromhex(params["reference_block_hash"])
        if len(block_hash) != 32:
            raise usage("reference_block_hash must be 32 bytes (64 hex)")
        computed["signature"] = ed25519.sign(gw.public_key + struct.pack("<I", h) + block_hash, gw.seed)
        extra.update(gateway_key=gw.public_key.hex(), reference_height=h, reference_block_hash=params["reference_block_hash"])
    return extra


def multisig_address(participants: List[bytes], nonce: int, min_signatures: int) -> bytes:
    """SHA3-256(min u32le || nonce u64le || count u32le || sorted participant addresses)."""
    s = sorted(participants)
    return hashlib.sha3_256(struct.pack("<I", min_signatures) + u64(nonce) + struct.pack("<I", len(s)) + b"".join(s)).digest()


def custom_body(spec: dict, params: Dict[str, str], sender: KeyPair, ctx: SigningContext, timestamp: int) -> Tuple[bytes, dict]:
    if spec["command"] == "multisig":
        return _multisig(params, ctx, timestamp)
    if spec["command"] == "app-settle":
        return _settle(params)
    raise ValueError("no custom body for " + spec["command"])


def _multisig(p: Dict[str, str], ctx: SigningContext, timestamp: int) -> Tuple[bytes, dict]:
    participants = [parse_address(a).bytes for a in split_list(p["participants"])]
    if not participants:
        raise usage("Need at least one participant")
    min_sigs = parse_integer(p["min_signatures"], "uint32", "min_signatures")
    nonce = parse_integer(p.get("nonce") or "0", "int64", "nonce")
    signers = split_list(p["signer_privkeys"])
    if not signers:
        raise usage("Need at least one signer key")
    recipient = parse_address(p["recipient"])
    amount = parse_integer(p["amount"], "int64", "amount")
    inner_fee = parse_integer(p.get("inner_fee") or "10000000", "int64", "inner_fee")
    ms_addr = multisig_address(participants, nonce, min_sigs)
    inner = unsigned_bytes(SEND_ZBC, timestamp, struct.pack("<i", 0) + ms_addr, recipient.bytes, inner_fee, u64(amount))
    inner_hash = hashlib.sha3_256(inner).digest()
    inner_digest = signing_digest(inner, ctx)
    sigs = []
    for sk in signers:
        if not is_hex(sk, 64):
            raise usage("Invalid signer key")
        kp = key_pair(sk)
        sigs.append((kp.account_bytes.hex(), ed25519.sign(inner_digest, kp.seed)))
    sigs.sort()   # the node keeps them in a map ordered by address hex
    body = struct.pack("<I", 1) + struct.pack("<I", min_sigs) + u64(nonce) + struct.pack("<I", len(participants)) + b"".join(participants)
    body += struct.pack("<I", len(inner)) + inner + struct.pack("<I", 1) + inner_hash + struct.pack("<I", len(sigs))
    for addr_hex, sig in sigs:
        body += bytes.fromhex(addr_hex) + struct.pack("<I", len(sig)) + sig
    extra = {"multisig_address": ms_addr.hex(), "multisig_zbc_address": parse_address(ms_addr.hex()).display, "min_signatures": min_sigs,
             "inner_tx_hash": inner_hash.hex(), "fund_hint": "send ZBC to multisig_zbc_address before the signatures complete, else the inner tx stays in mempool"}
    return body, extra


def _settle(p: Dict[str, str]) -> Tuple[bytes, dict]:
    app_id = parse_integer(p["app_id"], "int64", "app_id")
    if not (is_hex(p["p0_privkey"], 64) and is_hex(p["p1_privkey"], 64)):
        raise usage("seat keys must be 64 hex")
    seats = [key_pair(p["p0_privkey"]), key_pair(p["p1_privkey"])]
    turn = parse_integer(p.get("opening_turn") or "0", "uint8", "opening_turn")
    if turn not in (0, 1):
        raise usage("opening_turn must be 0 or 1")
    cells = [parse_integer(c, "uint8", "move") for c in split_list(p["moves"])]
    if not cells:
        raise usage("no moves given")
    state = bytearray(9)
    entries = b""
    for k, cell in enumerate(cells):
        seat = (turn + k) % 2
        if cell > 8 or state[cell] != 0:
            raise usage("illegal move at seq %d" % (k + 1))
        move = bytes([cell])
        digest = hashlib.sha3_256(u64(app_id) + struct.pack("<I", k + 1) + hashlib.sha3_256(bytes(state)).digest() + move).digest()
        entries += bytes([seat]) + struct.pack("<H", len(move)) + move + ed25519.sign(digest, seats[seat].seed)
        state[cell] = seat + 1
    body = u64(app_id) + struct.pack("<I", len(cells)) + struct.pack("<I", len(cells)) + entries
    return body, {"app_id": app_id, "opening_turn": turn, "final_seq": len(cells)}
