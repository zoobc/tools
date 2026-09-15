# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
"""The transaction envelope, escrow block, chain-bound digest, signature, hash and submit payload (spec/signing.md)."""
import hashlib
import struct
from dataclasses import dataclass, field
from typing import Optional, Union

from . import ed25519
from .address import EMPTY, is_hex, parse_address
from .keys import KeyPair, key_pair

TX_SIGNING_TAG = b"ZBC-TX"
EMPTY_ACCOUNT = struct.pack("<i", EMPTY)
SEND_ZBC, APPROVAL_ESCROW = 1, 4
APPROVE, REJECT, EXPIRE = 0, 1, 2


def u64(v: int) -> bytes:
    """int64 or uint64 as 8 little-endian bytes (two's complement for negatives)."""
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


@dataclass
class Escrow:
    approver: str
    commission: int = 0
    timeout: int = 0
    instruction: str = ""

    def to_bytes(self) -> bytes:
        ins = self.instruction.encode()
        return parse_address(self.approver).bytes + u64(self.commission) + u64(self.timeout) + struct.pack("<I", len(ins)) + ins + b"\x00"

    def to_payload(self) -> dict:
        d = {"approver_address": parse_address(self.approver).bytes.hex(), "commission": self.commission, "timeout": self.timeout}
        if self.instruction:
            d["instruction"] = self.instruction
        return d


@dataclass
class SigningContext:
    version: int
    genesis_hash: bytes = b""

    @classmethod
    def of(cls, genesis: Union[str, bytes]) -> "SigningContext":
        if isinstance(genesis, bytes):
            if len(genesis) != 32:
                raise ValueError("genesis hash must be 32 bytes")
            return cls(2, genesis)
        if genesis in ("v1", "legacy"):
            return cls(1)
        if not is_hex(genesis, 64):
            raise ValueError("--genesis must be the 64-hex genesis block hash (or 'v1' for the legacy digest)")
        return cls(2, bytes.fromhex(genesis))


def unsigned_bytes(tx_type: int, timestamp: int, sender: bytes, recipient: bytes, fee: int, body: bytes,
                   escrow: Optional[Escrow] = None, message: bytes = b"", version: int = 1) -> bytes:
    """Fields 1-11 of the envelope: the bytes the digest covers."""
    out = struct.pack("<I", tx_type) + bytes([version & 0xFF]) + u64(timestamp) + sender
    out += EMPTY_ACCOUNT if (not recipient or not any(recipient)) else recipient
    out += u64(fee) + struct.pack("<I", len(body)) + body
    out += escrow.to_bytes() if escrow else EMPTY_ACCOUNT
    return out + struct.pack("<I", len(message)) + message


def signing_digest(unsigned: bytes, ctx: SigningContext) -> bytes:
    """SHA3-256('ZBC-TX' || genesis || unsigned) for version 2; SHA3-256(unsigned) for version 1."""
    return hashlib.sha3_256((TX_SIGNING_TAG + ctx.genesis_hash + unsigned) if ctx.version == 2 else unsigned).digest()


def transaction_hash(unsigned: bytes, signature: bytes) -> bytes:
    return hashlib.sha3_256(unsigned + signature).digest()


def transaction_id(tx_hash: bytes) -> int:
    """The int64 id: the first 8 bytes of the hash, little-endian, signed."""
    return struct.unpack("<q", tx_hash[:8])[0]


@dataclass
class SignedTransaction:
    unsigned: bytes
    digest: bytes
    signature: bytes
    bytes: bytes
    hash: bytes
    payload: dict
    signing_version: int
    genesis_hash: bytes = b""


def sign_transaction(tx_type: int, timestamp: int, sender: KeyPair, recipient: bytes, fee: int, body: bytes,
                     ctx: SigningContext, escrow: Optional[Escrow] = None, message: bytes = b"", version: int = 1) -> SignedTransaction:
    """Build, sign and hash a transaction for the chain of `ctx`; `recipient` is typed bytes or b''."""
    unsigned = unsigned_bytes(tx_type, timestamp, sender.account_bytes, recipient, fee, body, escrow, message, version)
    digest = signing_digest(unsigned, ctx)
    signature = ed25519.sign(digest, sender.seed)
    full = unsigned + signature
    if not recipient:
        recipient_json = ""
    elif len(recipient) == 36 and recipient[:4] == b"\x00\x00\x00\x00":
        recipient_json = recipient[4:].hex()
    else:
        recipient_json = recipient.hex()
    payload = {"version": version, "timestamp": timestamp, "sender_account_address": sender.public_key.hex(),
               "recipient_account_address": recipient_json, "transaction_type": tx_type, "fee": fee,
               "transaction_body_bytes": body.hex(), "signature": signature.hex()}
    if message:
        payload["message_hex"] = message.hex()
    if escrow:
        payload["escrow"] = escrow.to_payload()
    return SignedTransaction(unsigned, digest, signature, full, hashlib.sha3_256(full).digest(), payload, ctx.version, ctx.genesis_hash)


def send_zbc_body(amount: int) -> bytes:
    return u64(amount)


def approval_escrow_body(approval: int, escrowed_transaction_hash: bytes) -> bytes:
    if len(escrowed_transaction_hash) != 32:
        raise ValueError("Transaction hash must be 64 hex characters (the escrowed transaction's SHA3-256 hash)")
    return struct.pack("<I", approval) + escrowed_transaction_hash
