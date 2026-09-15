# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
"""Keys: seed -> key pair -> addresses; BIP-39 + SLIP-10 wallets (spec/signing.md section 1)."""
import hashlib
import hmac
import os
import re
import struct
from dataclasses import dataclass

from . import ed25519
from .address import ZOOBC, encode_zbc_address, is_hex, typed_address
from .bip39_words import WORDS

ZOOBC_COIN_TYPE = 883


@dataclass
class KeyPair:
    seed: bytes
    public_key: bytes

    @property
    def address(self) -> str:
        return encode_zbc_address(self.public_key, "ZBC")

    @property
    def node_address(self) -> str:
        return encode_zbc_address(self.public_key, "ZNK")

    @property
    def account_bytes(self) -> bytes:
        """36-byte typed account address: 00000000 || public key."""
        return typed_address(ZOOBC, self.public_key)


def key_pair(seed) -> KeyPair:
    """From a 32-byte seed, or its 64-hex form."""
    if isinstance(seed, str):
        if not is_hex(seed, 64):
            raise ValueError("Private key must be 64 hex characters (32 bytes)")
        seed = bytes.fromhex(seed)
    if len(seed) != 32:
        raise ValueError("Private key must be 64 hex characters (32 bytes)")
    return KeyPair(seed, ed25519.public_key(seed))


def random_seed() -> bytes:
    return os.urandom(32)


def validate_mnemonic(mnemonic: str) -> bool:
    words = mnemonic.split()
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    bits = ""
    for w in words:
        try:
            bits += format(WORDS.index(w), "011b")
        except ValueError:
            return False
    cs = len(words) // 3
    entropy = int(bits[:-cs], 2).to_bytes((len(bits) - cs) // 8, "big")
    return bits[-cs:] == format(hashlib.sha256(entropy).digest()[0], "08b")[:cs]


def mnemonic_from_entropy(entropy: bytes) -> str:
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError("entropy must be 16-32 bytes, a multiple of 4")
    bits = "".join(format(b, "08b") for b in entropy)
    bits += format(hashlib.sha256(entropy).digest()[0], "08b")[: len(entropy) // 4]
    return " ".join(WORDS[int(bits[i:i + 11], 2)] for i in range(0, len(bits), 11))


def generate_mnemonic(words: int = 24) -> str:
    return mnemonic_from_entropy(os.urandom((words * 11 - words // 3) // 8))


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """PBKDF2-HMAC-SHA512(mnemonic, 'mnemonic' + passphrase, 2048 rounds, 64 bytes)."""
    return hashlib.pbkdf2_hmac("sha512", " ".join(mnemonic.split()).encode(), ("mnemonic" + passphrase).encode(), 2048, 64)


def slip10_derive(path: str, seed: bytes) -> bytes:
    """SLIP-10 for Ed25519 along a hardened-only path such as m/44'/883'/0'. Returns the 32-byte key."""
    if not re.match(r"^m(/[0-9]+')+$", path):
        raise ValueError("invalid derivation path: " + path)
    digest = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    key, chain = digest[:32], digest[32:]
    for seg in path.split("/")[1:]:
        index = int(seg[:-1])
        if index >= 0x80000000:
            raise ValueError("path index too large")
        digest = hmac.new(chain, b"\x00" + key + struct.pack(">I", index + 0x80000000), hashlib.sha512).digest()
        key, chain = digest[:32], digest[32:]
    return key


@dataclass
class WalletAccount(KeyPair):
    index: int = 0
    path: str = ""


def wallet_account(mnemonic: str, index: int, passphrase: str = "") -> WalletAccount:
    """Account `index` of a mnemonic wallet: m/44'/883'/index'."""
    path = "m/44'/%d'/%d'" % (ZOOBC_COIN_TYPE, index)
    kp = key_pair(slip10_derive(path, mnemonic_to_seed(mnemonic, passphrase)))
    return WalletAccount(kp.seed, kp.public_key, index, path)
