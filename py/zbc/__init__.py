# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
"""ZooBC tools: keys, addresses, message signing, transactions and the node client. No dependencies."""
from .address import (ParsedAddress, account_type_name, decode_zbc_address, encode_zbc_address, is_hex, parse_address,
                      parse_key32, typed_address)
from .api import Client
from .body import build_body, encode_field, parse_integer, validate_param
from .custom import compute_fields, custom_body, multisig_address, proof_of_ownership
from .errors import ToolError, classify_node_error, error_class, usage
from .keys import (KeyPair, WalletAccount, generate_mnemonic, key_pair, mnemonic_from_entropy, mnemonic_to_seed,
                   random_seed, slip10_derive, validate_mnemonic, wallet_account)
from .message import SCHEME as MESSAGE_SIGNING_SCHEME, message_digest, public_key_of_address, sign_message, verify_message
from .transaction import (APPROVAL_ESCROW, APPROVE, EXPIRE, REJECT, SEND_ZBC, Escrow, SignedTransaction, SigningContext,
                          approval_escrow_body, send_zbc_body, sign_transaction, signing_digest, transaction_hash,
                          transaction_id, unsigned_bytes)
from ._commands import COMMANDS, COMMAND_BY_NAME

__version__ = "0.1.0"
__all__ = [n for n in dir() if not n.startswith("_")]
