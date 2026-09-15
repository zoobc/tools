# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
"""The node/gateway HTTP client (spec/api.md), on urllib: node info, submit, status, transaction, account, latest block."""
import json
import socket
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

from .address import is_hex
from .errors import INTERNAL, NODE_BUSY, NODE_UNREACHABLE, NOT_FOUND, TIMEOUT, ToolError, classify_node_error
from .transaction import SigningContext

_HEADERS = {"Accept": "application/json", "User-Agent": "zbc-cli/1.0"}


class Client:
    def __init__(self, api: str = "http://localhost:8080", timeout_seconds: int = 20):
        self.api = api.rstrip("/")
        self.timeout = timeout_seconds

    def _call(self, method: str, path: str, body: Optional[bytes] = None) -> Tuple[int, str, Any]:
        headers = dict(_HEADERS)
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.api + path, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as res:
                status, text = res.status, res.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, text = e.code, e.read().decode("utf-8", "replace")
        except (socket.timeout, TimeoutError) as e:
            raise ToolError(TIMEOUT, "Timed out: %s on %s" % (path, self.api))
        except urllib.error.URLError as e:
            reason = e.reason
            if isinstance(reason, (socket.timeout, TimeoutError)) or "timed out" in str(reason):
                raise ToolError(TIMEOUT, "Timed out: %s on %s" % (path, self.api))
            raise ToolError(NODE_UNREACHABLE, "Connection failed: %s on %s: %s" % (path, self.api, reason))
        except OSError as e:
            raise ToolError(NODE_UNREACHABLE, "Connection failed: %s on %s: %s" % (path, self.api, e))
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        return status, text, parsed

    def node_info(self) -> Dict[str, Any]:
        status, text, j = self._call("GET", "/api/v1/node/info")
        if status != 200:
            raise ToolError(NODE_BUSY if status >= 500 else NODE_UNREACHABLE,
                            "cannot read /api/v1/node/info from %s (HTTP %d) to learn which chain to sign for; pass --genesis <hex> to sign for a known chain" % (self.api, status),
                            http_code=status)
        return j or {}

    def signing_rule(self) -> SigningContext:
        """The chain's signing rule as the node reports it."""
        info = self.node_info()
        if int(info.get("signing_version") or 1) >= 2:
            g = str(info.get("genesis_hash") or "")
            if not is_hex(g, 64):
                raise ToolError(INTERNAL, "node enforces chain-bound signing but reports no genesis hash; pass --genesis <hex>")
            return SigningContext(2, bytes.fromhex(g))
        return SigningContext(1)

    def submit(self, payload: dict) -> Tuple[int, Any, bool]:
        """POST /api/v1/transactions -> (http code, body, accepted). Raises ToolError on transport failure."""
        status, text, j = self._call("POST", "/api/v1/transactions", json.dumps(payload).encode())
        return status, (j if j is not None else text), status in (200, 202)

    def submit_or_raise(self, payload: dict) -> Any:
        status, body, accepted = self.submit(payload)
        if not accepted:
            text = body.get("error") if isinstance(body, dict) and isinstance(body.get("error"), str) else str(body)
            raise ToolError(classify_node_error(status, text), text, http_code=status, api_response=body)
        return body

    def status(self, tx_hash: str) -> Dict[str, Any]:
        """GET /api/v1/transactions/<hash>/status; a 404 answers status not_found rather than raising."""
        status, text, j = self._call("GET", "/api/v1/transactions/%s/status" % tx_hash)
        if status not in (200, 404):
            raise ToolError(classify_node_error(status, text), text, http_code=status, api_response=j if j is not None else text)
        out = {"transaction_hash": tx_hash, "status": "not_found" if status == 404 else "unknown"}
        out.update(j or {})
        out["http_code"] = status
        return out

    def transaction(self, tx_hash: str) -> Dict[str, Any]:
        status, text, j = self._call("GET", "/api/v1/transactions/%s" % tx_hash)
        if status != 200:
            raise ToolError(NOT_FOUND if status == 404 else classify_node_error(status, text), "Transaction not found" if status == 404 else text,
                            http_code=status, api_response=j if j is not None else text)
        return j

    def account(self, address: str) -> Dict[str, Any]:
        status, text, j = self._call("GET", "/api/v1/accounts/%s" % urllib.request.quote(address, safe=""))
        if status != 200:
            raise ToolError(NOT_FOUND if status == 404 else classify_node_error(status, text), "Account not found" if status == 404 else text,
                            http_code=status, api_response=j if j is not None else text)
        return j

    def latest_block(self) -> Tuple[bytes, int]:
        """(hash, height) of the latest block, from `block_hash` (node) or `hash` (gateway)."""
        status, text, j = self._call("GET", "/api/v1/blocks/latest")
        j = j or {}
        h = str(j.get("block_hash") or j.get("hash") or "")
        if status != 200 or not is_hex(h, 64):
            raise ToolError(INTERNAL, "Failed to fetch latest block from " + self.api, http_code=status)
        return bytes.fromhex(h), int(j.get("height") or 0)
