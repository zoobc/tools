// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

//! The node/gateway HTTP client (spec/api.md): node info, submit, status, transaction, account, latest block.

use crate::custom::ReferenceBlock;
use crate::encoding::is_hex;
use crate::errors::{classify_node_error, internal, ToolError, NODE_BUSY, NODE_UNREACHABLE, NOT_FOUND, TIMEOUT};
use crate::transaction::{Payload, SigningContext};
use serde_json::{json, Map, Value};
use std::time::Duration;

pub struct Client {
    pub api: String,
    pub timeout: Duration,
    agent: ureq::Agent,
}

/// One HTTP answer.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub text: String,
    pub json: Option<Value>,
}

impl Reply {
    /// The parsed body, or the text when it was not JSON.
    pub fn body(&self) -> Value {
        self.json.clone().unwrap_or_else(|| Value::String(self.text.clone()))
    }
}

impl Client {
    pub fn new(api: &str, timeout_seconds: u64) -> Client {
        let timeout = Duration::from_secs(timeout_seconds);
        let agent = ureq::AgentBuilder::new().timeout(timeout).build();
        Client { api: api.trim_end_matches('/').to_string(), timeout, agent }
    }

    fn call(&self, method: &str, path: &str, body: Option<&str>) -> Result<Reply, ToolError> {
        let url = format!("{}{}", self.api, path);
        let req = self.agent.request(method, &url).set("Accept", "application/json").set("User-Agent", "zbc-cli/1.0");
        let res = match body {
            Some(b) => req.set("Content-Type", "application/json").send_string(b),
            None => req.call(),
        };
        let response = match res {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(ureq::Error::Transport(t)) => {
                let msg = t.to_string();
                let timed_out = matches!(t.kind(), ureq::ErrorKind::Io) && msg.to_lowercase().contains("timed out");
                return Err(if timed_out {
                    ToolError::new(TIMEOUT, format!("Timed out: {path} on {}", self.api))
                } else {
                    ToolError::new(NODE_UNREACHABLE, format!("Connection failed: {path} on {}: {msg}", self.api))
                });
            }
        };
        let status = response.status();
        let text = response.into_string().unwrap_or_default();
        let json = serde_json::from_str(&text).ok();
        Ok(Reply { status, text, json })
    }

    /// GET /api/v1/node/info.
    pub fn node_info(&self) -> Result<Map<String, Value>, ToolError> {
        let r = self.call("GET", "/api/v1/node/info", None)?;
        if r.status != 200 {
            let code = if r.status >= 500 { NODE_BUSY } else { NODE_UNREACHABLE };
            return Err(ToolError::new(code, format!("cannot read /api/v1/node/info from {} (HTTP {}) to learn which chain to sign for; pass --genesis <hex> to sign for a known chain", self.api, r.status)).with("http_code", json!(r.status)));
        }
        Ok(r.json.and_then(|v| v.as_object().cloned()).unwrap_or_default())
    }

    /// The chain's signing rule as the node reports it.
    pub fn signing_rule(&self) -> Result<SigningContext, ToolError> {
        let info = self.node_info()?;
        let sv = info.get("signing_version").and_then(Value::as_u64).unwrap_or(1);
        if sv >= 2 {
            let g = info.get("genesis_hash").and_then(Value::as_str).unwrap_or("");
            if !is_hex(g, 64) {
                return Err(internal("node enforces chain-bound signing but reports no genesis hash; pass --genesis <hex>"));
            }
            return Ok(SigningContext { version: 2, genesis_hash: hex::decode(g).unwrap() });
        }
        Ok(SigningContext { version: 1, genesis_hash: Vec::new() })
    }

    /// POST /api/v1/transactions -> (reply, accepted). Transport failures are errors.
    pub fn submit(&self, payload: &Payload) -> Result<(Reply, bool), ToolError> {
        let r = self.call("POST", "/api/v1/transactions", Some(&serde_json::to_string(payload).unwrap()))?;
        let ok = r.status == 200 || r.status == 202;
        Ok((r, ok))
    }

    /// Submit and fail with a classified error when the node rejects.
    pub fn submit_or_fail(&self, payload: &Payload) -> Result<Reply, ToolError> {
        let (r, ok) = self.submit(payload)?;
        if ok { Ok(r) } else { Err(rejection_error(&r)) }
    }

    /// GET /api/v1/transactions/<hash>/status; a 404 answers status not_found rather than failing.
    pub fn status(&self, hash: &str) -> Result<Map<String, Value>, ToolError> {
        let r = self.call("GET", &format!("/api/v1/transactions/{hash}/status"), None)?;
        if r.status != 200 && r.status != 404 {
            return Err(rejection_error(&r));
        }
        let mut out = Map::new();
        out.insert("transaction_hash".into(), json!(hash));
        out.insert("status".into(), json!(if r.status == 404 { "not_found" } else { "unknown" }));
        if let Some(Value::Object(m)) = &r.json {
            for (k, v) in m {
                out.insert(k.clone(), v.clone());
            }
        }
        out.insert("http_code".into(), json!(r.status));
        Ok(out)
    }

    /// GET /api/v1/transactions/<hash>; exit 7 when unknown.
    pub fn transaction(&self, hash: &str) -> Result<Value, ToolError> {
        let r = self.call("GET", &format!("/api/v1/transactions/{hash}"), None)?;
        if r.status != 200 {
            let mut e = rejection_error(&r);
            if r.status == 404 {
                e.code = NOT_FOUND;
                e.message = "Transaction not found".into();
            }
            return Err(e);
        }
        Ok(r.body())
    }

    /// GET /api/v1/accounts/<address>; exit 7 when unknown.
    pub fn account(&self, address: &str) -> Result<Value, ToolError> {
        let r = self.call("GET", &format!("/api/v1/accounts/{address}"), None)?;
        if r.status != 200 {
            let mut e = rejection_error(&r);
            if r.status == 404 {
                e.code = NOT_FOUND;
                e.message = "Account not found".into();
            }
            return Err(e);
        }
        Ok(r.body())
    }

    /// GET /api/v1/blocks/latest: the reference block for a proof of ownership (`block_hash`, or a gateway's `hash`).
    pub fn latest_block(&self) -> Result<ReferenceBlock, ToolError> {
        let r = self.call("GET", "/api/v1/blocks/latest", None)?;
        let m = r.json.as_ref().and_then(Value::as_object);
        let h = m.and_then(|m| m.get("block_hash").or_else(|| m.get("hash"))).and_then(Value::as_str).unwrap_or("");
        if r.status != 200 || !is_hex(h, 64) {
            return Err(internal(format!("Failed to fetch latest block from {}", self.api)).with("http_code", json!(r.status)));
        }
        let height = m.and_then(|m| m.get("height")).and_then(Value::as_u64).unwrap_or(0) as u32;
        Ok(ReferenceBlock { hash: hex::decode(h).unwrap(), height })
    }
}

/// Classify a node's rejection reply (spec/api.md section 2).
pub fn rejection_error(r: &Reply) -> ToolError {
    let text = r.json.as_ref().and_then(|j| j.get("error")).and_then(Value::as_str).map(String::from).unwrap_or_else(|| r.text.clone());
    ToolError::new(classify_node_error(r.status, &text), text).with("http_code", json!(r.status)).with("api_response", r.body())
}
