// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** The node/gateway HTTP client (spec/api.md): node info, submit, status, transaction, account, latest block. */
import { classifyNodeError, ExitCode, ToolError } from "./errors.js";
import { SubmitPayload } from "./transaction.js";
import { hexToBytes, isHex } from "./util/bytes.js";
import { stringifyJson } from "./util/json.js";

export interface ClientOptions {
  /** Base URL, e.g. https://gateway.example or http://localhost:8080; a path is kept. */
  api?: string;
  /** Seconds each call may take. Default 20. */
  timeoutSeconds?: number;
  /** A fetch implementation; defaults to the global one. */
  fetch?: typeof fetch;
}

export interface NodeInfo { signing_version?: number; genesis_hash?: string; height?: number; version?: string; [k: string]: unknown }
export interface SubmitResult { http_code: number; body: unknown; text: string; accepted: boolean }
export interface TxStatus { transaction_hash: string; status: "staging" | "mempool" | "confirmed" | "not_found" | string; block_height?: number; [k: string]: unknown }

export class Client {
  readonly api: string;
  readonly timeoutSeconds: number;
  private readonly f: typeof fetch;
  constructor(opts: ClientOptions = {}) {
    this.api = (opts.api ?? "http://localhost:8080").replace(/\/+$/, "");
    this.timeoutSeconds = opts.timeoutSeconds ?? 20;
    this.f = opts.fetch ?? globalThis.fetch;
    if (!this.f) throw new Error("no fetch available");
  }

  private async call(method: "GET" | "POST", path: string, body?: string): Promise<{ status: number; text: string; json: unknown }> {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), this.timeoutSeconds * 1000);
    try {
      const res = await this.f(this.api + path, {
        method, body, signal: ctl.signal,
        headers: body === undefined ? { Accept: "application/json", "User-Agent": "zbc-cli/1.0" }
                                    : { Accept: "application/json", "User-Agent": "zbc-cli/1.0", "Content-Type": "application/json" },
      });
      const text = await res.text();
      let json: unknown = null;
      try { json = JSON.parse(text); } catch { json = null; }
      return { status: res.status, text, json };
    } catch (e: unknown) {
      const aborted = e instanceof Error && e.name === "AbortError";
      throw new ToolError(aborted ? ExitCode.timeout : ExitCode.node_unreachable,
        (aborted ? "Timed out: " : "Connection failed: ") + path + " on " + this.api + (aborted ? "" : ": " + describe(e)));
    } finally {
      clearTimeout(timer);
    }
  }

  /** GET /api/v1/node/info. */
  async nodeInfo(): Promise<NodeInfo> {
    const r = await this.call("GET", "/api/v1/node/info");
    if (r.status !== 200) throw new ToolError(r.status >= 500 ? ExitCode.node_busy : ExitCode.node_unreachable,
      `cannot read /api/v1/node/info from ${this.api} (HTTP ${r.status}) to learn which chain to sign for; pass --genesis <hex> to sign for a known chain`, { http_code: r.status });
    return r.json as NodeInfo;
  }

  /** The chain's signing rule as the node reports it: `{version: 2, genesisHash}` or `{version: 1}`. */
  async signingRule(): Promise<{ version: 2; genesisHash: Uint8Array } | { version: 1 }> {
    const info = await this.nodeInfo();
    const sv = Number(info.signing_version ?? 1);
    if (sv >= 2) {
      const g = String(info.genesis_hash ?? "");
      if (!isHex(g, 64)) throw new ToolError(ExitCode.internal, "node enforces chain-bound signing but reports no genesis hash; pass --genesis <hex>");
      return { version: 2, genesisHash: hexToBytes(g) };
    }
    return { version: 1 };
  }

  /** POST /api/v1/transactions. Resolves for any HTTP answer; throws ToolError on transport failure. */
  async submit(payload: SubmitPayload): Promise<SubmitResult> {
    const r = await this.call("POST", "/api/v1/transactions", stringifyJson(payload));
    return { http_code: r.status, body: r.json ?? r.text, text: r.text, accepted: r.status === 200 || r.status === 202 };
  }

  /** Submit and throw a classified ToolError when the node rejects. */
  async submitOrThrow(payload: SubmitPayload): Promise<SubmitResult> {
    const r = await this.submit(payload);
    if (!r.accepted) {
      const j = r.body as { error?: unknown } | null;
      const text = j && typeof j === "object" && typeof j.error === "string" ? j.error : r.text;
      throw new ToolError(classifyNodeError(r.http_code, text), text, { http_code: r.http_code, api_response: r.body });
    }
    return r;
  }

  /** GET /api/v1/transactions/<hash>/status. A 404 answers `not_found` rather than throwing. */
  async status(hash: string): Promise<TxStatus & { http_code: number }> {
    const r = await this.call("GET", `/api/v1/transactions/${hash}/status`);
    const j = (r.json ?? {}) as Record<string, unknown>;
    if (r.status !== 200 && r.status !== 404) throw new ToolError(classifyNodeError(r.status, r.text), r.text, { http_code: r.status, api_response: r.json ?? r.text });
    return { transaction_hash: hash, status: String(j.status ?? (r.status === 404 ? "not_found" : "unknown")), ...j, http_code: r.status } as TxStatus & { http_code: number };
  }

  /** GET /api/v1/transactions/<hash>: the transaction, or a ToolError with exit 7 when unknown. */
  async transaction(hash: string): Promise<Record<string, unknown>> {
    const r = await this.call("GET", `/api/v1/transactions/${hash}`);
    if (r.status !== 200) throw new ToolError(r.status === 404 ? ExitCode.not_found : classifyNodeError(r.status, r.text), r.status === 404 ? "Transaction not found" : r.text, { http_code: r.status, api_response: r.json ?? r.text });
    return r.json as Record<string, unknown>;
  }

  /** GET /api/v1/accounts/<address>: balances, or a ToolError with exit 7 when the account is unknown. */
  async account(address: string): Promise<Record<string, unknown>> {
    const r = await this.call("GET", `/api/v1/accounts/${encodeURIComponent(address)}`);
    if (r.status !== 200) throw new ToolError(r.status === 404 ? ExitCode.not_found : classifyNodeError(r.status, r.text), r.status === 404 ? "Account not found" : r.text, { http_code: r.status, api_response: r.json ?? r.text });
    return r.json as Record<string, unknown>;
  }

  /** GET /api/v1/blocks/latest: the reference block for a proof of ownership (`block_hash` or a gateway's `hash`). */
  async latestBlock(): Promise<{ hash: Uint8Array; height: number }> {
    const r = await this.call("GET", "/api/v1/blocks/latest");
    const j = (r.json ?? {}) as Record<string, unknown>;
    const h = String(j.block_hash ?? j.hash ?? "");
    if (r.status !== 200 || !isHex(h, 64)) throw new ToolError(ExitCode.internal, "Failed to fetch latest block from " + this.api, { http_code: r.status });
    return { hash: hexToBytes(h), height: Number(j.height ?? 0) };
  }
}

function describe(e: unknown): string {
  if (e instanceof Error) {
    const cause = (e as { cause?: unknown }).cause;
    return e.message + (cause instanceof Error ? " (" + cause.message + ")" : "");
  }
  return String(e);
}
