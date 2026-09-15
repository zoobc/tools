<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** The node/gateway HTTP client (spec/api.md) on PHP's stream wrapper: node info, submit, status, transaction, account, latest block. */
final class Client
{
    public readonly string $api;

    public function __construct(string $api = 'http://localhost:8080', public readonly int $timeoutSeconds = 20)
    {
        $this->api = rtrim($api, '/');
    }

    private function call(string $method, string $path, ?string $body = null): Reply
    {
        $headers = "Accept: application/json\r\nUser-Agent: zbc-cli/1.0\r\n" . ($body !== null ? "Content-Type: application/json\r\n" : '');
        $ctx = stream_context_create(['http' => ['method' => $method, 'header' => $headers, 'content' => $body ?? '', 'timeout' => $this->timeoutSeconds, 'ignore_errors' => true],
                                      'ssl' => ['verify_peer' => true]]);
        $start = microtime(true);
        $text = @file_get_contents($this->api . $path, false, $ctx);
        if ($text === false) {
            $err = error_get_last()['message'] ?? 'unknown error';
            if (microtime(true) - $start >= $this->timeoutSeconds - 0.5 || stripos($err, 'timed out') !== false) { throw new ToolError(ExitCode::TIMEOUT, "Timed out: $path on {$this->api}"); }
            throw new ToolError(ExitCode::NODE_UNREACHABLE, "Connection failed: $path on {$this->api}: $err");
        }
        $status = 0;
        foreach ($http_response_header ?? [] as $h) { if (preg_match('#^HTTP/\S+ (\d{3})#', $h, $m)) { $status = (int) $m[1]; } }
        $json = json_decode($text, true);
        return new Reply($status, $text, json_last_error() === JSON_ERROR_NONE ? $json : null);
    }

    /** GET /api/v1/node/info. */
    public function nodeInfo(): array
    {
        $r = $this->call('GET', '/api/v1/node/info');
        if ($r->status !== 200) {
            throw new ToolError($r->status >= 500 ? ExitCode::NODE_BUSY : ExitCode::NODE_UNREACHABLE,
                "cannot read /api/v1/node/info from {$this->api} (HTTP {$r->status}) to learn which chain to sign for; pass --genesis <hex> to sign for a known chain", ['http_code' => $r->status]);
        }
        return is_array($r->json) ? $r->json : [];
    }

    /** The chain's signing rule as the node reports it. */
    public function signingRule(): SigningContext
    {
        $info = $this->nodeInfo();
        if ((int) ($info['signing_version'] ?? 1) >= 2) {
            $g = (string) ($info['genesis_hash'] ?? '');
            if (!Encoding::isHex($g, 64)) { throw ToolError::internal('node enforces chain-bound signing but reports no genesis hash; pass --genesis <hex>'); }
            return new SigningContext(2, hex2bin($g));
        }
        return new SigningContext(1);
    }

    /** POST /api/v1/transactions -> [Reply, accepted]. Transport failures throw. */
    public function submit(array $payload): array
    {
        $r = $this->call('POST', '/api/v1/transactions', json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        return [$r, $r->status === 200 || $r->status === 202];
    }

    /** Submit and throw a classified ToolError when the node rejects. */
    public function submitOrThrow(array $payload): Reply
    {
        [$r, $ok] = $this->submit($payload);
        if (!$ok) { throw self::rejectionError($r); }
        return $r;
    }

    /** GET /api/v1/transactions/<hash>/status; a 404 answers status not_found rather than throwing. */
    public function status(string $hash): array
    {
        $r = $this->call('GET', "/api/v1/transactions/$hash/status");
        if ($r->status !== 200 && $r->status !== 404) { throw self::rejectionError($r); }
        $out = ['transaction_hash' => $hash, 'status' => $r->status === 404 ? 'not_found' : 'unknown'];
        if (is_array($r->json)) { $out = array_merge($out, $r->json); }
        $out['http_code'] = $r->status;
        return $out;
    }

    /** GET /api/v1/transactions/<hash>; exit 7 when unknown. */
    public function transaction(string $hash): mixed
    {
        $r = $this->call('GET', "/api/v1/transactions/$hash");
        if ($r->status !== 200) { $e = self::rejectionError($r); throw $r->status === 404 ? new ToolError(ExitCode::NOT_FOUND, 'Transaction not found', $e->extra) : $e; }
        return $r->body();
    }

    /** GET /api/v1/accounts/<address>; exit 7 when unknown. */
    public function account(string $address): mixed
    {
        $r = $this->call('GET', '/api/v1/accounts/' . rawurlencode($address));
        if ($r->status !== 200) { $e = self::rejectionError($r); throw $r->status === 404 ? new ToolError(ExitCode::NOT_FOUND, 'Account not found', $e->extra) : $e; }
        return $r->body();
    }

    /** GET /api/v1/blocks/latest: the reference block for a proof of ownership (`block_hash`, or a gateway's `hash`). */
    public function latestBlock(): ReferenceBlock
    {
        $r = $this->call('GET', '/api/v1/blocks/latest');
        $m = is_array($r->json) ? $r->json : [];
        $h = (string) ($m['block_hash'] ?? $m['hash'] ?? '');
        if ($r->status !== 200 || !Encoding::isHex($h, 64)) { throw new ToolError(ExitCode::INTERNAL, "Failed to fetch latest block from {$this->api}", ['http_code' => $r->status]); }
        return new ReferenceBlock(hex2bin($h), (int) ($m['height'] ?? 0));
    }

    /** Classify a node's rejection reply (spec/api.md section 2). */
    public static function rejectionError(Reply $r): ToolError
    {
        $text = (is_array($r->json) && isset($r->json['error']) && is_string($r->json['error'])) ? $r->json['error'] : $r->text;
        return new ToolError(ExitCode::classifyNodeError($r->status, $text), $text, ['http_code' => $r->status, 'api_response' => $r->body()]);
    }
}
