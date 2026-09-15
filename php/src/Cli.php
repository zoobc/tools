<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** zbc-cli: every transaction as a subcommand, plus sign-message and verify-message (spec/cli-contract.md). */
final class Cli
{
    private const DEFAULT_FEE = 5000000;
    private const CATEGORY = [
        'send-zbc' => 'value', 'liquid-payment' => 'value', 'liquid-payment-stop' => 'value',
        'transfer-token' => 'tokens', 'issue-token' => 'tokens', 'mint-token' => 'tokens', 'burn-token' => 'tokens', 'finance-token' => 'tokens',
        'swap-create' => 'exchange', 'swap-accept' => 'exchange', 'swap-cancel' => 'exchange', 'market-create' => 'exchange', 'order-place' => 'exchange', 'order-cancel' => 'exchange',
        'app-create' => 'apps', 'app-join' => 'apps', 'app-move' => 'apps', 'app-resign' => 'apps', 'app-claim' => 'apps', 'app-settle' => 'apps',
        'store-file' => 'storage', 'add-prepaid-storage' => 'storage', 'dfs-create-file' => 'storage',
        'register-node' => 'node', 'update-node' => 'node', 'remove-node' => 'node', 'claim-node' => 'node', 'governance-vote' => 'node',
        'register-gateway' => 'gateway', 'unregister-gateway' => 'gateway', 'gateway-heartbeat' => 'gateway', 'archival-register' => 'gateway',
        'archival-unregister' => 'gateway', 'relay-register' => 'gateway', 'relay-unregister' => 'gateway',
        'register-release' => 'governance', 'revoke-release' => 'governance', 'release-authority-propose' => 'governance', 'release-authority-accept' => 'governance',
        'sign-message' => 'keys', 'verify-message' => 'keys',
    ];
    private const MESSAGE_COMMANDS = [
        'sign-message' => ['Sign a message with a private key (ZBC-MSG-v1, off-chain, no node needed)', [
            ['name' => 'sender_privkey', 'kind' => 'privkey', 'required' => true, 'help' => 'Sender private key (64 hex)'],
            ['name' => 'message', 'kind' => 'string', 'required' => true, 'help' => 'text to sign (hex bytes with --hex)']]],
        'verify-message' => ['Verify a ZBC-MSG-v1 message signature against a ZBC_ address (off-chain)', [
            ['name' => 'address', 'kind' => 'string', 'required' => true, 'help' => "signer's ZBC_ address (or 64-hex public key)"],
            ['name' => 'message', 'kind' => 'string', 'required' => true, 'help' => 'the signed text (hex bytes with --hex)'],
            ['name' => 'signature', 'kind' => 'string', 'required' => true, 'help' => '64-byte Ed25519 signature, 128 hex']]],
    ];
    private const USAGE_TEXT = <<<'TXT'
Options:
  -v, --verbose         Verbose output (default is JSON)
  --json-input          Read parameters from JSON on stdin
  --chain <name>        Read the recipient as this chain: zbc, btc, eth, sol, dot, ada, xrp, trx, xtz
  --message <text>      Optional transaction message
  --encrypt             Encrypt --message to the recipient (ZBC only)
  --genesis <hex|v1>    Sign for this chain (its genesis block hash) without asking the node; 'v1' = legacy unbound digest. Default: ask --api.
  --escrow-approver <addr>   Escrow approver address
  --escrow-commission <n>    Escrow commission (atomic units)
  --escrow-timeout <n>       Escrow timeout as a FUTURE Unix timestamp (seconds)
  --escrow-instruction <s>   Escrow instruction
  --fee <n>             Transaction fee (default: 5000000 = 0.05 ZBC)
  --api <url>           API endpoint (default: $ZBC_API, else http://localhost:8080)
  --timeout <s>         Bound for each HTTP call, seconds (default: $ZBC_TIMEOUT, else 20; also --timeout-seconds)
  --hex                 sign-message/verify-message: the message is hex bytes, not text
  --offline             Build, sign and hash, print unsigned_bytes, digest, signature, transaction_bytes and transaction_hash, exit 0 without submitting. Needs --genesis.
  --timestamp <n>       Transaction timestamp, Unix seconds (default: now)

Environment:
  ZBC_KEY               Sender private key (64 hex), used when the key argument is omitted or '-'
  ZBC_API, ZBC_TIMEOUT  Defaults for --api and --timeout
  ZOOBC_GENESIS_HASH    Default for --genesis

Exit codes:
  0 ok  1 internal  2 usage  3 node unreachable  4 insufficient balance  5 fee too low
  6 rejected by node  7 not found  8 timeout  9 node busy (5xx)  10 signature invalid
  JSON errors carry the same code as "exit_code" and its name as "error_class".

TXT;

    private static function commandOf(string $cmd): ?array
    {
        if (isset(self::MESSAGE_COMMANDS[$cmd])) { return [self::MESSAGE_COMMANDS[$cmd][0], self::MESSAGE_COMMANDS[$cmd][1], 0]; }
        $d = Spec::command($cmd);
        return $d ? [$d['description'], $d['params'], $d['type']] : null;
    }

    private static function out(Io $io, array $v): void { ($io->stdout)(json_encode($v, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n"); }
    private static function emitError(Io $io, ToolError $e, bool $verbose): int
    {
        if ($verbose) { ($io->stderr)("Error: {$e->getMessage()}\n"); } else { self::out($io, $e->toArray()); }
        return $e->getCode();
    }
    private static function isInt(string $s): bool { return (bool) preg_match('/^-?\d+$/', $s); }

    private static function checkEscrow(Escrow $e): void
    {
        if ($e->approver === '') { throw ToolError::usage('Escrow requires --escrow-approver'); }
        if ($e->timeout <= 0) { throw ToolError::usage('Escrow requires --escrow-timeout > 0'); }
        if ($e->commission < 0) { throw ToolError::usage('Escrow commission cannot be negative'); }
    }

    /** @return array{0: string[], 1: array} positionals and options */
    private static function parseArgs(array $argv, Io $io): array
    {
        $env = $io->env;
        $o = ['api' => $env('ZBC_API') ?: 'http://localhost:8080', 'fee' => self::DEFAULT_FEE, 'timeout' => 20, 'genesis' => '', 'jsonInput' => false, 'verbose' => false,
              'message' => null, 'encrypt' => false, 'chain' => '', 'escrow' => null, 'hex' => false, 'offline' => false, 'timestamp' => null, 'token' => null, 'help' => false];
        $t = $env('ZBC_TIMEOUT'); if ($t !== null && ctype_digit($t) && (int) $t > 0) { $o['timeout'] = (int) $t; }
        $positional = []; $escrow = ['approver' => '', 'commission' => 0, 'timeout' => 0, 'instruction' => '']; $escrowSeen = false;
        $n = count($argv);
        for ($i = 0; $i < $n; $i++) {
            $a = $argv[$i];
            $need = function (string $what = '') use (&$i, $argv, $n, $a): string { if ($i + 1 >= $n) { throw ToolError::usage("$a requires a value$what"); } return $argv[++$i]; };
            $integer = function (string $s, string $what): int { if (!self::isInt($s)) { throw ToolError::usage($what); } return (int) $s; };
            switch ($a) {
                case '-v': case '--verbose': $o['verbose'] = true; break;
                case '--json': $o['verbose'] = false; break;
                case '--json-input': $o['jsonInput'] = true; break;
                case '--encrypt': $o['encrypt'] = true; break;
                case '--hex': $o['hex'] = true; break;
                case '--offline': $o['offline'] = true; break;
                case '-h': case '--help': $o['help'] = true; break;
                case '--message': $o['message'] = $need(); break;
                case '--fee': $o['fee'] = $integer($need(), '--fee must be a whole number of atomic units'); break;
                case '--api': $o['api'] = $need(); break;
                case '--timeout': case '--timeout-seconds':
                    $v = $need(' (seconds)');
                    if (!ctype_digit($v)) { throw ToolError::usage("$a must be a whole number of seconds"); }
                    $o['timeout'] = (int) $v; if ($o['timeout'] <= 0) { throw ToolError::usage("$a must be > 0"); }
                    break;
                case '--genesis': $o['genesis'] = $need(); break;
                case '--chain': $o['chain'] = $need(); break;
                case '--token': $o['token'] = $need(); break;
                case '--timestamp':
                    $ts = $integer($need(' (Unix seconds)'), '--timestamp must be a whole number of Unix seconds');
                    if ($ts <= 0) { throw ToolError::usage('--timestamp must be > 0'); }
                    $o['timestamp'] = $ts; break;
                case '--escrow-approver': $escrow['approver'] = $need(); $escrowSeen = true; break;
                case '--escrow-commission': $escrow['commission'] = $integer($need(), '--escrow-commission must be a whole number of atomic units'); $escrowSeen = true; break;
                case '--escrow-timeout': $escrow['timeout'] = $integer($need(), '--escrow-timeout must be a Unix timestamp in seconds'); $escrowSeen = true; break;
                case '--escrow-instruction': $escrow['instruction'] = $need(); $escrowSeen = true; break;
                default:
                    if (strlen($a) > 1 && $a[0] === '-' && !ctype_digit($a[1]) && $a[1] !== '.') { throw ToolError::usage("Unknown option: $a"); }
                    $positional[] = $a;
            }
        }
        if ($o['offline'] && $o['genesis'] === '' && !($env('ZOOBC_GENESIS_HASH') ?? '')) { throw ToolError::usage('--offline needs --genesis <hex|v1> (or ZOOBC_GENESIS_HASH): nothing is asked of a node'); }
        if ($escrowSeen) { $e = new Escrow($escrow['approver'], $escrow['commission'], $escrow['timeout'], $escrow['instruction']); self::checkEscrow($e); $o['escrow'] = $e; }
        return [$positional, $o];
    }

    private static function isPlaceholder(string $s): bool { return in_array($s, ['-', '@env', 'env:ZBC_KEY'], true); }

    private static function resolveParams(array $params, array $positional, array &$o, Io $io): array
    {
        $values = []; $env = $io->env;
        $keyIsFirst = ($params[0]['name'] ?? '') === 'sender_privkey';
        $envKey = $keyIsFirst ? ($env('ZBC_KEY') ?? '') : '';
        if ($o['jsonInput']) {
            $text = trim(($io->stdin)());
            if ($text === '') { throw ToolError::usage('No JSON input received on stdin'); }
            $j = json_decode($text, true);
            if (!is_array($j) || array_is_list($j) && $j !== []) { throw ToolError::usage('Invalid JSON input'); }
            foreach ($params as $p) {
                if (array_key_exists($p['name'], $j)) { $v = is_string($j[$p['name']]) ? $j[$p['name']] : json_encode($j[$p['name']]); }
                elseif (($p['default'] ?? '') !== '') { $v = $p['default']; }
                elseif ($p['name'] === 'sender_privkey' && $envKey !== '') { $v = $envKey; }
                elseif ($p['required']) { throw ToolError::usage("Missing required field: {$p['name']}"); }
                else { $v = ''; }
                if ($keyIsFirst && $p['name'] === 'sender_privkey' && self::isPlaceholder($v)) { if ($envKey === '') { throw ToolError::usage("sender_privkey is '-' but ZBC_KEY is not set"); } $v = $envKey; }
                $values[$p['name']] = $v;
            }
            $num = function (string $k, string $what) use ($j): ?int {
                if (!array_key_exists($k, $j)) { return null; }
                $s = is_int($j[$k]) ? (string) $j[$k] : (is_string($j[$k]) ? $j[$k] : '');
                if (!self::isInt($s)) { throw ToolError::usage("$what must be a whole number"); }
                return (int) $s;
            };
            if (($f = $num('fee', 'fee')) !== null) { $o['fee'] = $f; }
            if (($t = $num('timeout_seconds', 'timeout_seconds')) !== null) { if ($t <= 0) { throw ToolError::usage('timeout_seconds must be > 0'); } $o['timeout'] = $t; }
            if (($ts = $num('timestamp', 'timestamp')) !== null) { if ($ts <= 0) { throw ToolError::usage('timestamp must be > 0'); } $o['timestamp'] = $ts; }
            if (isset($j['offline']) && is_bool($j['offline'])) { $o['offline'] = $j['offline']; }
            if (isset($j['api_url']) && is_string($j['api_url'])) { $o['api'] = $j['api_url']; }
            if (isset($j['message']) && is_string($j['message'])) { $o['message'] = $j['message']; }
            if (isset($j['hex']) && is_bool($j['hex'])) { $o['hex'] = $j['hex']; }
            if (($j['verbose'] ?? false) === true) { $o['verbose'] = true; }
            if (isset($j['escrow']) && is_array($j['escrow'])) {
                $em = $j['escrow'];
                $e = new Escrow((string) ($em['approver'] ?? ''), (int) ($em['commission'] ?? 0), (int) ($em['timeout'] ?? 0), (string) ($em['instruction'] ?? ''));
                self::checkEscrow($e); $o['escrow'] = $e;
            }
            if ($o['offline'] && $o['genesis'] === '' && !($env('ZOOBC_GENESIS_HASH') ?? '')) { throw ToolError::usage('--offline needs --genesis <hex|v1> (or ZOOBC_GENESIS_HASH): nothing is asked of a node'); }
            return $values;
        }
        if ($positional === [] && $io->isTty && $o['verbose']) {
            $lines = explode("\n", ($io->stdin)());
            foreach ($params as $n => $p) {
                ($io->stdout)("  {$p['help']}" . (($p['default'] ?? '') !== '' ? " [{$p['default']}]" : '') . ': ');
                $v = trim($lines[$n] ?? '');
                if ($v === '') { $v = $p['default'] ?? ''; }
                if ($p['name'] === 'sender_privkey' && ($v === '' || self::isPlaceholder($v))) { $v = $envKey; }
                if ($p['required'] && $v === '') { throw ToolError::usage("Missing required argument: {$p['name']}"); }
                $values[$p['name']] = $v;
            }
            return $values;
        }
        $pos = $positional;
        if ($keyIsFirst) {
            $required = count(array_filter($params, fn($p) => $p['required'] && ($p['default'] ?? '') === ''));
            if ($pos !== [] && self::isPlaceholder($pos[0])) { if ($envKey === '') { throw ToolError::usage("key argument is '-' but ZBC_KEY is not set"); } $pos[0] = $envKey; }
            elseif ($envKey !== '' && count($pos) + 1 === $required) { array_unshift($pos, $envKey); }
        }
        foreach ($params as $i => $p) {
            if ($i < count($pos)) { $values[$p['name']] = $pos[$i]; }
            elseif (($p['default'] ?? '') !== '') { $values[$p['name']] = $p['default']; }
            elseif ($p['required']) { throw ToolError::usage("Missing required argument: {$p['name']}" . ($i === 0 && $keyIsFirst ? ' (pass it, or set ZBC_KEY)' : '')); }
            else { $values[$p['name']] = ''; }
        }
        if (count($pos) > count($params)) {
            $feeArg = $pos[count($params)];
            if (!self::isInt($feeArg)) { throw ToolError::usage("Fee must be a whole number of atomic units, got \"$feeArg\". The API endpoint is passed with --api URL, not as a positional argument."); }
            $o['fee'] = (int) $feeArg;
        }
        if (count($pos) > count($params) + 1) { $o['api'] = $pos[count($params) + 1]; }
        return $values;
    }

    private static function printList(Io $io): void
    {
        $all = [];
        foreach (Spec::commands() as $c) { $all[$c['command']] = $c['description']; }
        foreach (self::MESSAGE_COMMANDS as $k => $v) { $all[$k] = $v[0]; }
        ksort($all, SORT_STRING);
        $groups = [];
        foreach ($all as $cmd => $desc) { $groups[self::CATEGORY[$cmd] ?? 'other'][] = sprintf('  %-26s%s', $cmd, $desc); }
        $s = 'ZooBC unified transaction CLI — ' . count($all) . " commands.\n  Default: JSON in, JSON out.   --verbose: prompt each field + text output.\n  echo '{...}' | zbc-cli <cmd> --json-input     zbc-cli help <cmd>  (fields for one tx)\n\n";
        foreach (['value', 'tokens', 'exchange', 'apps', 'storage', 'account', 'node', 'gateway', 'governance', 'keys', 'other'] as $g) {
            if (isset($groups[$g])) { $s .= "[$g]\n" . implode("\n", $groups[$g]) . "\n\n"; }
        }
        $s .= "First param is the sender private key (or set ZBC_KEY and omit it / pass '-'); verify-message takes an address.\n`zbc-cli help <cmd>` shows a command's JSON fields; `zbc-cli <cmd> --help` the options, env vars and exit codes.\n";
        ($io->stdout)($s);
    }

    private static function printHelp(string $cmd, Io $io): int
    {
        $c = self::commandOf($cmd);
        if ($c === null) { ($io->stderr)("Unknown command: $cmd (try `zbc-cli list`)\n"); return ExitCode::USAGE; }
        [$desc, $params, $type] = $c;
        $s = "$cmd — $desc  (tx type $type)\nJSON fields (default: JSON in/out; --json-input reads them on stdin; positional order matches):\n";
        $sample = [];
        foreach ($params as $p) {
            $s .= sprintf("  %-18s%s%s%s\n", $p['name'], $p['required'] ? '(required) ' : '(optional) ', $p['help'], ($p['default'] ?? '') !== '' ? "  [default: {$p['default']}]" : '');
            $sample[$p['name']] = ($p['default'] ?? '') !== '' ? $p['default'] : '...';
        }
        $s .= 'Sample: ' . json_encode($sample, JSON_UNESCAPED_SLASHES) . "\nRun with --verbose to be prompted for each field and get human-readable output.\n";
        ($io->stdout)($s);
        return 0;
    }

    private static function printUsage(string $cmd, array $params, Io $io): void
    {
        $args = implode('', array_map(fn($p) => $p['required'] ? " <{$p['name']}>" : " [{$p['name']}]", $params));
        $list = implode('', array_map(fn($p) => sprintf("  %-22s%s\n", $p['name'], $p['help']), $params));
        ($io->stdout)("zbc-cli $cmd\n\nUsage:\n  zbc-cli $cmd [options]$args [fee] [api_url]\n\n" . self::USAGE_TEXT . "\nParameters:\n$list");
    }

    private static function messageBytes(string $text, bool $hex): string
    {
        if (!$hex) { return $text; }
        if (!Encoding::isHex($text)) { throw ToolError::usage('--hex message is not valid hex'); }
        return hex2bin($text);
    }

    private static function runSignMessage(array $v, array $o, Io $io): int
    {
        try { $kp = KeyPair::fromHex($v['sender_privkey']); } catch (\InvalidArgumentException) { throw ToolError::usage('Private key must be 64 hex characters (32 bytes)'); }
        $s = Message::sign($kp, self::messageBytes($v['message'], $o['hex']));
        if ($o['verbose']) { ($io->stdout)("Address:   {$s['address']}\nDigest:    {$s['digest']}\nSignature: {$s['signature']}\n"); return 0; }
        $m = ['success' => true] + $s;
        if (!$o['hex']) { $m['message'] = $v['message']; }
        self::out($io, $m);
        return 0;
    }

    private static function runVerifyMessage(array $v, array $o, Io $io): int
    {
        $pub = Message::publicKeyOf($v['address']);
        if ($pub === null) { throw ToolError::usage('address must be a ZBC_ account (Ed25519) address'); }
        $msg = self::messageBytes($v['message'], $o['hex']);
        if (!Encoding::isHex($v['signature'])) { throw ToolError::usage('signature must be hex'); }
        if (strlen($v['signature']) !== 128) { throw ToolError::usage('signature must be 64 bytes (128 hex characters)'); }
        $valid = Message::verify($v['address'], $msg, hex2bin($v['signature']));
        $address = Address::encode($pub, 'ZBC');
        $code = $valid ? ExitCode::OK : ExitCode::VERIFY_FAILED;
        if ($o['verbose']) { ($io->stdout)(($valid ? 'VALID' : 'INVALID') . " signature for $address\n"); return $code; }
        self::out($io, ['success' => true, 'valid' => $valid, 'scheme' => Message::SCHEME, 'address' => $address, 'digest' => bin2hex(Message::digest($msg)),
                        'exit_code' => $code, 'error_class' => ExitCode::errorClass($code)]);
        return $code;
    }

    private static function signingContext(array $o, Client $client, Io $io): SigningContext
    {
        $g = $o['genesis'] !== '' ? $o['genesis'] : (($io->env)('ZOOBC_GENESIS_HASH') ?? '');
        if ($g !== '') { try { return SigningContext::of($g); } catch (\InvalidArgumentException $e) { throw ToolError::usage($e->getMessage()); } }
        try { return $client->signingRule(); } catch (ToolError $e) {
            if ($e->getCode() === ExitCode::NODE_UNREACHABLE || $e->getCode() === ExitCode::TIMEOUT) {
                throw new ToolError($e->getCode(), ($e->getCode() === ExitCode::TIMEOUT ? 'timed out reading' : 'cannot read') . " /api/v1/node/info from {$o['api']} to learn which chain to sign for; pass --genesis <hex> to sign for a known chain");
            }
            throw $e;
        }
    }

    private static function runTransaction(array $def, array $v, array $o, Io $io): int
    {
        foreach ($def['params'] as $p) { $cur = $v[$p['name']] ?? ''; if ($cur !== '' || $p['required']) { $v[$p['name']] = Body::validateParam($p, $cur); } }
        if ($o['encrypt']) { throw ToolError::usage('--encrypt is not available in this implementation yet; send the message in clear or use the C++ tools'); }
        try { $sender = KeyPair::fromHex($v[$def['sender_key']] ?? ''); } catch (\InvalidArgumentException $e) { throw ToolError::usage($e->getMessage()); }
        $client = new Client($o['api'], $o['timeout']);
        $ctx = self::signingContext($o, $client, $io);
        $timestamp = $o['timestamp'] ?? time();
        $recipient = ''; $extra = [];
        if ($def['recipient'] === 'required') {
            try { $r = Address::parse($v['recipient'], $o['chain']); } catch (\InvalidArgumentException $e) { throw ToolError::usage("invalid recipient address: {$e->getMessage()}"); }
            $recipient = $r->bytes(); $extra['recipient'] = $r->display; $extra['recipient_type'] = $r->typeName();
        }
        if ($o['token'] !== null) { if ($def['command'] !== 'liquid-payment') { throw ToolError::usage('--token applies to liquid-payment only'); } $v['token_id'] = $o['token']; }
        $files = [];
        foreach ($def['params'] as $p) {
            if ($p['kind'] === 'file') { $d = @file_get_contents($v[$p['name']]); if ($d === false) { throw ToolError::usage("cannot read {$p['name']}: {$v[$p['name']]}"); } $files[$p['name']] = $d; }
        }
        $block = $def['needs_node'] ? $client->latestBlock() : null;
        $input = new CustomInput($def, $v, $sender, $ctx, $timestamp, $block);
        if (in_array($def['custom'] ?? null, ['multisig', 'settle'], true)) {
            [$body, $more] = Custom::body($input); $extra += $more;
        } else {
            $bc = new BodyContext($sender, $files);
            $extra += Custom::computeFields($input, $bc);
            $body = Body::build($def, $v, $bc);
        }
        foreach ($def['params'] as $p) {
            if (in_array($p['kind'], ['privkey', 'file'], true) || $p['name'] === 'recipient' || array_key_exists($p['name'], $extra)) { continue; }
            $val = $v[$p['name']] ?? '';
            $extra[$p['name']] = (in_array($p['kind'], ['int64', 'uint64', 'uint32', 'uint8'], true) && self::isInt($val)) ? (int) $val : $val;
        }
        if ($def['command'] === 'approve-escrow') {
            unset($extra['transaction_hash']);
            $extra['escrowed_transaction_hash'] = $v['transaction_hash'];
            $extra['transaction_id'] = Transaction::id(hex2bin($v['transaction_hash']));
        }
        $extra['sender'] = $sender->address();
        try { $signed = Transaction::sign($def['type'], $timestamp, $sender, $recipient, $o['fee'], $body, $ctx, $o['escrow'], $o['message'] ?? ''); }
        catch (\InvalidArgumentException $e) { throw ToolError::usage("Invalid escrow approver: {$e->getMessage()}"); }
        $fields = ['transaction_hash' => bin2hex($signed->hash), 'transaction_type' => $def['type'], 'sender_account_address' => $signed->payload['sender_account_address'],
                   'recipient_account_address' => $signed->payload['recipient_account_address'], 'fee' => $o['fee'], 'timestamp' => $timestamp];
        $common = [];
        if (($o['message'] ?? '') !== '') { $common['message'] = $o['message']; }
        if (isset($signed->payload['escrow'])) { $common['escrow'] = $signed->payload['escrow']; }
        $common += $extra;
        if ($o['offline']) {
            if ($o['verbose']) {
                $g = $signed->genesisHash !== '' ? ' (genesis ' . bin2hex($signed->genesisHash) . ')' : '';
                ($io->stdout)("OFFLINE: transaction built and signed, not submitted\n\nTransaction hash:  " . bin2hex($signed->hash) . "\nSigning version:   {$signed->signingVersion}$g\nTimestamp:         $timestamp\n"
                    . 'Unsigned bytes:    ' . bin2hex($signed->unsigned) . "\nDigest:            " . bin2hex($signed->digest) . "\nSignature:         " . bin2hex($signed->signature)
                    . "\nTransaction bytes: " . bin2hex($signed->bytes) . "\nPayload:           " . json_encode($signed->payload, JSON_UNESCAPED_SLASHES) . "\n");
                return 0;
            }
            $m = ['success' => true, 'offline' => true] + $fields + ['signing_version' => $signed->signingVersion];
            if ($signed->genesisHash !== '') { $m['genesis_hash'] = bin2hex($signed->genesisHash); }
            $m += ['unsigned_bytes' => bin2hex($signed->unsigned), 'digest' => bin2hex($signed->digest), 'signature' => bin2hex($signed->signature),
                   'transaction_bytes' => bin2hex($signed->bytes), 'payload' => $signed->payload] + $common;
            self::out($io, $m);
            return 0;
        }
        [$reply, $accepted] = $client->submit($signed->payload);
        if (!$accepted) {
            $e = Client::rejectionError($reply);
            if ($o['verbose']) { ($io->stderr)('FAILED: Transaction submission rejected (' . ExitCode::errorClass($e->getCode()) . ")\nHTTP {$reply->status}: {$reply->text}\n"); }
            else { self::out($io, $e->toArray()); }
            return $e->getCode();
        }
        if ($o['verbose']) { ($io->stdout)("SUCCESS: {$def['command']} submitted!\n\nTransaction Hash: " . bin2hex($signed->hash) . "\n"); return 0; }
        self::out($io, ['success' => true] + $fields + ['api_response' => $reply->body()] + $common);
        return 0;
    }

    /** The combined command; returns the exit code. */
    public static function run(array $args, Io $io): int
    {
        if ($args === []) {
            ($io->stdout)("ZooBC unified transaction CLI\nUsage: zbc-cli <command> <params...> [--api URL] [--fee N] [--timeout S] [--verbose] [--json-input]\n       zbc-cli list   (show all commands)      zbc-cli <command> --help  (options, env vars, exit codes)\n");
            return ExitCode::USAGE;
        }
        $cmd = $args[0];
        if ($cmd === 'help' && count($args) >= 2) { return self::printHelp($args[1], $io); }
        if (in_array($cmd, ['list', '--help', '-h', 'help'], true)) { self::printList($io); return 0; }
        if (self::commandOf($cmd) === null) { ($io->stderr)("Unknown command: $cmd (try `zbc-cli list`)\n"); return ExitCode::USAGE; }
        return self::runTool($cmd, array_slice($args, 1), $io);
    }

    /** One command with its own arguments. */
    public static function runTool(string $cmd, array $args, Io $io): int
    {
        $c = self::commandOf($cmd);
        if ($c === null) { ($io->stderr)("Unknown command: $cmd (try `zbc-cli list`)\n"); return ExitCode::USAGE; }
        $params = $c[1]; $verbose = false;
        try {
            [$positional, $o] = self::parseArgs($args, $io);
            $verbose = $o['verbose'];
            if ($o['help']) { self::printUsage($cmd, $params, $io); return 0; }
            $values = self::resolveParams($params, $positional, $o, $io);
            $verbose = $o['verbose'];
            return match ($cmd) {
                'sign-message' => self::runSignMessage($values, $o, $io),
                'verify-message' => self::runVerifyMessage($values, $o, $io),
                default => self::runTransaction(Spec::command($cmd), $values, $o, $io),
            };
        } catch (ToolError $e) { return self::emitError($io, $e, $verbose); }
        catch (\Throwable $e) { return self::emitError($io, ToolError::internal($e->getMessage()), $verbose); }
    }
}
