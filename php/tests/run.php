#!/usr/bin/env php
<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
// Every file in spec/vectors, through the library and in-process through the CLI. No test framework
// needed: php tests/run.php exits 0 when every check passes, 1 otherwise, and prints what failed.
declare(strict_types=1);

spl_autoload_register(function (string $class): void {
    if (str_starts_with($class, 'Zoobc\\Zbc\\')) { require __DIR__ . '/../src/' . substr($class, 10) . '.php'; }
});

use Zoobc\Zbc\{Address, Body, BodyContext, Cli, Custom, CustomInput, Encoding, Escrow, Io, KeyPair, Message, ReferenceBlock, SigningContext, Spec, Transaction, Wallet};

$dir = __DIR__ . '/../../spec/vectors';
$load = fn(string $f) => json_decode(file_get_contents("$dir/$f"), true, 512, JSON_THROW_ON_ERROR);
$failures = 0; $checks = 0;
function check(string $name, bool $ok, string $detail = ''): void
{
    global $failures, $checks; $checks++;
    if (!$ok) { $failures++; fwrite(STDERR, "FAIL $name $detail\n"); }
}
function cli(array $args, string $stdin = '', array $env = []): array
{
    $out = ''; $err = '';
    $io = new Io(fn() => $stdin, function (string $s) use (&$out) { $out .= $s; }, function (string $s) use (&$err) { $err .= $s; }, fn(string $k) => $env[$k] ?? null, false);
    return [Cli::run($args, $io), $out, $err];
}
function canonical(mixed $v): string
{
    if (is_array($v)) { ksort($v, SORT_STRING); foreach ($v as $k => $x) { $v[$k] = is_array($x) ? json_decode(canonical($x), true) : $x; } }
    return json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

// keys.json
$d = $load('keys.json');
foreach ($d['seeds'] as $s) {
    $kp = KeyPair::fromHex($s['seed']);
    check("keys seed {$s['seed']}", bin2hex($kp->publicKey) === $s['public_key'] && $kp->address() === $s['address'] && $kp->nodeAddress() === $s['node_address']);
}
foreach ($d['wallets'] as $w) {
    check('mnemonic valid', Wallet::validateMnemonic($w['mnemonic']));
    foreach ($w['accounts'] as $a) {
        [$kp, $path] = Wallet::account($w['mnemonic'], $a['index'], $w['passphrase']);
        check("wallet account {$a['index']} {$w['passphrase']}", $path === $a['path'] && bin2hex($kp->seed) === $a['seed'] && $kp->address() === $a['address'] && $kp->nodeAddress() === $a['node_address']);
    }
}

// addresses.json
foreach ($load('addresses.json')['vectors'] as $v) {
    $input = $v['input']; $chain = $v['chain'] ?? '';
    try { $p = Address::parse($input, $chain); $ok = $v['valid'] && $p->type === $v['account_type'] && bin2hex($p->bytes()) === $v['address_bytes']; $detail = $v['valid'] ? bin2hex($p->bytes()) : 'accepted, reference refuses it'; }
    catch (InvalidArgumentException $e) { $ok = !$v['valid']; $detail = $e->getMessage(); }
    check("address $input $chain", $ok, $detail);
}

// messages.json
$m = $load('messages.json');
foreach ($m['vectors'] as $v) {
    $kp = KeyPair::fromHex($v['seed']); $msg = hex2bin($v['message_hex']);
    $s = Message::sign($kp, $msg);
    check("sign-message {$v['seed']}", $s['address'] === $v['address'] && $s['public_key'] === $v['public_key'] && $s['digest'] === $v['digest'] && $s['signature'] === $v['signature']);
    check("verify-message {$v['seed']}", Message::verify($v['address'], $msg, hex2bin($v['signature'])));
}
foreach ($m['invalid'] as $n) {
    $sig = Encoding::isHex($n['signature']) ? hex2bin($n['signature']) : '';
    check("invalid message: {$n['case']}", !Message::verify($n['address'], $n['message'], $sig));
}

// transactions
function checkSigned(array $v, string $body): void
{
    $name = $v['name']; $e = $v['expected'];
    check("$name body", bin2hex($body) === $e['body'], bin2hex($body));
    $def = Spec::command($v['command']);
    $kp = KeyPair::fromHex($v['key']);
    $recipient = $def['recipient'] === 'required' ? Address::parse($v['params']['recipient'])->bytes() : '';
    $escrow = isset($v['escrow']) ? new Escrow($v['escrow']['approver'], $v['escrow']['commission'], $v['escrow']['timeout'], $v['escrow']['instruction'] ?? '') : null;
    $signed = Transaction::sign($v['type'], $v['timestamp'], $kp, $recipient, $v['fee'], $body, SigningContext::of($v['genesis']), $escrow, $v['message'] ?? '');
    check("$name unsigned", bin2hex($signed->unsigned) === $e['unsigned_bytes']);
    check("$name digest", bin2hex($signed->digest) === $e['digest']);
    check("$name signature", bin2hex($signed->signature) === $e['signature']);
    check("$name bytes", bin2hex($signed->bytes) === $e['transaction_bytes']);
    check("$name hash", bin2hex($signed->hash) === $e['transaction_hash']);
    check("$name payload", canonical($signed->payload) === canonical($e['payload']), canonical($signed->payload));
}
foreach ($load('transactions.json')['vectors'] as $v) {
    $p = $v['params'];
    $body = $v['command'] === 'send-zbc' ? Transaction::sendZbcBody((int) $p['amount']) : Transaction::approvalEscrowBody((int) $p['approval'], hex2bin($p['transaction_hash']));
    checkSigned($v, $body);
}
foreach ($load('transactions-all.json')['vectors'] as $v) {
    $def = Spec::command($v['command']); $kp = KeyPair::fromHex($v['key']); $ctx = SigningContext::of($v['genesis']);
    $block = isset($v['reference_block']) ? new ReferenceBlock(hex2bin($v['reference_block']['block_hash']), $v['reference_block']['height']) : null;
    $input = new CustomInput($def, $v['params'], $kp, $ctx, $v['timestamp'], $block);
    if (in_array($def['custom'] ?? null, ['multisig', 'settle'], true)) { [$body] = Custom::body($input); }
    else {
        $bc = new BodyContext($kp, array_map('hex2bin', $v['files'] ?? []));
        Custom::computeFields($input, $bc);
        $body = Body::build($def, $v['params'], $bc);
    }
    checkSigned($v, $body);
}
check('transaction id', Transaction::id(hex2bin('4ac2d11be8fe534bf2b2776fa7c1a3ece08e17f3b71e8d796545f5edde8b86fa')) === 5427962248764179018);

// CLI: offline reproduces every vector
foreach (array_merge($load('transactions.json')['vectors'], $load('transactions-all.json')['vectors']) as $v) {
    $def = Spec::command($v['command']);
    if ($def['needs_node'] || array_filter($def['params'], fn($p) => $p['kind'] === 'file')) { continue; }
    $p = $v['params']; $args = [$def['command'], $v['key']];
    foreach (array_slice($def['params'], 1) as $pd) { if ($def['command'] === 'liquid-payment' && $pd['name'] === 'token_id') { continue; } $args[] = $p[$pd['name']] ?? $pd['default'] ?? ''; }
    array_push($args, '--fee', (string) $v['fee'], '--timestamp', (string) $v['timestamp'], '--genesis', $v['genesis'], '--offline');
    if (isset($v['message'])) { array_push($args, '--message', $v['message']); }
    if (isset($v['escrow'])) {
        $e = $v['escrow']; array_push($args, '--escrow-approver', $e['approver'], '--escrow-commission', (string) $e['commission'], '--escrow-timeout', (string) $e['timeout']);
        if (($e['instruction'] ?? '') !== '') { array_push($args, '--escrow-instruction', $e['instruction']); }
    }
    if ($def['command'] === 'liquid-payment' && ($p['token_id'] ?? '0') !== '0') { array_push($args, '--token', $p['token_id']); }
    [$code, $out, $err] = cli($args);
    $j = json_decode($out, true) ?? [];
    check("cli offline {$v['name']}", $code === 0 && ($j['transaction_hash'] ?? '') === $v['expected']['transaction_hash'] && ($j['unsigned_bytes'] ?? '') === $v['expected']['unsigned_bytes']
        && canonical($j['payload'] ?? null) === canonical($v['expected']['payload']), "exit $code $out$err");
}
// CLI: exit codes
foreach ($load('cli.json')['vectors'] as $c) {
    [$code, $out, $err] = cli($c['args'], $c['stdin'] ?? '');
    $j = json_decode($out, true) ?? [];
    check("cli exit: {$c['case']}", $code === $c['exit_code'] && (!isset($c['error_class']) || ($j['error_class'] ?? null) === $c['error_class']), "exit $code $out$err");
}
// CLI: messages
foreach ($m['vectors'] as $v) {
    $msg = $v['hex_input'] ? $v['message_hex'] : $v['message']; $flag = $v['hex_input'] ? ['--hex'] : [];
    [$code, $out] = cli(array_merge(['sign-message', $v['seed'], $msg], $flag));
    check("cli sign-message {$v['seed']}", $code === 0 && (json_decode($out, true)['signature'] ?? '') === $v['signature']);
    [$code2, $out2] = cli(array_merge(['verify-message', $v['address'], $msg, $v['signature']], $flag));
    check("cli verify-message {$v['seed']}", $code2 === 0 && (json_decode($out2, true)['valid'] ?? false) === true);
}
foreach ($m['invalid'] as $n) { [$code] = cli(['verify-message', $n['address'], $n['message'], $n['signature']]); check("cli invalid message: {$n['case']}", $code === $n['exit_code'], "exit $code"); }
// CLI: json input and ZBC_KEY
$v = $load('transactions.json')['vectors'][0]; $p = $v['params'];
[$code, $out, $err] = cli(['send-zbc', '--json-input', '--genesis', $v['genesis']], json_encode(['sender_privkey' => $v['key'], 'recipient' => $p['recipient'], 'amount' => $p['amount'], 'fee' => $v['fee'], 'timestamp' => $v['timestamp'], 'offline' => true]));
check('cli json-input', $code === 0 && (json_decode($out, true)['transaction_hash'] ?? '') === $v['expected']['transaction_hash'], "$out$err");
foreach ([[$p['recipient'], $p['amount']], ['-', $p['recipient'], $p['amount']]] as $args) {
    [$code, $out, $err] = cli(array_merge(['send-zbc'], $args, ['--timestamp', (string) $v['timestamp'], '--genesis', $v['genesis'], '--offline']), '', ['ZBC_KEY' => $v['key']]);
    check('cli ZBC_KEY ' . implode(' ', $args), $code === 0 && (json_decode($out, true)['transaction_hash'] ?? '') === $v['expected']['transaction_hash'], "$out$err");
}
[$code, $out] = cli(['send-zbc', $v['key'], $p['recipient'], '1', '--api', 'http://127.0.0.1:9', '--genesis', 'v1', '--timeout', '2']);
check('cli unreachable node', $code === 3 && (json_decode($out, true)['error_class'] ?? '') === 'node_unreachable', "exit $code $out");

echo "$checks checks, $failures failures\n";
exit($failures === 0 ? 0 : 1);
