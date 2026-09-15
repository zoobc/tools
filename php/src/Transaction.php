<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** The envelope, chain-bound digest, signature, hash and submit payload (spec/signing.md). */
final class Transaction
{
    public const SEND_ZBC = 1, APPROVAL_ESCROW = 4;
    public const APPROVE = 0, REJECT = 1, EXPIRE = 2;

    public static function emptyAccount(): string { return Encoding::le32(Address::EMPTY); }

    /** Fields 1–11 of the envelope: what the digest covers. $recipient is typed bytes or ''. */
    public static function unsignedBytes(int $type, int $timestamp, string $sender, string $recipient, int $fee, string $body, ?Escrow $escrow = null, string $message = '', int $version = 1): string
    {
        $rec = ($recipient === '' || trim($recipient, "\0") === '') ? self::emptyAccount() : $recipient;
        return Encoding::le32($type) . chr($version & 0xff) . Encoding::le64($timestamp) . $sender . $rec . Encoding::le64($fee) . Encoding::le32(strlen($body)) . $body
            . ($escrow ? $escrow->bytes() : self::emptyAccount()) . Encoding::le32(strlen($message)) . $message;
    }

    /** SHA3-256('ZBC-TX' || genesis || unsigned) for version 2; SHA3-256(unsigned) for version 1. */
    public static function signingDigest(string $unsigned, SigningContext $ctx): string
    {
        return $ctx->version === 2 ? Encoding::sha3('ZBC-TX', $ctx->genesisHash, $unsigned) : Encoding::sha3($unsigned);
    }

    public static function hash(string $unsigned, string $signature): string { return Encoding::sha3($unsigned, $signature); }

    /** The int64 id: the first 8 bytes of the hash, little-endian, signed. */
    public static function id(string $hash): int { return Encoding::readLe64($hash, 0); }

    /** Build, sign and hash a transaction for the chain of $ctx. */
    public static function sign(int $type, int $timestamp, KeyPair $sender, string $recipient, int $fee, string $body, SigningContext $ctx,
                                ?Escrow $escrow = null, string $message = '', int $version = 1): SignedTransaction
    {
        $unsigned = self::unsignedBytes($type, $timestamp, $sender->accountBytes(), $recipient, $fee, $body, $escrow, $message, $version);
        $digest = self::signingDigest($unsigned, $ctx);
        $signature = $sender->sign($digest);
        $full = $unsigned . $signature;
        if ($recipient === '') { $recipientJson = ''; }
        elseif (strlen($recipient) === 36 && substr($recipient, 0, 4) === "\0\0\0\0") { $recipientJson = bin2hex(substr($recipient, 4)); }
        else { $recipientJson = bin2hex($recipient); }
        $payload = ['version' => $version, 'timestamp' => $timestamp, 'sender_account_address' => bin2hex($sender->publicKey), 'recipient_account_address' => $recipientJson,
                    'transaction_type' => $type, 'fee' => $fee, 'transaction_body_bytes' => bin2hex($body), 'signature' => bin2hex($signature)];
        if ($message !== '') { $payload['message_hex'] = bin2hex($message); }
        if ($escrow) { $payload['escrow'] = $escrow->payload(); }
        return new SignedTransaction($unsigned, $digest, $signature, $full, Encoding::sha3($full), $payload, $ctx->version, $ctx->genesisHash);
    }

    /** The 8-byte amount. */
    public static function sendZbcBody(int $amount): string { return Encoding::le64($amount); }

    /** approval u32le then the 32-byte escrowed transaction hash. */
    public static function approvalEscrowBody(int $approval, string $escrowedHash): string
    {
        if (strlen($escrowedHash) !== 32) { throw new \InvalidArgumentException("Transaction hash must be 64 hex characters (the escrowed transaction's SHA3-256 hash)"); }
        return Encoding::le32($approval) . $escrowedHash;
    }
}
