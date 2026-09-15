<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** The hand-written parts the descriptions mark computed or custom (spec/transactions/README.md). */
final class Custom
{
    /** owner (36) || block hash (32) || height u32le, then the owner's signature over those bytes. */
    public static function proofOfOwnership(KeyPair $owner, ReferenceBlock $block): string
    {
        $msg = $owner->accountBytes() . $block->hash . Encoding::le32($block->height);
        return $msg . $owner->sign($msg);
    }

    /** Fill $ctx->computed for the fields the generic serialiser cannot produce; returns extra output fields. */
    public static function computeFields(CustomInput $in, BodyContext $ctx): array
    {
        $p = $in->params; $extra = [];
        switch ($in->def['command']) {
            case 'store-file':
                $pieces = Encoding::isHex($p['piece_ids'] ?? '') ? hex2bin($p['piece_ids']) : '';
                if ($pieces === '' || strlen($pieces) % 32 !== 0) { throw ToolError::usage('piece_ids must be a nonzero multiple of 32 bytes'); }
                $ctx->computed['piece_count'] = Encoding::le32(intdiv(strlen($pieces), 32));
                $extra['piece_count'] = intdiv(strlen($pieces), 32);
                break;
            case 'register-node': case 'update-node': case 'claim-node':
                if ($in->block === null) { throw ToolError::internal('proof of ownership needs the latest block'); }
                $ctx->computed['proof_of_ownership'] = self::proofOfOwnership($in->sender, $in->block);
                $extra['node_znk'] = KeyPair::fromHex($p['node_privkey'])->nodeAddress();
                $extra['owner_zbc'] = $in->sender->address();
                break;
            case 'fee-vote-reveal':
                $info = hex2bin($p['recent_block_hash']) . Encoding::le32(Body::parseInteger($p['recent_block_height'], 'uint32', 'recent_block_height'))
                    . Encoding::le64(Body::parseInteger($p['fee_vote'], 'int64', 'fee_vote'));
                $sig = $in->sender->sign($info);
                $ctx->computed['voter_signature'] = Encoding::le32(strlen($sig)) . $sig;
                break;
            case 'gateway-heartbeat':
                try { $gw = KeyPair::fromHex($p['gateway_privkey']); } catch (\InvalidArgumentException) { throw ToolError::usage('gateway_privkey is not a valid key'); }
                $h = Body::parseInteger($p['reference_height'], 'uint32', 'reference_height');
                if (!Encoding::isHex($p['reference_block_hash'] ?? '', 64)) { throw ToolError::usage('reference_block_hash must be 32 bytes (64 hex)'); }
                $ctx->computed['signature'] = $gw->sign($gw->publicKey . Encoding::le32($h) . hex2bin($p['reference_block_hash']));
                $extra['gateway_key'] = bin2hex($gw->publicKey); $extra['reference_height'] = $h; $extra['reference_block_hash'] = $p['reference_block_hash'];
                break;
        }
        return $extra;
    }

    /** SHA3-256(min u32le || nonce u64le || count u32le || sorted participant addresses). */
    public static function multisigAddress(array $participants, int $nonce, int $minSignatures): string
    {
        $sorted = $participants; sort($sorted, SORT_STRING);
        return Encoding::sha3(Encoding::le32($minSignatures) . Encoding::le64($nonce) . Encoding::le32(count($sorted)) . implode('', $sorted));
    }

    /** The two fully custom bodies: multisig and app-settle. Returns [body, extra]. */
    public static function body(CustomInput $in): array
    {
        return match ($in->def['command']) {
            'multisig' => self::multisig($in),
            'app-settle' => self::settle($in),
            default => throw ToolError::internal("no custom body for {$in->def['command']}"),
        };
    }

    private static function multisig(CustomInput $in): array
    {
        $p = $in->params;
        $participants = [];
        foreach (Body::splitList($p['participants'] ?? '') as $a) {
            try { $participants[] = Address::parse($a)->bytes(); } catch (\InvalidArgumentException) { throw ToolError::usage("Invalid participant address: $a"); }
        }
        if ($participants === []) { throw ToolError::usage('Need at least one participant'); }
        $minSigs = Body::parseInteger($p['min_signatures'] ?? '', 'uint32', 'min_signatures');
        $nonce = Body::parseInteger(($p['nonce'] ?? '') === '' ? '0' : $p['nonce'], 'int64', 'nonce');
        $signers = Body::splitList($p['signer_privkeys'] ?? '');
        if ($signers === []) { throw ToolError::usage('Need at least one signer key'); }
        try { $recipient = Address::parse($p['recipient'] ?? ''); } catch (\InvalidArgumentException $e) { throw ToolError::usage("Invalid recipient: {$e->getMessage()}"); }
        $amount = Body::parseInteger($p['amount'] ?? '', 'int64', 'amount');
        $innerFee = Body::parseInteger(($p['inner_fee'] ?? '') === '' ? '10000000' : $p['inner_fee'], 'int64', 'inner_fee');
        $ms = self::multisigAddress($participants, $nonce, $minSigs);
        $inner = Transaction::unsignedBytes(Transaction::SEND_ZBC, $in->timestamp, Address::typed(Address::ZOOBC, $ms), $recipient->bytes(), $innerFee, Transaction::sendZbcBody($amount));
        $innerHash = Encoding::sha3($inner);
        $innerDigest = Transaction::signingDigest($inner, $in->ctx);
        $sigs = [];
        foreach ($signers as $sk) {
            try { $kp = KeyPair::fromHex($sk); } catch (\InvalidArgumentException) { throw ToolError::usage('Invalid signer key'); }
            $sigs[bin2hex($kp->accountBytes())] = $kp->sign($innerDigest);
        }
        ksort($sigs, SORT_STRING);   // the node keeps them in a map ordered by address hex
        $body = Encoding::le32(1) . Encoding::le32($minSigs) . Encoding::le64($nonce) . Encoding::le32(count($participants)) . implode('', $participants);
        $body .= Encoding::le32(strlen($inner)) . $inner . Encoding::le32(1) . $innerHash . Encoding::le32(count($sigs));
        foreach ($sigs as $addr => $sig) { $body .= hex2bin($addr) . Encoding::le32(strlen($sig)) . $sig; }
        $extra = ['multisig_address' => bin2hex($ms), 'multisig_zbc_address' => Address::encode($ms, 'ZBC'), 'min_signatures' => $minSigs,
                  'inner_tx_hash' => bin2hex($innerHash), 'fund_hint' => 'send ZBC to multisig_zbc_address before the signatures complete, else the inner tx stays in mempool'];
        return [$body, $extra];
    }

    private static function settle(CustomInput $in): array
    {
        $p = $in->params;
        $appId = Body::parseInteger($p['app_id'] ?? '', 'int64', 'app_id');
        try { $seats = [KeyPair::fromHex($p['p0_privkey'] ?? ''), KeyPair::fromHex($p['p1_privkey'] ?? '')]; } catch (\InvalidArgumentException) { throw ToolError::usage('seat keys must be 64 hex'); }
        $turn = Body::parseInteger(($p['opening_turn'] ?? '') === '' ? '0' : $p['opening_turn'], 'uint8', 'opening_turn');
        if ($turn !== 0 && $turn !== 1) { throw ToolError::usage('opening_turn must be 0 or 1'); }
        $cells = array_map(fn($c) => Body::parseInteger($c, 'uint8', 'move'), Body::splitList($p['moves'] ?? ''));
        if ($cells === []) { throw ToolError::usage('no moves given'); }
        $state = str_repeat("\0", 9); $entries = '';
        foreach ($cells as $k => $cell) {
            $seat = ($turn + $k) % 2;
            if ($cell > 8 || $state[$cell] !== "\0") { throw ToolError::usage('illegal move at seq ' . ($k + 1)); }
            $move = chr($cell);
            $digest = Encoding::sha3(Encoding::le64($appId) . Encoding::le32($k + 1) . Encoding::sha3($state) . $move);
            $entries .= chr($seat) . Encoding::le16(strlen($move)) . $move . $seats[$seat]->sign($digest);
            $state[$cell] = chr($seat + 1);
        }
        $body = Encoding::le64($appId) . Encoding::le32(count($cells)) . Encoding::le32(count($cells)) . $entries;
        return [$body, ['app_id' => $appId, 'opening_turn' => $turn, 'final_seq' => count($cells)]];
    }
}
