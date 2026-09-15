# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package ZBC::Custom;
# The hand-written parts the descriptions mark computed or custom (spec/transactions/README.md).
use strict; use warnings;
use Exporter 'import';
use ZBC::SHA3 ();
use ZBC::Ed25519 ();
use ZBC::Address qw(parse_address);
use ZBC::Body qw(parse_integer split_list);
use ZBC::Encoding qw(is_hex from_hex to_hex);
use ZBC::ExitCode qw(usage);
use ZBC::Keys qw(key_pair);
use ZBC::Transaction qw(SEND_ZBC u32 u64 unsigned_bytes signing_digest);

our @EXPORT_OK = qw(proof_of_ownership compute_fields multisig_address custom_body);
our %EXPORT_TAGS = (all => \@EXPORT_OK);

# owner address (36) || block hash (32) || height u32le, then the owner's signature over those 72 bytes.
sub proof_of_ownership {
    my ($owner, $block_hash, $height) = @_;
    my $msg = $owner->account_bytes . $block_hash . u32($height);
    return $msg . ZBC::Ed25519::sign($msg, $owner->seed);
}

# Fill `computed` for the fields the generic serialiser cannot produce; returns a hash of extra output fields.
# `reference_block` is [hash bytes, height] from GET /api/v1/blocks/latest, for the proof of ownership.
sub compute_fields {
    my ($spec, $params, $sender, $computed, $reference_block) = @_;
    my ($cmd, %extra) = ($spec->{command});
    if ($cmd eq 'store-file') {
        my $pieces = from_hex($params->{piece_ids} // '');
        die usage("piece_ids must be a nonzero multiple of 32 bytes") if !length($pieces) || length($pieces) % 32;
        $computed->{piece_count} = u32(length($pieces) / 32);
        $extra{piece_count} = length($pieces) / 32;
    } elsif ($cmd eq 'register-node' || $cmd eq 'update-node' || $cmd eq 'claim-node') {
        die "proof of ownership needs the latest block" unless $reference_block;
        $computed->{proof_of_ownership} = proof_of_ownership($sender, $reference_block->[0], $reference_block->[1]);
        $extra{node_znk} = key_pair($params->{node_privkey})->node_address;
        $extra{owner_zbc} = $sender->address;
    } elsif ($cmd eq 'fee-vote-reveal') {
        my $info = from_hex($params->{recent_block_hash}) . u32(parse_integer($params->{recent_block_height}, 'uint32', 'recent_block_height'))
                 . u64(parse_integer($params->{fee_vote}, 'int64', 'fee_vote'));
        my $sig = ZBC::Ed25519::sign($info, $sender->seed);
        $computed->{voter_signature} = u32(length $sig) . $sig;
    } elsif ($cmd eq 'gateway-heartbeat') {
        die usage("gateway_privkey is not a valid key") unless is_hex($params->{gateway_privkey} // '', 64);
        my $gw = key_pair($params->{gateway_privkey});
        my $h = parse_integer($params->{reference_height}, 'uint32', 'reference_height');
        my $block_hash = from_hex($params->{reference_block_hash} // '');
        die usage("reference_block_hash must be 32 bytes (64 hex)") unless length($block_hash) == 32;
        $computed->{signature} = ZBC::Ed25519::sign($gw->public_key . u32($h) . $block_hash, $gw->seed);
        @extra{qw(gateway_key reference_height reference_block_hash)} = (to_hex($gw->public_key), 0 + $h, $params->{reference_block_hash});
    }
    return \%extra;
}

# SHA3-256(min u32le || nonce u64le || count u32le || sorted participant addresses).
sub multisig_address {
    my ($participants, $nonce, $min_signatures) = @_;
    my @s = sort @$participants;
    return ZBC::SHA3::sha3_256(u32($min_signatures) . u64($nonce) . u32(scalar @s) . join('', @s));
}

# (body bytes, extra output fields) of the two fully custom bodies: multisig and app-settle.
sub custom_body {
    my ($spec, $params, $sender, $ctx, $timestamp) = @_;
    return _multisig($params, $ctx, $timestamp) if $spec->{command} eq 'multisig';
    return _settle($params) if $spec->{command} eq 'app-settle';
    die "no custom body for $spec->{command}";
}

sub _multisig {
    my ($p, $ctx, $timestamp) = @_;
    my @participants = map { parse_address($_)->bytes } split_list($p->{participants});
    die usage("Need at least one participant") unless @participants;
    my $min_sigs = parse_integer($p->{min_signatures}, 'uint32', 'min_signatures');
    my $nonce = parse_integer(length($p->{nonce} // '') ? $p->{nonce} : '0', 'int64', 'nonce');
    my @signers = split_list($p->{signer_privkeys});
    die usage("Need at least one signer key") unless @signers;
    my $recipient = parse_address($p->{recipient});
    my $amount = parse_integer($p->{amount}, 'int64', 'amount');
    my $inner_fee = parse_integer(length($p->{inner_fee} // '') ? $p->{inner_fee} : '10000000', 'int64', 'inner_fee');
    my $ms_addr = multisig_address(\@participants, $nonce, $min_sigs);
    my $inner = unsigned_bytes(SEND_ZBC, $timestamp, pack('l<', 0) . $ms_addr, $recipient->bytes, $inner_fee, u64($amount));
    my $inner_hash = ZBC::SHA3::sha3_256($inner);
    my $inner_digest = signing_digest($inner, $ctx);
    my @sigs;
    for my $sk (@signers) {
        die usage("Invalid signer key") unless is_hex($sk, 64);
        my $kp = key_pair($sk);
        push @sigs, [to_hex($kp->account_bytes), ZBC::Ed25519::sign($inner_digest, $kp->seed)];
    }
    @sigs = sort { $a->[0] cmp $b->[0] } @sigs;   # the node keeps them in a map ordered by address hex
    my $body = u32(1) . u32($min_sigs) . u64($nonce) . u32(scalar @participants) . join('', @participants);
    $body .= u32(length $inner) . $inner . u32(1) . $inner_hash . u32(scalar @sigs);
    $body .= from_hex($_->[0]) . u32(length $_->[1]) . $_->[1] for @sigs;
    my %extra = (multisig_address => to_hex($ms_addr), multisig_zbc_address => parse_address(to_hex($ms_addr))->display, min_signatures => 0 + $min_sigs,
                 inner_tx_hash => to_hex($inner_hash), fund_hint => 'send ZBC to multisig_zbc_address before the signatures complete, else the inner tx stays in mempool');
    return ($body, \%extra);
}

sub _settle {
    my ($p) = @_;
    my $app_id = parse_integer($p->{app_id}, 'int64', 'app_id');
    die usage("seat keys must be 64 hex") unless is_hex($p->{p0_privkey} // '', 64) && is_hex($p->{p1_privkey} // '', 64);
    my @seats = (key_pair($p->{p0_privkey}), key_pair($p->{p1_privkey}));
    my $turn = parse_integer(length($p->{opening_turn} // '') ? $p->{opening_turn} : '0', 'uint8', 'opening_turn');
    die usage("opening_turn must be 0 or 1") unless $turn == 0 || $turn == 1;
    my @cells = map { parse_integer($_, 'uint8', 'move') } split_list($p->{moves});
    die usage("no moves given") unless @cells;
    my @state = (0) x 9;
    my $entries = '';
    for my $k (0 .. $#cells) {
        my $cell = $cells[$k];
        my $seat = ($turn + $k) % 2;
        die usage(sprintf 'illegal move at seq %d', $k + 1) if $cell > 8 || $state[$cell] != 0;
        my $move = chr $cell;
        my $digest = ZBC::SHA3::sha3_256(u64($app_id) . u32($k + 1) . ZBC::SHA3::sha3_256(pack 'C9', @state) . $move);
        $entries .= chr($seat) . pack('S<', length $move) . $move . ZBC::Ed25519::sign($digest, $seats[$seat]->seed);
        $state[$cell] = $seat + 1;
    }
    my $body = u64($app_id) . u32(scalar @cells) . u32(scalar @cells) . $entries;
    return ($body, { app_id => 0 + $app_id, opening_turn => 0 + $turn, final_seq => scalar @cells });
}

1;
