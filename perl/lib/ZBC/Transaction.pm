# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package ZBC::Transaction;
# The transaction envelope, escrow block, chain-bound digest, signature, hash and submit payload (spec/signing.md).
use strict; use warnings;
use Exporter 'import';
use ZBC::SHA3 ();
use ZBC::Ed25519 ();
use ZBC::Address qw(EMPTY parse_address);
use ZBC::Encoding qw(is_hex from_hex to_hex);
use ZBC::Keys qw(key_pair);

our @EXPORT_OK = qw(TX_SIGNING_TAG EMPTY_ACCOUNT SEND_ZBC APPROVAL_ESCROW APPROVE REJECT EXPIRE u32 u64 unsigned_bytes signing_digest
                    transaction_hash transaction_id sign_transaction send_zbc_body approval_escrow_body);
our %EXPORT_TAGS = (all => \@EXPORT_OK);

use constant { TX_SIGNING_TAG => 'ZBC-TX', SEND_ZBC => 1, APPROVAL_ESCROW => 4, APPROVE => 0, REJECT => 1, EXPIRE => 2 };
use constant EMPTY_ACCOUNT => pack('l<', EMPTY);

sub u32 { my ($v) = @_; return pack 'L<', $v; }
# int64 or uint64 as 8 little-endian bytes (two's complement for negatives).
sub u64 { my ($v) = @_; return "$v" =~ /^-/ ? pack('q<', $v) : pack('Q<', $v); }

package ZBC::Escrow;
sub new {
    my ($class, %f) = @_;
    return bless { approver => $f{approver}, commission => $f{commission} // 0, timeout => $f{timeout} // 0, instruction => $f{instruction} // '' }, $class;
}
sub approver    { $_[0]->{approver} }
sub commission  { $_[0]->{commission} }
sub timeout     { $_[0]->{timeout} }
sub instruction { $_[0]->{instruction} }
sub to_bytes {
    my ($self) = @_;
    my $ins = $self->{instruction};
    return ZBC::Address::parse_address($self->{approver})->bytes . ZBC::Transaction::u64($self->{commission}) . ZBC::Transaction::u64($self->{timeout})
         . ZBC::Transaction::u32(length $ins) . $ins . "\0";
}
sub to_payload {
    my ($self) = @_;
    my $d = { approver_address => ZBC::Encoding::to_hex(ZBC::Address::parse_address($self->{approver})->bytes),
              commission => 0 + $self->{commission}, timeout => 0 + $self->{timeout} };
    $d->{instruction} = $self->{instruction} if length $self->{instruction};
    return $d;
}

package ZBC::SigningContext;
sub new { my ($class, $version, $genesis_hash) = @_; return bless { version => $version, genesis_hash => $genesis_hash // '' }, $class; }
sub version      { $_[0]->{version} }
sub genesis_hash { $_[0]->{genesis_hash} }
# From 64-hex genesis (version 2), 32 raw bytes, or 'v1'/'legacy' (version 1); dies otherwise.
sub of {
    my ($class, $genesis) = @_;
    return $class->new(2, $genesis) if length($genesis) == 32 && $genesis !~ /^[0-9a-fA-F]{32}$/;
    return $class->new(1) if $genesis eq 'v1' || $genesis eq 'legacy';
    die "--genesis must be the 64-hex genesis block hash (or 'v1' for the legacy digest)" unless ZBC::Encoding::is_hex($genesis, 64);
    return $class->new(2, ZBC::Encoding::from_hex($genesis));
}

package ZBC::SignedTransaction;
sub new { my ($class, %f) = @_; return bless {%f}, $class; }
sub unsigned        { $_[0]->{unsigned} }
sub digest          { $_[0]->{digest} }
sub signature       { $_[0]->{signature} }
sub bytes           { $_[0]->{bytes} }
sub hash            { $_[0]->{hash} }
sub payload         { $_[0]->{payload} }
sub signing_version { $_[0]->{signing_version} }
sub genesis_hash    { $_[0]->{genesis_hash} }

package ZBC::Transaction;

# Fields 1-11 of the envelope: the bytes the digest covers. `recipient` is typed bytes or ''; `escrow` a ZBC::Escrow or undef.
sub unsigned_bytes {
    my ($tx_type, $timestamp, $sender, $recipient, $fee, $body, $escrow, $message, $version) = @_;
    $message //= ''; $version //= 1;
    my $out = u32($tx_type) . chr($version & 0xFF) . u64($timestamp) . $sender;
    $out .= (!defined $recipient || $recipient eq '' || $recipient !~ /[^\0]/) ? EMPTY_ACCOUNT : $recipient;
    $out .= u64($fee) . u32(length $body) . $body;
    $out .= $escrow ? $escrow->to_bytes : EMPTY_ACCOUNT;
    return $out . u32(length $message) . $message;
}

# SHA3-256('ZBC-TX' || genesis || unsigned) for version 2; SHA3-256(unsigned) for version 1.
sub signing_digest {
    my ($unsigned, $ctx) = @_;
    return ZBC::SHA3::sha3_256($ctx->version == 2 ? TX_SIGNING_TAG . $ctx->genesis_hash . $unsigned : $unsigned);
}

sub transaction_hash { my ($unsigned, $signature) = @_; return ZBC::SHA3::sha3_256($unsigned . $signature); }

# The int64 id: the first 8 bytes of the hash, little-endian, signed.
sub transaction_id { my ($hash) = @_; return unpack 'q<', substr($hash, 0, 8); }

# Build, sign and hash a transaction for the chain of `ctx`. Returns a ZBC::SignedTransaction.
sub sign_transaction {
    my ($tx_type, $timestamp, $sender, $recipient, $fee, $body, $ctx, $escrow, $message, $version) = @_;
    $recipient //= ''; $message //= ''; $version //= 1;
    my $unsigned = unsigned_bytes($tx_type, $timestamp, $sender->account_bytes, $recipient, $fee, $body, $escrow, $message, $version);
    my $digest = signing_digest($unsigned, $ctx);
    my $signature = ZBC::Ed25519::sign($digest, $sender->seed);
    my $full = $unsigned . $signature;
    my $recipient_json = $recipient eq '' ? '' : (length($recipient) == 36 && substr($recipient, 0, 4) eq "\0\0\0\0") ? to_hex(substr $recipient, 4) : to_hex($recipient);
    my $payload = { version => 0 + $version, timestamp => 0 + $timestamp, sender_account_address => to_hex($sender->public_key),
                    recipient_account_address => $recipient_json, transaction_type => 0 + $tx_type, fee => 0 + $fee,
                    transaction_body_bytes => to_hex($body), signature => to_hex($signature) };
    $payload->{message_hex} = to_hex($message) if length $message;
    $payload->{escrow} = $escrow->to_payload if $escrow;
    return ZBC::SignedTransaction->new(unsigned => $unsigned, digest => $digest, signature => $signature, bytes => $full,
                                       hash => ZBC::SHA3::sha3_256($full), payload => $payload, signing_version => $ctx->version, genesis_hash => $ctx->genesis_hash);
}

sub send_zbc_body { my ($amount) = @_; return u64($amount); }

sub approval_escrow_body {
    my ($approval, $escrowed_transaction_hash) = @_;
    die "Transaction hash must be 64 hex characters (the escrowed transaction's SHA3-256 hash)" unless length($escrowed_transaction_hash) == 32;
    return u32($approval) . $escrowed_transaction_hash;
}

1;
