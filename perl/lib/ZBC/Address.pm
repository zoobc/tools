# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package ZBC::Address;
# Account addresses: the ZBC_/ZNK_/ZBS_ text form and every recipient form of spec/addresses.md.
# Parsing functions die with a one-line message (no trailing newline) on invalid input.
use strict; use warnings;
use Exporter 'import';
use ZBC::SHA3 ();
use ZBC::Encoding qw(is_hex from_hex to_hex base32_encode base32_decode base58_decode base58check_decode segwit_decode
                     bech32_decode_plain ss58_decode RIPPLE_ALPHABET);

our @EXPORT_OK = qw(zbc_significant ZOOBC BITCOIN EMPTY ESTONIA_EID ETHEREUM BITCOIN_P2PKH BITCOIN_P2SH BITCOIN_P2WPKH BITCOIN_P2WSH BITCOIN_TAPROOT
                    DATASET SOLANA POLKADOT CARDANO RIPPLE TRON TEZOS account_type_name payload_length typed_address
                    encode_zbc_address decode_zbc_address parse_address parse_key32);
our %EXPORT_TAGS = (all => \@EXPORT_OK);

use constant { ZOOBC => 0, BITCOIN => 1, EMPTY => 2, ESTONIA_EID => 3, ETHEREUM => 4, BITCOIN_P2PKH => 5, BITCOIN_P2SH => 6,
               BITCOIN_P2WPKH => 7, BITCOIN_P2WSH => 8, BITCOIN_TAPROOT => 9, DATASET => 10, SOLANA => 11, POLKADOT => 12,
               CARDANO => 13, RIPPLE => 14, TRON => 15, TEZOS => 16 };

my %TYPE_NAMES = (0 => 'ZooBC', 1 => 'Bitcoin', 3 => 'Estonia eID', 4 => 'Ethereum', 5 => 'Bitcoin P2PKH', 6 => 'Bitcoin P2SH',
                  7 => 'Bitcoin P2WPKH', 8 => 'Bitcoin P2WSH', 9 => 'Bitcoin Taproot', 10 => 'DataSet', 11 => 'Solana',
                  12 => 'Polkadot', 13 => 'Cardano', 14 => 'Ripple', 15 => 'Tron', 16 => 'Tezos');
my %CHAINS = (zbc => 'zbc', zoobc => 'zbc', btc => 'btc', bitcoin => 'btc', eth => 'eth', ethereum => 'eth', evm => 'eth',
              sol => 'sol', solana => 'sol', dot => 'dot', polkadot => 'dot', substrate => 'dot', ada => 'ada', cardano => 'ada',
              xrp => 'xrp', ripple => 'xrp', trx => 'trx', tron => 'trx', xtz => 'xtz', tezos => 'xtz', zbs => 'zbs', dataset => 'zbs');

sub account_type_name { my ($t) = @_; return $TYPE_NAMES{$t} // "type $t"; }

# Payload length by account type, as the node parses an envelope.
sub payload_length { my ($t) = @_; return 20 if grep { $t == $_ } (1, 4, 5, 6, 7, 14, 15, 16); return $t == 13 ? 28 : 32; }

sub typed_address { my ($t, $payload) = @_; return pack('l<', $t) . $payload; }

# PREFIX_ + base32(payload || SHA3-256(payload || prefix)[0..2]) in seven groups of eight.
sub encode_zbc_address {
    my ($payload, $prefix) = @_;
    $prefix //= 'ZBC';
    die "address payload must be 32 bytes and the prefix 3 characters" unless length($payload) == 32 && length($prefix) == 3;
    my $check = substr ZBC::SHA3::sha3_256($payload . $prefix), 0, 3;
    my $b32 = base32_encode($payload . $check);
    return $prefix . join '', map { '_' . substr($b32, 8 * $_, 8) } 0 .. 6;
}

# The 59 significant characters of a ZooBC address: separators (_ -) and whitespace dropped, upper case (addresses.md 2).
sub zbc_significant { my ($text) = @_; (my $n = $text // '') =~ s/[-_\s]//g; return uc $n; }

# (upper-case prefix, 32-byte payload) of a ZooBC address in any spelling, or an empty list.
sub decode_zbc_address {
    my ($text) = @_;
    my $norm = zbc_significant($text);
    return () if length($norm) < 3;
    my $prefix = substr $norm, 0, 3;
    my $body = substr $norm, 3;
    return () if length($body) != 56;
    my $raw = base32_decode($body);
    return () unless defined $raw && length($raw) == 35;
    my $payload = substr $raw, 0, 32;
    return () if substr(ZBC::SHA3::sha3_256($payload . $prefix), 0, 3) ne substr($raw, 32);
    return ($prefix, $payload);
}

package ZBC::Address::Parsed;
# What parse_address returns: type, payload, display (the text as given, or the ZBC_ form of a raw key).
sub new { my ($class, $type, $payload, $display) = @_; return bless { type => $type, payload => $payload, display => $display }, $class; }
sub type      { $_[0]->{type} }
sub payload   { $_[0]->{payload} }
sub display   { $_[0]->{display} }
sub bytes     { ZBC::Address::typed_address($_[0]->{type}, $_[0]->{payload}) }
sub type_name { ZBC::Address::account_type_name($_[0]->{type}) }

package ZBC::Address;

# Shape only: PREFIX then a separator, or the bare form: 59 significant characters, ZBC/ZBS prefix, base32 body.
sub _looks_zbc {
    my ($a) = @_;
    return 1 if length($a) > 4 && substr($a, 3, 1) =~ /[_-]/;
    my $n = zbc_significant($a);
    return (length($n) == 59 && $n =~ /^(?:ZBC|ZBS)[A-Z2-7]{56}$/) ? 1 : 0;
}

sub _zbc_form {
    my ($a) = @_;
    my ($prefix, $payload) = decode_zbc_address($a);
    die "invalid ZooBC address checksum" unless defined $prefix;
    return ZBC::Address::Parsed->new($prefix eq 'ZBS' ? DATASET : ZOOBC, $payload, $a);
}

sub _hinted {
    my ($a, $hint) = @_;
    if ($hint eq 'eth') {
        my $h = substr($a, 0, 2) =~ /^0[xX]$/ ? substr($a, 2) : $a;
        die "not a 20-byte Ethereum address" unless is_hex($h, 40);
        return ZBC::Address::Parsed->new(ETHEREUM, from_hex($h), $a);
    }
    if ($hint eq 'sol') {
        my $d = base58_decode($a);
        die "not a 32-byte Solana address" unless defined $d && length($d) == 32;
        return ZBC::Address::Parsed->new(SOLANA, $d, $a);
    }
    if ($hint eq 'dot') {
        my ($prefix, $id) = ss58_decode($a);
        die "not a valid SS58 address" unless defined $id;
        return ZBC::Address::Parsed->new(POLKADOT, $id, $a);
    }
    return _zbc_form($a) if $hint eq 'zbc' || $hint eq 'zbs';
    return _auto($a);
}

sub _auto {
    my ($a) = @_;
    if (length($a) == 42 && substr($a, 0, 2) =~ /^0[xX]$/ && is_hex(substr($a, 2), 40)) {
        return ZBC::Address::Parsed->new(ETHEREUM, from_hex(substr $a, 2), $a);
    }
    return _zbc_form($a) if _looks_zbc($a);
    my $low5 = lc substr $a, 0, 5;
    if ($low5 =~ /^(bc1|tb1|bcrt1)/) {
        my ($hrp, $version, $prog) = segwit_decode($a);
        die "invalid Bitcoin bech32 address" unless defined $hrp;
        return ZBC::Address::Parsed->new(BITCOIN_P2WPKH, $prog, $a) if $version == 0 && length($prog) == 20;
        return ZBC::Address::Parsed->new(BITCOIN_P2WSH, $prog, $a) if $version == 0 && length($prog) == 32;
        return ZBC::Address::Parsed->new(BITCOIN_TAPROOT, $prog, $a) if $version == 1 && length($prog) == 32;
        die "unsupported Bitcoin witness program";
    }
    if (substr($a, 0, 1) =~ /[13]/ && length($a) >= 26 && length($a) <= 35) {
        my $raw = base58_decode($a);
        if (defined $raw && length($raw) == 25) {
            my $body = base58check_decode($a);
            if (defined $body && length($body) == 21) {
                my $v = ord substr $body, 0, 1;
                return ZBC::Address::Parsed->new(BITCOIN_P2PKH, substr($body, 1), $a) if $v == 0x00;
                return ZBC::Address::Parsed->new(BITCOIN_P2SH, substr($body, 1), $a) if $v == 0x05;
            }
        }
    }
    if (length($a) > 5 && lc(substr $a, 0, 5) eq 'addr1') {
        my ($hrp, $data) = bech32_decode_plain($a);
        if (defined $hrp && $hrp eq 'addr' && length($data) == 29 && ord(substr $data, 0, 1) == 0x61) {
            return ZBC::Address::Parsed->new(CARDANO, substr($data, 1), $a);
        }
        die "invalid Cardano address (expected a mainnet enterprise addr1… address)";
    }
    if (substr($a, 0, 1) eq 'T' && length($a) == 34) {
        my $body = base58check_decode($a);
        return ZBC::Address::Parsed->new(TRON, substr($body, 1), $a) if defined $body && length($body) == 21 && ord(substr $body, 0, 1) == 0x41;
        die "invalid Tron address";
    }
    if (substr($a, 0, 1) eq 'r' && length($a) >= 25 && length($a) <= 35) {
        my $body = base58check_decode($a, RIPPLE_ALPHABET);
        return ZBC::Address::Parsed->new(RIPPLE, substr($body, 1), $a) if defined $body && length($body) == 21 && ord(substr $body, 0, 1) == 0x00;
        die "invalid Ripple address";
    }
    if (substr($a, 0, 3) eq 'tz1') {
        my $body = base58check_decode($a);
        return ZBC::Address::Parsed->new(TEZOS, substr($body, 3), $a) if defined $body && length($body) == 23 && substr($body, 0, 3) eq "\x06\xa1\x9f";
        die "invalid Tezos address";
    }
    my ($prefix, $id) = ss58_decode($a);
    return ZBC::Address::Parsed->new(POLKADOT, $id, $a) if defined $id && length($id) == 32;
    if (length($a) >= 32 && length($a) <= 44) {
        my $d = base58_decode($a);
        return ZBC::Address::Parsed->new(SOLANA, $d, $a) if defined $d && length($d) == 32;
    }
    if (is_hex($a, 64)) {
        my $key = from_hex($a);
        return ZBC::Address::Parsed->new(ZOOBC, $key, encode_zbc_address($key, 'ZBC'));
    }
    die "unrecognised address. Supported: ZooBC (ZBC_/ZBS_), Bitcoin, Ethereum, Solana, Polkadot, Cardano, Ripple, Tron, Tezos";
}

# Read a recipient in the order of spec/addresses.md section 3; `chain` forces one reading (--chain).
sub parse_address {
    my ($text, $chain) = @_;
    (my $a = $text // '') =~ s/^\s+|\s+$//g;
    die "empty address" if $a eq '';
    if (defined $chain && $chain ne '') {
        my $hint = $CHAINS{lc $chain};
        die "unknown chain $chain" unless defined $hint;
        my $parsed = eval { _hinted($a, $hint) };
        return $parsed if $parsed;
        my $err = $@;
        my $up = uc $a;
        my $plain = (length($a) == 42 && substr($a, 0, 2) =~ /^0[xX]$/) || $up =~ /^(ZBC|ZNK|ZBS)/ || substr($a, 0, 1) =~ /[13]/
                 || lc(substr $a, 0, 5) =~ /^(bc1|tb1|bcrt1)/ || length($a) == 64;
        die $err unless $plain;
        return _auto($a);
    }
    return _auto($a);
}

# A registry key parameter: 64 hex (optionally 0x) or a ZNK_/ZBG_/ZBR_/ZBC_ text address; 32 bytes.
sub parse_key32 {
    my ($text) = @_;
    if (length($text) == 66 && substr($text, 3, 1) eq '_') {
        my ($prefix, $payload) = decode_zbc_address($text);
        die "invalid address checksum" unless defined $prefix;
        return $payload;
    }
    my $h = substr($text, 0, 2) =~ /^0[xX]$/ ? substr($text, 2) : $text;
    die "key must be a 64-hex string or a ZNK_/ZBG_/ZBR_ address" unless is_hex($h, 64);
    return from_hex($h);
}

1;
