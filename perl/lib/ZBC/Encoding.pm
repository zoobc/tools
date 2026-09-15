# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package ZBC::Encoding;
# Hex, base32 (no padding), base58 and base58check (Bitcoin and Ripple alphabets), bech32/bech32m, SS58.
use strict; use warnings;
use Exporter 'import';
use Digest::SHA qw(sha256);
use Math::BigInt try => 'GMP,FastCalc';
use ZBC::Blake2b;

our @EXPORT_OK = qw(is_hex from_hex to_hex base32_encode base32_decode base58_encode base58_decode base58check_decode
                    segwit_decode bech32_decode_plain ss58_decode BITCOIN_ALPHABET RIPPLE_ALPHABET);
our %EXPORT_TAGS = (all => \@EXPORT_OK);

use constant BITCOIN_ALPHABET => '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
use constant RIPPLE_ALPHABET  => 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';

# True for an even-length hex string (of `length` characters when given).
sub is_hex { my ($s, $len) = @_; return 0 unless defined $s && $s =~ /^[0-9a-fA-F]*$/ && length($s) % 2 == 0; return defined $len ? length($s) == $len : 1; }
sub from_hex { my ($s) = @_; return pack 'H*', $s; }
sub to_hex   { my ($b) = @_; return unpack 'H*', $b; }

my $B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
my %B32V; $B32V{substr $B32, $_, 1} = $_ for 0 .. 31;

sub base32_encode {
    my ($data) = @_;
    my $bits = unpack 'B*', $data;
    $bits .= '0' x ((5 - length($bits) % 5) % 5);
    return join '', map { substr $B32, oct("0b$_"), 1 } $bits =~ /(.{5})/g;
}

# Bytes of upper-case unpadded base32, or undef for an invalid string.
sub base32_decode {
    my ($text) = @_;
    return undef if $text =~ /[^A-Z2-7]/;
    my $bits = join '', map { sprintf '%05b', $B32V{$_} } split //, $text;
    my $rest = length($bits) % 8;
    return undef if $rest >= 5;                       # would need another character
    return undef if $rest && substr($bits, -$rest) =~ /1/;   # padding bits must be zero
    return pack 'B*', substr($bits, 0, length($bits) - $rest);
}

# Bytes of a base58 string, or undef for a bad character.
sub base58_decode {
    my ($text, $alphabet) = @_;
    $alphabet //= BITCOIN_ALPHABET;
    my $n = Math::BigInt->bzero;
    for my $c (split //, $text) {
        my $v = index $alphabet, $c;
        return undef if $v < 0;
        $n->bmul(58)->badd($v);
    }
    my $hex = $n->is_zero ? '' : substr($n->as_hex, 2);
    $hex = "0$hex" if length($hex) % 2;
    my $zero = substr $alphabet, 0, 1;
    my $zeros = 0; $zeros++ while $zeros < length($text) && substr($text, $zeros, 1) eq $zero;
    return ("\0" x $zeros) . pack('H*', $hex);
}

sub base58_encode {
    my ($data, $alphabet) = @_;
    $alphabet //= BITCOIN_ALPHABET;
    my $n = length($data) ? Math::BigInt->from_hex(unpack 'H*', $data) : Math::BigInt->bzero;
    my $out = '';
    while (!$n->is_zero) { my ($q, $r) = $n->copy->bdiv(58); $out = substr($alphabet, $r->numify, 1) . $out; $n = $q; }
    my $zeros = 0; $zeros++ while $zeros < length($data) && substr($data, $zeros, 1) eq "\0";
    return (substr($alphabet, 0, 1) x $zeros) . $out;
}

# The body of a base58check string (checksum = SHA-256d[0..3]), or undef.
sub base58check_decode {
    my ($text, $alphabet) = @_;
    my $raw = base58_decode($text, $alphabet);
    return undef unless defined $raw && length($raw) >= 5;
    my ($body, $check) = (substr($raw, 0, -4), substr($raw, -4));
    return substr(sha256(sha256($body)), 0, 4) eq $check ? $body : undef;
}

my $CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
my @GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3);

sub _polymod {
    my $chk = 1;
    for my $v (@_) {
        my $b = $chk >> 25;
        $chk = (($chk & 0x1FFFFFF) << 5) ^ $v;
        for my $i (0 .. 4) { $chk ^= $GEN[$i] if ($b >> $i) & 1; }
    }
    return $chk;
}

sub _hrp_expand { my ($hrp) = @_; return ((map { ord($_) >> 5 } split //, $hrp), 0, (map { ord($_) & 31 } split //, $hrp)); }

# (hrp, 5-bit data without the checksum, 'bech32' | 'bech32m'), or an empty list.
sub bech32_decode_raw {
    my ($text) = @_;
    return () if length($text) > 1023 || (lc($text) ne $text && uc($text) ne $text);
    my $low = lc $text;
    my $pos = rindex $low, '1';
    return () if $pos < 1 || $pos + 7 > length $low;
    my $hrp = substr $low, 0, $pos;
    my @data;
    for my $c (split //, substr($low, $pos + 1)) { my $v = index $CHARSET, $c; return () if $v < 0; push @data, $v; }
    my $pm = _polymod(_hrp_expand($hrp), @data);
    my $enc = $pm == 1 ? 'bech32' : $pm == 0x2BC830A3 ? 'bech32m' : undef;
    return () unless defined $enc;
    return ($hrp, [@data[0 .. $#data - 6]], $enc);
}

# Regroup bits; undef when the input does not fit (strict when not padding).
sub convert_bits {
    my ($data, $from, $to, $pad) = @_;
    my ($acc, $bits, @out) = (0, 0);
    my $maxv = (1 << $to) - 1;
    for my $v (@$data) {
        return undef if $v < 0 || ($v >> $from);
        $acc = ($acc << $from) | $v; $bits += $from;
        while ($bits >= $to) { $bits -= $to; push @out, ($acc >> $bits) & $maxv; }
    }
    if ($pad) { push @out, ($acc << ($to - $bits)) & $maxv if $bits; }
    elsif ($bits >= $from || (($acc << ($to - $bits)) & $maxv)) { return undef; }
    return \@out;
}

# (hrp, witness version, program bytes) of a segwit address, or an empty list.
sub segwit_decode {
    my ($text) = @_;
    my ($hrp, $data, $enc) = bech32_decode_raw($text);
    return () unless defined $hrp && @$data;
    my $version = $data->[0];
    my $prog = convert_bits([@$data[1 .. $#$data]], 5, 8, 0);
    return () unless defined $prog && @$prog >= 2 && @$prog <= 40 && $version <= 16;
    return () if $version == 0 && @$prog != 20 && @$prog != 32;
    return () if ($version == 0) != ($enc eq 'bech32');
    return ($hrp, $version, pack('C*', @$prog));
}

# (hrp, 8-bit payload) of plain bech32 (Cardano addresses), or an empty list.
sub bech32_decode_plain {
    my ($text) = @_;
    my ($hrp, $data, $enc) = bech32_decode_raw($text);
    return () unless defined $hrp && $enc eq 'bech32';
    my $b = convert_bits($data, 5, 8, 0);
    return defined $b ? ($hrp, pack('C*', @$b)) : ();
}

# (prefix, 32-byte account id) of an SS58 address, or an empty list. Checksum = BLAKE2b-512('SS58PRE' || prefix || id)[0..1].
sub ss58_decode {
    my ($text) = @_;
    my $raw = base58_decode($text);
    return () unless defined $raw;
    my @b = unpack 'C*', $raw;
    my ($plen, $prefix);
    if (@b >= 35 && $b[0] < 64) { ($plen, $prefix) = (1, $b[0]); }
    elsif (@b >= 36 && $b[0] >= 64 && $b[0] < 128) { ($plen, $prefix) = (2, (($b[0] & 0x3F) << 2) | ($b[1] >> 6) | (($b[1] & 0x3F) << 8)); }
    else { return (); }
    my $body = substr $raw, 0, -2;
    return () if length($body) - $plen != 32;
    return () if substr(ZBC::Blake2b::blake2b_512('SS58PRE' . $body), 0, 2) ne substr($raw, -2);
    return ($prefix, substr($body, $plen));
}

1;
