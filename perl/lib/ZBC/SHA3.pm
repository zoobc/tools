# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package ZBC::SHA3;
# SHA3-256 (FIPS 202): Keccak-f[1600] on 64-bit unsigned integers (a 64-bit perl is required).
use strict; use warnings; no warnings "portable";

my @RC = map { hex } qw(0000000000000001 0000000000008082 800000000000808a 8000000080008000 000000000000808b 0000000080000001
    8000000080008081 8000000000008009 000000000000008a 0000000000000088 0000000080008009 000000008000000a
    000000008000808b 800000000000008b 8000000000008089 8000000000008003 8000000000008002 8000000000000080
    000000000000800a 800000008000000a 8000000080008081 8000000000008080 0000000080000001 8000000080008008);
my @ROT = (0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14);
my $M64 = 0xFFFFFFFFFFFFFFFF;

sub _rotl { my ($x, $n) = @_; return $x if $n == 0; return (($x << $n) | ($x >> (64 - $n))) & $M64; }

sub _keccak_f {
    my ($s) = @_;
    for my $round (0 .. 23) {
        my @c = map { $s->[$_] ^ $s->[$_ + 5] ^ $s->[$_ + 10] ^ $s->[$_ + 15] ^ $s->[$_ + 20] } 0 .. 4;
        for my $x (0 .. 4) {
            my $d = $c[($x + 4) % 5] ^ _rotl($c[($x + 1) % 5], 1);
            $s->[$x + $_] ^= $d for (0, 5, 10, 15, 20);
        }
        my @b = (0) x 25;
        for my $x (0 .. 4) { for my $y (0 .. 4) { $b[$y + 5 * ((2 * $x + 3 * $y) % 5)] = _rotl($s->[$x + 5 * $y], $ROT[$x + 5 * $y]); } }
        for my $y (0, 5, 10, 15, 20) { for my $x (0 .. 4) { $s->[$x + $y] = $b[$x + $y] ^ ((~$b[($x + 1) % 5 + $y] & $M64) & $b[($x + 2) % 5 + $y]); } }
        $s->[0] ^= $RC[$round];
    }
}

# SHA3-256 of the concatenation of the arguments (byte strings).
sub sha3_256 {
    my $msg = join '', @_;
    my $rate = 136;
    my $padded = $msg . "\x06";
    $padded .= "\0" x ($rate - length($padded) % $rate) if length($padded) % $rate;
    substr($padded, -1) = chr(ord(substr($padded, -1)) | 0x80);
    my @s = (0) x 25;
    for (my $off = 0; $off < length $padded; $off += $rate) {
        my @lanes = unpack 'Q<17', substr($padded, $off, $rate);
        $s[$_] ^= $lanes[$_] for 0 .. 16;
        _keccak_f(\@s);
    }
    return pack 'Q<4', @s[0 .. 3];
}

1;
