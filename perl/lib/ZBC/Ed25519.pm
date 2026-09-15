# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package ZBC::Ed25519;
# Ed25519 (RFC 8032) on Math::BigInt: public key from a 32-byte seed, deterministic detached
# signatures, verification. Math::BigInt is not constant time; keep seeds on machines you trust.
use strict; use warnings;
use Math::BigInt try => 'GMP,FastCalc';
use Digest::SHA qw(sha512);

my $P = Math::BigInt->new(2)->bpow(255)->bsub(19);
my $L = Math::BigInt->new(2)->bpow(252)->badd('27742317777372353535851937790883648493');
my $D = Math::BigInt->new(-121665)->bmul(Math::BigInt->new(121666)->bmodinv($P))->bmod($P);
my $E4 = $P->copy->bsub(1); $E4 = scalar $E4->bdiv(4);
my $E8 = $P->copy->badd(3); $E8 = scalar $E8->bdiv(8);
my $I = Math::BigInt->new(2)->bmodpow($E4, $P);
my $ONE = Math::BigInt->bone;
my $TWO = Math::BigInt->new(2);

sub _from_le { my ($b) = @_; return Math::BigInt->from_hex(unpack 'H*', scalar reverse $b); }
sub _to_le { my ($n, $len) = @_; my $h = substr($n->as_hex, 2); $h = ('0' x (2 * $len - length $h)) . $h; return scalar reverse pack 'H*', $h; }

sub _recover_x {
    my ($y, $sign) = @_;
    my $y2 = $y->copy->bmul($y)->bmod($P);
    my $u = $y2->copy->bsub(1)->bmod($P);
    my $v = $D->copy->bmul($y2)->badd(1)->bmod($P);
    my $x = $u->copy->bmul($v->copy->bmodinv($P))->bmod($P)->bmodpow($E8, $P);
    $x = $x->bmul($I)->bmod($P) if $v->copy->bmul($x)->bmul($x)->bsub($u)->bmod($P)->is_zero == 0;
    return undef if $v->copy->bmul($x)->bmul($x)->bsub($u)->bmod($P)->is_zero == 0;
    $x = $P->copy->bsub($x) if ($x->is_odd ? 1 : 0) != $sign;
    return $x;
}

my $GY = Math::BigInt->new(4)->bmul(Math::BigInt->new(5)->bmodinv($P))->bmod($P);
my $GX = _recover_x($GY, 0);
my @G = ($GX, $GY, $ONE->copy, $GX->copy->bmul($GY)->bmod($P));
my @ZERO = (Math::BigInt->bzero, $ONE->copy, $ONE->copy, Math::BigInt->bzero);

sub _add {
    my ($p, $q) = @_;
    my $a = $p->[1]->copy->bsub($p->[0])->bmul($q->[1]->copy->bsub($q->[0]))->bmod($P);
    my $b = $p->[1]->copy->badd($p->[0])->bmul($q->[1]->copy->badd($q->[0]))->bmod($P);
    my $c = $TWO->copy->bmul($p->[3])->bmul($q->[3])->bmul($D)->bmod($P);
    my $d = $TWO->copy->bmul($p->[2])->bmul($q->[2])->bmod($P);
    my ($e, $f, $g, $h) = ($b->copy->bsub($a), $d->copy->bsub($c), $d->copy->badd($c), $b->copy->badd($a));
    return [$e->copy->bmul($f)->bmod($P), $g->copy->bmul($h)->bmod($P), $f->copy->bmul($g)->bmod($P), $e->copy->bmul($h)->bmod($P)];
}

sub _bits { my ($s) = @_; my $bin = reverse $s->as_bin =~ s/^0b//r; $bin .= '0' x (256 - length $bin) if length($bin) < 256; return $bin; }

# Scalar multiplication of any point: double-and-add over the 256 bits of the scalar.
sub _mul {
    my ($p, $s) = @_;
    my $r = [@ZERO]; my $q = $p;
    my $bin = _bits($s);
    for my $i (0 .. 255) {
        $r = _add($r, $q) if substr($bin, $i, 1) eq '1';
        $q = _add($q, $q);
    }
    return $r;
}

# Multiplication of the base point: the doublings G, 2G, 4G, ... are computed once per process.
my @G_POW;
sub _mul_base {
    my ($s) = @_;
    unless (@G_POW) { my $q = \@G; for (0 .. 255) { push @G_POW, $q; $q = _add($q, $q); } }
    my $r = [@ZERO];
    my $bin = _bits($s);
    for my $i (0 .. 255) { $r = _add($r, $G_POW[$i]) if substr($bin, $i, 1) eq '1'; }
    return $r;
}

sub _encode {
    my ($p) = @_;
    my $zi = $p->[2]->copy->bmodinv($P);
    my $x = $p->[0]->copy->bmul($zi)->bmod($P); my $y = $p->[1]->copy->bmul($zi)->bmod($P);
    my $out = _to_le($y, 32);
    substr($out, 31) = chr(ord(substr($out, 31)) | 0x80) if $x->is_odd;
    return $out;
}

sub _decode {
    my ($b) = @_;
    return undef unless length($b) == 32;
    my $raw = _from_le($b);
    my $sign = (ord(substr($b, 31)) & 0x80) ? 1 : 0;
    my $y = $raw->copy->band(Math::BigInt->new(2)->bpow(255)->bsub(1));
    return undef if $y->bcmp($P) >= 0;
    my $x = _recover_x($y, $sign);
    return undef unless defined $x;
    return undef if $x->is_zero && $sign == 1;
    return [$x, $y, $ONE->copy, $x->copy->bmul($y)->bmod($P)];
}

sub _clamp {
    my ($h) = @_;
    my $k = substr($h, 0, 32);
    substr($k, 0, 1) = chr(ord(substr($k, 0, 1)) & 248);
    substr($k, 31, 1) = chr((ord(substr($k, 31, 1)) & 127) | 64);
    return _from_le($k);
}

# The 32-byte public key of a 32-byte seed (remembered per seed for the life of the process).
my %PUBLIC;
sub public_key {
    my ($seed) = @_;
    die "seed must be 32 bytes\n" unless length($seed) == 32;
    return $PUBLIC{$seed} //= _encode(_mul_base(_clamp(sha512($seed))));
}

# Detached 64-byte signature of the message with the 32-byte seed.
sub sign {
    my ($message, $seed) = @_;
    die "seed must be 32 bytes\n" unless length($seed) == 32;
    my $h = sha512($seed);
    my $a = _clamp($h);
    my $prefix = substr($h, 32);
    my $pub = public_key($seed);
    my $r = _from_le(sha512($prefix . $message))->bmod($L);
    my $R = _encode(_mul_base($r));
    my $k = _from_le(sha512($R . $pub . $message))->bmod($L);
    my $s = $r->copy->badd($k->copy->bmul($a))->bmod($L);
    return $R . _to_le($s, 32);
}

# True when the signature verifies; never dies.
sub verify {
    my ($message, $signature, $pub) = @_;
    return 0 unless length($signature) == 64 && length($pub) == 32;
    my $A = _decode($pub) or return 0;
    my $R = _decode(substr($signature, 0, 32)) or return 0;
    my $s = _from_le(substr($signature, 32));
    return 0 if $s->bcmp($L) >= 0;
    my $k = _from_le(sha512(substr($signature, 0, 32) . $pub . $message))->bmod($L);
    return _encode(_mul_base($s)) eq _encode(_add($R, _mul($A, $k))) ? 1 : 0;
}

1;
