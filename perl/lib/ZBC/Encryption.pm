# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package ZBC::Encryption;
# Sealed transaction messages (spec/signing.md section 8): 'ZBE1' || libsodium sealed box to the recipient's
# Ed25519 key converted to X25519. X25519 (RFC 7748) on Math::BigInt, HSalsa20, XSalsa20 and Poly1305 in
# pure Perl: none of them is in core. Not constant time; keep seeds on machines you trust.
use strict; use warnings; no warnings 'portable';
use Exporter 'import';
use Digest::SHA qw(sha512);
use Math::BigInt try => 'GMP,FastCalc';
use ZBC::Blake2b ();

our @EXPORT_OK = qw(SEALED_MAGIC SEALED_OVERHEAD x25519 x25519_base ed25519_pk_to_x25519 ed25519_seed_to_x25519 hsalsa20 xsalsa20_stream
                    poly1305 secretbox secretbox_open is_sealed seal open_sealed);
our %EXPORT_TAGS = (all => \@EXPORT_OK);
use constant { SEALED_MAGIC => 'ZBE1', SEALED_OVERHEAD => 52 };

my $P = Math::BigInt->new(2)->bpow(255)->bsub(19);
my $A24 = Math::BigInt->new(121665);
my $MASK255 = Math::BigInt->new(2)->bpow(255)->bsub(1);
my $POLY_P = Math::BigInt->new(2)->bpow(130)->bsub(5);
my $POLY_RMASK = Math::BigInt->from_hex('0ffffffc0ffffffc0ffffffc0fffffff');
my $MASK128 = Math::BigInt->new(2)->bpow(128)->bsub(1);

sub _from_le { my ($b) = @_; return Math::BigInt->from_hex(unpack 'H*', scalar reverse $b); }
sub _to_le { my ($n, $len) = @_; my $h = substr($n->as_hex, 2); $h = ('0' x (2 * $len - length $h)) . $h; return scalar reverse pack 'H*', $h; }
sub _clamp { my ($k) = @_; substr($k, 0, 1) = chr(ord(substr($k, 0, 1)) & 248); substr($k, 31, 1) = chr((ord(substr($k, 31, 1)) & 127) | 64); return $k; }

# X25519(scalar, u): 32 bytes. The scalar is clamped as the RFC prescribes.
sub x25519 {
    my ($scalar, $u) = @_;
    die "X25519 takes 32-byte inputs\n" unless length($scalar) == 32 && length($u) == 32;
    my $s = _from_le(_clamp($scalar));
    my $x1 = _from_le($u)->band($MASK255);
    my ($x2, $z2, $x3, $z3, $swap) = (Math::BigInt->bone, Math::BigInt->bzero, $x1->copy, Math::BigInt->bone, 0);
    my $bits = reverse $s->as_bin =~ s/^0b//r;
    $bits .= '0' x (256 - length $bits) if length($bits) < 256;
    for my $t (reverse 0 .. 254) {
        my $kt = 0 + substr($bits, $t, 1);
        $swap ^= $kt;
        if ($swap) { ($x2, $x3) = ($x3, $x2); ($z2, $z3) = ($z3, $z2); }
        $swap = $kt;
        my $a = $x2->copy->badd($z2)->bmod($P);  my $aa = $a->copy->bmul($a)->bmod($P);
        my $b = $x2->copy->bsub($z2)->bmod($P);  my $bb = $b->copy->bmul($b)->bmod($P);
        my $e = $aa->copy->bsub($bb)->bmod($P);
        my $c = $x3->copy->badd($z3)->bmod($P);  my $d = $x3->copy->bsub($z3)->bmod($P);
        my $da = $d->copy->bmul($a)->bmod($P);   my $cb = $c->copy->bmul($b)->bmod($P);
        my $t1 = $da->copy->badd($cb)->bmod($P); $x3 = $t1->copy->bmul($t1)->bmod($P);
        my $t2 = $da->copy->bsub($cb)->bmod($P); $z3 = $x1->copy->bmul($t2->copy->bmul($t2))->bmod($P);
        $x2 = $aa->copy->bmul($bb)->bmod($P);
        $z2 = $e->copy->bmul($aa->copy->badd($A24->copy->bmul($e)))->bmod($P);
    }
    if ($swap) { ($x2, $x3) = ($x3, $x2); ($z2, $z3) = ($z3, $z2); }
    return _to_le($x2->copy->bmul($z2->copy->bmodinv($P))->bmod($P), 32);
}

# The X25519 public key of a scalar: X25519(scalar, 9).
sub x25519_base { my ($scalar) = @_; return x25519($scalar, "\x09" . ("\0" x 31)); }

# Ed25519 public key -> X25519 public key of the same point: u = (1 + y) / (1 - y) mod p.
sub ed25519_pk_to_x25519 {
    my ($pk) = @_;
    die "public key must be 32 bytes\n" unless length($pk) == 32;
    my $y = _from_le($pk)->band($MASK255);
    my $den = Math::BigInt->bone->bsub($y)->bmod($P);
    die "public key has no X25519 form\n" if $den->is_zero;
    return _to_le(Math::BigInt->bone->badd($y)->bmul($den->bmodinv($P))->bmod($P), 32);
}

# Ed25519 seed -> X25519 secret key: the clamped first half of SHA-512(seed).
sub ed25519_seed_to_x25519 { my ($seed) = @_; return _clamp(substr(sha512($seed), 0, 32)); }

my @SIGMA = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574);   # "expand 32-byte k"
my @QUARTERS = ([0, 4, 8, 12], [5, 9, 13, 1], [10, 14, 2, 6], [15, 3, 7, 11], [0, 1, 2, 3], [5, 6, 7, 4], [10, 11, 8, 9], [15, 12, 13, 14]);
sub _rotl32 { my ($v, $c) = @_; return (($v << $c) | ($v >> (32 - $c))) & 0xFFFFFFFF; }
sub _rounds {
    my ($x) = @_;
    for (1 .. 10) {
        for my $q (@QUARTERS) {
            my ($a, $b, $c, $d) = @$q;
            $x->[$b] ^= _rotl32(($x->[$a] + $x->[$d]) & 0xFFFFFFFF, 7);
            $x->[$c] ^= _rotl32(($x->[$b] + $x->[$a]) & 0xFFFFFFFF, 9);
            $x->[$d] ^= _rotl32(($x->[$c] + $x->[$b]) & 0xFFFFFFFF, 13);
            $x->[$a] ^= _rotl32(($x->[$d] + $x->[$c]) & 0xFFFFFFFF, 18);
        }
    }
}
sub _state { my ($key) = @_; my @k = unpack 'V8', $key; my @x = (0) x 16; @x[0, 5, 10, 15] = @SIGMA; @x[1 .. 4] = @k[0 .. 3]; @x[11 .. 14] = @k[4 .. 7]; return \@x; }

# HSalsa20(key 32, input 16) -> 32 bytes.
sub hsalsa20 {
    my ($key, $in) = @_;
    my $x = _state($key);
    @{$x}[6 .. 9] = unpack 'V4', $in;
    _rounds($x);
    return pack 'V8', @{$x}[0, 5, 10, 15, 6, 7, 8, 9];
}

sub _block {
    my ($key, $n8, $ctr) = @_;
    my $x0 = _state($key);
    @{$x0}[6, 7] = unpack 'V2', $n8;
    $x0->[8] = $ctr & 0xFFFFFFFF; $x0->[9] = ($ctr >> 32) & 0xFFFFFFFF;
    my @x = @$x0;
    _rounds(\@x);
    return pack 'V16', map { ($x[$_] + $x0->[$_]) & 0xFFFFFFFF } 0 .. 15;
}

# The XSalsa20 keystream of a 32-byte key and a 24-byte nonce.
sub xsalsa20_stream {
    my ($key, $nonce, $len) = @_;
    my $sub = hsalsa20($key, substr($nonce, 0, 16));
    my $n8 = substr $nonce, 16, 8;
    my ($out, $c) = ('', 0);
    $out .= _block($sub, $n8, $c++) while length($out) < $len;
    return substr $out, 0, $len;
}

# Poly1305 one-time authenticator (RFC 8439 section 2.5).
sub poly1305 {
    my ($key, $msg) = @_;
    my $r = _from_le(substr $key, 0, 16)->band($POLY_RMASK);
    my $s = _from_le(substr $key, 16, 16);
    my $acc = Math::BigInt->bzero;
    for (my $i = 0; $i < length $msg; $i += 16) {
        $acc->badd(_from_le(substr($msg, $i, 16) . "\x01"))->bmul($r)->bmod($POLY_P);
    }
    return _to_le($acc->badd($s)->band($MASK128), 16);
}

# crypto_secretbox_easy: tag (16) || ciphertext.
sub secretbox {
    my ($key, $nonce, $plaintext) = @_;
    my $stream = xsalsa20_stream($key, $nonce, 32 + length $plaintext);
    my $c = $plaintext ^ substr($stream, 32);
    return poly1305(substr($stream, 0, 32), $c) . $c;
}

# crypto_secretbox_open_easy: the plaintext, or undef when the tag does not verify.
sub secretbox_open {
    my ($key, $nonce, $boxed) = @_;
    return undef if length($boxed) < 16;
    my $c = substr $boxed, 16;
    my $stream = xsalsa20_stream($key, $nonce, 32 + length $c);
    return undef if poly1305(substr($stream, 0, 32), $c) ne substr($boxed, 0, 16);
    return $c ^ substr($stream, 32);
}

sub _box_key { my ($sk, $pk) = @_; return hsalsa20(x25519($sk, $pk), "\0" x 16); }
sub _nonce { my ($epk, $rpk) = @_; return ZBC::Blake2b::blake2b($epk . $rpk, 24); }

# True when the field starts with the marker (it may still fail to open).
sub is_sealed { my ($field) = @_; return length($field) >= 4 && substr($field, 0, 4) eq SEALED_MAGIC ? 1 : 0; }

# Seal $plaintext to the recipient's 32-byte Ed25519 public key. The ephemeral secret key is random unless given (tests).
sub seal {
    my ($plaintext, $recipient_public_key, $ephemeral_secret_key) = @_;
    my $rpk = ed25519_pk_to_x25519($recipient_public_key);
    my $esk = $ephemeral_secret_key;
    unless (defined $esk) {
        open my $fh, '<:raw', '/dev/urandom' or die "cannot open /dev/urandom: $!";
        read($fh, $esk, 32) == 32 or die "short read from /dev/urandom";
        close $fh;
    }
    die "ephemeral secret key must be 32 bytes\n" unless length($esk) == 32;
    my $epk = x25519_base($esk);
    return SEALED_MAGIC . $epk . secretbox(_box_key($esk, $rpk), _nonce($epk, $rpk), $plaintext);
}

# The plaintext of a sealed field opened with the recipient's 32-byte seed, or undef when it is not a sealed message or the key does not open it.
sub open_sealed {
    my ($field, $recipient_seed) = @_;
    return undef unless is_sealed($field) && length($field) >= SEALED_OVERHEAD && length($recipient_seed) == 32;
    my $sk = ed25519_seed_to_x25519($recipient_seed);
    my $pk = x25519_base($sk);
    my $epk = substr $field, 4, 32;
    return secretbox_open(_box_key($sk, $epk), _nonce($epk, $pk), substr($field, 36));
}

1;
