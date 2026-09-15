# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package ZBC::Message;
# ZBC-MSG-v1 message signing (spec/signing.md section 5).
use strict; use warnings;
use Exporter 'import';
use ZBC::SHA3 ();
use ZBC::Ed25519 ();
use ZBC::Address qw(decode_zbc_address);
use ZBC::Encoding qw(is_hex from_hex to_hex);
use ZBC::Keys qw(key_pair);

our @EXPORT_OK = qw(SCHEME message_digest sign_message public_key_of_address verify_message);
our %EXPORT_TAGS = (all => \@EXPORT_OK);
use constant SCHEME => 'ZBC-MSG-v1';

sub message_digest { my ($message) = @_; return ZBC::SHA3::sha3_256('ZBC-MSG' . $message); }

# A hash with scheme, address, public_key, message_hex, digest and signature (hex).
sub sign_message {
    my ($seed, $message) = @_;
    my $kp = key_pair($seed);
    my $digest = message_digest($message);
    return { scheme => SCHEME, address => $kp->address, public_key => to_hex($kp->public_key), message_hex => to_hex($message),
             digest => to_hex($digest), signature => to_hex(ZBC::Ed25519::sign($digest, $kp->seed)) };
}

# The public key behind a ZBC_ address or 64 hex, or undef.
sub public_key_of_address {
    my ($address) = @_;
    return from_hex($address) if is_hex($address, 64);
    my ($prefix, $payload) = decode_zbc_address($address);
    return defined $prefix && $prefix eq 'ZBC' ? $payload : undef;
}

# 1 when the signature (64 bytes or 128 hex) verifies; 0 for anything else, never dies.
sub verify_message {
    my ($address, $message, $signature) = @_;
    my $pub = public_key_of_address($address);
    return 0 unless defined $pub;
    if (length($signature) != 64) {
        return 0 unless is_hex($signature, 128);
        $signature = from_hex($signature);
    }
    return ZBC::Ed25519::verify(message_digest($message), $signature, $pub);
}

1;
