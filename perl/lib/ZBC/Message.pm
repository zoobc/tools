# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package ZBC::Message;
# ZBC-MSG-v2 message signing (spec/signing.md section 5a): the digest binds the message to one chain,
#   digest = SHA3-256('ZBC-MSG-v2' || genesis_hash (32) || message), signature = Ed25519(seed, digest).
# ZBC-MSG-v1 (section 5, SHA3-256('ZBC-MSG' || message)) is still verified until V1_SUNSET, never produced.
use strict; use warnings;
use Exporter 'import';
use ZBC::SHA3 ();
use ZBC::Ed25519 ();
use ZBC::Address qw(decode_zbc_address);
use ZBC::Encoding qw(is_hex from_hex to_hex);
use ZBC::Keys qw(key_pair);

our @EXPORT_OK = qw(SCHEME SCHEME_V1 V1_SUNSET message_digest message_digest_v2 sign_message public_key_of_address verify_message);
our %EXPORT_TAGS = (all => \@EXPORT_OK);
use constant SCHEME    => 'ZBC-MSG-v2';
use constant SCHEME_V1 => 'ZBC-MSG-v1';
use constant V1_SUNSET => 1796083200;    # 2026-12-01T00:00:00Z: v1 signatures are refused from here on

# The legacy v1 digest.
sub message_digest { my ($message) = @_; return ZBC::SHA3::sha3_256('ZBC-MSG' . $message); }

# The v2 digest; `genesis_hash` is the chain's genesis block hash, 32 raw bytes.
sub message_digest_v2 {
    my ($message, $genesis_hash) = @_;
    die "ZBC-MSG-v2 needs the chain's genesis hash (32 bytes)" unless defined $genesis_hash && length($genesis_hash) == 32;
    return ZBC::SHA3::sha3_256('ZBC-MSG-v2' . $genesis_hash . $message);
}

# A hash with scheme, genesis_hash, address, public_key, message_hex, digest and signature (hex).
sub sign_message {
    my ($seed, $message, $genesis_hash) = @_;
    my $kp = key_pair($seed);
    my $digest = message_digest_v2($message, $genesis_hash);
    return { scheme => SCHEME, genesis_hash => to_hex($genesis_hash), address => $kp->address, public_key => to_hex($kp->public_key),
             message_hex => to_hex($message), digest => to_hex($digest), signature => to_hex(ZBC::Ed25519::sign($digest, $kp->seed)) };
}

# The public key behind a ZBC_ address or 64 hex, or undef.
sub public_key_of_address {
    my ($address) = @_;
    return from_hex($address) if is_hex($address, 64);
    my ($prefix, $payload) = decode_zbc_address($address);
    return defined $prefix && $prefix eq 'ZBC' ? $payload : undef;
}

# The scheme the signature (64 bytes or 128 hex) verifies under: 'ZBC-MSG-v2' when `genesis_hash` (32 bytes) is given
# and the v2 digest verifies, else 'ZBC-MSG-v1' while `now` (default: the clock) is before V1_SUNSET; 0 for anything
# else, never dies.
sub verify_message {
    my ($address, $message, $signature, $genesis_hash, $now) = @_;
    my $pub = public_key_of_address($address);
    return 0 unless defined $pub;
    if (length($signature) != 64) {
        return 0 unless is_hex($signature, 128);
        $signature = from_hex($signature);
    }
    if (defined $genesis_hash && length($genesis_hash) == 32) {
        return SCHEME if ZBC::Ed25519::verify(message_digest_v2($message, $genesis_hash), $signature, $pub);
    }
    $now = time unless defined $now;
    return SCHEME_V1 if $now < V1_SUNSET && ZBC::Ed25519::verify(message_digest($message), $signature, $pub);
    return 0;
}

1;
