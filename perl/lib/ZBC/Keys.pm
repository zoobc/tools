# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package ZBC::Keys;
# Keys: seed -> key pair -> addresses; BIP-39 + SLIP-10 wallets (spec/signing.md section 1).
use strict; use warnings;
use Exporter 'import';
use Digest::SHA qw(sha256 sha512 hmac_sha512);
use ZBC::Ed25519 ();
use ZBC::Address qw(ZOOBC encode_zbc_address typed_address);
use ZBC::Encoding qw(is_hex from_hex);
use ZBC::Bip39Words;

our @EXPORT_OK = qw(key_pair random_seed validate_mnemonic mnemonic_from_entropy generate_mnemonic mnemonic_to_seed slip10_derive wallet_account);
our %EXPORT_TAGS = (all => \@EXPORT_OK);
use constant ZOOBC_COIN_TYPE => 883;

package ZBC::KeyPair;
sub new { my ($class, %f) = @_; return bless {%f}, $class; }
sub seed          { $_[0]->{seed} }
sub public_key    { $_[0]->{public_key} }
sub address       { ZBC::Address::encode_zbc_address($_[0]->{public_key}, 'ZBC') }
sub node_address  { ZBC::Address::encode_zbc_address($_[0]->{public_key}, 'ZNK') }
# 36-byte typed account address: 00000000 || public key.
sub account_bytes { ZBC::Address::typed_address(ZBC::Address::ZOOBC, $_[0]->{public_key}) }
# Wallet accounts also know their index and derivation path.
sub index { $_[0]->{index} }
sub path  { $_[0]->{path} }

package ZBC::Keys;

# From a 32-byte seed, or its 64-hex form.
sub key_pair {
    my ($seed) = @_;
    if (length($seed) != 32) {
        die "Private key must be 64 hex characters (32 bytes)" unless is_hex($seed, 64);
        $seed = from_hex($seed);
    }
    return ZBC::KeyPair->new(seed => $seed, public_key => ZBC::Ed25519::public_key($seed));
}

sub random_seed {
    open my $fh, '<:raw', '/dev/urandom' or die "cannot open /dev/urandom: $!";
    read($fh, my $seed, 32) == 32 or die "short read from /dev/urandom";
    close $fh;
    return $seed;
}

my %INDEX; $INDEX{$ZBC::Bip39Words::WORDS[$_]} = $_ for 0 .. $#ZBC::Bip39Words::WORDS;

sub validate_mnemonic {
    my ($mnemonic) = @_;
    my @words = split ' ', $mnemonic;
    return 0 unless grep { @words == $_ } (12, 15, 18, 21, 24);
    my $bits = '';
    for my $w (@words) { return 0 unless exists $INDEX{$w}; $bits .= sprintf '%011b', $INDEX{$w}; }
    my $cs = int(@words / 3);
    my $entropy = pack 'B*', substr($bits, 0, length($bits) - $cs);
    return substr($bits, -$cs) eq substr(unpack('B8', sha256($entropy)), 0, $cs) ? 1 : 0;
}

sub mnemonic_from_entropy {
    my ($entropy) = @_;
    die "entropy must be 16-32 bytes, a multiple of 4" unless grep { length($entropy) == $_ } (16, 20, 24, 28, 32);
    my $bits = unpack('B*', $entropy) . substr(unpack('B8', sha256($entropy)), 0, length($entropy) / 4);
    return join ' ', map { $ZBC::Bip39Words::WORDS[oct "0b$_"] } $bits =~ /(.{11})/g;
}

sub generate_mnemonic {
    my ($words) = @_;
    $words //= 24;
    my $n = ($words * 11 - int($words / 3)) / 8;
    open my $fh, '<:raw', '/dev/urandom' or die "cannot open /dev/urandom: $!";
    read($fh, my $entropy, $n) == $n or die "short read from /dev/urandom";
    return mnemonic_from_entropy($entropy);
}

# PBKDF2-HMAC-SHA512(mnemonic, 'mnemonic' + passphrase, 2048 rounds, 64 bytes).
sub mnemonic_to_seed {
    my ($mnemonic, $passphrase) = @_;
    my $password = join ' ', split ' ', $mnemonic;
    my $salt = 'mnemonic' . ($passphrase // '');
    my $u = hmac_sha512($salt . pack('N', 1), $password);
    my $t = $u;
    for (2 .. 2048) { $u = hmac_sha512($u, $password); $t ^= $u; }
    return $t;
}

# SLIP-10 for Ed25519 along a hardened-only path such as m/44'/883'/0'. Returns the 32-byte key.
sub slip10_derive {
    my ($path, $seed) = @_;
    die "invalid derivation path: $path" unless $path =~ /^m(\/[0-9]+')+$/;
    my $digest = hmac_sha512($seed, 'ed25519 seed');
    my ($key, $chain) = (substr($digest, 0, 32), substr($digest, 32));
    for my $seg (split /\//, substr($path, 2)) {
        my $index = 0 + substr($seg, 0, -1);
        die "path index too large" if $index >= 0x80000000;
        $digest = hmac_sha512("\0" . $key . pack('N', $index + 0x80000000), $chain);
        ($key, $chain) = (substr($digest, 0, 32), substr($digest, 32));
    }
    return $key;
}

# Account `index` of a mnemonic wallet: m/44'/883'/index'.
sub wallet_account {
    my ($mnemonic, $index, $passphrase) = @_;
    my $path = sprintf "m/44'/%d'/%d'", ZOOBC_COIN_TYPE, $index;
    my $kp = key_pair(slip10_derive($path, mnemonic_to_seed($mnemonic, $passphrase)));
    return ZBC::KeyPair->new(%$kp, index => $index, path => $path);
}

1;
