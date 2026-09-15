# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package ZBC::Body;
# Parameter validation and the generic body serialiser driven by spec/transactions (encodings of index.json).
use strict; use warnings;
use Exporter 'import';
use Math::BigInt try => 'GMP,FastCalc';
use ZBC::Address qw(parse_address parse_key32);
use ZBC::Encoding qw(is_hex from_hex);
use ZBC::ExitCode qw(usage);
use ZBC::Keys qw(key_pair);
use ZBC::Transaction qw(u32 u64);

our @EXPORT_OK = qw(parse_integer split_list validate_param encode_field build_body);
our %EXPORT_TAGS = (all => \@EXPORT_OK);

my %LIMITS = (int64 => ['-9223372036854775808', '9223372036854775807'], uint64 => ['0', '18446744073709551615'],
              uint32 => ['0', '4294967295'], uint8 => ['0', '255']);

# The canonical decimal string of a whole number within the range of `kind`; dies with a usage error otherwise.
sub parse_integer {
    my ($value, $kind, $name) = @_;
    (my $s = $value // '') =~ s/^\s+|\s+$//g;
    die usage(sprintf '%s must be a whole number, got "%s"', $name, $value // '') unless $s =~ /^-?\d+$/;
    my $n = Math::BigInt->new($s);
    my $lim = $LIMITS{$kind} // $LIMITS{int64};
    die usage("$name is out of range for $kind") if $n->bcmp($lim->[0]) < 0 || $n->bcmp($lim->[1]) > 0;
    return $n->bstr;
}

sub split_list { my ($s) = @_; return grep { length } map { s/^\s+|\s+$//gr } split /,/, $s // ''; }

sub _strip { my ($e) = @_; $e = "$e"; $e =~ s/ at \S+ line \d+\.?\n?$//s; chomp $e; return $e; }

# Check one parameter value against its kind (spec/transactions/index.json param_kinds); returns the value to keep.
sub validate_param {
    my ($p, $value) = @_;
    my ($kind, $name) = ($p->{kind}, $p->{name});
    if ($kind eq 'privkey') {
        die usage("$name must be 64 hex characters (a 32-byte private key)") unless is_hex($value, 64);
    } elsif ($kind eq 'address') {
        eval { parse_address($value); 1 } or die usage("invalid $name: " . _strip($@));
    } elsif ($kind eq 'address_list') {
        for my $a (split_list($value)) { eval { parse_address($a); 1 } or die usage("invalid $name entry $a: " . _strip($@)); }
    } elsif ($kind eq 'key') {
        eval { parse_key32($value); 1 } or die usage("invalid $name: " . _strip($@));
    } elsif (exists $LIMITS{$kind}) {
        my $n = Math::BigInt->new(parse_integer($value, $kind, $name));
        if ((defined $p->{min} && $n->bcmp($p->{min}) < 0) || (defined $p->{max} && $n->bcmp($p->{max}) > 0)) {
            die usage(sprintf '%s must be between %s and %s', $name, $p->{min} // '-inf', $p->{max} // 'inf');
        }
        return $value =~ s/^\s+|\s+$//gr;
    } elsif ($kind eq 'hex32') {
        die usage("$name must be 64 hex characters (32 bytes)") unless is_hex($value, 64);
    } elsif ($kind eq 'hexbytes') {
        die usage("$name must be hex") unless is_hex($value);
    }
    return $value;
}

sub _holds {
    my ($when, $params) = @_;
    die "unsupported condition $when" unless $when =~ /^(\w+) != (0|'')$/;
    my $v = $params->{$1} // '';
    return $2 eq '0' ? (($v eq '' ? 0 : $v) != 0) : ($v ne '');
}

# The bytes of one body field. `files` maps file parameters to their bytes; `computed` holds what custom hooks produced.
sub encode_field {
    my ($f, $params, $sender, $files, $computed) = @_;
    return $computed->{ $f->{name} } if $computed && exists $computed->{ $f->{name} };
    my ($enc, $src) = ($f->{encoding}, $f->{from});
    my $value = $params->{$src} // '';
    if ($f->{when_zero} && ($value eq '' || ($value =~ /^-?\d+$/ && $value <= 0))) { $value = $params->{ $f->{when_zero} } // '0'; }
    return chr(parse_integer($value, 'uint8', $f->{name})) if $enc eq 'u8';
    return pack('S<', parse_integer($value, 'uint32', $f->{name})) if $enc eq 'u16le';
    return u32(parse_integer($value, 'uint32', $f->{name})) if $enc eq 'u32le';
    return u64(parse_integer($value, 'int64', $f->{name})) if $enc eq 'u64le';
    if ($enc eq 'hex') {
        my $b = from_hex($value);
        die usage(sprintf '%s must be %d bytes (%d hex)', $src, $f->{size}, 2 * $f->{size}) if defined $f->{size} && length($b) != $f->{size};
        return $b;
    }
    if ($enc eq 'hex16') { my $b = from_hex($value); return pack('S<', length $b) . $b; }
    if ($enc eq 'bytes32') { my $b = ($files && exists $files->{$src}) ? $files->{$src} : from_hex($value); return u32(length $b) . $b; }
    return pack('S<', length $value) . $value if $enc eq 'str16';
    return u32(length $value) . $value if $enc eq 'str32';
    return parse_address($value)->bytes if $enc eq 'address';
    return join('', map { parse_address($_)->bytes } split_list($value)) if $enc eq 'address_list';
    if ($enc eq 'address_list8') {
        my @items = split_list($value);
        die usage("$src: at most 255 entries") if @items > 255;
        return chr(scalar @items) . join('', map { parse_address($_)->bytes } @items);
    }
    return $sender->account_bytes if $enc eq 'sender_address';
    if ($enc eq 'pubkey_of_key') {
        die usage("$src must be 64 hex characters (a 32-byte private key)") unless is_hex($value, 64);
        return key_pair($value)->public_key;
    }
    return parse_key32($value) if $enc eq 'key32';
    return from_hex($f->{value} // '') if $enc eq 'literal';
    die "field $f->{name} needs a custom hook" if $enc eq 'custom';
    die "unknown encoding $enc";
}

# The whole body of a non-custom transaction.
sub build_body {
    my ($spec, $params, $sender, $files, $computed) = @_;
    my $out = '';
    for my $f (@{ $spec->{body} }) {
        next if $f->{when} && !_holds($f->{when}, $params);
        $out .= encode_field($f, $params, $sender, $files, $computed);
    }
    return $out;
}

1;
