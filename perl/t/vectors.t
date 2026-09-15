# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
# Every file in spec/vectors, run through the library and in-process through zbc-cli.  prove -l t  (from perl/)
use strict; use warnings;
use Test::More;
use FindBin;
use JSON::PP;
use lib "$FindBin::Bin/../lib";
use ZBC::Address qw(parse_address);
use ZBC::Body qw(build_body);
use ZBC::CLI;
use ZBC::Commands;
use ZBC::Custom qw(compute_fields custom_body);
use ZBC::Encoding qw(from_hex to_hex);
use ZBC::Keys qw(key_pair validate_mnemonic wallet_account);
use ZBC::Message qw(sign_message verify_message);
use ZBC::Transaction qw(sign_transaction send_zbc_body approval_escrow_body transaction_id);

my $V = "$FindBin::Bin/../../spec/vectors";
my $JSON = JSON::PP->new->utf8->canonical;
my %ENV_CLEAN = map { $_ => $ENV{$_} } grep { !/^(ZBC_KEY|ZBC_API|ZBC_TIMEOUT|ZOOBC_GENESIS_HASH)$/ } keys %ENV;

sub load { my ($name) = @_; open my $fh, '<:raw', "$V/$name" or die "$V/$name: $!"; return $JSON->decode(do { local $/; <$fh> }); }
sub bytes_of { my ($s) = @_; return $s unless defined $s; utf8::encode($s) if utf8::is_utf8($s); return $s; }
sub bytes_deep { my ($h) = @_; return { map { $_ => bytes_of($h->{$_}) } keys %$h }; }

# (exit code, stdout, stderr) of zbc-cli run in-process with byte-string arguments.
sub run_cli {
    my ($args, %opt) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die $!;
    open my $efh, '>', \$err or die $!;
    my $code = ZBC::CLI::run([map { bytes_of($_) } @$args], out => $ofh, err => $efh, env => $opt{env} // \%ENV_CLEAN, stdin => bytes_of($opt{stdin}));
    close $ofh; close $efh;
    return ($code, $out, $err);
}

sub envelope {
    my ($v, $body) = @_;
    my $spec = ZBC::Commands::by_name($v->{command});
    my $sender = key_pair($v->{key});
    my $recipient = $spec->{recipient} eq 'required' ? parse_address(bytes_of($v->{params}{recipient}))->bytes : '';
    my $escrow = $v->{escrow} ? ZBC::Escrow->new(%{ bytes_deep($v->{escrow}) }) : undef;
    return sign_transaction($v->{type}, $v->{timestamp}, $sender, $recipient, $v->{fee}, $body, ZBC::SigningContext->of($v->{genesis}), $escrow, bytes_of($v->{message} // ''));
}

sub check_signed {
    my ($v, $signed) = @_;
    my $e = $v->{expected};
    is(to_hex($signed->unsigned), $e->{unsigned_bytes}, "$v->{name}: unsigned bytes");
    is(to_hex($signed->digest), $e->{digest}, "$v->{name}: digest");
    is(to_hex($signed->signature), $e->{signature}, "$v->{name}: signature");
    is(to_hex($signed->bytes), $e->{transaction_bytes}, "$v->{name}: transaction bytes");
    is(to_hex($signed->hash), $e->{transaction_hash}, "$v->{name}: transaction hash");
    is($JSON->encode(ZBC::CLI::_chars($signed->payload)), $JSON->encode($e->{payload}), "$v->{name}: payload");
}

sub body_of {
    my ($v) = @_;
    my $spec = ZBC::Commands::by_name($v->{command});
    my $sender = key_pair($v->{key});
    my $ctx = ZBC::SigningContext->of($v->{genesis});
    my $params = bytes_deep($v->{params});
    my $custom = $spec->{custom} // '';
    if ($custom eq 'multisig' || $custom eq 'settle') { my ($body) = custom_body($spec, $params, $sender, $ctx, $v->{timestamp}); return $body; }
    my %computed;
    my $ref = $v->{reference_block} ? [from_hex($v->{reference_block}{block_hash}), $v->{reference_block}{height}] : undef;
    compute_fields($spec, $params, $sender, \%computed, $ref);
    my %files = map { $_ => from_hex($v->{files}{$_}) } keys %{ $v->{files} // {} };
    return build_body($spec, $params, $sender, \%files, \%computed);
}

subtest 'keys.json: seeds and wallets' => sub {
    my $d = load('keys.json');
    for my $s (@{ $d->{seeds} }) {
        my $kp = key_pair($s->{seed});
        is(to_hex($kp->public_key), $s->{public_key}, "public key of $s->{seed}");
        is($kp->address, $s->{address}, 'address');
        is($kp->node_address, $s->{node_address}, 'node address');
    }
    for my $w (@{ $d->{wallets} }) {
        ok(validate_mnemonic($w->{mnemonic}), 'mnemonic validates');
        for my $a (@{ $w->{accounts} }) {
            my $acct = wallet_account($w->{mnemonic}, $a->{index}, $w->{passphrase});
            is_deeply([$acct->path, to_hex($acct->seed), $acct->address, $acct->node_address], [@$a{qw(path seed address node_address)}], "account $a->{index}");
        }
    }
};

subtest 'addresses.json: every recipient form' => sub {
    for my $v (@{ load('addresses.json')->{vectors} }) {
        my $p = eval { parse_address(bytes_of($v->{input}), bytes_of($v->{chain} // '')) };
        if ($v->{valid}) { ok($p, "$v->{input} parses") and is_deeply([$p->type, to_hex($p->bytes)], [$v->{account_type}, $v->{address_bytes}], "$v->{input}: type and bytes"); }
        else { ok(!$p, "$v->{input} is rejected"); }
    }
};

subtest 'messages.json: ZBC-MSG-v1' => sub {
    my $m = load('messages.json');
    for my $v (@{ $m->{vectors} }) {
        my $s = sign_message($v->{seed}, from_hex($v->{message_hex}));
        is_deeply([@$s{qw(address public_key digest signature)}], [@$v{qw(address public_key digest signature)}], "sign $v->{message_hex}");
        ok(verify_message($v->{address}, from_hex($v->{message_hex}), $v->{signature}), 'verifies');
    }
    for my $n (@{ $m->{invalid} }) { ok(!verify_message($n->{address}, bytes_of($n->{message}), $n->{signature}), "invalid: $n->{case}"); }
};

subtest 'transactions.json: SendZBC and ApprovalEscrow' => sub {
    for my $v (@{ load('transactions.json')->{vectors} }) {
        my $body = $v->{command} eq 'send-zbc' ? send_zbc_body($v->{params}{amount}) : approval_escrow_body($v->{params}{approval}, from_hex($v->{params}{transaction_hash}));
        is(to_hex($body), $v->{expected}{body}, "$v->{name}: body");
        check_signed($v, envelope($v, $body));
    }
};

subtest 'transactions-all.json: every transaction type from the spec' => sub {
    for my $v (@{ load('transactions-all.json')->{vectors} }) {
        my $body = body_of($v);
        is(to_hex($body), $v->{expected}{body}, "$v->{name}: body");
        check_signed($v, envelope($v, $body));
    }
};

subtest 'transaction id' => sub {
    is(transaction_id(from_hex('4ac2d11be8fe534bf2b2776fa7c1a3ece08e17f3b71e8d796545f5edde8b86fa')), 5427962248764179018, 'first 8 bytes, int64 LE');
};

subtest 'zbc-cli --offline reproduces every vector' => sub {
    for my $v (@{ load('transactions.json')->{vectors} }, @{ load('transactions-all.json')->{vectors} }) {
        my $spec = ZBC::Commands::by_name($v->{command});
        next if $spec->{needs_node} || grep { $_->{kind} eq 'file' } @{ $spec->{params} };
        my @args = ($v->{command}, $v->{key});
        for my $p (@{ $spec->{params} }[1 .. $#{ $spec->{params} }]) {
            next if $v->{command} eq 'liquid-payment' && $p->{name} eq 'token_id';
            push @args, $v->{params}{ $p->{name} } // $p->{default} // '';
        }
        push @args, '--fee', $v->{fee}, '--timestamp', $v->{timestamp}, '--genesis', $v->{genesis}, '--offline';
        push @args, '--message', $v->{message} if defined $v->{message} && length $v->{message};
        if (my $e = $v->{escrow}) {
            push @args, '--escrow-approver', $e->{approver}, '--escrow-commission', $e->{commission}, '--escrow-timeout', $e->{timeout};
            push @args, '--escrow-instruction', $e->{instruction} if defined $e->{instruction} && length $e->{instruction};
        }
        push @args, '--token', $v->{params}{token_id} if $v->{command} eq 'liquid-payment' && ($v->{params}{token_id} // '0') ne '0';
        my ($rc, $out, $err) = run_cli(\@args);
        is($rc, 0, "$v->{name}: exit 0") or diag "$out$err";
        my $j = eval { $JSON->decode($out) } // {};
        is($j->{transaction_hash}, $v->{expected}{transaction_hash}, "$v->{name}: transaction hash");
        is($JSON->encode($j->{payload}), $JSON->encode($v->{expected}{payload}), "$v->{name}: payload");
    }
};

subtest 'cli.json: exit codes and error classes' => sub {
    for my $c (@{ load('cli.json')->{vectors} }) {
        my ($rc, $out, $err) = run_cli($c->{args}, stdin => $c->{stdin});
        is($rc, $c->{exit_code}, "$c->{case}: exit $c->{exit_code}") or diag "$out$err";
        if (defined $c->{error_class}) { my $j = eval { $JSON->decode($out) } // {}; is($j->{error_class}, $c->{error_class}, "$c->{case}: error_class"); }
    }
};

subtest 'zbc-cli sign-message and verify-message' => sub {
    my $m = load('messages.json');
    for my $v (@{ $m->{vectors} }) {
        my @hexflag = $v->{hex_input} ? ('--hex') : ();
        my $msg = $v->{hex_input} ? $v->{message_hex} : $v->{message};
        my ($rc, $out) = run_cli(['sign-message', $v->{seed}, $msg, @hexflag]);
        is($rc, 0, 'sign-message exits 0');
        is(($JSON->decode($out))->{signature}, $v->{signature}, 'signature');
        ($rc, $out) = run_cli(['verify-message', $v->{address}, $msg, $v->{signature}, @hexflag]);
        is($rc, 0, 'verify-message exits 0');
        ok(($JSON->decode($out))->{valid}, 'valid');
    }
    for my $n (@{ $m->{invalid} }) {
        my ($rc) = run_cli(['verify-message', $n->{address}, $n->{message}, $n->{signature}]);
        is($rc, $n->{exit_code}, "invalid: $n->{case}");
    }
};

subtest 'zbc-cli --json-input and ZBC_KEY' => sub {
    my $v = load('transactions.json')->{vectors}[0];
    my $stdin = $JSON->encode({ sender_privkey => $v->{key}, recipient => $v->{params}{recipient}, amount => $v->{params}{amount}, fee => $v->{fee}, timestamp => $v->{timestamp}, offline => JSON::PP::true });
    my ($rc, $out, $err) = run_cli(['send-zbc', '--json-input', '--genesis', $v->{genesis}], stdin => $stdin);
    is($rc, 0, 'json input exits 0') or diag "$out$err";
    is(($JSON->decode($out))->{transaction_hash}, $v->{expected}{transaction_hash}, 'json input hash');
    my %env = (%ENV_CLEAN, ZBC_KEY => $v->{key});
    for my $args ([$v->{params}{recipient}, $v->{params}{amount}], ['-', $v->{params}{recipient}, $v->{params}{amount}]) {
        ($rc, $out, $err) = run_cli(['send-zbc', @$args, '--timestamp', $v->{timestamp}, '--genesis', $v->{genesis}, '--offline'], env => \%env);
        is($rc, 0, 'ZBC_KEY exits 0') or diag "$out$err";
        is(($JSON->decode($out))->{transaction_hash}, $v->{expected}{transaction_hash}, 'ZBC_KEY hash');
    }
};

done_testing;
