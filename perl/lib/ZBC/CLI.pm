# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package ZBC::CLI;
# zbc-cli: every transaction as a subcommand, plus sign-message and verify-message (spec/cli-contract.md).
# run(\@argv, %io) returns the exit code; %io may replace stdin/stdout/stderr/env so tests run it in-process.
use strict; use warnings;
use JSON::PP;
use ZBC::Address qw(parse_address);
use ZBC::Body qw(build_body validate_param parse_integer);
use ZBC::Client;
use ZBC::Commands;
use ZBC::Custom qw(compute_fields custom_body);
use ZBC::Encoding qw(is_hex from_hex to_hex);
use ZBC::Error;
use ZBC::ExitCode qw(:all);
use ZBC::Keys qw(key_pair);
use ZBC::Message qw(SCHEME message_digest public_key_of_address sign_message verify_message);
use ZBC::Transaction qw(sign_transaction transaction_id);

use constant DEFAULT_FEE => 5000000;
my %CATEGORY = (
    'send-zbc' => 'value', 'liquid-payment' => 'value', 'liquid-payment-stop' => 'value',
    'transfer-token' => 'tokens', 'issue-token' => 'tokens', 'mint-token' => 'tokens', 'burn-token' => 'tokens', 'finance-token' => 'tokens',
    'swap-create' => 'exchange', 'swap-accept' => 'exchange', 'swap-cancel' => 'exchange', 'market-create' => 'exchange', 'order-place' => 'exchange', 'order-cancel' => 'exchange',
    'app-create' => 'apps', 'app-join' => 'apps', 'app-move' => 'apps', 'app-resign' => 'apps', 'app-claim' => 'apps', 'app-settle' => 'apps',
    'store-file' => 'storage', 'add-prepaid-storage' => 'storage', 'dfs-create-file' => 'storage',
    'register-node' => 'node', 'update-node' => 'node', 'remove-node' => 'node', 'claim-node' => 'node', 'governance-vote' => 'node',
    'register-gateway' => 'gateway', 'unregister-gateway' => 'gateway', 'gateway-heartbeat' => 'gateway', 'archival-register' => 'gateway',
    'archival-unregister' => 'gateway', 'relay-register' => 'gateway', 'relay-unregister' => 'gateway',
    'register-release' => 'governance', 'revoke-release' => 'governance', 'release-authority-propose' => 'governance', 'release-authority-accept' => 'governance',
    'sign-message' => 'keys', 'verify-message' => 'keys',
);
my %MESSAGE_COMMANDS = (
    'sign-message' => ['Sign a message with a private key (ZBC-MSG-v1, off-chain, no node needed)', [
        { name => 'sender_privkey', kind => 'privkey', required => 1, help => 'Sender private key (64 hex)' },
        { name => 'message', kind => 'string', required => 1, help => 'text to sign (hex bytes with --hex)' } ]],
    'verify-message' => ['Verify a ZBC-MSG-v1 message signature against a ZBC_ address (off-chain)', [
        { name => 'address', kind => 'string', required => 1, help => "signer's ZBC_ address (or 64-hex public key)" },
        { name => 'message', kind => 'string', required => 1, help => 'the signed text (hex bytes with --hex)' },
        { name => 'signature', kind => 'string', required => 1, help => '64-byte Ed25519 signature, 128 hex' } ]],
);

my $JSON_OUT = JSON::PP->new->utf8->canonical->pretty;
my $JSON_IN = JSON::PP->new->utf8;
my $JSON_LINE = JSON::PP->new->utf8->canonical;

# ---- the I/O of one run ------------------------------------------------------------------------------------------

our $IO;
sub _env { my ($k) = @_; return $IO->{env}{$k}; }
sub _print { my ($fh, $text) = @_; utf8::encode($text) if utf8::is_utf8($text); print {$fh} $text; }
sub _out_text { _print($IO->{out}, $_[0]); }
sub _err_text { _print($IO->{err}, $_[0]); }

# Deep copy with every byte string decoded from UTF-8, for JSON encoding.
sub _chars {
    my ($v) = @_;
    return $v unless defined $v;
    if (ref $v eq 'HASH') { return { map { $_ => _chars($v->{$_}) } keys %$v }; }
    if (ref $v eq 'ARRAY') { return [map { _chars($_) } @$v]; }
    return $v if ref $v;
    return $v if utf8::is_utf8($v) || $v !~ /[^\x00-\x7F]/;
    my $copy = $v; utf8::decode($copy); return $copy;
}
# Deep copy with every character string encoded to UTF-8 bytes, for values read from JSON.
sub _bytes {
    my ($v) = @_;
    return $v unless defined $v;
    if (ref $v eq 'HASH') { return { map { $_ => _bytes($v->{$_}) } keys %$v }; }
    if (ref $v eq 'ARRAY') { return [map { _bytes($_) } @$v]; }
    return $v if ref $v;
    my $copy = $v; utf8::encode($copy) if utf8::is_utf8($copy); return $copy;
}
sub _out_json { _print($IO->{out}, $JSON_OUT->encode(_chars($_[0]))); }

sub _emit_error {
    my ($e, $verbose) = @_;
    if ($verbose) { _err_text("Error: " . $e->message . "\n"); } else { _out_json($e->to_json); }
    return $e->code;
}

sub _strip { my ($e) = @_; $e = "$e"; $e =~ s/ at \S+ line \d+\.?\n?$//s; chomp $e; return $e; }
sub _has_default { my ($p) = @_; return defined $p->{default} && length $p->{default}; }
sub _is_int { my ($s) = @_; return defined $s && $s =~ /^-?\d+$/; }

# ---- options -------------------------------------------------------------------------------------------------------

sub _options {
    my %o = (api => _env('ZBC_API') || 'http://localhost:8080', fee => DEFAULT_FEE, timeout => 20, genesis => '', json_input => 0, verbose => 0,
             encrypt => 0, hex => 0, offline => 0, help => 0, message => undef, chain => '', escrow => undef, timestamp => undef, token => undef);
    my $env_to = _env('ZBC_TIMEOUT') // '';
    $o{timeout} = 0 + $env_to if _is_int($env_to) && $env_to > 0;
    return \%o;
}

sub _check_escrow {
    my ($e) = @_;
    die usage("Escrow requires --escrow-approver") unless defined $e->{approver} && length $e->{approver};
    die usage("Escrow requires --escrow-timeout > 0") unless defined $e->{timeout} && $e->{timeout} > 0;
    die usage("Escrow commission cannot be negative") if defined $e->{commission} && $e->{commission} < 0;
    $e->{commission} //= 0;
    $e->{instruction} //= '';
    return $e;
}

# (positional arguments, options) of the command line after the command name.
sub parse_args {
    my ($argv) = @_;
    my ($o, @positional, %escrow) = (_options());
    my $i = 0;
    my $need = sub { my ($what) = @_; die usage("$argv->[$i] requires a value" . ($what // '')) if $i + 1 >= @$argv; return $argv->[++$i]; };
    my $integer = sub { my ($s, $what) = @_; die usage($what) unless _is_int($s); return parse_integer($s, 'int64', $argv->[$i - 1] // 'value'); };
    while ($i < @$argv) {
        my $a = $argv->[$i];
        if ($a eq '-v' || $a eq '--verbose') { $o->{verbose} = 1; }
        elsif ($a eq '--json') { $o->{verbose} = 0; }
        elsif ($a eq '--json-input') { $o->{json_input} = 1; }
        elsif ($a eq '--encrypt') { $o->{encrypt} = 1; }
        elsif ($a eq '--hex') { $o->{hex} = 1; }
        elsif ($a eq '--offline') { $o->{offline} = 1; }
        elsif ($a eq '-h' || $a eq '--help') { $o->{help} = 1; }
        elsif ($a eq '--message') { $o->{message} = $need->(); }
        elsif ($a eq '--fee') { $o->{fee} = $integer->($need->(), '--fee must be a whole number of atomic units'); }
        elsif ($a eq '--api') { $o->{api} = $need->(); }
        elsif ($a eq '--timeout' || $a eq '--timeout-seconds') {
            my $v = $need->(' (seconds)');
            die usage("$a must be a whole number of seconds") unless $v =~ /^\d+$/;
            die usage("$a must be > 0") unless $v > 0;
            $o->{timeout} = 0 + $v;
        }
        elsif ($a eq '--genesis') { $o->{genesis} = $need->(); }
        elsif ($a eq '--chain') { $o->{chain} = $need->(); }
        elsif ($a eq '--token') { $o->{token} = $need->(); }
        elsif ($a eq '--timestamp') {
            my $v = $need->(' (Unix seconds)');
            $o->{timestamp} = $integer->($v, '--timestamp must be a whole number of Unix seconds');
            die usage("--timestamp must be > 0") unless $o->{timestamp} > 0;
        }
        elsif ($a eq '--escrow-approver') { $escrow{approver} = $need->(); }
        elsif ($a eq '--escrow-commission') { $escrow{commission} = $integer->($need->(), '--escrow-commission must be a whole number of atomic units'); }
        elsif ($a eq '--escrow-timeout') { $escrow{timeout} = $integer->($need->(), '--escrow-timeout must be a Unix timestamp in seconds'); }
        elsif ($a eq '--escrow-instruction') { $escrow{instruction} = $need->(); }
        elsif (length($a) > 1 && substr($a, 0, 1) eq '-' && substr($a, 1, 1) !~ /[0-9.]/) { die usage("Unknown option: $a"); }
        else { push @positional, $a; }
        $i++;
    }
    die usage("--offline needs --genesis <hex|v1> (or ZOOBC_GENESIS_HASH): nothing is asked of a node") if $o->{offline} && !length($o->{genesis}) && !length(_env('ZOOBC_GENESIS_HASH') // '');
    $o->{escrow} = _check_escrow(\%escrow) if %escrow;
    return (\@positional, $o);
}

sub _is_placeholder { my ($s) = @_; return defined $s && ($s eq '-' || $s eq '@env' || $s eq 'env:ZBC_KEY'); }

sub _read_stdin {
    return $IO->{stdin} if defined $IO->{stdin};
    my $fh = $IO->{in};
    local $/;
    my $text = <$fh>;
    return $text // '';
}

# The parameter values (name => string) from JSON on stdin, interactive prompts, or the positional arguments.
sub resolve_params {
    my ($params, $positional, $o) = @_;
    my %values;
    my $key_is_first = @$params && $params->[0]{name} eq 'sender_privkey';
    my $env_key = $key_is_first ? (_env('ZBC_KEY') // '') : '';
    if ($o->{json_input}) {
        (my $text = _read_stdin()) =~ s/^\s+|\s+$//g;
        die usage("No JSON input received on stdin") unless length $text;
        my $j = eval { $JSON_IN->decode($text) };
        die usage("Invalid JSON input") unless ref $j eq 'HASH';
        $j = _bytes($j);
        for my $p (@$params) {
            my $n = $p->{name};
            if (exists $j->{$n}) {
                my $v = $j->{$n};
                $values{$n} = !defined $v ? 'null' : JSON::PP::is_bool($v) ? ($v ? 'true' : 'false') : ref $v ? $JSON_LINE->encode($v) : "$v";
            } elsif (_has_default($p)) { $values{$n} = $p->{default}; }
            elsif ($n eq 'sender_privkey' && length $env_key) { $values{$n} = $env_key; }
            elsif ($p->{required}) { die usage("Missing required field: $n"); }
            else { $values{$n} = ''; }
            if ($key_is_first && $n eq 'sender_privkey' && _is_placeholder($values{$n})) {
                die usage("sender_privkey is '-' but ZBC_KEY is not set") unless length $env_key;
                $values{$n} = $env_key;
            }
        }
        my $num = sub {
            my ($k, $what) = @_;
            return undef unless exists $j->{$k};
            my $s = (ref $j->{$k} || JSON::PP::is_bool($j->{$k}) || !defined $j->{$k}) ? '' : "$j->{$k}";
            die usage("$what must be a whole number") unless _is_int($s);
            return 0 + $s;
        };
        my $fee = $num->('fee', 'fee'); $o->{fee} = $fee if defined $fee;
        my $to = $num->('timeout_seconds', 'timeout_seconds');
        if (defined $to) { die usage("timeout_seconds must be > 0") if $to <= 0; $o->{timeout} = $to; }
        my $ts = $num->('timestamp', 'timestamp');
        if (defined $ts) { die usage("timestamp must be > 0") if $ts <= 0; $o->{timestamp} = $ts; }
        $o->{offline} = $j->{offline} ? 1 : 0 if JSON::PP::is_bool($j->{offline});
        $o->{api} = $j->{api_url} if defined $j->{api_url} && !ref $j->{api_url};
        $o->{message} = $j->{message} if defined $j->{message} && !ref $j->{message} && !JSON::PP::is_bool($j->{message});
        $o->{hex} = $j->{hex} ? 1 : 0 if JSON::PP::is_bool($j->{hex});
        $o->{verbose} = 1 if JSON::PP::is_bool($j->{verbose}) && $j->{verbose};
        if (ref $j->{escrow} eq 'HASH') {
            my %e = %{ $j->{escrow} };
            for my $k (qw(commission timeout)) {
                next unless exists $e{$k};
                die usage("escrow.$k must be a whole number") unless defined $e{$k} && !ref $e{$k} && _is_int("$e{$k}");
                $e{$k} = 0 + $e{$k};
            }
            $o->{escrow} = _check_escrow(\%e);
        }
        die usage("--offline needs --genesis <hex|v1> (or ZOOBC_GENESIS_HASH): nothing is asked of a node") if $o->{offline} && !length($o->{genesis}) && !length(_env('ZOOBC_GENESIS_HASH') // '');
        return \%values;
    }
    if (!@$positional && $o->{verbose} && !defined $IO->{stdin} && -t $IO->{in}) {
        my $in = $IO->{in};
        for my $p (@$params) {
            _out_text(sprintf "  %s%s: ", $p->{help}, _has_default($p) ? " [$p->{default}]" : '');
            my $answer = <$in>; $answer //= ''; $answer =~ s/^\s+|\s+$//g;
            $values{ $p->{name} } = length($answer) ? $answer : ($p->{default} // '');
            if ($p->{name} eq 'sender_privkey' && (!length($values{ $p->{name} }) || _is_placeholder($values{ $p->{name} }))) { $values{ $p->{name} } = $env_key; }
            die usage("Missing required argument: $p->{name}") if $p->{required} && !length $values{ $p->{name} };
        }
        return \%values;
    }
    my @pos = @$positional;
    if ($key_is_first) {
        my $required = grep { $_->{required} && !_has_default($_) } @$params;
        if (@pos && _is_placeholder($pos[0])) {
            die usage("key argument is '-' but ZBC_KEY is not set") unless length $env_key;
            $pos[0] = $env_key;
        } elsif (length($env_key) && @pos + 1 == $required) {
            unshift @pos, $env_key;
        }
    }
    for my $i (0 .. $#$params) {
        my $p = $params->[$i];
        if ($i < @pos) { $values{ $p->{name} } = $pos[$i]; }
        elsif (_has_default($p)) { $values{ $p->{name} } = $p->{default}; }
        elsif ($p->{required}) { die usage("Missing required argument: $p->{name}" . ($i == 0 && $key_is_first ? " (pass it, or set ZBC_KEY)" : '')); }
        else { $values{ $p->{name} } = ''; }
    }
    my @extra = @pos[scalar(@$params) .. $#pos];
    if (@extra) {
        die usage(sprintf 'Fee must be a whole number of atomic units, got "%s". The API endpoint is passed with --api URL, not as a positional argument.', $extra[0]) unless _is_int($extra[0]);
        $o->{fee} = parse_integer($extra[0], 'int64', 'fee');
    }
    $o->{api} = $extra[1] if @extra > 1;
    return \%values;
}

# ---- help ---------------------------------------------------------------------------------------------------------

# (description, params, tx type) of a command, or an empty list.
sub _command {
    my ($cmd) = @_;
    return ($MESSAGE_COMMANDS{$cmd}[0], $MESSAGE_COMMANDS{$cmd}[1], 0) if $MESSAGE_COMMANDS{$cmd};
    my $d = ZBC::Commands::by_name($cmd);
    return $d ? ($d->{description}, $d->{params}, $d->{type}) : ();
}

sub print_list {
    my %groups;
    my @entries = ((map { [$_->{command}, $_->{description}] } ZBC::Commands::all()), (map { [$_, $MESSAGE_COMMANDS{$_}[0]] } keys %MESSAGE_COMMANDS));
    for my $e (sort { $a->[0] cmp $b->[0] } @entries) { push @{ $groups{ $CATEGORY{ $e->[0] } // 'other' } }, sprintf "  %-26s%s", @$e; }
    my @out = (sprintf("ZooBC unified transaction CLI — %d commands.", scalar @entries), "  Default: JSON in, JSON out.   --verbose: prompt each field + text output.",
               "  echo '{...}' | zbc-cli <cmd> --json-input     zbc-cli help <cmd>  (fields for one tx)", "");
    for my $g (qw(value tokens exchange apps storage account node gateway governance keys other)) { push @out, "[$g]", @{ $groups{$g} }, "" if $groups{$g}; }
    push @out, "First param is the sender private key (or set ZBC_KEY and omit it / pass '-'); verify-message takes an address.",
               "`zbc-cli help <cmd>` shows a command's JSON fields; `zbc-cli <cmd> --help` the options, env vars and exit codes.";
    _out_text(join("\n", @out) . "\n");
}

sub print_help {
    my ($cmd) = @_;
    my ($desc, $params, $tx_type) = _command($cmd);
    unless (defined $desc) { _err_text("Unknown command: $cmd (try `zbc-cli list`)\n"); return USAGE; }
    my @lines = (sprintf("%s — %s  (tx type %d)", $cmd, $desc, $tx_type), "JSON fields (default: JSON in/out; --json-input reads them on stdin; positional order matches):");
    my %sample;
    for my $p (@$params) {
        push @lines, sprintf "  %-18s%s%s%s", $p->{name}, $p->{required} ? '(required) ' : '(optional) ', $p->{help}, _has_default($p) ? "  [default: $p->{default}]" : '';
        $sample{ $p->{name} } = _has_default($p) ? $p->{default} : '...';
    }
    push @lines, "Sample: " . $JSON_LINE->encode(\%sample), "Run with --verbose to be prompted for each field and get human-readable output.";
    _out_text(join("\n", @lines) . "\n");
    return 0;
}

my $USAGE_TEXT = <<'END';
Options:
  -v, --verbose         Verbose output (default is JSON)
  --json-input          Read parameters from JSON on stdin
  --chain <name>        Read the recipient as this chain: zbc, btc, eth, sol, dot, ada, xrp, trx, xtz
  --message <text>      Optional transaction message
  --encrypt             Encrypt --message to the recipient (ZBC only)
  --genesis <hex|v1>    Sign for this chain (its genesis block hash) without asking the node; 'v1' = legacy unbound digest. Default: ask --api.
  --escrow-approver <addr>   Escrow approver address
  --escrow-commission <n>    Escrow commission (atomic units)
  --escrow-timeout <n>       Escrow timeout as a FUTURE Unix timestamp (seconds)
  --escrow-instruction <s>   Escrow instruction
  --fee <n>             Transaction fee (default: 5000000 = 0.05 ZBC)
  --api <url>           API endpoint (default: $ZBC_API, else http://localhost:8080)
  --timeout <s>         Bound for each HTTP call, seconds (default: $ZBC_TIMEOUT, else 20; also --timeout-seconds)
  --hex                 sign-message/verify-message: the message is hex bytes, not text
  --offline             Build, sign and hash, print unsigned_bytes, digest, signature, transaction_bytes and transaction_hash, exit 0 without submitting. Needs --genesis.
  --timestamp <n>       Transaction timestamp, Unix seconds (default: now)

Environment:
  ZBC_KEY               Sender private key (64 hex), used when the key argument is omitted or '-'
  ZBC_API, ZBC_TIMEOUT  Defaults for --api and --timeout
  ZOOBC_GENESIS_HASH    Default for --genesis

Exit codes:
  0 ok  1 internal  2 usage  3 node unreachable  4 insufficient balance  5 fee too low
  6 rejected by node  7 not found  8 timeout  9 node busy (5xx)  10 signature invalid
  JSON errors carry the same code as "exit_code" and its name as "error_class".
END

sub print_usage {
    my ($cmd, $params) = @_;
    my $args = join '', map { $_->{required} ? " <$_->{name}>" : " [$_->{name}]" } @$params;
    _out_text(sprintf "zbc-cli %s\n\nUsage:\n  zbc-cli %s [options]%s [fee] [api_url]\n\n%s\nParameters:\n%s\n", $cmd, $cmd, $args, $USAGE_TEXT,
              join("\n", map { sprintf "  %-22s%s", $_->{name}, $_->{help} } @$params));
}

# ---- the commands -------------------------------------------------------------------------------------------------

sub _message_bytes {
    my ($text, $hex_input) = @_;
    return $text unless $hex_input;
    die usage("--hex message is not valid hex") unless is_hex($text);
    return from_hex($text);
}

sub run_sign_message {
    my ($v, $o) = @_;
    die usage("Private key must be 64 hex characters (32 bytes)") unless is_hex($v->{sender_privkey}, 64);
    my $s = sign_message($v->{sender_privkey}, _message_bytes($v->{message}, $o->{hex}));
    if ($o->{verbose}) { _out_text("Address:   $s->{address}\nDigest:    $s->{digest}\nSignature: $s->{signature}\n"); }
    else {
        my %out = (success => JSON::PP::true, %$s);
        $out{message} = $v->{message} unless $o->{hex};
        _out_json(\%out);
    }
    return 0;
}

sub run_verify_message {
    my ($v, $o) = @_;
    my $pub = public_key_of_address($v->{address});
    die usage("address must be a ZBC_ account (Ed25519) address") unless defined $pub;
    my $msg = _message_bytes($v->{message}, $o->{hex});
    die usage("signature must be hex") unless is_hex($v->{signature});
    die usage("signature must be 64 bytes (128 hex characters)") unless length($v->{signature}) == 128;
    my $valid = verify_message($v->{address}, $msg, $v->{signature});
    my $address = parse_address(to_hex($pub))->display;
    my $code = $valid ? OK : VERIFY_FAILED;
    if ($o->{verbose}) { _out_text(($valid ? 'VALID' : 'INVALID') . " signature for $address\n"); }
    else {
        _out_json({ success => JSON::PP::true, valid => $valid ? JSON::PP::true : JSON::PP::false, scheme => SCHEME, address => $address,
                    digest => to_hex(message_digest($msg)), exit_code => 0 + $code, error_class => $valid ? 'ok' : 'verify_failed' });
    }
    return $code;
}

sub _signing_context {
    my ($o, $client) = @_;
    my $g = length($o->{genesis}) ? $o->{genesis} : (_env('ZOOBC_GENESIS_HASH') // '');
    if (length $g) {
        my $ctx = eval { ZBC::SigningContext->of($g) };
        die usage(_strip($@)) unless $ctx;
        return $ctx;
    }
    my $ctx = eval { $client->signing_rule };
    return $ctx if $ctx;
    my $e = $@;
    if (ref $e && $e->isa('ZBC::Error') && ($e->code == NODE_UNREACHABLE || $e->code == TIMEOUT)) {
        die ZBC::Error->new($e->code, sprintf("%s /api/v1/node/info from %s to learn which chain to sign for; pass --genesis <hex> to sign for a known chain",
                                                $e->code == TIMEOUT ? 'timed out reading' : 'cannot read', $o->{api}));
    }
    die $e;
}

sub run_transaction {
    my ($spec, $v, $o) = @_;
    for my $p (@{ $spec->{params} }) {
        $v->{ $p->{name} } = validate_param($p, $v->{ $p->{name} } // '') if length($v->{ $p->{name} } // '') || $p->{required};
    }
    die usage("--encrypt is not available in this implementation yet; send the message in clear or use the C++ tools") if $o->{encrypt};
    my $sender = key_pair($v->{ $spec->{sender_key} });
    my $client = ZBC::Client->new($o->{api}, $o->{timeout});
    my $ctx = _signing_context($o, $client);
    my $timestamp = defined $o->{timestamp} ? $o->{timestamp} : time;
    my ($recipient, %extra) = ('');
    if ($spec->{recipient} eq 'required') {
        my $r = eval { parse_address($v->{recipient}, $o->{chain}) };
        die usage("invalid recipient address: " . _strip($@)) unless $r;
        $recipient = $r->bytes;
        @extra{qw(recipient recipient_type)} = ($r->display, $r->type_name);
    }
    if (defined $o->{token}) {
        die usage("--token applies to liquid-payment only") unless $spec->{command} eq 'liquid-payment';
        $v->{token_id} = $o->{token};
    }
    my %files;
    for my $p (@{ $spec->{params} }) {
        next unless $p->{kind} eq 'file';
        my $path = $v->{ $p->{name} };
        open(my $fh, '<:raw', $path) or die usage("cannot read $p->{name}: $path");
        $files{ $p->{name} } = do { local $/; <$fh> };
        close $fh;
    }
    my $reference = $spec->{needs_node} ? $client->latest_block : undef;
    my $body;
    my $custom = $spec->{custom} // '';
    if ($custom eq 'multisig' || $custom eq 'settle') {
        (my $more, $body) = ();
        ($body, $more) = custom_body($spec, $v, $sender, $ctx, $timestamp);
        %extra = (%extra, %$more);
    } else {
        my %computed;
        my $more = compute_fields($spec, $v, $sender, \%computed, $reference);
        %extra = (%extra, %$more);
        $body = build_body($spec, $v, $sender, \%files, \%computed);
    }
    for my $p (@{ $spec->{params} }) {
        next if $p->{kind} eq 'privkey' || $p->{kind} eq 'file' || exists $extra{ $p->{name} } || $p->{name} eq 'recipient';
        my $val = $v->{ $p->{name} };
        $extra{ $p->{name} } = ($p->{kind} =~ /^(int64|uint64|uint32|uint8)$/ && _is_int($val)) ? 0 + $val : $val;
    }
    if ($spec->{command} eq 'approve-escrow') {
        $extra{escrowed_transaction_hash} = $v->{transaction_hash};
        $extra{transaction_id} = transaction_id(from_hex($v->{transaction_hash}));
        delete $extra{transaction_hash};
    }
    $extra{sender} = $sender->address;
    my $escrow = $o->{escrow} ? ZBC::Escrow->new(%{ $o->{escrow} }) : undef;
    my $signed = eval { sign_transaction($spec->{type}, $timestamp, $sender, $recipient, $o->{fee}, $body, $ctx, $escrow, $o->{message} // '') };
    unless ($signed) { my $e = $@; die $e if ref $e; die usage("Invalid escrow approver: " . _strip($e)); }
    my %fields = (transaction_hash => to_hex($signed->hash), transaction_type => 0 + $spec->{type}, sender_account_address => $signed->payload->{sender_account_address},
                  recipient_account_address => $signed->payload->{recipient_account_address}, fee => 0 + $o->{fee}, timestamp => 0 + $timestamp);
    my %common;
    $common{message} = $o->{message} if defined $o->{message} && length $o->{message};
    $common{escrow} = $signed->payload->{escrow} if $signed->payload->{escrow};
    %common = (%common, %extra);
    if ($o->{offline}) {
        if ($o->{verbose}) {
            _out_text(sprintf "OFFLINE: transaction built and signed, not submitted\n\nTransaction hash:  %s\nSigning version:   %d%s\nTimestamp:         %d\n"
                              . "Unsigned bytes:    %s\nDigest:            %s\nSignature:         %s\nTransaction bytes: %s\nPayload:           %s\n",
                      $fields{transaction_hash}, $signed->signing_version, length($signed->genesis_hash) ? " (genesis " . to_hex($signed->genesis_hash) . ")" : '',
                      $timestamp, to_hex($signed->unsigned), to_hex($signed->digest), to_hex($signed->signature), to_hex($signed->bytes), $JSON_LINE->encode(_chars($signed->payload)));
        } else {
            my %out = (success => JSON::PP::true, offline => JSON::PP::true, %fields, signing_version => 0 + $signed->signing_version);
            $out{genesis_hash} = to_hex($signed->genesis_hash) if length $signed->genesis_hash;
            %out = (%out, unsigned_bytes => to_hex($signed->unsigned), digest => to_hex($signed->digest), signature => to_hex($signed->signature),
                    transaction_bytes => to_hex($signed->bytes), payload => $signed->payload, %common);
            _out_json(\%out);
        }
        return 0;
    }
    my ($status, $body_json, $accepted) = $client->submit(_chars($signed->payload));
    unless ($accepted) {
        my $text = (ref $body_json eq 'HASH' && defined $body_json->{error} && !ref $body_json->{error}) ? $body_json->{error} : (ref $body_json ? $JSON_LINE->encode($body_json) : $body_json);
        my $err = ZBC::Error->new(classify_node_error($status, $text), $text, http_code => $status, api_response => $body_json);
        if ($o->{verbose}) { _err_text(sprintf "FAILED: Transaction submission rejected (%s)\nHTTP %d: %s\n", error_class($err->code), $status, $text); }
        else { _out_json($err->to_json); }
        return $err->code;
    }
    if ($o->{verbose}) { _out_text(sprintf "SUCCESS: %s submitted!\n\nTransaction Hash: %s\n", $spec->{command}, $fields{transaction_hash}); }
    else { _out_json({ success => JSON::PP::true, %fields, api_response => $body_json, %common }); }
    return 0;
}

# ---- entry point --------------------------------------------------------------------------------------------------

# run(\@argv, in => $fh, out => $fh, err => $fh, env => \%env, stdin => $text) -> exit code
sub run {
    my ($argv, %io) = @_;
    local $IO = { in => $io{in} // \*STDIN, out => $io{out} // \*STDOUT, err => $io{err} // \*STDERR, env => $io{env} // \%ENV, stdin => $io{stdin} };
    unless (@$argv) {
        _out_text("ZooBC unified transaction CLI\nUsage: zbc-cli <command> <params...> [--api URL] [--fee N] [--timeout S] [--verbose] [--json-input]\n"
                  . "       zbc-cli list   (show all commands)      zbc-cli <command> --help  (options, env vars, exit codes)\n");
        return USAGE;
    }
    my $cmd = $argv->[0];
    return print_help($argv->[1]) if $cmd eq 'help' && @$argv >= 2;
    if ($cmd eq 'list' || $cmd eq '--help' || $cmd eq '-h' || $cmd eq 'help') { print_list(); return 0; }
    my ($desc, $params) = _command($cmd);
    unless (defined $desc) { _err_text("Unknown command: $cmd (try `zbc-cli list`)\n"); return USAGE; }
    my $verbose = 0;
    my $code = eval {
        my ($positional, $o) = parse_args([@$argv[1 .. $#$argv]]);
        $verbose = $o->{verbose};
        if ($o->{help}) { print_usage($cmd, $params); return 0; }
        my $values = resolve_params($params, $positional, $o);
        $verbose = $o->{verbose};
        return run_sign_message($values, $o) if $cmd eq 'sign-message';
        return run_verify_message($values, $o) if $cmd eq 'verify-message';
        return run_transaction(ZBC::Commands::by_name($cmd), $values, $o);
    };
    return $code if defined $code;
    my $e = $@;
    return _emit_error($e, $verbose) if ref $e && $e->isa('ZBC::Error');
    return _emit_error(ZBC::Error->new(INTERNAL, _strip($e)), $verbose);
}

1;
