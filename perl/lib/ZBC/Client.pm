# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package ZBC::Client;
# The node/gateway HTTP client (spec/api.md) on HTTP::Tiny: node info, submit, status, transaction, account, latest block.
# Every method dies with a ZBC::Error on failure.
use strict; use warnings;
use HTTP::Tiny;
use JSON::PP;
use ZBC::Encoding qw(is_hex from_hex);
use ZBC::Error;
use ZBC::ExitCode qw(INTERNAL NODE_BUSY NODE_UNREACHABLE NOT_FOUND TIMEOUT classify_node_error);
use ZBC::Transaction ();

my $JSON = JSON::PP->new->utf8->canonical;

sub new {
    my ($class, $api, $timeout_seconds) = @_;
    $api //= 'http://localhost:8080';
    $api =~ s{/+$}{};
    return bless { api => $api, timeout => $timeout_seconds // 20,
                   http => HTTP::Tiny->new(agent => 'zbc-cli/1.0', timeout => $timeout_seconds // 20, default_headers => { Accept => 'application/json' }) }, $class;
}

sub api { $_[0]->{api} }

# (HTTP status, body text, parsed JSON or undef)
sub _call {
    my ($self, $method, $path, $body) = @_;
    my %opts = (headers => {});
    if (defined $body) { $opts{content} = $body; $opts{headers}{'Content-Type'} = 'application/json'; }
    my $res = $self->{http}->request($method, $self->{api} . $path, \%opts);
    if ($res->{status} == 599) {    # HTTP::Tiny's own failures: no connection, timeout, bad URL
        (my $why = $res->{content} // '') =~ s/\s+$//;
        die ZBC::Error->new(TIMEOUT, "Timed out: $path on $self->{api}") if $why =~ /timed? ?out/i;
        die ZBC::Error->new(NODE_UNREACHABLE, "Connection failed: $path on $self->{api}: $why");
    }
    my $text = $res->{content} // '';
    my $parsed = eval { $JSON->decode($text) };
    return (0 + $res->{status}, $text, $parsed);
}

sub node_info {
    my ($self) = @_;
    my ($status, $text, $j) = $self->_call('GET', '/api/v1/node/info');
    if ($status != 200) {
        die ZBC::Error->new($status >= 500 ? NODE_BUSY : NODE_UNREACHABLE,
            "cannot read /api/v1/node/info from $self->{api} (HTTP $status) to learn which chain to sign for; pass --genesis <hex> to sign for a known chain",
            http_code => $status);
    }
    return ref $j eq 'HASH' ? $j : {};
}

# The chain's signing rule as the node reports it: a ZBC::SigningContext.
sub signing_rule {
    my ($self) = @_;
    my $info = $self->node_info;
    if (($info->{signing_version} || 1) >= 2) {
        my $g = "" . ($info->{genesis_hash} // '');
        die ZBC::Error->new(INTERNAL, "node enforces chain-bound signing but reports no genesis hash; pass --genesis <hex>") unless is_hex($g, 64);
        return ZBC::SigningContext->new(2, from_hex($g));
    }
    return ZBC::SigningContext->new(1);
}

# POST /api/v1/transactions -> (http code, parsed body or text, accepted). Dies on transport failure only.
sub submit {
    my ($self, $payload) = @_;
    my ($status, $text, $j) = $self->_call('POST', '/api/v1/transactions', $JSON->encode($payload));
    return ($status, defined $j ? $j : $text, ($status == 200 || $status == 202) ? 1 : 0);
}

sub submit_or_die {
    my ($self, $payload) = @_;
    my ($status, $body, $accepted) = $self->submit($payload);
    return $body if $accepted;
    my $text = (ref $body eq 'HASH' && defined $body->{error} && !ref $body->{error}) ? $body->{error} : (ref $body ? $JSON->encode($body) : $body);
    die ZBC::Error->new(classify_node_error($status, $text), $text, http_code => $status, api_response => $body);
}

# GET /api/v1/transactions/<hash>/status; a 404 answers status not_found rather than dying.
sub status {
    my ($self, $tx_hash) = @_;
    my ($status, $text, $j) = $self->_call('GET', "/api/v1/transactions/$tx_hash/status");
    die ZBC::Error->new(classify_node_error($status, $text), $text, http_code => $status, api_response => defined $j ? $j : $text) unless $status == 200 || $status == 404;
    my %out = (transaction_hash => $tx_hash, status => $status == 404 ? 'not_found' : 'unknown', (ref $j eq 'HASH' ? %$j : ()), http_code => $status);
    return \%out;
}

sub transaction {
    my ($self, $tx_hash) = @_;
    my ($status, $text, $j) = $self->_call('GET', "/api/v1/transactions/$tx_hash");
    return $j if $status == 200;
    die ZBC::Error->new($status == 404 ? NOT_FOUND : classify_node_error($status, $text), $status == 404 ? 'Transaction not found' : $text,
                        http_code => $status, api_response => defined $j ? $j : $text);
}

sub _url_encode { my ($s) = @_; $s =~ s/([^A-Za-z0-9\-_.~])/sprintf '%%%02X', ord $1/ge; return $s; }

sub account {
    my ($self, $address) = @_;
    my ($status, $text, $j) = $self->_call('GET', '/api/v1/accounts/' . _url_encode($address));
    return $j if $status == 200;
    die ZBC::Error->new($status == 404 ? NOT_FOUND : classify_node_error($status, $text), $status == 404 ? 'Account not found' : $text,
                        http_code => $status, api_response => defined $j ? $j : $text);
}

# [hash bytes, height] of the latest block, from `block_hash` (node) or `hash` (gateway).
sub latest_block {
    my ($self) = @_;
    my ($status, $text, $j) = $self->_call('GET', '/api/v1/blocks/latest');
    $j = {} unless ref $j eq 'HASH';
    my $h = "" . ($j->{block_hash} || $j->{hash} || '');
    die ZBC::Error->new(INTERNAL, "Failed to fetch latest block from $self->{api}", http_code => $status) if $status != 200 || !is_hex($h, 64);
    return [from_hex($h), 0 + ($j->{height} || 0)];
}

1;
