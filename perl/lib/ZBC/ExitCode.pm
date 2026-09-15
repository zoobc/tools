# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package ZBC::ExitCode;
# Exit codes and error classes of spec/cli-contract.md section 5, and the node-error classification of spec/api.md.
use strict; use warnings;
use Exporter 'import';
use ZBC::Error;

use constant { OK => 0, INTERNAL => 1, USAGE => 2, NODE_UNREACHABLE => 3, INSUFFICIENT_BALANCE => 4, FEE_TOO_LOW => 5,
               REJECTED => 6, NOT_FOUND => 7, TIMEOUT => 8, NODE_BUSY => 9, VERIFY_FAILED => 10 };
our @EXPORT_OK = qw(OK INTERNAL USAGE NODE_UNREACHABLE INSUFFICIENT_BALANCE FEE_TOO_LOW REJECTED NOT_FOUND TIMEOUT NODE_BUSY
                    VERIFY_FAILED error_class usage classify_node_error);
our %EXPORT_TAGS = (all => \@EXPORT_OK);

my %NAMES = (0 => 'ok', 1 => 'internal', 2 => 'usage', 3 => 'node_unreachable', 4 => 'insufficient_balance', 5 => 'fee_too_low',
             6 => 'rejected', 7 => 'not_found', 8 => 'timeout', 9 => 'node_busy', 10 => 'verify_failed');

sub error_class { my ($code) = @_; return $NAMES{$code} // 'internal'; }

# A usage error (exit 2) to die with.
sub usage { my ($message) = @_; return ZBC::Error->new(USAGE, $message); }

# Classify a node's rejection into an exit code (spec/api.md section 2).
sub classify_node_error {
    my ($http_code, $text) = @_;
    return NODE_UNREACHABLE if $http_code == 0;
    return NODE_BUSY if $http_code >= 500;
    my $t = lc($text // '');
    return FEE_TOO_LOW if index($t, 'fee too low') >= 0;
    return INSUFFICIENT_BALANCE if index($t, 'insufficient balance') >= 0 || index($t, 'insufficient spendable') >= 0 || index($t, 'account does not exist') >= 0;
    return NOT_FOUND if index($t, 'not found') >= 0 || index($t, 'unknown token') >= 0 || index($t, 'unknown or expired token') >= 0 || index($t, 'unknown app') >= 0;
    return REJECTED;
}

1;
