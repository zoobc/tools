# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package ZBC::Error;
# An error that carries its exit code; die with it, catch it with eval. `extra` is merged into the JSON error object.
use strict; use warnings;
use JSON::PP ();
use overload '""' => sub { $_[0]->{message} }, fallback => 1;

sub new { my ($class, $code, $message, %extra) = @_; return bless { code => $code, message => $message, extra => \%extra }, $class; }
sub code    { $_[0]->{code} }
sub message { $_[0]->{message} }
sub extra   { $_[0]->{extra} }

sub to_json {
    my ($self) = @_;
    require ZBC::ExitCode;
    return { success => JSON::PP::false, error => $self->{message}, exit_code => 0 + $self->{code},
             error_class => ZBC::ExitCode::error_class($self->{code}), %{ $self->{extra} } };
}

1;
