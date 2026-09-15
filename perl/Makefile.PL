# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
use strict; use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'ZBC',
    VERSION          => '1.0.0',
    ABSTRACT         => 'ZooBC keys, addresses, message signing, transactions, node client and zbc-cli',
    AUTHOR           => 'ZooBC Foundation',
    LICENSE          => 'mit',
    MIN_PERL_VERSION => '5.016',
    EXE_FILES        => ['bin/zbc-cli'],
    PREREQ_PM        => { 'Digest::SHA' => 0, 'JSON::PP' => 0, 'HTTP::Tiny' => 0, 'Math::BigInt' => 0 },
    TEST_REQUIRES    => { 'Test::More' => 0 },
    test             => { TESTS => 't/*.t' },
    META_MERGE       => { 'meta-spec' => { version => 2 }, resources => { repository => { type => 'git', url => 'https://github.com/zoobc/tools.git', web => 'https://github.com/zoobc/tools' } } },
);
