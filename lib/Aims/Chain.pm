#!/usr/bin/perl
#
# This module is part of aims, an iptables scripting language.
# http://bueller.ca/software/aims
#
# Copyright (c) 2014 Matt Ferris
# Released under the BSD 2-clause license
# http://bueller.ca/software/aims/license
#
package Aims::NAT;

use strict;
use warnings;

use Aims::Main qw(
    newrule getrule skiprule ruleskipped
    setcomment getcomment
    ifexists protoexists copyline if2host
    addline getoption tokenpos protocheck
);
use Aims::Error qw(error warn debug);
use Mexpar::Parser qw(ontoken);

use Exporter qw(import);
our @EXPORT_OK = qw();


my $chains = {};


#
# Handle 'chain' action
#
ontoken('T_ACTION_CHAIN', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    my $rule = getrule();
    my $nextt = $line->[$tpos+1];
    my $chain = $nextt->{'value'};

    if (defined($chains->{$chain})) {
        my $err = {
            code => 'E_CHAIN_ALREADY_DEFINED',
            file => $nextt->{'file'},
            line => $nextt->{'line'},
            char => $nextt->{'char'},
            chain => $chain
        };

        if (getoption('strict') eq 'on') {
            error($err);
        }
        else {
            warn($err);
            skiprule();
        }
    }
    else {
        $rule->{'command'} = '-N';
        $rule->{'chain'} = $chain;
        $chains->{$chain} = 1;
    }
});


#
# Handle 'send-to' clause
#
ontoken('T_CLAUSE_SENDTO', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    my $rule = getrule();
    my $nextt = $line->[$tpos+1];
    my $chain = $nextt->{'value'};

    if (!defined($chains->{$chain})) {
        error({
            code => 'E_UNDEFINED_CHAIN',
            file => $nextt->{'file'},
            line => $nextt->{'line'},
            char => $nextt->{'char'},
            chain => $chain
        });
    }
    else {
        $rule->{'target'} = $chain;
    }
});


#
# Handle 'table' clause
#
ontoken('T_CLAUSE_TABLE', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    my $rule = getrule();
    my $nextt = $line->[$tpos+1];

    $rule->{'table'} = $nextt->{'value'};
});


1;
