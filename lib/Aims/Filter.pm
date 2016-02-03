#!/usr/bin/perl
#
# This module is part of aims, an iptables scripting language.
# http://bueller.ca/software/aims
#
# Copyright (c) 2014 Matt Ferris
# Released under the BSD 2-clause license
# http://bueller.ca/software/aims/license
#
package Aims::Filter;

use strict;
use warnings;

use File::Spec;

use Aims::Main qw(
    newrule getrule skiprule ruleskipped
    setcomment getcomment
    ifexists getifnet getifbcast getifaddr getifmask if2host
    protoexists bracelist parenlist arraylist
    tokenpos getoption protocheck
);
use Aims::Error qw(error warn debug);
use Mexpar::Parser qw(ontoken handle);

use Exporter qw(import);
our @EXPORT_OK = qw();


#
# Handle 'accept' clauses
#
ontoken('T_ACTION_ACCEPT', sub {
    my $rule = getrule();
    $rule->{'target'} = 'ACCEPT';
});


#
# Handle 'drop' clauses
#
ontoken('T_ACTION_DROP', sub {
    my $rule = getrule();
    $rule->{'target'} = 'DROP';
});


#
# Handle 'reject' clauses
#
ontoken('T_ACTION_REJECT', sub {
    my $rule = getrule();
    $rule->{'target'} = 'REJECT';
});


#
# Handle 'policy' clauses
#
ontoken('T_ACTION_POLICY', sub {
    my $rule = getrule();
    $rule->{'command'} = '-P';
});


#
# Handle 'for' clauses
#
ontoken('T_CLAUSE_FOR', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }
    my $rule = getrule();

    if ($line->[$tpos+1]->{'type'} eq 'T_OPEN_BRACE') {
        bracelist($tpos+1, $line);
        return;
    }
    elsif ($line->[$tpos+1]->{'type'} eq 'T_ARRAY') {
        arraylist($tpos+1, $line);
        return;
    }

    my $chain = $line->[$tpos+1]->{'value'};

    if ($chain eq 'input') {
        $chain = 'INPUT';
    }
    elsif ($chain eq 'output') {
        $chain = 'OUTPUT';
    }
    elsif ($chain eq 'forward') {
        $chain = 'FORWARD';
    }
    elsif ($line->[0]->{'type'} =~ /^T_ACTION_(ACCEPT|REJECT|DROP)$/) {
        if ($chain =~ /^(prerouting|postrouting)$/) {
            my $err = {
                code => 'E_INVALID_CHAIN',
                file => $token->{'file'},
                line => $token->{'line'},
                got => $1,
                reason => "can't filter in prerouting or postrouting chains"
            };

            if (getoption('strict') eq 'on') {
                error($err);
            }
            else {
                warn($err);
            }
        }
    }
    else {
        if ($chain eq 'prerouting') { $chain = 'PREROUTING'; }
        elsif ($chain eq 'postrouting') { $chain = 'POSTROUTING'; }
    }

    $rule->{'chain'} = $chain;
});


#
# Handle 'in' clauses
#
ontoken('T_CLAUSE_IN', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }
    my $rule = getrule();

    if ($line->[$tpos+1]->{'type'} eq 'T_OPEN_BRACE') {
        bracelist($tpos+1, $line);
        return;
    }
    elsif ($line->[$tpos+1]->{'type'} eq 'T_ARRAY') {
        arraylist($tpos+1, $line);
        return;
    }

    my $chain;
    my $ift = $line->[$tpos+1];
    my $if = $ift->{'value'};
    my $negated = 0;

    # check for a negated match
    if ($if =~ /^\!(.+)$/) {
        $negated = 1;
        $if = $1;
    }

    if (!ifexists($if)) {
        warn({
            code => 'W_INTERFACE_NOT_FOUND',
            file => $ift->{'file'},
            line => $ift->{'line'},
            char => $ift->{'char'},
            value => $ift->{'value'}
        });
    }

    my $forpos = tokenpos('T_CLAUSE_FOR', $line);
    if ($forpos >= 0) {
        if ($line->[$forpos+1]->{'value'} eq 'output') {
            my $err = {
                code => 'W_BAD_FILTER_LOGIC',
                file => $ift->{'file'},
                line => $token->{'line'},
                char => $token->{'char'},
                reason => "ingress interface will never match in output chain"
            };

            if (getoption('strict') eq 'on') {
                error($err);
            }
            else {
                warn($err);
            }
        }
    }
    else {
        if ($rule->{'chain'} eq 'OUTPUT') {
            $chain = 'FORWARD';
        }
        elsif ($rule->{'chain'} eq '') {
            $chain = 'INPUT';
        }

        $rule->{'chain'} = $chain;
    }

    my $expr = "-i $if";
    if ($negated == 1) {
        $expr = "'!' $expr";
    }

    push(@{$rule->{'matchexp'}}, $expr);
});


#
# Handle 'out' clauses
#
ontoken('T_CLAUSE_OUT', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }
    my $rule = getrule();

    if ($line->[$tpos+1]->{'type'} eq 'T_OPEN_BRACE') {
        bracelist($tpos+1, $line);
        return;
    }
    elsif ($line->[$tpos+1]->{'type'} eq 'T_ARRAY') {
        arraylist($tpos+1, $line);
        return;
    }

    my $chain;
    my $ift = $line->[$tpos+1];
    my $if = $ift->{'value'};
    my $negated = 0;

    # check for a negated match
    if ($if =~ /^\!(.+)$/) {
        $negated = 1;
        $if = $1;
    }

    if (!ifexists($if)) {
        warn({
            code => 'W_INTERFACE_NOT_FOUND',
            file => $ift->{'file'},
            line => $ift->{'line'},
            char => $ift->{'char'},
            value => $ift->{'value'}
        });
    }

    my $forpos = tokenpos('T_CLAUSE_FOR', $line);
    if ($forpos >= 0) {
        if ($line->[$forpos+1]->{'value'} eq 'input') {
            my $err = {
                code => 'W_BAD_FILTER_LOGIC',
                file => $token->{'file'},
                line => $token->{'line'},
                char => $token->{'char'},
                reason => "egress interface will never match in input chain"
            };

            if (getoption('strict') eq 'on') {
                error($err);
            }
            else {
                warn($err);
            }
        }
    }
    else {
        if ($rule->{'chain'} eq 'INPUT') {
            $chain = 'FORWARD';
        }
        else {
            $chain = 'OUTPUT';
        }
        $rule->{'chain'} = $chain;
    }

    my $expr = "-o $if";
    if ($negated == 1) {
        $expr = "'!' $expr";
    }

    push(@{$rule->{'matchexp'}}, $expr);
});


#
# Handle 'proto' clauses
#
ontoken('T_CLAUSE_PROTO', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }
    my $rule = getrule();

    if ($line->[$tpos+1]->{'type'} eq 'T_OPEN_BRACE') {
        bracelist($tpos+1, $line);
        return;
    }
    elsif ($line->[$tpos+1]->{'type'} eq 'T_ARRAY') {
        arraylist($tpos+1, $line);
        return;
    }

    my $protot = $line->[$tpos+1];
    my $proto = $protot->{'value'};
    my $negated = 0;

    # check for negated match
    if ($proto =~ /^\!(.+)$/) {
        $negated = 1;
        $proto = $1;
    }

    if (!protoexists($proto)) {
        my $err = {
             code => 'E_UNDEFINED_PROTOCOL',
             file => $protot->{'file'},
             line => $protot->{'line'},
             char => $protot->{'char'},
             proto => $protot->{'value'}
        };

        if (getoption('strict') eq 'on') {
            error($err);
        }
        else {
            warn($err);
        }
    }

    my $expr = "-p $proto";
    if ($negated == 1) {
        $expr = "'!' $expr";
    }

    push(@{$rule->{'matchexp'}}, $expr);
});


#
# Handle 'from' clauses
#
ontoken('T_CLAUSE_FROM', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }
    my $rule = getrule();
    my $nextt = $line->[$tpos+1];

    if ($nextt->{'type'} eq 'T_OPEN_BRACE') {
        bracelist($tpos+1, $line);
        return;
    }
    elsif ($nextt->{'type'} eq 'T_ARRAY') {
        arraylist($tpos+1, $line);
        return;
    }
    elsif ($nextt->{'type'} eq 'T_ANY') {
        $nextt->{'value'} = '0.0.0.0/0';
    }
    elsif ($nextt->{'type'} eq 'T_IPV4') {
        $rule->{'family'} = 'inet';
    }
    elsif ($nextt->{'type'} eq 'T_IPV6') {
        $rule->{'family'} = 'inet6';
    }

    if ($nextt->{'type'} eq 'T_CLAUSE_PORT') {
        handle('_SPORT', [$line->[$tpos+1], $tpos+1, $line]);
    }
    else {
        my $host = if2host($nextt->{'value'});
        my $expr = "-s $host";

        # check for a negated match
        if ($host =~ /^\!(.+)$/) {
            $expr = "'!' -s $1";
        }

        push(@{$rule->{'matchexp'}}, $expr);

        if ($line->[$tpos+2]->{'type'} eq 'T_CLAUSE_PORT') {
            handle('_SPORT', [$line->[$tpos+2], $tpos+2, $line]);
        }
    }
});


#
# Handle 'to' clauses
#
ontoken('T_CLAUSE_TO', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }
    my $rule = getrule();
    my $nextt = $line->[$tpos+1];

    if ($nextt->{'type'} eq 'T_OPEN_BRACE') {
        bracelist($tpos+1, $line);
        return;
    }
    elsif ($nextt->{'type'} eq 'T_ARRAY') {
        arraylist($tpos+1, $line);
        return;
    }
    elsif ($nextt->{'type'} eq 'T_ANY') {
        $nextt->{'value'} = '0.0.0.0/0';
    }
    elsif ($nextt->{'type'} eq 'T_IPV4') {
        $rule->{'family'} = 'inet';
    }
    elsif ($nextt->{'type'} eq 'T_IPV6') {
        $rule->{'family'} = 'inet6';
    }

    if ($nextt->{'type'} eq 'T_CLAUSE_PORT') {
        handle('_DPORT', [$line->[$tpos+1], $tpos+1, $line]);
    }
    else {
        my $host = if2host($nextt->{'value'});
        my $expr = "-d $host";

        # check for a negated match
        if ($host =~ /^\!(.+)$/) {
            $expr = "'!' -d $1";
        }

        push(@{$rule->{'matchexp'}}, $expr);

        if ($line->[$tpos+2]->{'type'} eq 'T_CLAUSE_PORT') {
            handle('_DPORT', [$line->[$tpos+2], $tpos+2, $line]);
        }
    }
});


#
# Handle 'state' clauses
#
ontoken('T_CLAUSE_STATE', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }
    my $rule = getrule();

    if ($line->[$tpos+1]->{'type'} eq 'T_OPEN_BRACE') {
        bracelist($tpos+1, $line);
        return;
    }
    elsif ($line->[$tpos+1]->{'type'} eq 'T_ARRAY') {
        arraylist($tpos+1, $line);
        return;
    }

    my $state = uc($line->[$tpos+1]->{'value'});

    push(@{$rule->{'matchexp'}}, "-m state --state $state");
});


#
# Handle 'reject-with' clause
#
ontoken('T_CLAUSE_REJECT_WITH', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }
    my $rule = getrule();

    my $nextt = $line->[$tpos+1];
    my $rejectwith = "--reject-with $nextt->{'value'}";
    push(@{$rule->{'targetexp'}}, $rejectwith);
});


#
# Handle psuedo token '_SPORT'
#
ontoken('_SPORT', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    my $rule = getrule();

    # check if a proto has been specified
    protocheck($token, $rule);

    my $port = $line->[$tpos+1];
    if ($port->{'type'} eq 'T_OPEN_BRACE') {
        bracelist($tpos+1, $line);
        return;
    }
    if ($port->{'type'} eq 'T_ARRAY') {
        arraylist($tpos+1, $line);
        return;
    }
    else {
        push(@{$rule->{'matchexp'}}, "--sport $port->{'value'}");
    }
});


#
# Handle psuedo token '_DPORT'
#
ontoken('_DPORT', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    my $rule = getrule();

    # check if a proto has been specified
    protocheck($token, $rule);

    my $port = $line->[$tpos+1];
    if ($port->{'type'} eq 'T_OPEN_BRACE') {
        bracelist($tpos+1, $line);
        return;
    }
    if ($port->{'type'} eq 'T_ARRAY') {
        arraylist($tpos+1, $line);
        return;
    }
    else {
        push(@{$rule->{'matchexp'}}, "--dport $port->{'value'}");
    }
});


1;
