#!/usr/bin/perl
#
# This module is part of aims, an iptables scripting language.
# http://bueller.ca/software/aims
#
# Copyright (c) 2013 Matt Ferris
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


#
# Handle 'rdr-to' clauses
#
ontoken('T_CLAUSE_RDR_TO', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }

    # produce error if not a match rule
    if ($line->[0]->{'type'} ne 'T_ACTION_MATCH') {
        error({
            code => 'E_INVALID_ACTION',
            file => $token->{'file'},
            line => $token->{'line'},
            char => $token->{'char'},
            got => $line->[0]->{'value'},
            reason => 'rdr-to only valid for match rules'
        });
    }

    my $rule = getrule();

    if ($rule->{'chain'} eq '') {
        $rule->{'chain'} = 'PREROUTING';
    }
    elsif ($rule->{'chain'} !~ /^OUTPUT|PREROUTING$/) {
        # if the chain was set explicity by 'for', then we need to
        # show an error, otherwise it was set implicity by 'in' or 'out'
        # and it's safe to change without an error
        if (tokenpos('T_CLAUSE_FOR', $line) > -1) {
            my $err = {
                code => 'E_INVALID_CHAIN',
                file => $token->{'file'},
                line => $token->{'line'},
                got => $rule->{'chain'},
                reason => 'rdr-to only valid for prerouting and output chains'
            };

            if (getoption('strict') eq 'on') {
                error($err);
            }
            else {
                $err->{'reason'} .= ', changing chain to PREROUTING';
                warn($err);
            }
        }

        $rule->{'chain'} = 'PREROUTING';
    }

    if ($rule->{'table'} ne '' && $rule->{'table'} ne 'nat') {
        my $err = {
            code => 'E_INVALID_TABLE',
            file => $token->{'file'},
            line => $token->{'line'},
            got => $rule->{'table'},
            reason => 'rdr-to only valid in the nat table'
        };

        if (getoption('strict') eq 'on') { error($err); }
        else { warn($err); }
    }

    $rule->{'table'} = 'nat';
    $rule->{'target'} = 'DNAT';
    my $peek = $line->[$tpos+1];

    # port only redirect
    if ($peek->{'type'} eq 'T_CLAUSE_PORT') {
        # make sure a proto has been specified
        protocheck($token, $rule);

        my $port = $line->[$tpos+2]->{'value'};
        my $exp;
        if ($port =~ /^(random|persistent)/) {
            $port = "--$1";
        }
        else {
            $exp = "--to-destination :$port";
        }
        push(@{$rule->{'targetexp'}}, $exp);
    }

    # ip and perhaps port redirect
    else {
        my $host;
        if ($peek->{'type'} eq 'T_ARRAY') {
            if (@{$peek->{'value'}} > 1) {
                my $err = {
                    code => 'W_TOO_MANY_VALUES',
                    file => $token->{'file'},
                    line => $token->{'line'},
                    char => $token->{'char'}
                };
                if (getoption('strict') eq 'on') { error($err); }
                else { warn($err); }
            }
            $host = if2host($peek->{'value'}->[0]);
        }
        else {
            $host = if2host($peek->{'value'});
        }
        my $exp = "--to-destination ".$host;
        # are we setting a port as well?
        my $peek2 = $line->[$tpos+2];
        if (defined($peek2) && $peek2->{'type'} eq 'T_CLAUSE_PORT') {
            # make sure a proto has been specified
            protocheck($token, $rule);
            $exp .= ":$line->[$tpos+3]->{'value'}";
        }
        push(@{$rule->{'targetexp'}}, $exp);
    }
});


#
# Handle 'nat-to' clauses
#
ontoken('T_CLAUSE_NAT_TO', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }

    # produce error if not a match rule
    if ($line->[0]->{'type'} ne 'T_ACTION_MATCH') {
        error({
            code => 'E_INVALID_ACTION',
            file => $token->{'file'},
            line => $token->{'line'},
            char => $token->{'char'},
            got => $line->[0]->{'value'},
            reason => 'rdr-to only valid for match rules'
        });
    }

    my $rule = getrule();

    if ($rule->{'chain'} ne '' && $rule->{'chain'} ne 'POSTROUTING') {
        # if the chain was set explicity by 'for', then we need to
        # show an error, otherwise it was set implicity by 'in' or 'out'
        # and it's safe to change without an error
        if (tokenpos('T_CLAUSE_FOR', $line) > -1) {
            my $err = {
                code => 'E_INVALID_CHAIN',
                file => $token->{'file'},
                line => $token->{'line'},
                got => $rule->{'chain'},
                reason => 'nat-to only valid for postrouting chain'
            };

            if (getoption('strict') eq 'on') {
                error($err);
            }
            else {
                $err->{'reason'} .= ', changing chain to POSTROUTING';
                warn($err);
            }
        }
    }

    if ($rule->{'table'} ne '' && $rule->{'table'} ne 'nat') {
        my $err = {
            code => 'E_INVALID_TABLE',
            file => $token->{'file'},
            line => $token->{'line'},
            got => $rule->{'chain'},
            reason => 'nat-to only valid in the nat table'
        };

        if (getoption('strict') eq 'on') { error($err); }
        else { warn($err); }
    }

    $rule->{'chain'} = 'POSTROUTING';
    $rule->{'table'} = 'nat';
    $rule->{'target'} = 'SNAT';
    my $peek = $line->[$tpos+1];

    # port only redirect
    if ($peek->{'type'} eq 'T_CLAUSE_PORT') {
        # make sure a proto has been specified
        protocheck($token, $rule);

        my $port = $line->[$tpos+2]->{'value'};
        my $exp;
        if ($port =~ /^(random)/) {
            $port = "--$1";
        }
        else {
            $exp = "--to-source :$port";
        }
        push(@{$rule->{'targetexp'}}, $exp);
    }

    # ip and perhaps port redirect
    else {
        my $host;
        if ($peek->{'type'} eq 'T_ARRAY') {
            if (@{$peek->{'value'}} > 1) {
                my $err = {
                    code => 'W_TOO_MANY_VALUES',
                    file => $token->{'file'},
                    line => $token->{'line'},
                    char => $token->{'char'}
                };
                if (getoption('strict') eq 'on') { error($err); }
                else { warn($err); }
            }
            $host = if2host($peek->{'value'}->[0]);
        }
        else {
            $host = if2host($peek->{'value'});
        }
        my $exp = "--to-source ".$host;
        # are we setting a port as well?
        my $peek2 = $line->[$tpos+2];
        if (defined($peek2) && $peek2->{'type'} eq 'T_CLAUSE_PORT') {
            # make sure a proto has been specified
            protocheck($token, $rule);
            $exp .= ":$line->[$tpos+3]->{'value'}";
        }
        push(@{$rule->{'targetexp'}}, $exp);
    }
});


1;
