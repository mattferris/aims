#!/usr/bin/perl
#
# This module is part of aims, an iptables scripting language.
#
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

    # don't process if a drop or reject rule
    if ($line->[0]->{'type'} =~ /^drop|reject$/) {
        return;
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
                $err->{'reason'} .= ', changing chain to POSTROUTING';
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
        my $exp = "--to-destination ".if2host($peek->{'value'});
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

    # don't process if a drop or reject rule
    if ($line->[0]->{'type'} =~ /^drop|reject$/) {
        return;
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
        my $exp = "--to-source ".if2host($peek->{'value'});
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
