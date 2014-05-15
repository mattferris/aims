#!/usr/bin/perl
#
# This module is part of mexpar, a lexical analyzer/parser with pluggable
# grammer support.
# http://bueller.ca/software/mexpar
#
# Copyright (c) 2014 Matt Ferris
# Released under the BSD 2-clause license
# http://bueller.ca/software/mexpar/license
#
package Mexpar::Parser;

use strict;
use warnings;

use Mexpar::Error qw(error);

use Exporter qw(import);
our @EXPORT_OK = qw(parse ontoken handle);


my $handlers = {};

#
# Parse the list of tokens and call and handlers
# registered to each token.
#
# $grammar The grammar to use
# $tokens The lexically analyzed token list
#
sub parse
{
    my ($grammar, $tokens, $rest) = @_;

    for (my $i = 0; $i<@$tokens; $i++) {
        my $t = $tokens->[$i];

        # Scan ahead to make sure we have the right subsequent tokens
        if (defined($t->{'next'})) {

            # repeating sequences
            if (defined($t->{'min'})) {
                my $j = 0;
                my $k = 0;
                my $seq = $t->{'next'};
                my $found = 0;
                my $nextt = $tokens->[$i+$j+1];
                while ($nextt->{'type'} !~ /$t->{'stop'}/) {
                    if ($nextt->{'type'} !~ /$seq->[$k]/) {
                        error({
                            code => 'E_UNEXPECTED_TOKEN',
                            expected => $seq->[$k],
                            got => $nextt->{'type'},
                            value => $nextt->{'value'},
                            line => $nextt->{'line'},
                            char => $nextt->{'char'},
                            definedby => $t->{'type'},
                            definedline => $t->{'line'},
                            definedchar => $t->{'char'},
                        });
                    }
                    if ($k >= $#{$seq}) {
                        $found++;
                        $k = 0;

                        # if the next token isn't the stop token, and a
                        # separator token has been specified, then we
                        # need to make sure we see it before looking
                        # for the  next sequence, so we peek ahead at
                        # least two tokens
                        my $peek2 = $tokens->[$i+$j+2];
                        my $peek3 = $tokens->[$i+$j+3];
                        if ($peek2->{'type'} eq $t->{'separator'}) {
                            # a separator is fine as long as the next token isn't a stop
                            if ($peek3->{'type'} eq $t->{'stop'}) {
                                error({
                                    code => 'E_UNEXPECTED_TOKEN',
                                    expected => $seq->[$k],
                                    got => $peek2->{'type'},
                                    value => $peek2->{'value'},
                                    line => $peek2->{'line'},
                                    char => $peek2->{'char'},
                                    definedby => $t->{'type'},
                                    definedline => $t->{'line'},
                                    definedchar => $t->{'char'}
                                });
                            }

                            # skip the separator and continue with the next sequence
                            else {
                                $j++;
                            }
                        }
                    }
                    else {
                        $k++;
                    }
                    $j++;
                    $nextt = $tokens->[$i+$j+1];
                }
                if ($found < $t->{'min'}) {
                    error({
                        code => 'E_MIN_REPEAT_NOT_MET',
                        line => $t->{'line'},
                        char => $t->{'char'},
                        min => $t->{'min'},
                        sequence => "@$seq",
                        found => $found,
                    });
                }
            }

            # non-repeating sequences
            else {
                for (my $j=0; $j<@{$t->{'next'}}; $j++) {
                    my $nextt = $tokens->[$i+$j+1];
                    if ($nextt->{'type'} !~ /$t->{'next'}->[$j]/) {
                        error({
                            code => 'E_UNEXPECTED_TOKEN',
                            expected => $t->{'next'}->[$j],
                            got => $nextt->{'type'},
                            value => $nextt->{'value'},
                            line => $nextt->{'line'},
                            char => $nextt->{'char'},
                            definedby => $t->{'type'},
                            definedline => $t->{'line'},
                            definedchar => $t->{'char'},
                        });
                    }
                }
            }
        }

#        if (defined($handlers->{$t->{'type'}})) {
#            foreach my $h (@{$handlers->{$t->{'type'}}}) {
#                &$h($t, $i, $tokens);
#            }
#        }
        handle($t->{'type'}, [$t, $i, $tokens]);
    }
}


#
# Register a handler for a given token.
#
# $t The token name
# $h The sub reference to call
#
sub ontoken
{
    my ($t, $h, $rest) = @_;

    if (!defined($handlers->{$t})) {
        $handlers->{$t} = [];
    }

    if (ref($h) ne 'CODE') {
        error({code=>'E_BAD_ARGVAL', expected=>'CODE', got=>ref($h)});
    }

    push(@{$handlers->{$t}}, $h);
}


#
# Call a handler for a given token.
#
# $t The token name
# $args The arrayref of arguments for the handler
#
sub handle
{
    my ($t, $args, $rest) = @_;

    if (defined($handlers->{$t})) {
        foreach my $h (@{$handlers->{$t}}) {
            &$h(@$args);
        }
    }
}


1;
