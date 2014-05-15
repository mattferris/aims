#!/usr/bin/perl
#
# This module is part of mexpar, a lexical analyzer/parser with pluggable
# grammar support.
# http://bueller.ca/software/mexpar
#
# Copyright (c) 2014 Matt Ferris
# Released under the BSD 2-clause license
# http://bueller.ca/software/mexpar/license
#
package Mexpar::Lexer;

use strict;
use warnings;

use Mexpar::Error qw(error);

use Exporter qw(import);
our @EXPORT_OK = qw(lex prepare);

#
# Process the stream and match tokens. Uses a moving window
# that allows the lexer to move forward and back within the
# window. Matches are evaluated on a longest match policy.
# Only once a string isn't matched by any token is the
# previous matched token returned.
#
sub lex
{
    my ($grammar, $in, $rest) = @_;
    my $buf = [];
    my $pos = 0;
    my $line = 1;
    my $char = 1;
    my $curmatch;
    my $symbol = '';
    my $tokens = [];

    if (!defined($grammar->{'_prepared'})) {
        error({code=>'E_GRAMMAR_NOT_PREPARED'});
    }

    fillbuf($buf, $in, \$pos);

    # read a character in from the buffer on each iteration appending
    # it to any existing characters in the current symbol
    CHARLOOP: while (defined(my $c = nextc($buf, $in, \$pos))) {
        # as long as $c isn't a newline, try and match $symbol
        if ($c !~ /\n/) {
            $char++;
            $symbol .= $c;

            # start inital matching of the token
            foreach my $tdef (@{$grammar->{'rules'}}) {
                my $token = resolve($symbol, $tdef);

                # save the matched token, but keep matching
                if (defined($token)) {
                    $curmatch = $token;
                    $curmatch->{'line'} = $line;
                    $curmatch->{'char'} = $char-length($symbol);
                    next CHARLOOP;
                }
            }
        }

        # if we didn't match any tokens, then we use the
        # last matched token 
        if (defined($curmatch)) {
            if (isgoodt($grammar, $curmatch->{'type'})) {
                push(@$tokens, $curmatch);
            }
            undef $curmatch;
            $symbol = '';
            rewind($buf, \$pos);
            $char--;
        }
        elsif ($c =~ /\n/) {
            if ($symbol ne '') {
                error({
                    code => 'E_UNDEFINED_SYMBOL',
                    symbol => $symbol,
                    line => $line,
                    char => $char-length($symbol)
                });
            }
            if (defined($grammar->{'eol'})) {
                my $nt = copyt($grammar->{'_prepared'}->{$grammar->{'eol'}});
                $nt->{'line'} = $line;
                $nt->{'char'} = $char;
                push(@$tokens, $nt);
            }
            $char = 1;
            $line++;
            $symbol = '';
        }
    }

    # collect any remaining matched token
    if (defined($curmatch) && isgoodt($grammar, $curmatch->{'type'})) {
        push(@$tokens, $curmatch);
    }
    elsif ($symbol ne '') {
        error({
            code => 'E_UNDEFINED_SYMBOL',
            symbol => $symbol,
            line => $line,
            char => $char-length($symbol)
        });
    }

    # finally, add an end-of-file token, if specified
    if (defined($grammar->{'eof'})) {
        my $nt = copyt($grammar->{'_prepared'}->{$grammar->{'eof'}});
        $nt->{'line'} = $line;
        $nt->{'char'} = $char+1;
        push(@$tokens, $nt);
    }

    return $tokens;
}


#
# Prepare the grammar for use
#
sub prepare
{
    my $grammar = shift;

    if (!defined($grammar->{'rules'})) {
        error({code=>'E_GRAMMAR_MISSING_RULES'});
    }

    # Generate a list of all tokens, make sure there
    # are no duplicates
    my $branches = [$grammar->{'rules'}];
    my $prepared= {};
    while (my $b = pop(@$branches)) {
        foreach my $r (@$b) {
            if (defined($r->{'sub'})) {
                push(@$branches, $r->{'sub'});
            }

            $prepared->{$r->{'type'}} = $r;
        }
    }

    $grammar->{'_prepared'} = $prepared;
}


#
# Advance the window so there are equal characters 
# on either side of position.
#
sub fillbuf
{
    my ($buf, $in, $pos, $rest) = @_;
    my $len = 10;
    my $i = 0;

    if ($$pos > 8) { 
        $i = 3;
        $$pos -= $i;
        splice(@$buf, 0, $i);
    }

    my $ref = ref($in);
    if ($ref eq 'GLOB') {
        while (defined(my $c = getc($in))) {
            push(@$buf, $c);
            if ($#{$buf} + $i++ >= $len) {
                last;
            }
        }
    }
    elsif ($ref eq 'ARRAY') {
        my $line = shift(@$in);
        if (defined($line)) {
            for (my $i=0; $i<length($line); $i++) {
                my $c = substr($line, $i, 1);
                push(@$buf, $c);
            }
        }
        push(@$buf, undef);
    }
}


#
# Return the next character and advance the
# position by one.
#
sub nextc
{
    my ($buf, $in, $pos, $rest) = @_;

    if ($#{$buf} - $$pos <= 1) {
        fillbuf($buf, $in, $pos);
    }

    if ($#{$buf} - $$pos > 0) {
        return $buf->[$$pos++];
    }
    else {
        return undef;
    }
}


#
# Move the position backwards by one.
#
sub rewind
{
    my ($buf, $pos, $rest) = @_;
    $$pos--;
}


#
# Return the next character without advancing
# the position.
#
sub peek
{
    my ($buf, $pos, $rest) = @_;

    if ($buf->[$pos]) {
        return $buf->[$pos];
    }
    else
    {
        return undef;
    }
}


#
# Recursively match tokens, return the most specific match.
#
sub resolve
{
    my ($in, $tdef, $rest) = @_;
    my $match = 0;
    my $return;

    if ($in =~ /$tdef->{'pattern'}/m) {
        if ($1) {
            $return = copyt($tdef);
            $return->{'value'} = $1;
        }

        # if the current token definition contains sub definitions
        # then try and match those instead
        if (defined($tdef->{'sub'})) {
            foreach my $t (@{$tdef->{'sub'}}) {
		my $token = resolve($in, $t);
                if (defined($token)) {
                    $return = $token;
                }
            }
        }
    }

    return $return;
}


#
# Copy the token
#
sub copyt
{
    my ($t, $next, $rest) = @_;

#    my $newt = {
#        'type' => $t->{'type'},
#        'pattern' => $t->{'pattern'}
#    };

#    if ($t->{'next'}) {
#        $newt->{'next'} = $t->{'next'};
#    }

    my $newt = {};
    foreach my $k (keys(%$t)) {
        $newt->{$k} = $t->{$k};
    }

    return $newt;
}


#
# Check if the current token should be accepted
#
sub isgoodt
{
    my ($grammar, $type, $rest) = @_;
    my $isgood = 1;

    if (defined($grammar->{'ignore'}) && $type =~ /$grammar->{'ignore'}/) {
        $isgood = 0;
    }

    return $isgood;
}


1;
