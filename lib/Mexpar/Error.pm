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
package Mexpar::Error;

use strict;
use warnings;

use Exporter qw(import delegate);
our @EXPORT_OK = qw(error delegate mkerrmsg);

my $delegate;

my $errors = {
    E_GRAMMAR_MISSING_RULES => 'the supplied grammar has no rules defined',
    E_GRAMMAR_NOT_PREPARED => 'grammar not prepared, call prepare() before lex()',
    E_MIN_REPEAT_NOT_MET => "the token sequence ([sequence]) was repeated ".
        "[found] times but expected at least [min] times on line [line] at char [char]",
    E_UNDEFINED_SYMBOL => "undefined symbol '[symbol]' on line [line] at char [char]",
    E_UNEXPECTED_TOKEN => "unexpected token [got] ('[value]'), expected [expected] ".
        "on line [line] at char [char], ".
        "defined by [definedby] on line [definedline] at char [definedchar]",
};


#
# Display error message
#
# arg0 The error code
# arg1..n The values to replace in the defined error string
#
# Returns void
#
sub error
{
    # call the delgate instead, if defined
    if (defined($delegate)) {
        &$delegate(@_);
        return;
    }

    my $msg = mkerrmsg(@_);

    die("error: $msg\n");
}


#
# Produce an error msg from a template
#
sub mkerrmsg
{
    my $args = shift;
    my $errcode = $args->{'code'};
    my $errstr;

    if (defined($errors->{$errcode})) {
        $errstr = $errors->{$errcode};

        foreach my $k (keys(%$args)) {
            $errstr =~ s/\[$k\]/$args->{$k}/g;
        }
    }
    else
    {
        $errstr = "an error has occured but the specified error code hasn't been defined '$errcode'";
    }

    return $errstr;
}


#
# Use a different error handler
#
# arg0 The reference to the sub to use as the handler
#
# Returns the reference to the current delegate,
# or undef if no current delegate exists
#
sub delegate
{
    my $d = shift;

    if (ref($d) eq 'CODE') {
        $delegate = $d;
    }
    else {
        die("error: must pass a sub reference for delegate\n");
    }
}

1;
