#!/usr/bin/perl
#
# This module is part of aims, an iptables scripting language.
#
#
package Aims::Error;

use strict;
use warnings;

use Mexpar::Error qw(delegate);

use Exporter qw(import);
our @EXPORT_OK = qw(error warn debug);

my $codes = {
    E_BAD_FIRST_TOKEN => '[file]: rule must start with an action or variable declaration, '.
        'but starts with \'[value]\' ([type]) instead on line [line]',

    E_COMPILE_NO_CHAIN_SET => '[file]: no chain set in rule on line [line]',

    E_COMPILE_NO_TARGET_SET => '[file]: no target set in rule on line [line]',

    E_FILE_NOT_FOUND => 'file not found [file]',

    E_FOPEN_FAILED => 'failed to open file [file], [reason]',

    E_INVALID_TABLE => '[file]: invalid table specified \'[got]\', [reason] '.
        'on line [line]',

    E_PIPE_READ_FAILED => 'failed to read from pipe, [reason]',

    E_PORT_WITHOUT_PROTOCOL => '[file]: port specified without protocol '.
        'on line [line] at char [char]',

    E_REFERENCED_FILE_NOT_FOUND => '[file]: file not found [include]'.
        'on line [line]',

    E_REFERENCED_FOPEN_FAILED => '[file]: failed to open file '.
        '[include], [reason] on line [line]',

    E_INVALID_CHAIN => '[file]: invalid chain specified \'[got]\', [reason] '.
        'on line [line]',

    E_UNDEFINED_PROTOCOL => '[file]: undefined protocol \'[proto]\' specified '.
        'on line [line] at char [char]',

    E_UNDEFINED_VARIABLE => '[file]: undefined variable \'[name]\' '.
        'on line [line] at char [char]',

    W_BAD_FILTER_LOGIC => '[file]: bad filter logic, [reason] '.
        'on line [line] at char [char]',

    W_INTERFACE_NOT_FOUND => '[file]: interface \'[value]\' not found '.
            'on line [line] at char [char]',
 
    W_PORT_WITHOUT_PROTOCOL => '[file]: port specified without protocol, '.
        'assuming \'all\' on line [line] at char [char]',
};

sub error
{
    my $args = shift;
    my $msg = mkmsg($args);
    print STDERR "error: $msg\n";
    exit 1;
}


sub warn
{
    my $args = shift;
    my $msg = mkmsg($args);
    print STDERR "warning: $msg\n";
}


sub debug
{
    my $msg = shift;
    print STDERR "debug: $msg\n";
}


sub mkmsg
{
    my $args = shift;
    my $msg = "haven't implemented any message for this yet";

    # if $args isn't a reference, treat is a scalar and use it as the message
    if (ref($args) eq '') {
        $msg = $args;
    }
    elsif (!defined($args->{'code'})) {
        $msg = "encountered error with no error code";
    }
    elsif (defined($codes->{$args->{'code'}})) {
        $msg = $codes->{$args->{'code'}};
        foreach my $k (keys(%$args)) {
            if (defined($args->{$k})) {
                $msg =~ s/\[$k\]/$args->{$k}/g;
            }
        }
    }
    else {
        $msg = "$args->{'code'}: $msg";
    }

    return $msg;
}
