#!/usr/bin/perl
#
# This module is part of aims, an iptables scripting language.
# http://bueller.ca/software/aims
#
# Copyright (c) 2014 Matt Ferris
# Released under the BSD 2-clause license
# http://bueller.ca/software/aims/license
#
package Aims::Primitives;

use strict;
use warnings;

use Aims::Grammar qw($grammar);
use Aims::Main qw(
    compile
    newrule getrule skiprule ruleskipped getruleset
    setcomment getcomment setvar getvar
    ifexists protoexists
    getoption setoption
    addline copyline
    newscope getscope endscope
);
use Aims::Error qw(error warn debug);
use Mexpar::Lexer qw(lex);
use Mexpar::Parser qw(ontoken handle);

use Exporter qw(import);
our @EXPORT_OK = qw();


#
# Handle newline tokens which indicate the end of a rule,
# so check the current rule for validity, then compile it
# and add it to the output.
#
sub newlineeof {
    my $token = shift;
    my $tpos = shift;

    my $valid = 1;
    my $errargs = {code=>'E_UNDEFINED'};
    my $rule = getrule();

    # ignore blank lines
    if ($token->{'char'} == 1) {
        # clear comments
        setcomment('');
        skiprule();
        return 1;
    }

    # if the rule isn't flagged for compilation, ignore it
    if (ruleskipped()) {
        return;
    }

    # if T_EOF and no other tokens exist in the rule, just return
    if ($token->{'type'} eq 'T_EOF' && $tpos == 0) {
        skiprule();
        return;
    }

    # bad rule, no chain set
    if ($rule->{'chain'} eq '') {
        $valid = 0;
        $errargs = {
            code => 'E_COMPILE_NO_CHAIN_SET',
            file => $token->{'file'},
            line => $token->{'line'}
        };
    }

    # bad rule, no target set
    if ($rule->{'command'} eq '-A' && $rule->{'target'} eq '') {
        $valid = 0;
        $errargs = {
            code => 'E_COMPILE_NO_TARGET_SET',
            file => $token->{'file'},
            line => $token->{'line'}
        };
    }

    if ($valid == 1) {
        if ($rule->{'comment'} eq '') {
            if (getoption('inline-comments') eq 'on' && getcomment() ne '') {
                $rule->{'comment'} = getcomment();
            }
            elsif (getoption('origin-comments') eq 'on') {
                my $absfile = File::Spec->rel2abs($token->{'file'});
                $rule->{'comment'} = "$absfile:$token->{'line'}";
            }
        }
    }
    else {
        error($errargs);
    }
}
ontoken('T_NEWLINE', \&newlineeof);
ontoken('T_EOF', \&newlineeof);


#
# Handle T_ARRAY
#
ontoken('T_ARRAY', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }
    skiprule();

    foreach my $t (@{$token->{'value'}}) {
        my $newline = copyline($line);
        splice(@$newline, $tpos, 1, $t);
        addline($newline);
    }
});


#
# Handle variables
#
ontoken('T_VARIABLE', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }
    skiprule();

    my $scope = getscope();
    my $variables = $scope->{'variables'};

    my $name = $token->{'value'};

    if (!defined($variables->{$name})) {
        error({
            code => 'E_UNDEFINED_VARIABLE',
            file => $token->{'file'},
            line => $token->{'line'},
            char => $token->{'char'},
            name => $token->{'value'}
        });
    }

    my $value = $variables->{$name};
    my $newline = copyline($line);
    splice(@$newline, $tpos, 1, @{$value});
    addline($newline);
});


#
# Handle equals '='
#
ontoken('T_EQUALS', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    skiprule();

    my $varname = $line->[0]->{'value'};
    my $varval = [];
    if ($line->[2]->{'type'} eq 'T_QUOTED_STRING') {
        my $t = $line->[2];
        $t->{'type'} = 'T_STRING';
        push(@$varval, $t);
    }
    elsif ($line->[2]->{'type'} eq 'T_CLAUSE_FILE') {
        handle('T_CLAUSE_FILE', [$line->[2], 2, $line]);
        push(@$varval, $line->[2]);
    }
    else {
        for (my $i=2; $i<$#{$line}; $i++) {
            push(@$varval, $line->[$i]);
        }
    }

    setvar($varname, $varval);
});


#
# Handle comments
#
ontoken('T_COMMENT', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    skiprule();
    if (getoption('inline-comments') ne 'on') {
        return;
    }
    else {
        my $cmt = $token->{'value'};
        $cmt =~ s/^#+\s*|^\s+|\s+$//;
        setcomment($cmt);
    }
});


#
# Parse a brace list { ... }
#
ontoken('T_OPEN_BRACE', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }

    my $list = [];

    # start at the next token, wich is the first list itemk
    my $bracelen = 1;
    my $depth = 1;
    for (my $i=1; $i<@$line; $i++) {
        my $t = $line->[$tpos+$i];
        if ($t->{'type'} eq 'T_CLOSE_BRACE') {
            $depth--;
            if ($depth == 0) {
                $bracelen++;
                last;
            }
        }
        elsif ($t->{'type'} eq 'T_OPEN_BRACE') {
            $depth++;
        }
        elsif ($t->{'type'} ne 'T_COMMA') {
            push(@$list, $t);
        }
        $bracelen++;
    }

    # use reverse to put the new rules in the order the values are in the list
    foreach my $t (reverse(@$list)) {
        my $newline = copyline($line);
        splice(@$newline, $tpos, $bracelen, $t);
        addline($newline);
    }

    # don't compile the current rule
    if (@$list > 0) {
        skiprule();
    }
});


#
# Parse a parenthesis list ( ... )
#
ontoken('T_OPEN_PARENTHESIS', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }

    my $opts = {};

    # start at the next token, which is the first option/value pair
    my $parenlen = 1;
    for (my $i=1; $i<@$line; $i++) {
        if ($line->[$tpos+$i]->{'type'} eq 'T_CLOSE_PARENTHESIS') {
            $parenlen++;
            last;
        }
        if ($line->[$tpos+$i]->{'type'} ne 'T_COMMA') {
            my $opt = $line->[$tpos+$i]->{'value'};
            my $val = $line->[$tpos+$i+1]->{'value'};
            $opts->{$opt} = $val;
            $i++;
        }
        $parenlen++;
    }

    splice(@$line, $tpos, $parenlen);
    $line->[$tpos-1]->{'options'} = $opts;
});


1;
