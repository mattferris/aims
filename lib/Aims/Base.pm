#!/usr/bin/perl
#
# This module is part of aims, an iptables scripting language.
# http://bueller.ca/software/aims
#
# Copyright (c) 2014 Matt Ferris
# Released under the BSD 2-clause license
# http://bueller.ca/software/aims/license
#
package Aims::Base;

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
    getipset
);
use Aims::Error qw(error warn debug);
use Mexpar::Lexer qw(lex);
use Mexpar::Parser qw(ontoken handle);

use Exporter qw(import);
our @EXPORT_OK = qw();


#
# Handle 'option' clauses
#
ontoken('T_ACTION_OPTION', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    skiprule();

    my $key = $line->[$tpos+1]->{'value'};
    my $val = $line->[$tpos+2]->{'value'};
    setoption($key, $val);
});


#
# Handle 'include' clauses
#
ontoken('T_ACTION_INCLUDE', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    skiprule();

    my $scope = getscope();
    my $curfile = $scope->{'file'};
    my $file = $line->[$tpos+1]->{'value'};

    # if $file is a relative path, append current files path
    if ($file !~ /^\//) {
        my @tmppath = split(/\//, $curfile);
        splice(@tmppath, -1, 1, $file);
        $file = join('/', @tmppath);
    }

    if (-d $file) {
        # strip trailing slash in directory path
        $file =~ s/\/$//;
        opendir(my $dh, $file);
        my @files = grep {/.+?\.rules$/} readdir($dh);
        foreach my $f (@files) {
            newscope();
            compile("$file/$f");
            endscope();
        }
        closedir($dh);
    }
    elsif (!-f $file) {
        error({
            code => 'E_REFERENCED_FILE_NOT_FOUND',
            file => $curfile,
            include => $file,
            line => $token->{'line'}
        });
    }
    else {
        newscope();
        compile($file);
        endscope();
    }
});


#
# Handle set clause
#
ontoken('T_ACTION_SET', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }

    my $rule = getrule();
    $rule->{'class'} = 'ipset';
});



#
# Handle 'log' clause
#
ontoken('T_CLAUSE_LOG', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }
    my $rule = getrule();

    if ($line->[0]->{'type'} ne 'T_ACTION_MATCH') {
        skiprule();
        my $logline = copyline($line);
        my $origline = copyline($line);

        # remove the paren list from the original rule
        if ($origline->[$tpos+1]->{'type'} eq 'T_OPEN_PARENTHESIS') {
            handle('T_OPEN_PARENTHESIS', [$line->[$tpos+1], $tpos+1, $line]);
        }

        # remove the log clause from the original rule
        # and re-add it
        splice(@$origline, $tpos, 1);
        addline($origline);

        $logline->[0]->{'type'} = 'T_ACTION_MATCH';
        $logline->[0]->{'value'} = 'match';

        # add the new match rule
        addline($logline);
    }
    else {
        $rule->{'target'} = 'LOG';

        # copy global logging options
        my $opts = {};
        my $keys = ['log-level', 'log-prefix', 'log-tcp-sequence', 'log-tcp-options', 'log-uid'];
        foreach my $k (@$keys) {
            $opts->{$k} = getoption($k);
        }

        # process supplied options via parenthesis ()
        my $peek = $line->[$tpos+1];
        my $logopts = {};
        if ($peek->{'type'} eq 'T_OPEN_PARENTHESIS') {
            handle('T_OPEN_PARENTHESIS', [$line->[$tpos+1], $tpos+1, $line]);
        }

        if (defined($token->{'options'})) {
            $logopts = $token->{'options'};
        }

        foreach my $k (keys(%$logopts)) {
            $opts->{$k} = $logopts->{$k};
        }

        # include logging options in the rule
        if ($opts->{'log-level'} ne '') {
            push(@{$rule->{'targetexp'}}, "--log-level '$opts->{'log-level'}'");
        }
        if ($opts->{'log-prefix'} ne '') {
            push(@{$rule->{'targetexp'}}, "--log-prefix '$opts->{'log-prefix'}'");
        }
        if ($opts->{'log-tcp-sequence'} eq 'on') {
            push(@{$rule->{'targetexp'}}, "--log-tcp-sequence");
        }
        if ($opts->{'log-tcp-options'} eq 'on') {
            push(@{$rule->{'targetexp'}}, "--log-tcp-options");;
        }
        if ($opts->{'log-uid'} eq 'on') {
            push(@{$rule->{'targetexp'}}, "--log-uid");
        }
    }
});


#
# Handle 'reverse' clauses
#
ontoken('T_CLAUSE_REVERSE', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }

    skiprule();

    my $newline = [];
    for (my $i=0; $i<@$line; $i++) {
        my $t = $line->[$i];
        my $newt = {
            type => $t->{'type'},
            file => $t->{'file'},
            line => $t->{'line'},
            char => $t->{'char'},
            value => $t->{'value'},
        };
        if ($t->{'type'} eq 'T_CLAUSE_FOR') {
            push(@$newline, $t);

            $i++;
            my $t = $line->[$i];
            $newt = {
                type => $t->{'type'},
                file => $t->{'file'},
                line => $t->{'line'},
                char => $t->{'char'},
                value => $t->{'value'},
            };

            if ($t->{'value'} eq 'input') {
                $newt->{'value'} = 'output';
            }
            elsif ($t->{'value'} eq 'output') {
                $newt->{'value'} = 'input';
            }

            push(@$newline, $newt);
        }
        elsif ($t->{'type'} eq 'T_CLAUSE_IN') {
            $newt->{'type'} = 'T_CLAUSE_OUT';
            push(@$newline, $newt);
        }
        elsif ($t->{'type'} eq 'T_CLAUSE_OUT') {
            $newt->{'type'} = 'T_CLAUSE_IN';
            push(@$newline, $newt);
        }
        elsif ($t->{'type'} eq 'T_CLAUSE_TO') {
            $newt->{'type'} = 'T_CLAUSE_FROM';
            push(@$newline, $newt);
        }
        elsif ($t->{'type'} eq 'T_CLAUSE_FROM') {
            $newt->{'type'} = 'T_CLAUSE_TO',
            push(@$newline, $newt);
        }
        elsif ($t->{'type'} eq 'T_CLAUSE_NAT_TO') {
            $newt->{'type'} = 'T_CLAUSE_RDR_TO';
            push(@$newline, $newt);
        }
        elsif ($t->{'type'} eq 'T_CLAUSE_RDR_TO') {
            $newt->{'type'} = 'T_CLAUSE_NAT_TO';
            push(@$newline, $newt);
        }
        elsif ($t->{'type'} ne 'T_CLAUSE_REVERSE') {
            push(@$newline, $t);
        }
    }

    # add the reversed rule
    addline($newline);

    # add the original rule without the reverse clause
    my $origline = copyline($line);
    splice(@$origline, $tpos, 1);
    addline($origline);
});


#
# Handle file clauses
#
ontoken('T_CLAUSE_FILE', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    skiprule();

    my $filename = $line->[$tpos+1]->{'value'};

    my $scope = getscope();
    my $curfile = $scope->{'file'};

    # if $filename is a relative path, append current files path
    if ($filename !~ /^\//) {
        my @tmppath = split(/\//, $curfile);
        splice(@tmppath, -1, 1, $filename);
        $filename = join('/', @tmppath);
    }

    if (!-f $filename) {
        error({
            code => 'E_REFERENCED_FILE_NOT_FOUND',
            file => $token->{'file'},
            line => $token->{'line'},
            include => $filename,
        });
    }

    open(my $fh, $filename) || error({
        code => 'E_REFERENCED_FOPEN_FAILED',
        file => $token->{'file'},
        line => $token->{'line'},
        include => $filename,
        reason => $!,
    });        

    my $values = [];
    while (<$fh>) {
        next if /^#/; # comments
        next if /^$/; # blank lines
        chomp;
        my $toks = lex($grammar, [$_]);
        unshift(@$values, $toks->[0]);
    }

    close($fh);

    # change this token
    $token->{'type'} = 'T_ARRAY';
    $token->{'value'} = $values;

    # splice out the filename token
    splice(@$line, $tpos+1, 1);
});


#
# Handle the mod clause
#
ontoken('T_CLAUSE_MOD', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }

    my $rule = getrule();
    my $mod = $line->[$tpos+1]->{'value'};

    my $nextt = $line->[$tpos+2];
    if ($nextt->{'type'} eq 'T_OPEN_PARENTHESIS') {
        handle('T_OPEN_PARENTHESIS', [$line->[$tpos+2], $tpos+2, $line]);
    }

    my $modopts = $line->[$tpos+1]->{'options'};
    my $matchexpr = [];
    foreach my $k (keys(%$modopts)) {
        my $expr = "--$k";
        if ($modopts->{$k} ne 'on') {
            $expr .= " '$modopts->{$k}'";
        }
        push(@$matchexpr, $expr);
    }

    push(@{$rule->{'matchexp'}}, "-m $mod ".join(" ", @$matchexpr));
});


#
# Handle the add clause
#
ontoken('T_CLAUSE_ADD', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }

    # make sure this is a set action (starts with T_ACTION_SET)
    if ($line->[0]->{'type'} ne 'T_ACTION_SET') {
        error({
            code => 'E_INVALID_ACTION',
            file => $token->{'file'},
            line => $token->{'line'},
            char => $token->{'char'},
            got  => $line->[0]->{'type'},
            reason => 'add only valid for set rules'
        });
    }

    my $setname = $line->[1]->{'value'};
    my $nextt = $line->[$tpos+1];

    if ($nextt->{'type'} eq 'T_ARRAY') {
        handle('T_ARRAY', [$nextt, $tpos+1, $line]);
        return;
    }

    my $rule = getrule();
    $rule->{'command'} = 'add';
    push(@{$rule->{'matchexp'}}, $nextt->{'value'});

    if (defined($line->[1]->{'options'})) {
        my $opts = $line->[1]->{'options'};

        if (defined($opts->{'timeout'})) {
            push(@{$rule->{'matchexp'}}, $opts->{'timeout'});
        }

        if (defined($opts->{'exist'}) && $opts->{'exist'} eq 'on') {
            $rule->{'command'} = '-exist add';
        }
    }
});


#
# Handle the add-to clause
#
ontoken('T_CLAUSE_ADD_TO', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }

    # make sure this is a match rule
    if ($line->[0]->{'type'} ne 'T_ACTION_MATCH') {
        error({
            code => 'E_INVALID_ACTION',
            file => $token->{'file'},
            line => $token->{'line'},
            char => $token->{'char'},
            got => $line->[0]->{'type'},
            reason => 'add-to online valid for match rules'
        });
    }

    my $rule = getrule();

    my $optt = $line->[$tpos+2];
    handle('T_OPEN_PARENTHESIS', [$optt, $tpos+2, $line]);

    my $sett = $line->[$tpos+1];

    $rule->{'target'} = 'SET';
    push(@{$rule->{'targetexp'}}, "--add-set $sett->{'value'}");

    # process options
    my $opts = {}; 
    if (defined($sett->{'options'})) {
        $opts = $sett->{'options'};
    }

    my $flags = getoption('set-flags');
    if (defined($opts->{'flags'})) {
        $flags = $opts->{'flags'};
    }

    push(@{$rule->{'targetexp'}}, $flags);
    
    if (defined($opts->{'timeout'})) {
        push(@{$rule->{'targetexp'}}, "--timeout $opts->{'timeout'}");
    }

    if (defined($opts->{'exist'}) && $opts->{'exist'} eq 'on') {
        push(@{$rule->{'targetexp'}}, "--exist");
    }

    my $setopts = getipset($sett->{'value'});
    $rule->{'family'} = $setopts->{'family'};
});


#
# Handle the del-from clause
#
ontoken('T_CLAUSE_DEL_FROM', sub {
    my $token = shift;
    my $tpos = shift;
    my $line = shift;

    if (ruleskipped()) { return; }

    # make sure this is a match rule
    if ($line->[0]->{'type'} ne 'T_ACTION_MATCH') {
        error({
            code => 'E_INVALID_ACTION',
            file => $token->{'file'},
            line => $token->{'line'},
            char => $token->{'char'},
            got => $line->[0]->{'type'},
            reason => 'del-from online valid for match rules'
        });
    }

    my $rule = getrule();

    my $optt = $line->[$tpos+2];
    handle('T_OPEN_PARENTHESIS', [$optt, $tpos+2, $line]);

    my $sett = $line->[$tpos+1];

    $rule->{'target'} = 'SET';
    push(@{$rule->{'targetexp'}}, "--del-set $sett->{'value'}");

    # process options
    my $opts = {}; 
    if (defined($sett->{'options'})) {
        $opts = $sett->{'options'};
    }

    my $flags = getoption('set-flags');
    if (defined($opts->{'flags'})) {
        $flags = $opts->{'flags'};
    }

    push(@{$rule->{'targetexp'}}, $flags);
});


1;
