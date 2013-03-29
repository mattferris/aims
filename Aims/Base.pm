#!/usr/bin/perl
#
# This module is part of aims, an iptables scripting language.
#
#
package Aims::Base;

use strict;
use warnings;

use Aims::Main qw(
    compile
    newrule getrule skiprule ruleskipped getruleset
    setcomment getcomment
    ifexists protoexists bracelist parenlist
    getoption setoption
    addline copyline
    newscope getscope endscope
);
use Aims::Error qw(error warn debug);
use Mexpar::Lexer qw(lex);
use Mexpar::Parser qw(ontoken);

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
    if ($rule->{'target'} eq '') {
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
    newscope();
    my $file = $line->[$tpos+1]->{'value'};
    if (!-f $file) {
        error({
            code => 'E_INCLUDE_FILE_NOT_FOUND',
            file => $curfile,
            include => $file,
            line => $token->{'line'}
        });
    }
    else {
        compile($file);
    }
    endscope();
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
            parenlist($tpos+1, $origline);
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
        if ($line->[$tpos+1]->{'type'} eq 'T_OPEN_PARENTHESIS') {
            my $logopts = parenlist($tpos+1, $line);
            foreach my $k (keys(%$logopts)) {
                $opts->{$k} = $logopts->{$k};
            }
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
        if ($t->{'type'} eq 'T_CLAUSE_FOR') {
            push(@$newline, $t);

            $i++;
            my $t = $line->[$i];
            my $newt = {
                type => $t->{'type'},
                line => $t->{'line'},
                char => $t->{'char'}
            };

            if ($t->{'value'} eq 'input') {
                $newt->{'value'} = 'output';
            }
            elsif ($t->{'value'} eq 'output') {
                $newt->{'value'} = 'input';
            }
            else {
                $newt->{'value'} = $t->{'value'};
            }

            push(@$newline, $newt);
        }
        elsif ($t->{'type'} eq 'T_CLAUSE_IN') {
            my $newt = {
                type => 'T_CLAUSE_OUT',
                line => $t->{'line'},
                char => $t->{'char'},
                value => 'out'
            };
            push(@$newline, $newt);
        }
        elsif ($t->{'type'} eq 'T_CLAUSE_OUT') {
            my $newt = {
                type => 'T_CLAUSE_IN',
                line => $t->{'line'},
                char => $t->{'char'},
                value => 'in'
            };
            push(@$newline, $newt);
        }
        elsif ($t->{'type'} eq 'T_CLAUSE_TO') {
            my $newt = {
                type => 'T_CLAUSE_FROM',
                line => $t->{'line'},
                char => $t->{'char'},
                value => 'from'
            };
            push(@$newline, $newt);
        }
        elsif ($t->{'type'} eq 'T_CLAUSE_FROM') {
            my $newt = {
                type => 'T_CLAUSE_TO',
                line => $t->{'line'},
                char => $t->{'char'},
                value => 'to'
            };
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
# Handle equals '='
#
ontoken('T_EQUALS', sub {
    skiprule();
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
        $cmt =~ s/^\s+|\s+$//;
        setcomment($cmt);
    }
});


1;
