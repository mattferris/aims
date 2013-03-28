#!/usr/bin/perl
#
# This module is part of aims, an iptables scripting language.
#
#
package Aims::Core;

use strict;
use warnings;

use File::Spec;

use Aims::Grammar qw($grammar);
use Aims::Error qw(error warn debug);

use Mexpar::Lexer qw(lex prepare);
use Mexpar::Parser qw(parse ontoken);
use Mexpar::Error qw(delegate mkerrmsg);

use Exporter qw(import);
our @EXPORT_OK = qw(compile);

my $curfile;

my $line;
my $lines = [];

my $rule = newrule();
my $ruleset = [];
my $compiled = [];

my $protocols = protocols();
my $interfaces = interfaces();
my $variables = {};
my $comment = '';

# prepare the grammar for use by lex()
prepare($grammar);

my $options = {
    'comment.inline' => 'off',
    'comment.origin' => 'off',
    'debug' => 'off',
    'log.level' => '',
    'log.prefix' => '',
    'log.tcp_sequence' => 'off',
    'log.tcp_options' => 'off',
    'log.uid' => 'off',
    'strict' => 'off',
};


#
#  Compile the rules store in $file.
#
#  $file The path to the rules file
#
#  Returns a list with lines of compiled output
#
sub compile
{
    my $file = shift;
    my $lastfile = $curfile;
    $curfile = $file;

    if (!(-f $file)) {
        error({code=>'E_FILE_NOT_FOUND', file=>$file});
    }

    open(my $fh, $file) || error('E_FOPEN_FAILED', $file);
    my $tokens = lex($grammar, $fh);
    close($fh);

    # break tokens into lines and process variables
    my $i = 0;
    my $j = 0;
    $lines->[0] = [];
    foreach my $t (@$tokens) {
        $t->{'file'} = $file;
        push(@{$lines->[$i]}, $t);
        $j++;
        if ($t->{'type'} =~ /T_NEWLINE|T_EOF/) {
            $i++;
            $lines->[$i] = [];
        }
    }

    while ($line = shift(@$lines)) {
        # replace any variables on the line
        my $i=0;
        foreach my $t (@$line) {
            if ($t->{'type'} eq 'T_VARIABLE') {
                my $varname = substr($t->{'value'}, 1);

                if (!defined($variables->{$varname})) {
                    error({
                        code => 'E_UNDEFINED_VARIABLE',
                        file => $t->{'file'},
                        line => $t->{'line'},
                        char => $t->{'char'},
                        name => $t->{'value'}
                    });
                }

                my $varval = $variables->{$varname};
                foreach my $vt (@$varval) {
                    $vt->{'file'} = $file;
                    $vt->{'line'} = $t->{'line'};
                    $vt->{'char'} = $t->{'char'};
                }
                splice(@$line, $i, 1, @$varval);
            }
            $i++;
        }

        # process any variable declarations
        my $hastokens = @$line > 1;
        my $vardef = $hastokens && $line->[0]->{'type'} eq 'T_STRING' && $line->[1]->{'type'} eq 'T_EQUALS';
        if ($vardef) {
            my $varname = $line->[0]->{'value'};
            my $varval = [];
            if ($line->[2]->{'type'} eq 'T_QUOTED_STRING') {
                 my $t = $line->[2];
                 $t->{'type'} = 'T_STRING';
                 push(@$varval, $t);
                 #$varval = lex($grammar, $tval);    
                 # get rid of T_EOF
                 #pop(@$varval);
            }
            else {
                for (my $i=2; $i<$#{$line}; $i++) {
                    push(@$varval, $line->[$i]);
                }
            }
            $variables->{$varname} = $varval;
        }

        # check that rule starts with an action or variable string
        my $comment = $hastokens && $line->[0]->{'type'} eq 'T_COMMENT';
        my $action = $hastokens && $line->[0]->{'type'} =~ /^T_ACTION.*/;
        if ($hastokens && !$comment && !$action && !$vardef) {
            error({
                code => 'E_BAD_FIRST_TOKEN',
                file => $line->[0]->{'file'},
                line => $line->[0]->{'line'},
                type => $line->[0]->{'type'},
                value => $line->[0]->{'value'},
            });
        }

        parse($grammar, $line);
    }

    foreach my $r (@$ruleset) {
        my $target = $r->{'target'};
        $target = '-j '.$target if $r->{'command'} ne '-P';
        my $mexp = join(' ', @{$r->{'matchexp'}});
        my $comment = "-m comment --comment '$r->{'comment'}'";
        my $texp = join(' ', @{$r->{'targetexp'}});
        my $cmd = "iptables $r->{'command'} $r->{'chain'}";
        $cmd .= " -t $r->{'table'}" if $r->{'table'} ne '';
        $cmd .= " $mexp" if $mexp ne '';
        $cmd .= " $comment" if $r->{'comment'} ne '';
        $cmd .= " $target";
        $cmd .= " $texp" if $texp ne '';
        push(@$compiled, $cmd);
    }

    $curfile = $lastfile;
    return $compiled;
}


#
# Load protocols from /etc/protocols
#
sub protocols
{
    my $protos = {};

    if (-f '/etc/protocols') {
        open(my $fh, '/etc/protocols')
            || error({code=>'E_FILE_READ_FAILED', file=>'/etc/protocols', reason=>$?});

        while (<$fh>) {
            my ($name, $rest) = split(/\s/);
            $protos->{$name} = 1;
        }

        close($fh);
    }
    else {
        # if we can't read /etc/protocols, use defaults
        $protos = {tcp=>1, udp=>1, icmp=>1, all=>1};
    }

    return $protos;
}


#
# Load interfaces
#
sub interfaces
{
    my $ifs;

    open(my $in, "ip address|")
        || error({code=>'E_PIPE_READ_FAILED', reason=>$?});

    my $curif;
    while (<$in>) {
        if (/^[0-9]+: ([^:]+):/) {
            $curif = $1;
            $ifs->{$curif} = {};
        }

        if (defined($curif)) {
            if (/^\slink\/ether\s([^\s]+)\s/) {
                $ifs->{$curif}->{'mac'} = $1;
            }
            elsif (/^\sinet\s([^\s]+)\s/) {
                my ($addr, $mask) = split(/\//, $1);
                $ifs->{$curif}->{'inet'} = $addr;
                $ifs->{$curif}->{'inetmask'} = $mask;
            }
            elsif (/^\sinet6\s([^\s]+)\s/) {
                my ($addr, $mask) = split(/\//, $1);
                $ifs->{$curif}->{'inet6'} = $addr;
                $ifs->{$curif}->{'inet6mask'} = $mask;
            }
        }
    }

    close($in);

    return $ifs;
}


#
# Return a new rule struct
#
sub newrule
{
    return {
        compile => 1, # rules like 'option' set this to 0 and are ignored
        command => '-A',
        chain => '',
        table => '',
        target => '',
        matchexp => [],
        comment => '',
        targetexp => [],
    };
}


#
# Create a deep copy of a list of tokens
#
sub copyline
{
    my $tokens = shift;

    my $newline = [];
    foreach my $t (@$tokens) {
        my $newt = {};
        foreach my $k (keys(%$t)) {
            $newt->{$k} = $t->{$k};
        }
        push(@$newline, $newt);
    }

    return $newline;
}


#
# Define a delegate error handler
#
delegate(sub {
    my $msg = mkerrmsg(@_);
    error("$curfile: $msg");
});


#
# Handle newline tokens which indicate the end of a rule,
# so check the current rule for validity, then compile it
# and add it to the output.
#
sub newlineeof {
    my $token = shift;
    my $valid = 1;
    my $errargs = {code=>'E_UNDEFINED'};

    my $tpos = shift;

    # ignore blank lines
    if ($token->{'char'} == 1) {
        # clear comments
        $comment = '';
        return 1;
    }

    # if the rule isn't flagged for compilation, ignore it
    if ($rule->{'compile'} == 0) {
        $rule = newrule();
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
            if ($options->{'comment.inline'} eq 'on' && $comment ne '') {
                $rule->{'comment'} = $comment;
            }
            elsif ($options->{'comment.origin'} eq 'on') {
                my $absfile = File::Spec->rel2abs($token->{'file'});
                $rule->{'comment'} = "$absfile:$token->{'line'}";
            }
        }
        push(@$ruleset, $rule);
        $rule = newrule();
    }
    else {
        error($errargs);
    }
}
ontoken('T_NEWLINE', \&newlineeof);
ontoken('T_EOF', \&newlineeof);


#
# Handle 'accept' clauses
#
ontoken('T_ACTION_ACCEPT', sub {
    $rule->{'target'} = 'ACCEPT';
});


#
# Handle 'drop' clauses
#
ontoken('T_ACTION_DROP', sub {
    $rule->{'target'} = 'DROP';
});


#
# Handle 'reject' clauses
#
ontoken('T_ACTION_REJECT', sub {
    $rule->{'target'} = 'REJECT';
});


#
# Handle 'policy' clauses
#
ontoken('T_ACTION_POLICY', sub {
    $rule->{'command'} = '-P';
});


#
# Handle 'option' clauses
#
ontoken('T_ACTION_OPTION', sub {
    my $token = shift;
    my $tpos = shift;
    my $tokens = shift;

    $rule->{'compile'} = 0;

    my $key = $tokens->[$tpos+1]->{'value'};
    my $val = $tokens->[$tpos+2]->{'value'};
    $options->{$key} = $val;
});


#
# Handle 'include' clauses
#
ontoken('T_ACTION_INCLUDE', sub {
    my $token = shift;
    my $tpos = shift;
    my $tokens = shift;

    $rule->{'compile'} = 0;

    my $file = $tokens->[$tpos+1]->{'value'};
    if (!-f $file) {
        error({
            code => 'E_INCLUDE_FILE_NOT_FOUND',
            file => $curfile,
            include => $file,
            line => $token->{'line'}
        });
    }
    else {
        open(my $in, $file)
            || error({
                code => 'E_INCLUDE_FOPEN_FAILED',
                file => $curfile,
                include => $file,
                line => $token->{'line'},
                reason => $?
            });

        my $lastfile = $curfile;
        $curfile = $file;

        $tokens = lex($grammar, $in);

        close($in);
        $curfile = $lastfile;

        my $newlines = [];
        my $line = [];
        foreach my $t (@$tokens) {
            $t->{'file'} = $file;
            push(@$line, $t);
            if ($t->{'type'} =~ /T_NEWLINE|T_EOF/) {
                push(@$newlines, $line);
                $line = [];
            }
        }

        while (my $l = pop(@$newlines)) {
            unshift(@$lines, $l);
        }
    }
});


#
# Handle 'for' clauses
#
ontoken('T_CLAUSE_FOR', sub {
    my $token = shift;
    my $tpos = shift;
    my $tokens = shift;

    if ($rule->{'compile'} == 0) { return; }

    if ($tokens->[$tpos+1]->{'type'} eq 'T_OPEN_BRACE') {
        bracelist($tpos+1, $tokens);
    }

    my $chain = $tokens->[$tpos+1]->{'value'};

    if ($chain eq 'input') {
        $chain = 'INPUT';
    }
    elsif ($chain eq 'output') {
        $chain = 'OUTPUT';
    }
    elsif ($chain eq 'forward') {
        $chain = 'FORWARD';
    }

    $rule->{'chain'} = $chain;
});


#
# Handle 'in' clauses
#
ontoken('T_CLAUSE_IN', sub {
    my $token = shift;
    my $tpos = shift;
    my $tokens = shift;

    if ($rule->{'compile'} == 0) { return; }

    if ($tokens->[$tpos+1]->{'type'} eq 'T_OPEN_BRACE') {
        bracelist($tpos+1, $tokens);
    }

    my $chain;
    my $ift = $tokens->[$tpos+1];
    my $if = $ift->{'value'};

    if (!defined($interfaces->{$if})) {
        warn({
            code => 'W_INTERFACE_NOT_FOUND',
            file => $ift->{'file'},
            line => $ift->{'line'},
            char => $ift->{'char'},
            value => $ift->{'value'}
        });
    }

    if ($rule->{'chain'} eq 'OUTPUT') {
        $chain = 'FORWARD';
    }
    else {
        $chain = 'INPUT';
    }

    $rule->{'chain'} = $chain;
    push(@{$rule->{'matchexp'}}, "-i $if");
});


#
# Handle 'out' clauses
#
ontoken('T_CLAUSE_OUT', sub {
    my $token = shift;
    my $tpos = shift;
    my $tokens = shift;

    if ($rule->{'compile'} == 0) { return; }

    if ($tokens->[$tpos+1]->{'type'} eq 'T_OPEN_BRACE') {
        bracelist($tpos+1, $tokens);
    }

    my $chain;
    my $ift = $tokens->[$tpos+1];
    my $if = $ift->{'value'};

    if (!defined($interfaces->{$if})) {
        warn({
            code => 'W_INTERFACE_NOT_FOUND',
            file => $ift->{'file'},
            line => $ift->{'line'},
            char => $ift->{'char'},
            value => $ift->{'value'}
        });
    }

    if ($rule->{'chain'} eq 'INPUT') {
        $chain = 'FORWARD';
    }
    else {
        $chain = 'OUTPUT';
    }

    $rule->{'chain'} = $chain;
    push(@{$rule->{'matchexp'}}, "-o $if");
});


#
# Handle 'proto' clauses
#
ontoken('T_CLAUSE_PROTO', sub {
    my $token = shift;
    my $tpos = shift;
    my $tokens = shift;

    if ($rule->{'compile'} == 0) { return; }

    if ($tokens->[$tpos+1]->{'type'} eq 'T_OPEN_BRACE') {
        bracelist($tpos+1, $tokens);
    }

    my $protot = $tokens->[$tpos+1];
    my $proto = $protot->{'value'};

    if (!defined($protocols->{$proto})) {
        my $err = {
             code => 'E_UNDEFINED_PROTOCOL',
             file => $protot->{'file'},
             line => $protot->{'line'},
             char => $protot->{'char'},
             proto => $protot->{'value'}
        };

        if ($options->{'strict'} eq 'on') {
            error($err);
        }
        else {
            warn($err);
        }
    }

    push(@{$rule->{'matchexp'}}, "-p $proto");
});


#
# Handle 'from' clauses
#
ontoken('T_CLAUSE_FROM', sub {
    my $token = shift;
    my $tpos = shift;
    my $tokens = shift;

    if ($rule->{'compile'} == 0) { return; }

    if ($tokens->[$tpos+1]->{'type'} eq 'T_OPEN_BRACE') {
        bracelist($tpos+1, $tokens);
    }

    my $nextt = $tokens->[$tpos+1];

    if ($nextt->{'type'} eq 'T_CLAUSE_PORT') {
        my $protospec = 0;
        foreach my $e (@{$rule->{'matchexp'}}) {
            if ($e =~ /^-p\s[a-z]+$/) {
                $protospec = 1;
            }
        }

        if ($protospec == 0) {
            my $err = {
                file => $nextt->{'file'},
                line => $nextt->{'line'},
                char => $nextt->{'char'}
            };

            if ($options->{'strict'} eq 'on') {
                $err->{'code'} = 'E_PORT_WITHOUT_PROTOCOL';
                error($err);
            }
            else {
                $err->{'code'} = 'W_PORT_WITHOUT_PROTOCOL';
                warn($err);
                push(@{$rule->{'matchexp'}}, '-p all');
            }
        }

        my $port = $tokens->[$tpos+2];
        if ($port->{'type'} eq 'T_OPEN_BRACE') {
            bracelist($tpos+2, $tokens);
        }
        else {
            push(@{$rule->{'matchexp'}}, "--sport $port->{'value'}");
        }
    }
    else {
        my $host = $nextt->{'value'};
        push(@{$rule->{'matchexp'}}, "-s $host");
    }
});


#
# Handle 'to' clauses
#
ontoken('T_CLAUSE_TO', sub {
    my $token = shift;
    my $tpos = shift;
    my $tokens = shift;

    if ($rule->{'compile'} == 0) { return; }

    if ($tokens->[$tpos+1]->{'type'} eq 'T_OPEN_BRACE') {
        bracelist($tpos+1, $tokens);
    }

    my $nextt = $tokens->[$tpos+1];

    if ($nextt->{'type'} eq 'T_CLAUSE_PORT') {
        my $protospec = 0;
        foreach my $e (@{$rule->{'matchexp'}}) {
            if ($e =~ /^-p\s[a-z]+$/) {
                $protospec = 1;
            }
        }

        if ($protospec == 0) {
            my $err = {
                file => $nextt->{'file'},
                line => $nextt->{'line'},
                char => $nextt->{'char'}
            };

            if ($options->{'strict'} eq 'on') {
                $err->{'code'} = 'E_PORT_WITHOUT_PROTOCOL';
                error($err);
            }
            else {
                $err->{'code'} = 'W_PORT_WITHOUT_PROTOCOL';
                warn($err);
                push(@{$rule->{'matchexp'}}, '-p all');
            }
        }

        my $port = $tokens->[$tpos+2];
        if ($port->{'type'} eq 'T_OPEN_BRACE') {
            bracelist($tpos+2, $tokens);
        }
        else {
            push(@{$rule->{'matchexp'}}, "--dport $port->{'value'}");
        }
    }
    else {
        my $host = $nextt->{'value'};
        push(@{$rule->{'matchexp'}}, "-d $host");
    }
});


#
# Handle 'state' clauses
#
ontoken('T_CLAUSE_STATE', sub {
    my $token = shift;
    my $tpos = shift;
    my $tokens = shift;

    if ($rule->{'compile'} == 0) { return; }

    if ($tokens->[$tpos+1]->{'type'} eq 'T_OPEN_BRACE') {
        bracelist($tpos+1, $tokens);
    }

    my $state = uc($tokens->[$tpos+1]->{'value'});

    push(@{$rule->{'matchexp'}}, "-m state --state $state");
});


#
# Handle 'log' clause
#
ontoken('T_CLAUSE_LOG', sub {
    my $token = shift;
    my $tpos = shift;
    my $tokens = shift;

    if ($rule->{'compile'} == 0) { return; }

    if ($tokens->[0]->{'type'} ne 'T_ACTION_MATCH') {
        $rule->{'compile'} = 0;
        my $logline = copyline($tokens);
        my $origline = copyline($tokens);

        # remove the paren list from the original rule
        my $haslogopts = 0;
        if ($origline->[$tpos+1]->{'type'} eq 'T_OPEN_PARENTHESIS') {
            $haslogopts = 1;
            parenlist($tpos+1, $origline);
        }

        # remove the log clause from the original rule
        # and re-add it
        splice(@$origline, $tpos, 1);
        unshift(@$lines, $origline);

        $logline->[0]->{'type'} = 'T_ACTION_MATCH';
        $logline->[0]->{'value'} = 'match';

        # add the new match rule
        unshift(@$lines, $logline);
    }
    else {
        $rule->{'target'} = 'LOG';

        # copy global logging options
        my $opts = {};
        my $keys = ['log.level', 'log.prefix', 'log.tcp_sequence', 'log.tcp_options', 'log.uid'];
        foreach my $k (@$keys) {
            $opts->{$k} = $options->{$k};
        }

        # process supplied options via parenthesis ()
        if ($tokens->[$tpos+1]->{'type'} eq 'T_OPEN_PARENTHESIS') {
            my $logopts = parenlist($tpos+1, $tokens);
            foreach my $k (keys(%$logopts)) {
                $opts->{$k} = $logopts->{$k};
            }
        }

        # include logging options in the rule
        if ($opts->{'log.level'} ne '') {
            push(@{$rule->{'targetexp'}}, "--log-level $opts->{'log.level'}");
        }
        if ($opts->{'log.prefix'} ne '') {
            push(@{$rule->{'targetexp'}}, "--log-prefix '$opts->{'log.prefix'}'");
        }
        if ($opts->{'log.tcp_sequence'} eq 'on') {
            push(@{$rule->{'targetexp'}}, "--log-tcp-sequence");
        }
        if ($opts->{'log.tcp_options'} eq 'on') {
            push(@{$rule->{'targetexp'}}, "--log-tcp-options");;
        }
        if ($opts->{'log.uid'} eq 'on') {
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
    my $tokens = shift;

    if ($rule->{'compile'} == 0) { return; }

    $rule->{'compile'} = 0; 

    my $newline = [];
    for (my $i=0; $i<@$tokens; $i++) {
        my $t = $tokens->[$i];
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
    unshift(@$lines, $newline);

    # add the original rule without the reverse clause
    my $origline = copyline($tokens);
    splice(@$origline, $tpos, 1);
    unshift(@$lines, $origline);
});


#
# Handle 'rdr-to' clauses
#
ontoken('T_CLAUSE_RDR_TO', sub {
    my $token = shift;
    my $tpos = shift;
    my $tokens = shift;

    if ($rule->{'compile'} == 0) { return; }

    if ($tokens->[0]->{'type'} eq 'T_ACTION_MATCH') {
        if ($rule->{'chain'} eq '') {
            $rule->{'chain'} = 'PREROUTING';
        }
        elsif ($rule->{'chain'} !~ /^OUTPUT|PREROUTING$/) {
            # see if the chain was set explicity by 'for'
            my $isfor = 0;
            foreach my $t (@$tokens) {
                if ($t->{'type'} eq 'T_CLAUSE_FOR') {
                    $isfor = 1;
                    last;
                }
            }

            # if the chain was set explicity by 'for', then we need to
            # show an error, otherwise it was set implicity by 'in' or 'out'
            # and it's safe to change without an error
            if ($isfor == 1) {
                my $err = {
                    code => 'E_INVALID_CHAIN',
                    file => $token->{'file'},
                    line => $token->{'line'},
                    got => $rule->{'chain'},
                    reason => 'rdr-to only valid for prerouting and output chains'
                };

                if ($options->{'strict'} eq 'on') {
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

            if ($options->{'strict'} eq 'on') { error($err); }
            else { warn($err); }
        }

        $rule->{'table'} = 'nat';
        $rule->{'target'} = 'DNAT';
        my $peek = $tokens->[$tpos+1];

        # port only redirect
        if ($peek->{'type'} eq 'T_CLAUSE_PORT') {
            my $port = $tokens->[$tpos+2]->{'value'};
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
            my $exp = "--to-destination $peek->{'value'}";
            # are we setting a port as well?
            my $peek2 = $tokens->[$tpos+2];
            if (defined($peek2) && $peek2->{'type'} eq 'T_CLAUSE_PORT') {
                $exp .= ":$tokens->[$tpos+3]->{'value'}";
            }
            push(@{$rule->{'targetexp'}}, $exp);
        }
    }
    else {
        $rule->{'compile'} = 0;

        my $origline = copyline($tokens);
        my $newline = copyline($tokens);

        my $peek = $tokens->[$tpos+1];
        my $peek2 = $tokens->[$tpos+2];
        my $splicelen = 2;
        if (defined($peek2) && $peek2->{'type'} eq 'T_CLAUSE_PORT') {
            $splicelen = 4;
        }
        elsif ($peek->{'type'} eq 'T_CLAUSE_PORT') {
            $splicelen = 3;
        }

        splice(@$origline, $tpos, $splicelen);
        unshift(@$lines, $origline);

        $newline->[0]->{'type'} = 'T_ACTION_MATCH';
        $newline->[0]->{'value'} = 'match';
        unshift(@$lines, $newline);
    }
});


#
# Handle 'nat-to' clauses
#
ontoken('T_CLAUSE_NAT_TO', sub {
    my $token = shift;
    my $tpos = shift;
    my $tokens = shift;

    if ($rule->{'compile'} == 0) { return; }

    if ($tokens->[0]->{'type'} eq 'T_ACTION_MATCH') {
        if ($rule->{'chain'} ne '' && $rule->{'chain'} ne 'POSTROUTING') {
            # see if the chain was set explicity by 'for'
            my $isfor = 0;
            foreach my $t (@$tokens) {
                if ($t->{'type'} eq 'T_CLAUSE_FOR') {
                    $isfor = 1;
                    last;
                }
            }

            # if the chain was set explicity by 'for', then we need to
            # show an error, otherwise it was set implicity by 'in' or 'out'
            # and it's safe to change without an error
            if ($isfor == 1) {
                my $err = {
                    code => 'E_INVALID_CHAIN',
                    file => $token->{'file'},
                    line => $token->{'line'},
                    got => $rule->{'chain'},
                    reason => 'nat-to only valid for postrouting chain'
                };

                if ($options->{'strict'} eq 'on') {
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

            if ($options->{'strict'} eq 'on') { error($err); }
            else { warn($err); }
        }

        $rule->{'chain'} = 'POSTROUTING';
        $rule->{'table'} = 'table';
        $rule->{'target'} = 'SNAT';
        my $peek = $tokens->[$tpos+1];

        # port only redirect
        if ($peek->{'type'} eq 'T_CLAUSE_PORT') {
            my $port = $tokens->[$tpos+2]->{'value'};
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
            my $exp = "--to-source $peek->{'value'}";
            # are we setting a port as well?
            my $peek2 = $tokens->[$tpos+2];
            if (defined($peek2) && $peek2->{'type'} eq 'T_CLAUSE_PORT') {
                $exp .= ":$tokens->[$tpos+3]->{'value'}";
            }
            push(@{$rule->{'targetexp'}}, $exp);
        }
    }
    else {
        $rule->{'compile'} = 0;

        my $origline = copyline($tokens);
        my $newline = copyline($tokens);

        my $peek = $tokens->[$tpos+1];
        my $peek2 = $tokens->[$tpos+2];
        my $splicelen = 2;
        if (defined($peek2) && $peek2->{'type'} eq 'T_CLAUSE_PORT') {
            $splicelen = 4;
        }
        elsif ($peek->{'type'} eq 'T_CLAUSE_PORT') {
            $splicelen = 3;
        }

        splice(@$origline, $tpos, $splicelen);
        unshift(@$lines, $origline);

        $newline->[0]->{'type'} = 'T_ACTION_MATCH';
        $newline->[0]->{'value'} = 'match';
        unshift(@$lines, $newline);
    }
});


#
# Handle equals '='
#
ontoken('T_EQUALS', sub {
    $rule->{'compile'} = 0;
});


#
# Handle comments
#
ontoken('T_COMMENT', sub {
    my $token = shift;
    my $tpos = shift;
    my $tokens = shift;

    $rule->{'compile'} = 0;
    if ($options->{'comment.inline'} ne 'on') {
        return;
    }
    else {
        my $cmt = $token->{'value'};
        $cmt =~ s/^\s+|\s+$//;
        $comment = $cmt;
    }
});


#
# Handle brace lists
#
sub bracelist
{
    my $tpos = shift;
    my $tokens = shift;

    my $list = [];

    # start at the next token, which is the first list item
    my $bracelen = 1;
    for (my $i=1; $i<@$tokens; $i++) {
        if ($tokens->[$tpos+$i]->{'type'} eq 'T_CLOSE_BRACE') {
            $bracelen++;
            last;
        }
        if ($tokens->[$tpos+$i]->{'type'} ne 'T_COMMA') {
            push(@$list, $tokens->[$tpos+$i]);
        }
        $bracelen++;
    }

    # use reverse to put the new rules in the order the values are in the list
    foreach my $e (reverse(@$list)) {
        my $newline = copyline($tokens);
        splice(@$newline, $tpos, $bracelen, $e);
        unshift(@$lines, $newline);
    }

    # don't compile the current rule
    if (@$list > 0) {
        $rule->{'compile'} = 0;
    }
}


#
# Handle parenthesis lists
#
sub parenlist
{
    my $tpos = shift;
    my $tokens = shift;

    my $opts = {};

    # start at the next token, which is the first option/value pair
    my $parenlen = 1;
    for (my $i=1; $i<@$tokens; $i++) {
        if ($tokens->[$tpos+$i]->{'type'} eq 'T_CLOSE_PARENTHESIS') {
            $parenlen++;
            last;
        }
        if ($tokens->[$tpos+$i]->{'type'} ne 'T_COMMA') {
            my $opt = $tokens->[$tpos+$i]->{'value'};
            my $val = $tokens->[$tpos+$i+1]->{'value'};
            $opts->{$opt} = $val;
            $i++;
        }
        $parenlen++;
    }

    splice(@$tokens, $tpos, $parenlen);

    return $opts;
}


1;
