package Mex::Grammars::foo;

use strict;
use warnings;

use vars qw($grammar);

$grammar = [
  {
    'type' => 'T_WHITESPACE',
    'pattern' => '^\s+$',
  },
  {
    'type' => 'T_ACTION',
    'pattern' => '^([a-z_]+)$',
    'sub' => [
      {
        'type' => 'T_ACTION_ACCEPT',
        'pattern' => 'accept',
      },
      {
        'type' => 'T_ACTION_IN',
        'pattern' => 'in',
      },
    ],
  },
];

1;
