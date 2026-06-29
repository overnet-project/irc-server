#!/usr/bin/env perl
use strictures 2;
use FindBin;
use lib grep {-d} ("$FindBin::Bin/../lib",);

use Overnet::Program::IRC::Script::ChatClient;

our $VERSION = '0.001';

exit Overnet::Program::IRC::Script::ChatClient->run(@ARGV);
