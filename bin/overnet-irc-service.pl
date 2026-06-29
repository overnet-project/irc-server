#!/usr/bin/env perl
use strictures 2;
use FindBin;
use lib grep {-d} ("$FindBin::Bin/../lib", "$FindBin::Bin/../../core-perl/lib",);

use Overnet::Program::IRC::Script::Service;

our $VERSION = '0.001';

exit Overnet::Program::IRC::Script::Service->run(@ARGV);
