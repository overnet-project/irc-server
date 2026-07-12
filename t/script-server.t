use strictures 2;

use Capture::Tiny qw(capture);
use Test2::V0;

use Overnet::Program::IRC::Script::Server;

sub _run {
  my (@argv) = @_;
  my ($stdout, $stderr, $exit) = capture {
    Overnet::Program::IRC::Script::Server->run(@argv);
  };
  return {
    stdout => $stdout,
    stderr => $stderr,
    exit   => $exit,
  };
}

subtest '--help prints usage to stdout' => sub {
  my $run = _run('--help');
  is $run->{exit}, 0, '--help exits successfully';
  like $run->{stdout}, qr/overnet-irc-server\ server/mxs, 'usage names the server command';
  is $run->{stderr}, q{}, 'nothing goes to stderr';
};

subtest 'unexpected arguments print usage to stderr' => sub {
  my $run = _run('--frobnicate');
  is $run->{exit}, 1, 'unexpected arguments fail';
  like $run->{stderr}, qr/overnet-irc-server\ server/mxs, 'usage goes to stderr';
  is $run->{stdout}, q{}, 'nothing goes to stdout';
};

subtest 'a clean server run returns success' => sub {
  my $ran  = 0;
  my $mock = mock 'Overnet::Program::IRC::Server' => (override => [run => sub { $ran++; return 1 },],);
  is +Overnet::Program::IRC::Script::Server->run, 0, 'a normally returning server run exits successfully';
  is $ran, 1, 'the server run method was invoked';
};

subtest 'a shutdown sentinel from the server is treated as success' => sub {
  my $mock = mock 'Overnet::Program::IRC::Server' => (override => [run => sub { die '__shutdown__' },],);
  is +Overnet::Program::IRC::Script::Server->run, 0, 'a shutdown sentinel exits successfully';

  my $located = mock 'Overnet::Program::IRC::Server' =>
    (override => [run => sub { die '__shutdown__ at lib/Server.pm line 1.' },],);
  is +Overnet::Program::IRC::Script::Server->run, 0, 'a shutdown sentinel with a location exits successfully';
};

subtest 'unexpected server errors are propagated' => sub {
  my $mock = mock 'Overnet::Program::IRC::Server' => (override => [run => sub { die "listener exploded\n" },],);
  like dies { Overnet::Program::IRC::Script::Server->run }, qr/listener\ exploded/mxs,
    'a non-shutdown error croaks';
};

done_testing;
