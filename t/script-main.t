use strictures 2;

use Capture::Tiny qw(capture);
use Test2::V0;

use Overnet::Program::IRC::Script::Main;

sub _run {
  my (@argv) = @_;
  my ($stdout, $stderr, $exit) = capture {
    Overnet::Program::IRC::Script::Main->run(@argv);
  };
  return {
    stdout => $stdout,
    stderr => $stderr,
    exit   => $exit,
  };
}

subtest '--help and -h print usage to stdout' => sub {
  for my $flag ('--help', '-h') {
    my $run = _run($flag);
    is $run->{exit}, 0, "$flag exits successfully";
    like $run->{stdout}, qr/Usage:/mxs,                  "$flag prints usage";
    like $run->{stdout}, qr/authority-relay-service/mxs, "$flag lists every command";
    is $run->{stderr}, q{}, "$flag writes nothing to stderr";
  }
};

subtest 'help without a command prints usage to stdout' => sub {
  my $run = _run('help');
  is $run->{exit}, 0, 'bare help exits successfully';
  like $run->{stdout}, qr/Usage:/mxs, 'bare help prints usage';
};

subtest 'help with extra arguments is rejected' => sub {
  my $run = _run('help', 'auth', 'extra');
  is $run->{exit}, 1, 'help with extra arguments fails';
  like $run->{stderr}, qr/Usage:\ overnet-irc-server\ help/mxs, 'the help usage line is printed to stderr';
};

subtest 'help with an unknown command is rejected' => sub {
  my $run = _run('help', 'frobnicate');
  is $run->{exit}, 1, 'help for an unknown command fails';
  like $run->{stderr}, qr/Unknown\ overnet-irc-server\ command:\ frobnicate/mxs, 'the unknown command is named';
};

subtest 'help with a known command dispatches --help' => sub {
  my $run = _run('help', 'auth');
  is $run->{exit}, 0, 'help auth exits successfully';
  like $run->{stdout}, qr/overnet-irc-server\ auth\ bridge/mxs, 'the auth subcommand usage is printed';
};

subtest 'a missing command prints usage to stderr' => sub {
  my $run = _run();
  is $run->{exit}, 1, 'no command fails';
  like $run->{stderr}, qr/Usage:/mxs, 'usage goes to stderr';

  my $empty = _run(q{});
  is $empty->{exit}, 1, 'an empty command fails';
  like $empty->{stderr}, qr/Usage:/mxs, 'usage goes to stderr for an empty command';
};

subtest 'an unknown command prints usage to stderr' => sub {
  my $run = _run('frobnicate');
  is $run->{exit}, 1, 'an unknown command fails';
  like $run->{stderr}, qr/Unknown\ overnet-irc-server\ command:\ frobnicate/mxs, 'the unknown command is named';
  like $run->{stderr}, qr/Usage:/mxs, 'usage follows the error';
};

subtest 'a known command is dispatched with its arguments' => sub {
  my $run = _run('auth', '--help');
  is $run->{exit}, 0, 'auth --help exits successfully';
  like $run->{stdout}, qr/overnet-irc-server\ auth\ bridge/mxs, 'the auth subcommand handled the dispatch';
};

subtest 'a command whose module cannot load croaks' => sub {
  my $module_file = 'Overnet/Program/IRC/Script/ChatClient.pm';
  ok !$INC{$module_file}, 'the chat-client module is not yet loaded'
    or bail_out('chat-client was loaded early; pick another command for the load-failure path');

  local @INC = (
    sub {
      my (undef, $file) = @_;
      die "forced load failure for $file\n" if $file eq $module_file;
      return;
    },
    @INC,
  );

  like dies { Overnet::Program::IRC::Script::Main->run('chat-client') },
    qr/forced\ load\ failure/mxs, 'a module load failure is propagated as an exception';
};

done_testing;
