use strictures 2;

use File::Spec;
use File::Temp qw(tempdir);
use FindBin;
use JSON ();
use Test2::V0;

use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/../../core-perl/lib";

use Overnet::Program::IRC::Script::Connect;

# Connecting took two terminals: one holding the auth agent in the foreground,
# another holding the proxy, with the socket path repeated between them. That is
# the last piece of ceremony between a configured user and their IRC client.
#
# The parts that matter are not the convenience. An agent left running after the
# proxy exits holds a user's signing key in memory indefinitely, and a wrapper
# that starts a second agent against an endpoint already in use produces a
# confusing failure instead of just working. Both are pinned here.
#
# The spawn and serve steps are monkeypatched, as the proxy's own smoke test
# does with its listening socket: this asserts the orchestration, not the
# ability of this container to run daemons.

sub _config_file {
  my (%args)   = @_;
  my $dir      = tempdir(CLEANUP => 1);
  my $path     = File::Spec->catfile($dir, 'auth-agent.json');
  my $endpoint = $args{endpoint} // File::Spec->catfile($dir, 'auth.sock');

  open my $fh, '>', $path or die "open: $!";
  print {$fh} JSON->new->encode({daemon => {endpoint => $endpoint}, identities => [], policies => [],})
    or die "print: $!";
  close $fh or die "close: $!";
  return ($path, $endpoint);
}

sub _capture {
  my (@argv) = @_;
  my ($out, $err) = (q{}, q{});
  my $status;
  {
    local *STDOUT;
    local *STDERR;
    open STDOUT, '>', \$out or die "reopen stdout: $!";
    open STDERR, '>', \$err or die "reopen stderr: $!";
    $status = Overnet::Program::IRC::Script::Connect->run(@argv);
  }
  return ($status, $out, $err);
}

subtest 'the socket comes from the config, not from a guess' => sub {
  my ($config, $endpoint) = _config_file();
  my @spawned;
  my $seen_sock;

  no warnings 'redefine';
  local *Overnet::Program::IRC::Script::Connect::_spawn_agent = sub {
    my (%args) = @_;
    push @spawned, $args{config_file};
    return 4242;
  };
  local *Overnet::Program::IRC::Script::Connect::_agent_listening = sub {0};
  local *Overnet::Program::IRC::Script::Connect::_await_agent     = sub {1};
  local *Overnet::Program::IRC::Script::Connect::_run_proxy       = sub {
    $seen_sock = $ENV{OVERNET_AUTH_SOCK};
    return 0;
  };
  local *Overnet::Program::IRC::Script::Connect::_stop_agent = sub {1};

  my ($status) = _capture('--config-file', $config);

  is $status,    0,         'connecting succeeds';
  is \@spawned,  [$config], 'the agent is started from the given config';
  is $seen_sock, $endpoint, 'the proxy is pointed at the endpoint the config declares';
};

subtest 'an agent that is already listening is reused, not duplicated' => sub {
  my ($config) = _config_file();
  my $spawns = 0;

  no warnings 'redefine';
  local *Overnet::Program::IRC::Script::Connect::_agent_listening = sub {1};
  local *Overnet::Program::IRC::Script::Connect::_spawn_agent     = sub { $spawns++; return 1 };
  local *Overnet::Program::IRC::Script::Connect::_run_proxy       = sub {0};
  my $stopped = 0;
  local *Overnet::Program::IRC::Script::Connect::_stop_agent = sub { $stopped++; return 1 };

  my ($status, $out) = _capture('--config-file', $config);

  is $status,  0, 'connecting succeeds against a running agent';
  is $spawns,  0, 'no second agent is started for an endpoint already in use';
  is $stopped, 0, 'and an agent this command did not start is left running';
  like $out, qr/already\ running/imx, 'the reuse is stated rather than silent';
};

# An agent holds the user's signing key. One left behind after the proxy exits
# keeps that key in memory with nothing watching it.
subtest 'an agent this command started is stopped when the proxy exits' => sub {
  my ($config) = _config_file();
  my @stopped;

  no warnings 'redefine';
  local *Overnet::Program::IRC::Script::Connect::_agent_listening = sub {0};
  local *Overnet::Program::IRC::Script::Connect::_spawn_agent     = sub {4242};
  local *Overnet::Program::IRC::Script::Connect::_await_agent     = sub {1};
  local *Overnet::Program::IRC::Script::Connect::_run_proxy       = sub {0};
  local *Overnet::Program::IRC::Script::Connect::_stop_agent      = sub {
    my (%args) = @_;
    push @stopped, $args{pid};
    return 1;
  };

  my ($status) = _capture('--config-file', $config);
  is $status,   0,      'connecting succeeds';
  is \@stopped, [4242], 'the agent that was started is stopped again';
};

subtest 'a proxy that dies still takes the agent down with it' => sub {
  my ($config) = _config_file();
  my @stopped;

  no warnings 'redefine';
  local *Overnet::Program::IRC::Script::Connect::_agent_listening = sub {0};
  local *Overnet::Program::IRC::Script::Connect::_spawn_agent     = sub {77};
  local *Overnet::Program::IRC::Script::Connect::_await_agent     = sub {1};
  local *Overnet::Program::IRC::Script::Connect::_run_proxy       = sub { die "proxy exploded\n" };
  local *Overnet::Program::IRC::Script::Connect::_stop_agent      = sub {
    my (%args) = @_;
    push @stopped, $args{pid};
    return 1;
  };

  my ($status, undef, $err) = _capture('--config-file', $config);

  isnt $status, 0, 'the failure is reported';
  like $err, qr/proxy\ exploded/mx, 'with the reason';
  is \@stopped, [77], 'and the agent is not orphaned by the failure';
};

subtest 'an agent that never comes up is a clear failure, not a hang' => sub {
  my ($config) = _config_file();
  my @stopped;
  my $proxy_ran = 0;

  no warnings 'redefine';
  local *Overnet::Program::IRC::Script::Connect::_agent_listening = sub {0};
  local *Overnet::Program::IRC::Script::Connect::_spawn_agent     = sub {99};
  local *Overnet::Program::IRC::Script::Connect::_await_agent     = sub {0};
  local *Overnet::Program::IRC::Script::Connect::_run_proxy       = sub { $proxy_ran++; return 0 };
  local *Overnet::Program::IRC::Script::Connect::_stop_agent      = sub {
    my (%args) = @_;
    push @stopped, $args{pid};
    return 1;
  };

  my ($status, undef, $err) = _capture('--config-file', $config);

  isnt $status, 0, 'the command fails';
  like $err, qr/did\ not\ start/imx, 'saying the agent never came up';
  is $proxy_ran, 0,    'the proxy is not run against an agent that is not there';
  is \@stopped,  [99], 'and the half-started agent is cleaned up';
};

subtest 'unrecognized options are handed to the proxy' => sub {
  my ($config) = _config_file();
  my $forwarded;

  no warnings 'redefine';
  local *Overnet::Program::IRC::Script::Connect::_agent_listening = sub {1};
  local *Overnet::Program::IRC::Script::Connect::_run_proxy       = sub {
    my (%args) = @_;
    $forwarded = $args{argv};
    return 0;
  };
  local *Overnet::Program::IRC::Script::Connect::_stop_agent = sub {1};

  _capture('--config-file', $config, '--server-host', 'irc.example.net', '--server-port', '6697', '--server-tls');

  is $forwarded, ['--server-host', 'irc.example.net', '--server-port', '6697', '--server-tls'],
    'the proxy receives the options this command does not own';
};

subtest 'a missing config says how to create one' => sub {
  my $dir = tempdir(CLEANUP => 1);
  my ($status, undef, $err) = _capture('--config-file', File::Spec->catfile($dir, 'absent.json'));

  isnt $status, 0, 'the command fails';
  like $err, qr/auth\ init/mx, 'and points at the command that writes the config';
};

# Ctrl-C is how a person stops a foreground command, so this is the ordinary
# exit path, not an edge case. Before the handler existed, interrupting connect
# left the agent -- and the user's signing key with it -- running unattended.
subtest 'interrupting the command takes the agent down too' => sub {
  my ($config) = _config_file();
  my @stopped;

  no warnings 'redefine';
  local *Overnet::Program::IRC::Script::Connect::_agent_listening = sub {0};
  local *Overnet::Program::IRC::Script::Connect::_spawn_agent     = sub {555};
  local *Overnet::Program::IRC::Script::Connect::_await_agent     = sub {1};
  local *Overnet::Program::IRC::Script::Connect::_stop_agent      = sub {
    my (%args) = @_;
    push @stopped, $args{pid};
    return 1;
  };

  my $handler;
  local *Overnet::Program::IRC::Script::Connect::_run_proxy = sub {
    $handler = $SIG{INT};
    return 0;
  };

  _capture('--config-file', $config);

  is ref($handler), 'CODE', 'an interrupt handler is in place while the proxy runs';

  # The handler exits the process, so the work it does before exiting is what
  # gets exercised here.
  @stopped = ();
  Overnet::Program::IRC::Script::Connect::_signal_cleanup(555);
  is \@stopped, [555], 'interrupting stops the agent this command started';

  @stopped = ();
  is Overnet::Program::IRC::Script::Connect::_signal_cleanup(undef), 0,
    'and an interrupt with no agent of ours to stop does nothing';
  is \@stopped, [], 'stopping nothing kills nothing';
};

subtest 'the agent is startable from a source checkout, not only an install' => sub {

  # make install marks overnet-auth-agent.pl executable; a from-source checkout,
  # which is how this project documents installing, leaves it mode 644. Running
  # it directly then fails on permissions, so the interpreter already running is
  # tried as well.
  my ($direct, $via_perl) = Overnet::Program::IRC::Script::Connect::_agent_exec_candidates(
    agent_command => 'overnet-auth-agent.pl',
    config_file   => '/tmp/agent.json',
  );

  is $direct, ['overnet-auth-agent.pl', '--config-file', '/tmp/agent.json'], 'the agent is run directly first';
  is $via_perl, [$^X, 'overnet-auth-agent.pl', '--config-file', '/tmp/agent.json'],
    'and through this perl if that cannot be executed';
};

# Everything above monkeypatches the process handling to assert the
# orchestration. These drive the real thing against a stand-in agent: a script
# that binds the configured socket and waits, which is all connect needs an
# agent to do.
subtest 'the process handling works against a real agent' => sub {
  my ($config, $endpoint) = _config_file();
  my $dir   = File::Spec->catdir((File::Spec->splitpath($config))[0, 1]);
  my $agent = File::Spec->catfile($dir, 'stand-in-agent.pl');

  open my $fh, '>', $agent or die "open: $!";
  print {$fh} <<'AGENT' or die "print: $!";
use strict; use warnings;
use IO::Socket::UNIX; use JSON ();
my (undef, $config) = @ARGV;
open my $in, '<', $config or die "open: $!";
my $json = do { local $/ = undef; <$in> };
close $in or die;
my $endpoint = JSON->new->decode($json)->{daemon}{endpoint};
unlink $endpoint;
my $sock = IO::Socket::UNIX->new(Local => $endpoint, Listen => 5) or die "listen: $!";
sleep 300;
AGENT
  close $fh or die "close: $!";

  ok !Overnet::Program::IRC::Script::Connect::_agent_listening(endpoint => $endpoint),
    'nothing is listening before the agent starts';

  my $pid = Overnet::Program::IRC::Script::Connect::_spawn_agent(
    agent_command => $agent,
    config_file   => $config,
  );
  ok $pid, 'the agent is spawned';

  ok Overnet::Program::IRC::Script::Connect::_await_agent(endpoint => $endpoint, pid => $pid),
    'waiting returns once it is listening';
  ok Overnet::Program::IRC::Script::Connect::_agent_listening(endpoint => $endpoint), 'and the endpoint answers';

  ok Overnet::Program::IRC::Script::Connect::_stop_agent(pid => $pid),                 'the agent is stopped';
  ok !Overnet::Program::IRC::Script::Connect::_agent_listening(endpoint => $endpoint), 'and stops answering';
};

subtest 'waiting gives up on an agent that exits instead of listening' => sub {
  my ($config, $endpoint) = _config_file();
  my $dir  = File::Spec->catdir((File::Spec->splitpath($config))[0, 1]);
  my $dead = File::Spec->catfile($dir, 'exits-immediately.pl');

  open my $fh, '>', $dead or die "open: $!";
  print {$fh} "exit 3;\n" or die "print: $!";
  close $fh               or die "close: $!";

  my $pid = Overnet::Program::IRC::Script::Connect::_spawn_agent(
    agent_command => $dead,
    config_file   => $config,
  );
  ok $pid, 'the child is spawned';

  # Without noticing the exit this would sit out the whole timeout for an agent
  # that is never coming.
  ok !Overnet::Program::IRC::Script::Connect::_await_agent(endpoint => $endpoint, pid => $pid),
    'waiting reports failure as soon as the child is gone';
};

subtest 'reading the endpoint out of a config' => sub {
  my ($config, $endpoint) = _config_file();
  is Overnet::Program::IRC::Script::Connect::_endpoint_from_config($config), $endpoint,
    'the configured endpoint is returned';

  my $dir    = File::Spec->catdir((File::Spec->splitpath($config))[0, 1]);
  my $no_dmn = File::Spec->catfile($dir, 'no-daemon.json');
  open my $fh, '>', $no_dmn or die "open: $!";
  print {$fh} '{"identities":[]}' or die "print: $!";
  close $fh                       or die "close: $!";

  like dies { Overnet::Program::IRC::Script::Connect::_endpoint_from_config($no_dmn) },
    qr/no\ daemon\ section/mx, 'a config with no daemon section is rejected';

  like dies { Overnet::Program::IRC::Script::Connect::_endpoint_from_config(File::Spec->catfile($dir, 'gone.json')) },
    qr/open/mx, 'an unreadable config is reported';
};

subtest 'a config with no endpoint is refused rather than guessed at' => sub {
  my ($config) = _config_file();
  my $dir      = File::Spec->catdir((File::Spec->splitpath($config))[0, 1]);
  my $bare     = File::Spec->catfile($dir, 'bare.json');
  open my $fh, '>', $bare or die "open: $!";
  print {$fh} '{"daemon":{}}' or die "print: $!";
  close $fh                   or die "close: $!";

  my ($status, undef, $err) = _capture('--config-file', $bare);
  isnt $status, 0, 'the command fails';
  like $err, qr/endpoint/mx, 'naming what is missing';
};

subtest 'the default config location follows the state directory' => sub {
  my $state = tempdir(CLEANUP => 1);
  local $ENV{XDG_STATE_HOME} = $state;
  is Overnet::Program::IRC::Script::Connect::_default_config_file(),
    File::Spec->catfile($state, 'overnet', 'auth-agent.json'),
    'the default config sits beside the identity, under the state directory';
};

subtest 'the proxy really is what gets run' => sub {

  # --help returns without opening a socket, which is enough to prove the
  # delegation reaches the proxy rather than something else.
  my ($out, $status) = (q{}, undef);
  {
    local *STDOUT;
    open STDOUT, '>', \$out or die "reopen stdout: $!";
    $status = Overnet::Program::IRC::Script::Connect::_run_proxy(argv => ['--help']);
  }
  is $status, 0, 'the proxy runs';
  like $out, qr/overnet-irc-server\ proxy/mx, 'and it is the proxy that ran';
};

subtest 'an agent that cannot be spawned at all is reported' => sub {
  my ($config) = _config_file();

  no warnings 'redefine';
  local *Overnet::Program::IRC::Script::Connect::_agent_listening = sub {0};
  local *Overnet::Program::IRC::Script::Connect::_spawn_agent     = sub {0};
  local *Overnet::Program::IRC::Script::Connect::_run_proxy       = sub {0};

  my ($status, undef, $err) = _capture('--config-file', $config);
  isnt $status, 0, 'the command fails';
  like $err, qr/could\ not\ start/mx, 'saying the agent could not be started';
};

# The handler ends the process, so it is exercised in a child: the exit status
# is the assertion.
subtest 'the interrupt handler exits with the signal status' => sub {
  my ($config) = _config_file();
  my $handler;

  no warnings 'redefine';
  local *Overnet::Program::IRC::Script::Connect::_agent_listening = sub {0};
  local *Overnet::Program::IRC::Script::Connect::_spawn_agent     = sub {321};
  local *Overnet::Program::IRC::Script::Connect::_await_agent     = sub {1};
  local *Overnet::Program::IRC::Script::Connect::_stop_agent      = sub {1};
  local *Overnet::Program::IRC::Script::Connect::_run_proxy       = sub { $handler = $SIG{INT}; return 0 };

  _capture('--config-file', $config);
  is ref($handler), 'CODE', 'the handler was installed';

  for my $case (['INT', 130], ['TERM', 143]) {
    my ($signal, $expected) = @{$case};
    my $pid = fork // die "fork: $!";
    if (!$pid) {
      $handler->($signal);
      exit 0;
    }
    waitpid $pid, 0;
    is $? >> 8, $expected, "handling $signal exits with $expected";
  }
};

subtest 'stopping nothing is not an error' => sub {
  ok Overnet::Program::IRC::Script::Connect::_stop_agent(pid => undef),
    'there is nothing to stop when no agent was started';
};

subtest 'help explains the command' => sub {
  my ($status, $out) = _capture('--help');
  is $status, 0, 'help succeeds';
  like $out, qr/connect/mx,       'names the command';
  like $out, qr/--config-file/mx, 'documents the config';
};

done_testing;
