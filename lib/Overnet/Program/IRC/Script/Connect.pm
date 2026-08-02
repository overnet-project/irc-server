package Overnet::Program::IRC::Script::Connect;

use strictures 2;

use English qw(-no_match_vars);
use File::Spec;
use Getopt::Long qw(GetOptionsFromArray);
use IO::Socket::UNIX;
use JSON        ();
use Time::HiRes qw(sleep time);

use Overnet::Program::IRC::Script::Util qw(default_state_dir checked_print_stderr checked_print_stdout);

our $VERSION = '0.001';

# Start the auth agent and the local proxy together.
#
# Connecting otherwise takes two terminals and a socket path repeated between
# them: the agent in one, held in the foreground, the proxy in the other. This
# runs both, taking the socket from the agent config rather than asking the user
# to restate it.
#
# Two behaviours here matter more than the convenience. An agent already
# listening on the configured endpoint is reused rather than duplicated, because
# a second agent on a bound socket fails in a way that reads like a broken
# install. And an agent this command started is always stopped when the proxy
# exits, however it exits: the agent holds the user's signing key, and one left
# behind keeps that key in memory with nothing watching it.

my $AGENT_COMMAND   = 'overnet-auth-agent.pl';
my $AGENT_WAIT_SECS = 10;

sub run {
  my ($class, @argv) = @_;

  # This runs in the foreground for as long as the session lasts, so its
  # progress lines have to appear when they happen rather than whenever a block
  # buffer happens to flush -- which, when the command is ended with Ctrl-C, may
  # be never.
  local $OUTPUT_AUTOFLUSH = 1;

  my %opt = (config_file => undef, agent_command => $AGENT_COMMAND, help => 0,);

  # Options this command does not own belong to the proxy, so leave them in
  # place rather than rejecting them.
  Getopt::Long::Configure('pass_through');
  my $parsed = GetOptionsFromArray(
    \@argv,
    'config-file=s'   => \$opt{config_file},
    'agent-command=s' => \$opt{agent_command},
    'help'            => \$opt{help},
  );
  Getopt::Long::Configure('no_pass_through');
  if (!$parsed) {
    checked_print_stderr(_usage());
    return 2;
  }
  if ($opt{help}) {
    checked_print_stdout(_usage());
    return 0;
  }

  my $config_file = $opt{config_file} || _default_config_file();
  if (!-f $config_file) {
    checked_print_stderr("no auth-agent config at $config_file\n"
        . "create one with 'overnet-irc-server auth init --server-name NAME --network NET'\n");
    return 1;
  }

  my $endpoint = eval { _endpoint_from_config($config_file) };
  if (!(defined $endpoint && length $endpoint)) {
    checked_print_stderr($EVAL_ERROR || "$config_file declares no daemon.endpoint\n");
    return 1;
  }

  my $started_pid;
  if (_agent_listening(endpoint => $endpoint)) {
    checked_print_stdout("auth agent already running on $endpoint\n");
  } else {
    $started_pid = _spawn_agent(config_file => $config_file, agent_command => $opt{agent_command},);
    if (!$started_pid) {
      checked_print_stderr("could not start $opt{agent_command}\n");
      return 1;
    }
    if (!_await_agent(endpoint => $endpoint, pid => $started_pid)) {
      checked_print_stderr("the auth agent did not start listening on $endpoint\n"
          . "run it directly to see why: $opt{agent_command} --config-file $config_file\n");
      _stop_agent(pid => $started_pid);
      return 1;
    }
    checked_print_stdout("auth agent started on $endpoint\n");
  }

  local $ENV{OVERNET_AUTH_SOCK} = $endpoint;

  # Ctrl-C is how a person stops a foreground command, so it is the usual exit
  # from here rather than an edge case. Without this the agent -- and the
  # signing key it holds -- outlives the terminal that started it.
  local $SIG{INT} = local $SIG{TERM} = sub {
    my ($signal) = @_;
    _signal_cleanup($started_pid);
    exit 128 + ($signal eq 'INT' ? 2 : 15);
  };

  my $status = eval { _run_proxy(argv => [@argv]) };
  my $error  = $EVAL_ERROR;

  # Whatever happened to the proxy, do not leave an agent holding a signing key
  # behind.
  if ($started_pid) {
    _stop_agent(pid => $started_pid);
  }

  if ($error) {
    checked_print_stderr($error);
    return 1;
  }
  return defined $status ? $status : 0;
}

# The work an interrupt has to do before the process goes away, kept apart from
# the exiting so it can be exercised directly.
sub _signal_cleanup {
  my ($pid) = @_;
  return 0 if !$pid;
  _stop_agent(pid => $pid);
  return 1;
}

sub _endpoint_from_config {
  my ($path) = @_;

  open my $fh, '<', $path
    or die "open $path failed: $OS_ERROR\n";
  my $json = do { local $INPUT_RECORD_SEPARATOR = undef; <$fh> };
  close $fh
    or die "close $path failed: $OS_ERROR\n";

  my $config = JSON->new->decode($json);
  if (!(ref($config) eq 'HASH' && ref($config->{daemon}) eq 'HASH')) {
    die "$path has no daemon section\n";
  }
  return $config->{daemon}{endpoint};
}

sub _agent_listening {
  my (%args) = @_;
  my $socket = IO::Socket::UNIX->new(Peer => $args{endpoint}, Type => SOCK_STREAM,);
  return 0 if !$socket;
  close $socket
    or die "close probe socket failed: $OS_ERROR\n";
  return 1;
}

# How to try to start the agent, in order.
#
# `make install` marks overnet-auth-agent.pl executable, but a from-source
# checkout -- the install this project documents -- leaves it mode 644, so
# running it directly fails with a permission error that has nothing to do with
# permissions the user can reason about. Falling back to the interpreter already
# running makes the documented checkout work without asking anyone to chmod it.
sub _agent_exec_candidates {
  my (%args) = @_;
  my @direct = ($args{agent_command}, '--config-file', $args{config_file});
  return (\@direct, [$EXECUTABLE_NAME, @direct]);
}

sub _spawn_agent {
  my (%args) = @_;

  my $pid = fork;
  if (!defined $pid) {
    return 0;
  }
  if (!$pid) {
    for my $candidate (_agent_exec_candidates(%args)) {

      # Skip a path we already know cannot be executed rather than failing into
      # it: attempting it warns about permissions on a run that then succeeds
      # through the next candidate, which reads like an error when it is not.
      # A bare command name is left to PATH resolution.
      my $command = $candidate->[0];
      if ($command =~ m{/}mxs && !-x $command) {
        next;
      }

      # A failed exec returns here rather than replacing this child, so the next
      # candidate still gets its turn.
      exec {$command} @{$candidate};
    }
    exit 127;
  }
  return $pid;
}

sub _await_agent {
  my (%args) = @_;
  my $deadline = time + $AGENT_WAIT_SECS;
  while (time < $deadline) {
    return 1 if _agent_listening(endpoint => $args{endpoint});

    # A child that has already exited is never going to listen.
    if (waitpid($args{pid}, 1) != 0) {
      return 0;
    }
    sleep 0.2;
  }
  return 0;
}

sub _stop_agent {
  my (%args) = @_;
  return 1 if !$args{pid};
  kill 'TERM', $args{pid};
  waitpid $args{pid}, 0;
  return 1;
}

sub _run_proxy {
  my (%args) = @_;
  require Overnet::Program::IRC::Script::Proxy;
  return Overnet::Program::IRC::Script::Proxy->run(@{$args{argv} || []});
}

sub _default_config_file {
  my $dir = default_state_dir();
  $dir =~ s{irc-server\z}{overnet}mxs;
  return File::Spec->catfile($dir, 'auth-agent.json');
}

sub _usage {
  return <<'USAGE';
overnet-irc-server connect - run the auth agent and the proxy together.

Starts the Overnet auth agent from your config (unless one is already running on
its endpoint), points the local IRC proxy at it, and runs the proxy in the
foreground. The agent is stopped again when the proxy exits.

usage:
  overnet-irc-server connect [options] [proxy options]

options:
  --config-file PATH   auth-agent config (default: ~/.local/state/overnet/auth-agent.json)
  --agent-command CMD  agent executable (default: overnet-auth-agent.pl)
  --help

Any option this command does not recognize is passed to the proxy, so the usual
proxy options work here:

  overnet-irc-server connect --server-host irc.example.net --server-port 6697 --server-tls

Then point your IRC client at 127.0.0.1:16668.
USAGE
}

1;

__END__

=head1 NAME

Overnet::Program::IRC::Script::Connect - run the auth agent and IRC proxy together

=head1 DESCRIPTION

Implements C<overnet-irc-server connect>. Starts the Overnet auth agent from a
config file unless one is already listening on the configured endpoint, runs the
local IRC proxy against it, and stops any agent it started when the proxy exits.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  Overnet::Program::IRC::Script::Connect->run(@ARGV);

=head1 SUBROUTINES/METHODS

=head2 run

Runs the command from C<@ARGV> and returns a process exit status.

=head1 DIAGNOSTICS

A missing config file, a config with no daemon endpoint, and an agent that never
starts listening are reported on stderr with a non-zero exit status.

=head1 CONFIGURATION AND ENVIRONMENT

Reads the agent endpoint from the auth-agent config and exports it as
C<OVERNET_AUTH_SOCK> for the proxy.

=head1 DEPENDENCIES

See the distribution metadata for runtime dependencies.

=head1 INCOMPATIBILITIES

No known incompatibilities are documented.

=head1 BUGS AND LIMITATIONS

An agent that was already running is left running, since this command did not
start it.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the project license.

=cut
