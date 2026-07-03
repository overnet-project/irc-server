package Overnet::Program::IRC::Script::AuthorityRelayService;

use strictures 2;
use Carp    qw(croak);
use English qw(-no_match_vars);
use File::Spec;
use FindBin;
use Getopt::Long qw(GetOptionsFromArray);
use IPC::Open3   qw(open3);
use Net::Nostr::Client;
use POSIX                               qw(WNOHANG);
use Symbol                              qw(gensym);
use Time::HiRes                         qw(sleep time);
use Overnet::Program::IRC::Script::Util qw(
  append_log
  checked_close
  checked_print_stderr
  checked_print_stdout
  default_state_dir
  executable_name
  write_health_file
);

our $VERSION = '0.001';

sub run {
  my ($class, @argv) = @_;

  my %options = (
    host       => '127.0.0.1',
    port       => 7_448,
    grant_kind => 14_142,
  );
  my $health_file;
  my $log_file;
  my $help = 0;

  my $parsed = GetOptionsFromArray(
    \@argv,
    'host=s'        => \$options{host},
    'port=i'        => \$options{port},
    'relay-url=s'   => \$options{relay_url},
    'grant-kind=i'  => \$options{grant_kind},
    'store-file=s'  => \$options{store_file},
    'health-file=s' => \$health_file,
    'log-file=s'    => \$log_file,
    'help'          => \$help,
  );
  if (!$parsed) {
    checked_print_stderr(_usage());
    return 1;
  }

  if ($help) {
    checked_print_stdout(_usage());
    return 0;
  }

  _validate_options(\%options);
  _fill_defaults(\%options);
  append_log($log_file, "starting authoritative IRC relay service\n");

  my $child = _spawn_relay_child(\%options);
  my $ready = eval {
    _wait_for_relay_ready($options{relay_url});
    _write_ready_health($health_file, \%options);
    append_log($log_file, sprintf("ready relay=%s listen=%s:%s\n", $options{relay_url}, $options{host}, $options{port}),
    );
    1;
  };
  if (!$ready) {
    my $error = $EVAL_ERROR;
    _stop_child($child);
    croak $error;
  }

  _run_until_shutdown($child, $health_file, $log_file, \%options);
  return 0;
}

sub _validate_options {
  my ($options) = @_;

  if (!(defined $options->{host} && !ref($options->{host}) && length($options->{host}))) {
    croak "--host is required\n";
  }

  if (!(defined $options->{port} && !ref($options->{port}) && $options->{port} =~ /\A\d+\z/mxs)) {
    croak "--port must be a non-negative integer\n";
  }

  if (!(defined $options->{grant_kind} && !ref($options->{grant_kind}) && $options->{grant_kind} =~ /\A[1-9]\d*\z/mxs))
  {
    croak "--grant-kind must be a positive integer\n";
  }

  if (defined $options->{store_file} && (ref($options->{store_file}) || $options->{store_file} eq q{})) {
    croak "--store-file must be a non-empty string\n";
  }

  return 1;
}

sub _fill_defaults {
  my ($options) = @_;

  if (!defined $options->{relay_url} || !length($options->{relay_url})) {
    $options->{relay_url} = sprintf('ws://%s:%d', $options->{host}, $options->{port});
  }

  if (!defined $options->{store_file} || !length($options->{store_file})) {
    $options->{store_file} = File::Spec->catfile(default_state_dir(), 'authority-relay-store.json');
  }

  return 1;
}

sub _spawn_relay_child {
  my ($options) = @_;

  my $program_path = File::Spec->catfile($FindBin::Bin, 'overnet-irc-server');
  return _spawn_child(
    executable_name(),     $program_path,  'authority-relay',      '--host',
    $options->{host},      '--port',       $options->{port},       '--relay-url',
    $options->{relay_url}, '--grant-kind', $options->{grant_kind}, '--store-file',
    $options->{store_file},
  );
}

sub _write_ready_health {
  my ($health_file, $options) = @_;

  write_health_file(
    $health_file,
    {
      status  => 'ready',
      details => {
        listen_host => $options->{host},
        listen_port => 0 + $options->{port},
        relay_url   => $options->{relay_url},
        grant_kind  => 0 + $options->{grant_kind},
        store_file  => $options->{store_file},
      },
    }
  );
  return 1;
}

sub _run_until_shutdown {
  my ($child, $health_file, $log_file, $options) = @_;

  my $shutdown_requested = 0;
  local $SIG{INT}  = sub { $shutdown_requested = 1; };
  local $SIG{TERM} = sub { $shutdown_requested = 1; };

  while (!$shutdown_requested) {
    _check_child($child, $health_file, $options);
    sleep 0.1;
  }

  _write_stopping_health($health_file, $options);
  append_log($log_file, "shutting down authoritative IRC relay service\n");
  _stop_child($child);
  _write_stopped_health($health_file, $options);
  append_log($log_file, "stopped authoritative IRC relay service\n");
  return 1;
}

sub _check_child {
  my ($child, $health_file, $options) = @_;

  my $reaped = waitpid($child->{pid}, WNOHANG);
  if ($reaped == $child->{pid}) {
    my $exit_code = $CHILD_ERROR >> 8;
    write_health_file(
      $health_file,
      {
        status  => 'failed',
        details => {
          exit_code => $exit_code,
          relay_url => $options->{relay_url},
        },
      }
    );
    croak "authoritative IRC relay exited unexpectedly ($exit_code)\n";
  }

  return 1;
}

sub _write_stopping_health {
  my ($health_file, $options) = @_;

  write_health_file(
    $health_file,
    {
      status  => 'stopping',
      details => _health_listen_details($options),
    }
  );
  return 1;
}

sub _write_stopped_health {
  my ($health_file, $options) = @_;

  write_health_file(
    $health_file,
    {
      status  => 'stopped',
      details => _health_listen_details($options),
    }
  );
  return 1;
}

sub _health_listen_details {
  my ($options) = @_;
  return {
    listen_host => $options->{host},
    listen_port => 0 + $options->{port},
    relay_url   => $options->{relay_url},
  };
}

sub _spawn_child {
  my (@command) = @_;
  my $stderr    = gensym();
  my $pid       = open3(my $stdin, my $stdout, $stderr, @command);
  checked_close($stdin, 'authoritative relay child stdin');
  return {
    pid    => $pid,
    stdout => $stdout,
    stderr => $stderr,
  };
}

sub _stop_child {
  my ($child) = @_;
  if (!$child || !$child->{pid}) {
    return 1;
  }

  kill 'TERM', $child->{pid};
  my $deadline = time() + 5;
  while (time() < $deadline) {
    my $reaped = waitpid($child->{pid}, WNOHANG);
    if ($reaped == $child->{pid}) {
      last;
    }
    sleep 0.05;
  }

  if (waitpid($child->{pid}, WNOHANG) == 0) {
    kill 'KILL', $child->{pid};
    waitpid($child->{pid}, 0);
  }

  _close_child_handle($child->{stdout}, 'authoritative relay child stdout');
  _close_child_handle($child->{stderr}, 'authoritative relay child stderr');
  return 1;
}

sub _close_child_handle {
  my ($handle, $description) = @_;
  if ($handle) {
    checked_close($handle, $description);
  }
  return 1;
}

sub _wait_for_relay_ready {
  my ($relay_url) = @_;
  my $deadline = time() + 5;

  while (time() < $deadline) {
    my $ok = eval {
      my $client = Net::Nostr::Client->new;
      $client->connect($relay_url);
      $client->disconnect;
      1;
    };
    if ($ok) {
      return 1;
    }
    sleep 0.05;
  }

  croak "authoritative IRC relay did not become ready at $relay_url\n";
}

sub _usage {
  return <<'USAGE';
Usage: overnet-irc-server authority-relay-service [options]

  --host HOST
  --port PORT
  --relay-url URL
  --grant-kind KIND
  --store-file PATH
  --health-file PATH
  --log-file PATH
  --help
USAGE
}

1;

=head1 NAME

Overnet::Program::IRC::Script::AuthorityRelayService - authoritative relay service runner

=head1 DESCRIPTION

Runs the C<overnet-irc-server authority-relay-service> command-line service wrapper.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  Overnet::Program::IRC::Script::AuthorityRelayService->run(@ARGV);

=head1 SUBROUTINES/METHODS

=head2 run

=head1 DIAGNOSTICS

Invalid arguments, child process failures, and failed IO operations are reported through exceptions.

=head1 CONFIGURATION AND ENVIRONMENT

Configuration is supplied through command-line arguments.

=head1 DEPENDENCIES

See the distribution metadata for runtime dependencies.

=head1 INCOMPATIBILITIES

No known incompatibilities are documented.

=head1 BUGS AND LIMITATIONS

No known bugs are documented.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the project license.

=cut
