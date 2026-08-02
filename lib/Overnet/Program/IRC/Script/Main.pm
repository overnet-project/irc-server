package Overnet::Program::IRC::Script::Main;

use strictures 2;
use Carp    qw(croak);
use English qw(-no_match_vars);

our $VERSION = '0.001';

my @COMMANDS = (
  ['connect',         'Overnet::Program::IRC::Script::Connect',     'Run the auth agent and IRC proxy together'],
  ['keygen',          'Overnet::Program::IRC::Script::Keygen',      'Create the Nostr identity you authenticate with'],
  ['auth',            'Overnet::Program::IRC::Script::Auth',        'Run auth-agent IRC helpers'],
  ['proxy',           'Overnet::Program::IRC::Script::Proxy',       'Run the local auth-hiding IRC proxy'],
  ['server',          'Overnet::Program::IRC::Script::Server',      'Run the hosted IRC server program'],
  ['service',         'Overnet::Program::IRC::Script::Service',     'Run the IRC service wrapper'],
  ['local-server',    'Overnet::Program::IRC::Script::LocalServer', 'Run the local demo server'],
  ['chat-client',     'Overnet::Program::IRC::Script::ChatClient',  'Run the local demo chat client'],
  ['authority-relay', 'Overnet::Program::IRC::Script::AuthorityRelay', 'Run the authoritative IRC relay'],
  ['authority-relay-service', 'Overnet::Program::IRC::Script::AuthorityRelayService', 'Run the relay service wrapper'],
);
my %COMMAND = map { $_->[0] => $_ } @COMMANDS;

sub run {
  my ($class, @argv) = @_;

  if (@argv && ($argv[0] eq '--help' || $argv[0] eq '-h')) {
    _print(\*STDOUT, _usage());
    return 0;
  }

  if (@argv && $argv[0] eq 'help') {
    shift @argv;
    return _help(@argv);
  }

  my $command = shift @argv;
  if (!defined $command || !length($command)) {
    _print(\*STDERR, _usage());
    return 1;
  }

  if (!$COMMAND{$command}) {
    _print(\*STDERR, "Unknown overnet-irc-server command: $command\n\n", _usage());
    return 1;
  }

  return _run_command($command, @argv);
}

sub _help {
  my (@argv) = @_;
  my $command = shift @argv;

  if (!defined $command || !length($command)) {
    _print(\*STDOUT, _usage());
    return 0;
  }

  if (@argv) {
    _print(\*STDERR, "Usage: overnet-irc-server help [command]\n");
    return 1;
  }

  if (!$COMMAND{$command}) {
    _print(\*STDERR, "Unknown overnet-irc-server command: $command\n\n", _usage());
    return 1;
  }

  return _run_command($command, '--help');
}

sub _run_command {
  my ($command, @argv) = @_;
  my $module      = $COMMAND{$command}->[1];
  my $module_file = $module . '.pm';
  $module_file =~ s{::}{/}gsmx;

  my $loaded = eval {
    require $module_file;
    1;
  };
  if (!$loaded) {
    croak $EVAL_ERROR;
  }

  return $module->run(@argv);
}

sub _usage {
  my $usage = <<'USAGE';
Usage:
  overnet-irc-server <command> [options]
  overnet-irc-server help [command]

Commands:
USAGE

  for my $command (@COMMANDS) {
    $usage .= sprintf("  %-24s %s\n", $command->[0], $command->[2]);
  }

  return $usage;
}

sub _print {
  my ($handle, @messages) = @_;
  print {$handle} @messages
    or croak "print failed: $OS_ERROR\n";
  return 1;
}

1;

=head1 NAME

Overnet::Program::IRC::Script::Main - unified IRC server command dispatcher

=head1 DESCRIPTION

Dispatches the C<overnet-irc-server> command to the IRC server subcommands.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  Overnet::Program::IRC::Script::Main->run(@ARGV);

=head1 SUBROUTINES/METHODS

=head2 run

=head1 DIAGNOSTICS

Invalid commands are reported through usage output.

=head1 CONFIGURATION AND ENVIRONMENT

Configuration is supplied through command-line arguments passed to subcommands.

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
