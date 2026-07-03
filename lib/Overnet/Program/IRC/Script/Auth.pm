package Overnet::Program::IRC::Script::Auth;

use strictures 2;
use Getopt::Long qw(GetOptionsFromArray);
use Overnet::Auth::Client;
use Overnet::Program::IRC::Auth::Helper;
use Overnet::Program::IRC::Script::Util qw(checked_print checked_print_stderr checked_print_stdout);

our $VERSION = '0.001';

sub run {
  my ($class, @argv) = @_;

  if (@argv && $argv[0] eq '--help') {
    checked_print_stdout(_usage());
    return 0;
  }

  my $command = shift @argv;
  my %options = (
    interactive => 1,
    program_id  => 'irc.bridge',
    quote       => 1,
  );
  my $help = 0;

  my $parsed = GetOptionsFromArray(
    \@argv,
    'auth-sock=s'                => \$options{auth_sock},
    'identity-id=s'              => \$options{identity_id},
    'program-id=s'               => \$options{program_id},
    'locator=s'                  => \$options{locator},
    'service-identity-scheme=s'  => \$options{service_identity_scheme},
    'service-identity-value=s'   => \$options{service_identity_value},
    'service-identity-display=s' => \$options{service_identity_display},
    'challenge=s'                => \$options{challenge},
    'scope=s'                    => \$options{scope},
    'relay-url=s'                => \$options{relay_url},
    'delegate-pubkey=s'          => \$options{delegate_pubkey},
    'session-id=s'               => \$options{session_id},
    'expires-at=s'               => \$options{expires_at},
    'nick=s'                     => \$options{nick},
    'line=s'                     => \$options{line},
    'interactive!'               => \$options{interactive},
    'quote!'                     => \$options{quote},
    'help'                       => \$help,
  );
  if (!$parsed) {
    checked_print_stderr(_usage());
    return 1;
  }

  if ($help || !defined $command || !length($command)) {
    checked_print_stdout(_usage());
    return $help ? 0 : 1;
  }

  if (!_valid_command($command)) {
    checked_print_stderr(_usage());
    return 1;
  }

  my $client = Overnet::Auth::Client->new(
    (
      defined($options{auth_sock})
      ? (endpoint => $options{auth_sock})
      : ()
    ),
  );

  if ($command eq 'bridge' && !defined($options{line})) {
    Overnet::Program::IRC::Auth::Helper->run(
      client  => $client,
      command => $command,
      input   => \*STDIN,
      output  => \*STDOUT,
      %options,
    );
    return 0;
  }

  my $output = Overnet::Program::IRC::Auth::Helper->run(
    client  => $client,
    command => $command,
    %options,
  );
  checked_print(\*STDOUT, $output);
  return 0;
}

sub _valid_command {
  my ($command) = @_;
  return 1 if $command eq 'auth';
  return 1 if $command eq 'delegate';
  return 1 if $command eq 'bridge';
  return 0;
}

sub _usage {
  return <<'USAGE';
Usage:
  overnet-irc-server auth auth [options]
  overnet-irc-server auth delegate [options]
  overnet-irc-server auth bridge [options]

Auth-agent options:
  --auth-sock PATH
  --identity-id ID
  --program-id PROGRAM_ID
  --locator LOCATOR
  --service-identity-scheme SCHEME
  --service-identity-value VALUE
  --service-identity-display DISPLAY
  --interactive / --no-interactive

Auth options:
  --challenge CHALLENGE
  --scope IRC_SCOPE

Delegate options:
  --relay-url URL
  --scope IRC_SCOPE
  --delegate-pubkey PUBKEY
  --session-id ID
  --expires-at UNIX_TIMESTAMP
  --nick NICK

Bridge options:
  --line IRC_NOTICE_LINE
  --scope IRC_SCOPE
  Scope is required for OVERNETAUTH bridge input and optional for SASL NOSTR AUTHENTICATE streams.
  If --line is omitted, read IRC lines continuously from stdin.
  Continuous bridge mode handles OVERNETAUTH notices and SASL NOSTR AUTHENTICATE challenges.

Shared output options:
  --quote
  --help
USAGE
}

1;

=head1 NAME

Overnet::Program::IRC::Script::Auth - IRC auth helper script runner

=head1 DESCRIPTION

Runs the C<overnet-irc-server auth> command-line helper.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  Overnet::Program::IRC::Script::Auth->run(@ARGV);

=head1 SUBROUTINES/METHODS

=head2 run

=head1 DIAGNOSTICS

Invalid command-line arguments are reported through usage output or exceptions.

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
