package Overnet::Program::IRC::Script::Server;

use strictures 2;
use Carp                                qw(croak);
use English                             qw(-no_match_vars);
use Overnet::Program::IRC::Script::Util qw(checked_print_stderr checked_print_stdout);
use Overnet::Program::IRC::Server;

our $VERSION = '0.001';

sub run {
  my ($class, @argv) = @_;

  if (@argv && $argv[0] eq '--help') {
    checked_print_stdout(_usage());
    return 0;
  }

  if (@argv) {
    checked_print_stderr(_usage());
    return 1;
  }

  my $server = Overnet::Program::IRC::Server->new;
  my $ok     = eval {
    $server->run;
    1;
  };
  my $error = $EVAL_ERROR;
  if (!$ok && !_is_shutdown_error($error)) {
    croak $error;
  }

  return 0;
}

sub _usage {
  return <<'USAGE';
Usage:
  overnet-irc-server server
USAGE
}

sub _is_shutdown_error {
  my ($error) = @_;
  if (!defined $error) {
    return 0;
  }
  return $error =~ /\A__shutdown__(?:\s+at\b.*)?\z/smx ? 1 : 0;
}

1;

=head1 NAME

Overnet::Program::IRC::Script::Server - IRC server script runner

=head1 DESCRIPTION

Runs the C<overnet-irc-server server> program entry point.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  Overnet::Program::IRC::Script::Server->run;

=head1 SUBROUTINES/METHODS

=head2 run

=head1 DIAGNOSTICS

Unexpected server failures are reported through exceptions.

=head1 CONFIGURATION AND ENVIRONMENT

Configuration is supplied through runtime initialization.

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
