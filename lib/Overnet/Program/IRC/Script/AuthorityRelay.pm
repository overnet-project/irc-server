package Overnet::Program::IRC::Script::AuthorityRelay;

use strictures 2;
use Carp                                     qw(croak);
use Getopt::Long                             qw(GetOptionsFromArray);
use Overnet::Authority::HostedChannel::Relay qw(build_authoritative_relay);
use Overnet::Program::IRC::Script::Util      qw(checked_print_stderr checked_print_stdout);

our $VERSION = '0.001';

sub run {
  my ($class, @argv) = @_;

  my %options = (
    host       => '127.0.0.1',
    port       => 7_448,
    grant_kind => 14_142,
  );
  my $help = 0;

  my $parsed = GetOptionsFromArray(
    \@argv,
    'host=s'       => \$options{host},
    'port=i'       => \$options{port},
    'relay-url=s'  => \$options{relay_url},
    'grant-kind=i' => \$options{grant_kind},
    'store-file=s' => \$options{store_file},
    'help'         => \$help,
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
  if (!defined $options{relay_url} || !length($options{relay_url})) {
    $options{relay_url} = sprintf('ws://%s:%d', $options{host}, $options{port});
  }

  my $relay = build_authoritative_relay(
    relay_url  => $options{relay_url},
    grant_kind => $options{grant_kind},
    (defined $options{store_file} ? (store_file => $options{store_file}) : ()),
  );

  local $SIG{INT}  = sub { $relay->stop; };
  local $SIG{TERM} = sub { $relay->stop; };

  $relay->run($options{host}, $options{port});
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

sub _usage {
  return <<'USAGE';
Usage: overnet-irc-authority-relay.pl [options]

  --host HOST
  --port PORT
  --relay-url URL
  --grant-kind KIND
  --store-file PATH
  --help
USAGE
}

1;

=head1 NAME

Overnet::Program::IRC::Script::AuthorityRelay - authoritative IRC relay script runner

=head1 DESCRIPTION

Runs the C<overnet-irc-authority-relay.pl> command-line relay launcher.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  Overnet::Program::IRC::Script::AuthorityRelay->run(@ARGV);

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
