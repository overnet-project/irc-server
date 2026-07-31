package Overnet::Program::IRC::Script::AuthInit;

use strictures 2;

use Carp           qw(croak);
use English        qw(-no_match_vars);
use File::Basename qw(dirname);
use File::Path     qw(make_path);
use File::Spec;
use Getopt::Long qw(GetOptionsFromArray);
use JSON         ();

use Overnet::Core::Nostr;
use Overnet::Program::IRC::Script::Util qw(default_state_dir checked_print_stderr checked_print_stdout);

our $VERSION = '0.001';

# Scaffold the auth-agent config a person needs to connect through the proxy.
#
# Hand-writing this is where onboarding failed. Three values have to line up
# exactly with what the client sends, and a mismatch in any of them surfaces at
# connect time as "approval is required but interactive approval is
# unavailable" -- a message that names none of them:
#
#   * the scope is irc://<server-name>/<network>, a derivation documented
#     nowhere a user would look;
#   * the proxy authenticates as program_id irc.proxy, while the config example
#     users copy from uses irc.bridge, so the documented config cannot
#     authenticate the documented client;
#   * two policies are required, session.authenticate and session.delegate.
#     Granting only the first logs in and then fails on joining a hosted
#     channel, which reads like a permissions problem on the channel.
#
# Generating the config from the server name and the user's key removes all
# three as things anyone has to know.

my $PROXY_PROGRAM_ID = 'irc.proxy';
my @REQUIRED_ACTIONS = ('session.authenticate', 'session.delegate');

sub run {
  my ($class, @argv) = @_;

  my %opt = (
    config_file => undef,
    key_file    => undef,
    pass_entry  => undef,
    server_name => undef,
    network     => undef,
    auth_sock   => undef,
    state_file  => undef,
    identity_id => 'default',
    program_id  => $PROXY_PROGRAM_ID,
    help        => 0,
  );
  my $parsed = GetOptionsFromArray(
    \@argv,
    'config-file=s' => \$opt{config_file},
    'key-file=s'    => \$opt{key_file},
    'pass-entry=s'  => \$opt{pass_entry},
    'server-name=s' => \$opt{server_name},
    'network=s'     => \$opt{network},
    'auth-sock=s'   => \$opt{auth_sock},
    'state-file=s'  => \$opt{state_file},
    'identity-id=s' => \$opt{identity_id},
    'program-id=s'  => \$opt{program_id},
    'help'          => \$opt{help},
  );
  if (!$parsed) {
    checked_print_stderr(_usage());
    return 2;
  }
  if ($opt{help}) {
    checked_print_stdout(_usage());
    return 0;
  }

  my $error = _validate(\%opt);
  if ($error) {
    checked_print_stderr($error . _usage());
    return 1;
  }

  my $config_file = $opt{config_file} || _default_config_file();

  # Refuse rather than replace: the file records which identity signs for this
  # server, and a regenerated one silently points the agent somewhere else.
  if (-e $config_file) {
    checked_print_stderr(
      "an auth-agent config already exists at $config_file\n" . "refusing to replace it; move it aside first\n");
    return 1;
  }

  my $config = eval { _build_config(\%opt, $config_file) };
  if (!$config) {
    checked_print_stderr($EVAL_ERROR || "could not build the auth-agent config\n");
    return 1;
  }

  my $written = eval { _write_config($config_file, $config); 1 };
  if (!$written) {
    checked_print_stderr($EVAL_ERROR || "could not write $config_file\n");
    return 1;
  }

  checked_print_stdout(_next_steps($config_file, $config));
  return 0;
}

sub _validate {
  my ($opt) = @_;

  for my $field (['server_name', '--server-name'], ['network', '--network']) {
    my ($key, $flag) = @{$field};
    if (!(defined $opt->{$key} && length $opt->{$key})) {
      return "$flag is required\n";
    }
  }
  if (
    !(
      (defined $opt->{key_file} && length $opt->{key_file}) || (defined $opt->{pass_entry} && length $opt->{pass_entry})
    )
  ) {
    return "an identity is required: pass --key-file PATH or --pass-entry NAME\n";
  }
  if (defined $opt->{key_file} && length $opt->{key_file} && !-f $opt->{key_file}) {
    return "no identity at $opt->{key_file}; create one with 'overnet-irc-server keygen'\n";
  }
  return;
}

sub _build_config {
  my ($opt, $config_file) = @_;

  # Exactly how the server derives the scope it challenges against.
  my $scope = sprintf 'irc://%s/%s', $opt->{server_name}, $opt->{network};

  my %identity = (identity_id => $opt->{identity_id},);
  if (defined $opt->{pass_entry} && length $opt->{pass_entry}) {
    $identity{backend_type}   = 'pass';
    $identity{backend_config} = {entry => $opt->{pass_entry},};
  } else {
    $identity{backend_type}   = 'direct_secret';
    $identity{backend_config} = {secret => $opt->{key_file},};

    # Advertising the pubkey lets the agent be inspected without unlocking the
    # secret, and lets a user check they handed their operator the right one.
    my $key = Overnet::Core::Nostr->load_key(privkey => $opt->{key_file});
    $identity{public_identity} = {scheme => 'nostr.pubkey', value => $key->pubkey_hex,};
  }

  my @policies = map {
    {
      identity_id => $opt->{identity_id},
      program_id  => $opt->{program_id},
      scope       => $scope,
      action      => $_,

      # The helper defaults the service locator to the scope, so a policy that
      # omits this matches nothing.
      locators => [$scope],
    }
  } @REQUIRED_ACTIONS;

  return {
    daemon => {
      endpoint => $opt->{auth_sock} || _default_socket(),

      # Without this the agent has no state writer, so any policy granted later
      # with policy-grant is lost on restart.
      state_file => $opt->{state_file} || _default_state_file($config_file),
    },
    identities => [\%identity],
    policies   => \@policies,
  };
}

sub _write_config {
  my ($path, $config) = @_;

  my $directory = dirname($path);
  if (!-d $directory) {
    make_path($directory);
  }

  my $encoder = JSON->new;
  $encoder->canonical(1);
  $encoder->pretty;
  my $json = $encoder->encode($config);
  open my $fh, '>', $path
    or croak "open $path failed: $OS_ERROR\n";
  print {$fh} $json
    or croak "write $path failed: $OS_ERROR\n";
  close $fh
    or croak "close $path failed: $OS_ERROR\n";

  # It names the path to a private key, and with a pass entry it can carry the
  # secret itself.
  chmod 0600, $path
    or croak "chmod failed for $path: $OS_ERROR\n";
  return 1;
}

sub _next_steps {
  my ($path, $config) = @_;

  my $endpoint = $config->{daemon}{endpoint};
  my $pubkey =
    defined $config->{identities}[0]{public_identity}
    ? $config->{identities}[0]{public_identity}{value}
    : undef;

  my $text = "auth-agent config written to $path\n\n";
  if (defined $pubkey) {
    $text .= "your public key (give this to the server operator):\n  $pubkey\n\n";
  }
  $text .=
      "start the agent, then the proxy, then point your IRC client at the proxy:\n"
    . "  overnet-auth-agent.pl --config-file $path\n"
    . "  export OVERNET_AUTH_SOCK=$endpoint\n"
    . "  overnet-irc-server proxy --server-host <server> --server-port <port>\n"
    . "  then in your IRC client: /connect 127.0.0.1 16668\n";
  return $text;
}

sub _default_config_file {
  return File::Spec->catfile(_overnet_dir(), 'auth-agent.json');
}

sub _default_socket {
  return File::Spec->catfile(_overnet_dir(), 'auth.sock');
}

sub _default_state_file {
  my ($config_file) = @_;
  return File::Spec->catfile(dirname($config_file), 'auth-state.json');
}

sub _overnet_dir {
  my $dir = default_state_dir();
  $dir =~ s{irc-server\z}{overnet}mxs;
  return $dir;
}

sub _usage {
  return <<'USAGE';
overnet-irc-server auth init - write the auth-agent config for a server.

Generates the config the Overnet auth agent needs to authenticate you to one
IRC server, so you do not have to know how the server derives its scope, which
program id the proxy authenticates as, or that two policies are required.

usage:
  overnet-irc-server auth init --server-name NAME --network NET
                              (--key-file PATH | --pass-entry NAME) [options]

options:
  --server-name NAME  the server's name, as it announces itself (required)
  --network NET       the network name the server runs (required)
  --key-file PATH     identity created by 'overnet-irc-server keygen'
  --pass-entry NAME   password-store entry holding the secret instead
  --config-file PATH  where to write (default: ~/.local/state/overnet/auth-agent.json)
  --auth-sock PATH    socket the agent listens on
  --state-file PATH   where the agent persists granted policies
  --identity-id ID    identity name inside the config (default: default)
  --program-id ID     client program id to authorize (default: irc.proxy)
  --help

An existing config is never replaced.
USAGE
}

1;

__END__

=head1 NAME

Overnet::Program::IRC::Script::AuthInit - scaffold an auth-agent config

=head1 DESCRIPTION

Implements C<overnet-irc-server auth init>. Writes the Overnet auth-agent
configuration needed to authenticate a user to one IRC server, deriving the
authorization scope from the server name and network and granting the two
actions the proxy requires.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  Overnet::Program::IRC::Script::AuthInit->run(@ARGV);

=head1 SUBROUTINES/METHODS

=head2 run

Runs the command from C<@ARGV> and returns a process exit status.

=head1 DIAGNOSTICS

Missing required options, a missing identity file, and refusing to replace an
existing config are reported on stderr with a non-zero exit status.

=head1 CONFIGURATION AND ENVIRONMENT

Configuration is supplied through command-line arguments. Default paths derive
from C<XDG_STATE_HOME> or C<HOME>.

=head1 DEPENDENCIES

See the distribution metadata for runtime dependencies.

=head1 INCOMPATIBILITIES

No known incompatibilities are documented.

=head1 BUGS AND LIMITATIONS

Scaffolds one server per config file.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the project license.

=cut
