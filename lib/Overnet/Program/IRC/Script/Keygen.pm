package Overnet::Program::IRC::Script::Keygen;

use strictures 2;

use Carp           qw(croak);
use English        qw(-no_match_vars);
use File::Basename qw(dirname);
use File::Path     qw(make_path);
use Getopt::Long   qw(GetOptionsFromArray);

use Overnet::Core::Nostr;
use Overnet::Program::IRC::Script::Util qw(default_state_dir);

our $VERSION = '0.001';

# Create the Nostr identity a person authenticates to an Overnet IRC server
# with. The server's SASL exchange asks the client to sign a kind-22242 auth
# event and a kind-14142 delegation grant, so without a key of their own a user
# cannot join a hosted channel at all. Everything needed already existed in
# Overnet::Core::Nostr; what was missing was a way to reach it without writing
# Perl.
#
# This is the user's identity, not the server's -- the server manages its own
# signing key under its state directory. Their pubkey is what an operator grants
# rights to, so it is printed on every successful run.

sub _default_key_file {
  my $dir = default_state_dir();
  $dir =~ s{irc-server\z}{overnet}mx;
  return File::Spec->catfile($dir, 'id.pem');
}

sub run {
  my ($class, @argv) = @_;
  my $argv   = \@argv;
  my $stdout = \*STDOUT;
  my $stderr = \*STDERR;

  my %opt    = (key_file => undef, import_file => undef, import_nsec => undef, show => 0, help => 0,);
  my $parsed = eval {
    GetOptionsFromArray(
      $argv,
      'key-file=s'    => \$opt{key_file},
      'import-file=s' => \$opt{import_file},
      'import-nsec=s' => \$opt{import_nsec},
      'show'          => \$opt{show},
      'help'          => \$opt{help},
    );
  };
  if (!$parsed) {
    print {$stderr} _usage();
    return 2;
  }

  if ($opt{help}) {
    print {$stdout} _usage();
    return 0;
  }

  my $path = defined $opt{key_file} && length $opt{key_file} ? $opt{key_file} : _default_key_file();

  if ($opt{show}) {
    return _show($path, $stdout, $stderr);
  }

  # Refuse rather than replace. The pubkey is the account: every membership and
  # operator right the relay has recorded is bound to it, and none of that can
  # be recovered once the private key is gone.
  if (-e $path) {
    print {$stderr} "an identity already exists at $path\n"
      . "refusing to replace it; move it aside first, or use --show to print its pubkey\n";
    return 1;
  }

  my $key = eval { _resolve_key(\%opt) };
  if (!$key) {
    my $error = $EVAL_ERROR || "could not create an identity\n";
    print {$stderr} $error;
    return 1;
  }

  my $written = eval { _write_key($key, $path); 1 };
  if (!$written) {
    print {$stderr} $EVAL_ERROR || "could not write $path\n";
    return 1;
  }

  print {$stdout} "identity written to $path\n";
  print {$stdout} $key->pubkey_hex, "\n";
  print {$stdout} "grant this pubkey access to a channel with the server operator\n";
  return 0;
}

sub _resolve_key {
  my ($opt) = @_;

  if (defined $opt->{import_file} && length $opt->{import_file}) {
    -f $opt->{import_file}
      or croak "no such key file: $opt->{import_file}\n";
    return Overnet::Core::Nostr->load_key(privkey => $opt->{import_file});
  }
  if (defined $opt->{import_nsec} && length $opt->{import_nsec}) {
    return Overnet::Core::Nostr->load_key(privkey => $opt->{import_nsec});
  }

  return Overnet::Core::Nostr->generate_key;
}

sub _write_key {
  my ($key, $path) = @_;

  my $directory = dirname($path);
  if (!-d $directory) {
    make_path($directory);
  }
  $key->save_privkey($path);

  # Written before anything else can read it: an auth agent will load this to
  # sign with, and a world-readable identity is a compromised one.
  chmod 0600, $path
    or croak "chmod failed for identity $path: $OS_ERROR\n";
  return 1;
}

sub _show {
  my ($path, $stdout, $stderr) = @_;

  if (!-f $path) {
    print {$stderr} "no identity at $path\n";
    return 1;
  }
  my $key = eval { Overnet::Core::Nostr->load_key(privkey => $path) };
  if (!$key) {
    print {$stderr} $EVAL_ERROR || "could not read the identity at $path\n";
    return 1;
  }
  print {$stdout} $key->pubkey_hex, "\n";
  return 0;
}

sub _usage {
  return <<'USAGE';
overnet-irc-server keygen - create the Nostr identity you authenticate with.

An Overnet IRC server asks your client to sign an auth event and a delegation
grant, so you need an identity of your own before you can join a hosted channel.
The printed public key is what a server operator grants access to.

usage:
  overnet-irc-server keygen [options]

options:
  --key-file PATH     where the identity lives (default: ~/.local/state/overnet/id.pem)
  --import-file PATH  adopt an existing key file instead of generating one
  --import-nsec NSEC  adopt an existing nsec1... or 64-char hex secret
  --show              print the public key of an existing identity and exit
  --help

The private key is written readable only by you, and an existing identity is
never replaced: losing it means losing every membership and operator right the
relay has recorded against its public key.
USAGE
}

1;

__END__

=head1 NAME

Overnet::Program::IRC::Script::Keygen - create a user's Nostr identity

=head1 DESCRIPTION

Implements C<overnet-irc-server keygen>. Generates or imports the Nostr key a
person authenticates to an Overnet IRC server with, stores it readable only by
its owner, and prints the corresponding public key.

This is the B<user's> identity. The server's own signing key is managed
separately under its state directory by the C<service> command.

=head1 METHODS

=head2 run

Runs the command. Accepts C<argv>, C<stdout>, and C<stderr>; returns a process
exit status.

=cut
