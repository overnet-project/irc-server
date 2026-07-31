use strictures 2;

use File::Spec;
use File::Temp qw(tempdir);
use FindBin;
use Test2::V0;

use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/../../core-perl/lib";

use Overnet::Core::Nostr;

# A user cannot talk to an Overnet IRC server without a Nostr identity of their
# own: the server's SASL exchange asks them to sign a kind-22242 auth event and
# a kind-14142 delegation grant. Until this command existed the only way to get
# one was to hand-write Perl against Overnet::Core::Nostr, so in practice nobody
# but the authors could authenticate.
#
# The key IS the account. Every channel membership and operator right the relay
# has recorded is bound to its pubkey and recoverable from nothing else, so
# refusing to overwrite matters more here than convenience does.
#
# These drive the installed command as a subprocess rather than calling run()
# directly: an earlier version of this test called the module and passed while
# --key-file was silently ignored through the real dispatcher, writing the key
# to the default path instead. Only the subprocess form exercises the wiring a
# user actually touches.

my $script = File::Spec->catfile($FindBin::Bin, '..', 'bin', 'overnet-irc-server');
ok -f $script, 'the overnet-irc-server command exists'
  or bail_out('overnet-irc-server is required');

sub _keygen {
  my (@argv)  = @_;
  my $command = join q{ }, map {qq{"$_"}} ($^X, $script, 'keygen', @argv);
  my $output  = qx{$command 2>&1};
  return ($? >> 8, $output);
}

sub _pubkey_of {
  my ($path) = @_;
  my $key = Overnet::Core::Nostr->load_key(privkey => $path);
  return $key->pubkey_hex;
}

subtest 'generating an identity writes it private and reports the public half' => sub {
  my $dir  = tempdir(CLEANUP => 1);
  my $path = File::Spec->catfile($dir, 'id.pem');

  my ($status, $output) = _keygen('--key-file', $path);

  is $status, 0, 'generating an identity succeeds' or diag($output);
  ok -f $path, 'the key was written where it was asked to be written'
    or diag($output);

  my $mode = (stat $path)[2] & oct('7777');
  is $mode, oct('600'), 'the private key is not readable by anyone else';

  # The printed pubkey must be the stored key's, or a user would hand their
  # operator an identity that cannot sign anything.
  my $stored = _pubkey_of($path);
  like $output, qr/\Q$stored\E/mx, 'the printed pubkey belongs to the stored identity';
};

subtest 'an existing identity is never silently replaced' => sub {
  my $dir  = tempdir(CLEANUP => 1);
  my $path = File::Spec->catfile($dir, 'id.pem');

  my ($first) = _keygen('--key-file', $path);
  is $first, 0, 'the first identity is created';
  my $original = _pubkey_of($path);

  my ($status, $output) = _keygen('--key-file', $path);

  isnt $status, 0, 'a second run refuses rather than overwriting';
  like $output, qr/already\ exists/imx, 'and says why';
  is _pubkey_of($path), $original, 'the existing identity is intact';
};

subtest 'an existing identity can be imported rather than invented' => sub {
  my $dir      = tempdir(CLEANUP => 1);
  my $existing = Overnet::Core::Nostr->generate_key;
  my $source   = File::Spec->catfile($dir, 'source.pem');
  $existing->save_privkey($source);

  my $path = File::Spec->catfile($dir, 'imported.pem');
  my ($status, $output) = _keygen('--key-file', $path, '--import-file', $source);

  is $status,           0,                     'importing succeeds' or diag($output);
  is _pubkey_of($path), $existing->pubkey_hex, 'the imported identity is preserved, not regenerated';

  my $mode = (stat $path)[2] & oct('7777');
  is $mode, oct('600'), 'an imported key is protected exactly like a generated one';
};

subtest 'the public key can be read back without regenerating anything' => sub {
  my $dir  = tempdir(CLEANUP => 1);
  my $path = File::Spec->catfile($dir, 'id.pem');
  _keygen('--key-file', $path);
  my $expected = _pubkey_of($path);

  my ($status, $output) = _keygen('--key-file', $path, '--show');

  is $status, 0, 'showing an existing identity succeeds' or diag($output);
  like $output, qr/\Q$expected\E/mx, 'it prints the stored pubkey';
};

subtest 'asking for an identity that does not exist is an error, not an empty answer' => sub {
  my $dir = tempdir(CLEANUP => 1);
  my ($status, $output) = _keygen('--key-file', File::Spec->catfile($dir, 'missing.pem'), '--show');

  isnt $status, 0, 'the command fails';
  like $output, qr/no\ identity/imx, 'and says the identity is missing';
};

subtest 'private key material is never printed' => sub {
  my $dir  = tempdir(CLEANUP => 1);
  my $path = File::Spec->catfile($dir, 'id.pem');

  my (undef, $output) = _keygen('--key-file', $path);

  unlike $output, qr/PRIVATE\ KEY/mx, 'no PEM private key in the output';
  unlike $output, qr/nsec1/mx,        'and no nsec either';
};

subtest 'help explains the command' => sub {
  my ($status, $output) = _keygen('--help');
  is $status, 0, 'help succeeds';
  like $output, qr/keygen/mx,        'names the command';
  like $output, qr/--import-file/mx, 'documents importing an existing identity';
  like $output, qr/--key-file/mx,    'documents where the identity is stored';
};

# The subprocess tests above prove the wiring a user touches, but a separate
# process is invisible to coverage instrumentation running in this one, so the
# same paths are also driven in-process here.
use Overnet::Program::IRC::Script::Keygen;

sub _run {
  my (@argv) = @_;
  my ($out, $err) = (q{}, q{});
  my $status;
  {
    local *STDOUT;
    local *STDERR;
    open STDOUT, '>', \$out or die "reopen stdout: $!";
    open STDERR, '>', \$err or die "reopen stderr: $!";
    $status = Overnet::Program::IRC::Script::Keygen->run(@argv);
  }
  return ($status, $out, $err);
}

subtest 'in-process: every outcome the command can reach' => sub {
  my $dir  = tempdir(CLEANUP => 1);
  my $path = File::Spec->catfile($dir, 'id.pem');

  my ($help_status, $help_out) = _run('--help');
  is $help_status, 0, 'help succeeds';
  like $help_out, qr/keygen/mx, 'and prints usage';

  my ($status, $out) = _run('--key-file', $path);
  is $status, 0, 'an identity is generated';
  like $out, qr/[0-9a-f]{64}/mx, 'and its pubkey reported';

  my ($again, undef, $again_err) = _run('--key-file', $path);
  isnt $again, 0, 'a second run refuses';
  like $again_err, qr/already\ exists/imx, 'naming the conflict';

  my ($shown, $show_out) = _run('--key-file', $path, '--show');
  is $shown, 0, 'an existing identity can be shown';
  like $show_out, qr/\Q@{[_pubkey_of($path)]}\E/mx, 'printing the stored pubkey';

  my ($missing, undef, $missing_err) = _run('--key-file', File::Spec->catfile($dir, 'nope.pem'), '--show');
  isnt $missing, 0, 'showing an absent identity fails';
  like $missing_err, qr/no\ identity/imx, 'saying so';

  # Import, both forms.
  my $source = File::Spec->catfile($dir, 'src.pem');
  my $donor  = Overnet::Core::Nostr->generate_key;
  $donor->save_privkey($source);

  my $imported = File::Spec->catfile($dir, 'imported.pem');
  my ($import_status) = _run('--key-file', $imported, '--import-file', $source);
  is $import_status,        0,                  'importing from a file succeeds';
  is _pubkey_of($imported), $donor->pubkey_hex, 'preserving the identity';

  my ($no_source, undef, $no_source_err) =
    _run('--key-file', File::Spec->catfile($dir, 'x.pem'), '--import-file', File::Spec->catfile($dir, 'absent.pem'));
  isnt $no_source, 0, 'importing a file that is not there fails';
  like $no_source_err, qr/no\ such\ key\ file/imx, 'naming the missing file';

  # A raw 64-hex secret, the other form load_key accepts.
  my $hex          = 'a' x 64;
  my $from_hex     = File::Spec->catfile($dir, 'from-hex.pem');
  my ($hex_status) = _run('--key-file', $from_hex, '--import-nsec', $hex);
  is $hex_status, 0, 'importing a raw secret succeeds';
  is _pubkey_of($from_hex), Overnet::Core::Nostr->load_key(privkey => $hex)->pubkey_hex,
    'and yields the identity that secret denotes';

  my ($bad_opt) = _run('--not-an-option');
  isnt $bad_opt, 0, 'an unknown option is rejected';
};

subtest 'in-process: the default location is used when none is given' => sub {
  my $state = tempdir(CLEANUP => 1);
  local $ENV{XDG_STATE_HOME} = $state;

  # Nothing under the state directory exists yet, so this also exercises
  # creating the directory on the way.
  my ($status, $out) = _run();
  is $status, 0, 'an identity is created without being told where' or diag($out);

  my $expected = File::Spec->catfile($state, 'overnet', 'id.pem');
  ok -f $expected, 'it lands under the state directory';
  like $out, qr/\Q@{[_pubkey_of($expected)]}\E/mx, 'and its pubkey is reported';
};

subtest 'in-process: unwritable and unreadable identities are reported, not ignored' => sub {
  my $dir = tempdir(CLEANUP => 1);

  # A path whose parent cannot be created, because a plain file is in the way.
  # This fails for root too, unlike a permission bit.
  my $blocker = File::Spec->catfile($dir, 'blocker');
  open my $fh, '>', $blocker or die "open: $!";
  close $fh or die "close: $!";

  my ($status, undef, $err) = _run('--key-file', File::Spec->catfile($blocker, 'sub', 'id.pem'));
  isnt $status, 0, 'a key that cannot be written is an error';
  ok length $err, 'and the reason is reported';

  # A file that exists but is not a key at all.
  my $garbage = File::Spec->catfile($dir, 'garbage.pem');
  open my $gh, '>', $garbage or die "open: $!";
  print {$gh} "not a key\n" or die "print: $!";
  close $gh                 or die "close: $!";

  my ($show_status, undef, $show_err) = _run('--key-file', $garbage, '--show');
  isnt $show_status, 0, 'an unreadable identity is an error';
  ok length $show_err, 'and the reason is reported';
};

done_testing;
