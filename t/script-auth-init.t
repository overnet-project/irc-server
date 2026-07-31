use strictures 2;

use File::Spec;
use File::Temp qw(tempdir);
use FindBin;
use JSON ();
use Test2::V0;

use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/../../core-perl/lib";

use Overnet::Core::Nostr;

# Writing an auth-agent config by hand is where onboarding actually failed.
# Three things have to line up exactly or the agent fails closed at connect
# time with "approval is required but interactive approval is unavailable",
# and none of the three are guessable:
#
#   1. scope is derived as irc://<server-name>/<network>, documented nowhere
#      a user would look;
#   2. the proxy authenticates as program_id "irc.proxy", but the config
#      example users copy from says "irc.bridge" -- so the documented config
#      cannot authenticate the documented client;
#   3. TWO policies are needed, session.authenticate AND session.delegate.
#      One gets you through login and then fails on joining a hosted channel.
#
# This command exists so none of that has to be known. These tests pin the
# generated config against the values the proxy and helper actually send.

my $script = File::Spec->catfile($FindBin::Bin, '..', 'bin', 'overnet-irc-server');
ok -f $script, 'the overnet-irc-server command exists'
  or bail_out('overnet-irc-server is required');

sub _init {
  my (@argv)  = @_;
  my $command = join q{ }, map {qq{"$_"}} ($^X, $script, 'auth', 'init', @argv);
  my $output  = qx{$command 2>&1};
  return ($? >> 8, $output);
}

sub _config {
  my ($path) = @_;
  open my $fh, '<', $path or die "open $path: $!";
  local $/ = undef;
  my $json = <$fh>;
  close $fh or die "close: $!";
  return JSON->new->decode($json);
}

sub _fixture {
  my $dir = tempdir(CLEANUP => 1);
  my $key = File::Spec->catfile($dir, 'id.pem');
  Overnet::Core::Nostr->generate_key->save_privkey($key);
  return ($dir, $key, File::Spec->catfile($dir, 'auth-agent.json'));
}

subtest 'the generated config authorizes the client that will actually connect' => sub {
  my ($dir, $key, $out) = _fixture();

  my ($status, $output) =
    _init('--config-file', $out, '--key-file', $key, '--server-name', 'irc.example.net', '--network', 'overnet',);
  is $status, 0, 'scaffolding succeeds' or diag($output);

  my $config   = _config($out);
  my @policies = @{$config->{policies} || []};

  # The proxy's own default program id. If these disagree the agent fails
  # closed and the user is told only that approval is unavailable.
  is [sort map { $_->{program_id} } @policies], ['irc.proxy', 'irc.proxy'],
    'policies name the program id the proxy authenticates as';

  is [sort map { $_->{action} } @policies], ['session.authenticate', 'session.delegate'],
    'both the login and the delegation actions are granted';

  is [map { $_->{scope} } @policies], ['irc://irc.example.net/overnet', 'irc://irc.example.net/overnet'],
    'the scope is derived from the server name and network, as the server derives it';
};

subtest 'the identity is wired to the key the user generated' => sub {
  my ($dir, $key, $out) = _fixture();
  my $expected = Overnet::Core::Nostr->load_key(privkey => $key)->pubkey_hex;

  my ($status, $output) =
    _init('--config-file', $out, '--key-file', $key, '--server-name', 'irc.example.net', '--network', 'overnet',);
  is $status, 0, 'scaffolding succeeds' or diag($output);

  my $config = _config($out);
  my ($identity) = @{$config->{identities} || []};

  is $identity->{backend_type},           'direct_secret', 'the key file is used directly';
  is $identity->{backend_config}{secret}, $key,            'the backend points at the generated identity';
  is $identity->{public_identity}{value}, $expected,       'the advertised pubkey is the key\'s own';

  my ($policy) = @{$config->{policies} || []};
  is $policy->{identity_id}, $identity->{identity_id},
    'the policies are bound to that identity, not a differently-named one';
};

subtest 'granted policies survive an agent restart' => sub {
  my ($dir, $key, $out) = _fixture();
  _init('--config-file', $out, '--key-file', $key, '--server-name', 'irc.example.net', '--network', 'overnet');

  # Without daemon.state_file the agent has no state writer, so anything
  # granted later with policy-grant is silently lost on restart.
  my $config = _config($out);
  ok defined $config->{daemon}{state_file} && length $config->{daemon}{state_file},
    'a state file is configured so later grants persist';
  ok defined $config->{daemon}{endpoint} && length $config->{daemon}{endpoint},
    'the socket the proxy will connect to is configured';
};

subtest 'an existing config is never silently overwritten' => sub {
  my ($dir, $key, $out) = _fixture();
  _init('--config-file', $out, '--key-file', $key, '--server-name', 'irc.example.net', '--network', 'overnet');

  my ($status, $output) =
    _init('--config-file', $out, '--key-file', $key, '--server-name', 'other.example.net', '--network', 'other',);

  isnt $status, 0, 'a second run refuses';
  like $output, qr/already\ exists/imx, 'and says why';

  my $config = _config($out);
  is $config->{policies}[0]{scope}, 'irc://irc.example.net/overnet', 'the original config is untouched';
};

subtest 'the config is not world readable' => sub {
  my ($dir, $key, $out) = _fixture();
  _init('--config-file', $out, '--key-file', $key, '--server-name', 'irc.example.net', '--network', 'overnet');

  # It names the path to the private key, and with a pass entry it can carry
  # the secret itself.
  my $mode = (stat $out)[2] & oct('7777');
  is $mode, oct('600'), 'only the owner can read the agent config';
};

subtest 'a password-store entry can be used instead of a key file' => sub {
  my ($dir, $key, $out) = _fixture();

  my ($status, $output) = _init('--config-file', $out, '--pass-entry', 'overnet-priv-key',
    '--server-name', 'irc.example.net', '--network', 'overnet',);
  is $status, 0, 'scaffolding from a pass entry succeeds' or diag($output);

  my $config = _config($out);
  my ($identity) = @{$config->{identities} || []};
  is $identity->{backend_type},          'pass',             'the pass backend is selected';
  is $identity->{backend_config}{entry}, 'overnet-priv-key', 'the entry is recorded';
};

subtest 'it refuses to guess when it has no identity to wire up' => sub {
  my ($dir, $key, $out) = _fixture();
  my ($status, $output) = _init('--config-file', $out, '--server-name', 'irc.example.net', '--network', 'overnet',);

  isnt $status, 0, 'a config with no identity is not written';
  like $output, qr/--key-file|--pass-entry/mx, 'and it says which option is missing';
  ok !-e $out, 'no half-configured file is left behind';
};

subtest 'a real auth agent authorizes the requests the proxy will make' => sub {

  # Asserting the JSON fields is not enough: they only have to agree with what
  # the agent matches on, and every earlier onboarding failure was a config
  # whose fields looked right and was still refused. Build the agent the daemon
  # would build from this config and ask it the questions the proxy asks.
  eval { require Overnet::Auth::Config; require Overnet::Auth::Agent; 1 }
    or skip_all('Overnet::Auth is not available');

  my ($dir, $key, $out) = _fixture();
  _init('--config-file', $out, '--key-file', $key, '--server-name', 'irc.example.net', '--network', 'overnet');

  my $config = Overnet::Auth::Config->load_file(path => $out);
  my $agent  = Overnet::Auth::Agent->new(%{$config->agent_args});
  my $scope  = 'irc://irc.example.net/overnet';

  for my $action (@{['session.authenticate', 'session.delegate']}) {
    ok $agent->_policy_matches(
      identity_id => 'default',
      program_id  => 'irc.proxy',
      scope       => $scope,
      action      => $action,
      service     => {locators => [$scope]},
      ),
      "the agent authorizes $action without falling back to approval";
  }

  # The generated config must not be a blanket permit.
  ok !$agent->_policy_matches(
    identity_id => 'default',
    program_id  => 'irc.proxy',
    scope       => 'irc://elsewhere.example.net/other',
    action      => 'session.authenticate',
    service     => {locators => ['irc://elsewhere.example.net/other']},
    ),
    'it does not authorize a different server';
};

subtest 'help explains the command' => sub {
  my ($status, $output) = _init('--help');
  is $status, 0, 'help succeeds';
  like $output, qr/--server-name/mx, 'documents the server name';
  like $output, qr/--key-file/mx,    'documents the identity';
};

# The subprocess tests above prove the wiring a user touches, but a separate
# process is invisible to coverage instrumentation running in this one, so the
# same paths are also driven in-process here.
use Overnet::Program::IRC::Script::AuthInit;

sub _run {
  my (@argv) = @_;
  my ($out, $err) = (q{}, q{});
  my $status;
  {
    local *STDOUT;
    local *STDERR;
    open STDOUT, '>', \$out or die "reopen stdout: $!";
    open STDERR, '>', \$err or die "reopen stderr: $!";
    $status = Overnet::Program::IRC::Script::AuthInit->run(@argv);
  }
  return ($status, $out, $err);
}

subtest 'in-process: every outcome the command can reach' => sub {
  my ($dir, $key, $out) = _fixture();

  my ($help_status, $help_out) = _run('--help');
  is $help_status, 0, 'help succeeds';
  like $help_out, qr/--server-name/mx, 'and prints usage';

  my ($bad_opt) = _run('--not-an-option');
  isnt $bad_opt, 0, 'an unknown option is rejected';

  my ($no_server, undef, $no_server_err) = _run('--config-file', $out, '--key-file', $key, '--network', 'overnet');
  isnt $no_server, 0, 'a missing server name fails';
  like $no_server_err, qr/--server-name\ is\ required/mx, 'naming the option';

  my ($no_net, undef, $no_net_err) =
    _run('--config-file', $out, '--key-file', $key, '--server-name', 'irc.example.net');
  isnt $no_net, 0, 'a missing network fails';
  like $no_net_err, qr/--network\ is\ required/mx, 'naming the option';

  my ($no_id, undef, $no_id_err) =
    _run('--config-file', $out, '--server-name', 'irc.example.net', '--network', 'overnet');
  isnt $no_id, 0, 'a missing identity fails';
  like $no_id_err, qr/--key-file/mx, 'pointing at the identity options';

  my ($absent, undef, $absent_err) = _run('--config-file', $out, '--key-file', File::Spec->catfile($dir, 'nope.pem'),
    '--server-name', 'irc.example.net', '--network', 'overnet',);
  isnt $absent, 0, 'a key file that is not there fails';
  like $absent_err, qr/keygen/mx, 'and says how to create one';

  my ($ok, $ok_out) =
    _run('--config-file', $out, '--key-file', $key, '--server-name', 'irc.example.net', '--network', 'overnet',);
  is $ok, 0, 'a complete invocation succeeds';
  like $ok_out, qr/auth-agent\ config\ written/mx, 'reporting where it went';
  like $ok_out, qr/overnet-auth-agent/mx,          'and what to run next';

  my ($again, undef, $again_err) =
    _run('--config-file', $out, '--key-file', $key, '--server-name', 'irc.example.net', '--network', 'overnet',);
  isnt $again, 0, 'a second run refuses';
  like $again_err, qr/already\ exists/imx, 'naming the conflict';

  # The pass backend takes a different branch and prints no pubkey, since the
  # secret is not readable from here.
  my $pass_out = File::Spec->catfile($dir, 'pass.json');
  my ($pass_status, $pass_stdout) = _run(
    '--config-file', $pass_out,
    '--pass-entry',  'overnet-priv-key',
    '--server-name', 'irc.example.net',
    '--network',     'overnet',
    '--auth-sock',   File::Spec->catfile($dir, 'auth.sock'),
    '--state-file',  File::Spec->catfile($dir, 'state.json'),
    '--identity-id', 'work',
  );
  is $pass_status, 0, 'a pass-backed config succeeds';
  unlike $pass_stdout, qr/public\ key/mx, 'and advertises no pubkey it cannot read';
};

subtest 'in-process: the default location is used when none is given' => sub {
  my $state = tempdir(CLEANUP => 1);
  local $ENV{XDG_STATE_HOME} = $state;

  my $dir = tempdir(CLEANUP => 1);
  my $key = File::Spec->catfile($dir, 'id.pem');
  Overnet::Core::Nostr->generate_key->save_privkey($key);

  my ($status, $out) = _run('--key-file', $key, '--server-name', 'irc.example.net', '--network', 'overnet');
  is $status, 0, 'a config is written without being told where' or diag($out);
  ok -f File::Spec->catfile($state, 'overnet', 'auth-agent.json'), 'it lands under the state directory';
};

subtest 'in-process: a config that cannot be built or written is reported' => sub {
  my $dir = tempdir(CLEANUP => 1);

  # A file that exists but holds no usable key: reading its pubkey fails while
  # building the config, before anything is written.
  my $garbage = File::Spec->catfile($dir, 'garbage.pem');
  open my $gh, '>', $garbage or die "open: $!";
  print {$gh} "not a key\n" or die "print: $!";
  close $gh                 or die "close: $!";

  my $out = File::Spec->catfile($dir, 'from-garbage.json');
  my ($status, undef, $err) =
    _run('--config-file', $out, '--key-file', $garbage, '--server-name', 'irc.example.net', '--network', 'overnet');
  isnt $status, 0, 'an unusable identity fails the build';
  ok length $err, 'and the reason is reported';
  ok !-e $out,    'leaving no half-written config behind';

  # A path whose parent cannot be created, because a plain file is in the way.
  my $key = File::Spec->catfile($dir, 'id.pem');
  Overnet::Core::Nostr->generate_key->save_privkey($key);
  my $blocker = File::Spec->catfile($dir, 'blocker');
  open my $fh, '>', $blocker or die "open: $!";
  close $fh or die "close: $!";

  my ($write_status, undef, $write_err) = _run('--config-file', File::Spec->catfile($blocker, 'sub', 'agent.json'),
    '--key-file', $key, '--server-name', 'irc.example.net', '--network', 'overnet',);
  isnt $write_status, 0, 'a config that cannot be written is an error';
  ok length $write_err, 'and the reason is reported';
};

done_testing;
