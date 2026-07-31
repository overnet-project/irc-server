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

done_testing;
