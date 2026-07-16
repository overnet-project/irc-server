use strictures 2;

use Capture::Tiny qw(capture);
use File::Spec;
use File::Temp qw(tempdir);
use JSON ();
use POSIX qw(_exit);
use Time::HiRes qw(sleep);
use Test2::V0;

use Overnet::Program::IRC::Script::AuthorityRelayService;

my $package = 'Overnet::Program::IRC::Script::AuthorityRelayService';
my $tempdir = tempdir(CLEANUP => 1);

sub _run {
  my (@argv) = @_;
  my ($stdout, $stderr, $exit) = capture {
    $package->run(@argv);
  };
  return {
    stdout => $stdout,
    stderr => $stderr,
    exit   => $exit,
  };
}

sub _read_health {
  my ($path) = @_;
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $content = do { local $/ = undef; <$fh> };
  close $fh or die "Can't close $path: $!";
  return JSON->new->decode($content);
}

sub _spawn_sleeper {
  my (@extra) = @_;
  return Overnet::Program::IRC::Script::AuthorityRelayService::_spawn_child($^X, '-e', join(q{ }, @extra, 'sleep 60'),
  );
}

sub _spawn_killer {
  my ($delay, @signals) = @_;
  my $parent = $$;
  my $pid    = fork;
  die "fork failed: $!" if !defined $pid;
  if (!$pid) {
    sleep $delay;
    for my $signal (@signals) {
      kill $signal, $parent;
    }
    _exit(0);
  }
  return $pid;
}

subtest '--help prints usage to stdout' => sub {
  my $run = _run('--help');
  is $run->{exit}, 0, '--help exits successfully';
  like $run->{stdout}, qr/authority-relay-service\ \[options\]/mxs, 'usage names the command';
};

subtest 'unknown options print usage to stderr' => sub {
  my $run = _run('--frobnicate');
  is $run->{exit}, 1, 'unknown options fail';
  like $run->{stderr}, qr/authority-relay-service\ \[options\]/mxs, 'usage goes to stderr';
};

subtest 'invalid option values croak' => sub {
  like dies { $package->run('--host', q{}) }, qr/--host\ is\ required/mxs, 'an empty host croaks';
  like dies { $package->run('--port=-1') }, qr/--port\ must\ be\ a\ non-negative\ integer/mxs,
    'a negative port croaks';
  like dies { $package->run('--grant-kind', 0) }, qr/--grant-kind\ must\ be\ a\ positive\ integer/mxs,
    'grant-kind zero croaks';
  like dies { $package->run('--store-file', q{}) }, qr/--store-file\ must\ be\ a\ non-empty\ string/mxs,
    'an empty store file croaks';
  like dies { $package->run('--snapshot-pubkey', 'nope') },
    qr/--snapshot-pubkey\ must\ be\ a\ 64-char\ lowercase\ hex\ pubkey/mxs, 'a malformed snapshot pubkey croaks';
};

subtest '_fill_defaults derives the relay URL and store file' => sub {
  my $options = {
    host => '192.0.2.5',
    port => 7_001,
  };
  {
    local $ENV{XDG_STATE_HOME} = $tempdir;
    Overnet::Program::IRC::Script::AuthorityRelayService::_fill_defaults($options);
  }
  is $options->{relay_url}, 'ws://192.0.2.5:7001', 'the relay URL defaults from host and port';
  is $options->{store_file}, File::Spec->catfile($tempdir, 'irc-server', 'authority-relay-store.json'),
    'the store file defaults into the state directory';

  my $explicit = {
    host       => '192.0.2.5',
    port       => 7_001,
    relay_url  => 'ws://relay.example.test:1',
    store_file => '/tmp/store.json',
  };
  Overnet::Program::IRC::Script::AuthorityRelayService::_fill_defaults($explicit);
  is $explicit->{relay_url},  'ws://relay.example.test:1', 'an explicit relay URL is kept';
  is $explicit->{store_file}, '/tmp/store.json',           'an explicit store file is kept';
};

subtest 'health writers record the service lifecycle' => sub {
  my $health_file = File::Spec->catfile($tempdir, 'health.json');
  my $options     = {
    host       => '127.0.0.1',
    port       => '7448',
    relay_url  => 'ws://127.0.0.1:7448',
    grant_kind => '14142',
    store_file => '/tmp/store.json',
  };

  Overnet::Program::IRC::Script::AuthorityRelayService::_write_ready_health($health_file, $options);
  is _read_health($health_file),
    {
    status  => 'ready',
    details => {
      listen_host => '127.0.0.1',
      listen_port => 7_448,
      relay_url   => 'ws://127.0.0.1:7448',
      grant_kind  => 14_142,
      store_file  => '/tmp/store.json',
    },
    },
    'ready health includes the listen and store details';

  Overnet::Program::IRC::Script::AuthorityRelayService::_write_stopping_health($health_file, $options);
  is _read_health($health_file)->{status}, 'stopping', 'stopping health is written';

  Overnet::Program::IRC::Script::AuthorityRelayService::_write_stopped_health($health_file, $options);
  is _read_health($health_file)->{status}, 'stopped', 'stopped health is written';
};

subtest '_spawn_child and _stop_child manage a live child process' => sub {
  my $child = _spawn_sleeper();
  ok $child->{pid}, 'the child process has a pid';
  is Overnet::Program::IRC::Script::AuthorityRelayService::_check_child($child, undef, {}), 1,
    'a running child passes the health check';
  is Overnet::Program::IRC::Script::AuthorityRelayService::_stop_child($child), 1, 'a TERM stops the child';

  is Overnet::Program::IRC::Script::AuthorityRelayService::_stop_child(undef), 1, 'a missing child is ignored';
  is Overnet::Program::IRC::Script::AuthorityRelayService::_stop_child({}),    1, 'a child without a pid is ignored';

  my $stubborn = _spawn_sleeper(q{$SIG{TERM} = 'IGNORE';});
  sleep 0.2;
  is Overnet::Program::IRC::Script::AuthorityRelayService::_stop_child($stubborn), 1,
    'a child that ignores TERM is killed';
};

subtest '_check_child reports an exited child as failed' => sub {
  my $health_file = File::Spec->catfile($tempdir, 'failed-health.json');
  my $child       = Overnet::Program::IRC::Script::AuthorityRelayService::_spawn_child($^X, '-e', 'exit 7');
  sleep 0.2;
  my $options = {relay_url => 'ws://127.0.0.1:7448',};
  like dies { Overnet::Program::IRC::Script::AuthorityRelayService::_check_child($child, $health_file, $options) },
    qr/authoritative\ IRC\ relay\ exited\ unexpectedly\ [(]7[)]/mxs, 'an exited child croaks';
  is _read_health($health_file),
    {
    status  => 'failed',
    details => {
      exit_code => 7,
      relay_url => 'ws://127.0.0.1:7448',
    },
    },
    'failed health names the exit code';
};

subtest '_wait_for_relay_ready succeeds once a client can connect' => sub {
  my @connected;
  my $client = mock 'Net::Nostr::Client' => (
    override => [
      connect    => sub { push @connected, $_[1]; return 1 },
      disconnect => sub { return 1 },
    ],
  );
  is Overnet::Program::IRC::Script::AuthorityRelayService::_wait_for_relay_ready('ws://127.0.0.1:1'), 1,
    'a connectable relay is ready';
  is \@connected, ['ws://127.0.0.1:1'], 'the probe connected to the relay URL';
};

subtest '_wait_for_relay_ready croaks when the relay never accepts' => sub {
  my $client = mock 'Net::Nostr::Client' => (override => [connect => sub { die "connection refused\n" },],);
  like dies { Overnet::Program::IRC::Script::AuthorityRelayService::_wait_for_relay_ready('ws://127.0.0.1:1') },
    qr/authoritative\ IRC\ relay\ did\ not\ become\ ready/mxs, 'an unreachable relay croaks after the deadline';
};

subtest '_spawn_relay_child launches the relay command' => sub {
  my $child = Overnet::Program::IRC::Script::AuthorityRelayService::_spawn_relay_child(
    {
      host             => '127.0.0.1',
      port             => 0,
      relay_url        => 'ws://127.0.0.1:0',
      grant_kind       => 14_142,
      store_file       => File::Spec->catfile($tempdir, 'spawn-store.json'),
      snapshot_pubkeys => ['a' x 64],
    }
  );
  ok $child->{pid}, 'the relay child was spawned';
  is Overnet::Program::IRC::Script::AuthorityRelayService::_stop_child($child), 1, 'the relay child was stopped';
};

subtest 'run supervises the child until shutdown' => sub {
  my $health_file = File::Spec->catfile($tempdir, 'run-health.json');
  my $log_file    = File::Spec->catfile($tempdir, 'run-log.txt');

  my $spawner = mock $package => (override => [_spawn_relay_child => sub { return _spawn_sleeper() },],);
  my $client  = mock 'Net::Nostr::Client' => (
    override => [
      connect    => sub { return 1 },
      disconnect => sub { return 1 },
    ],
  );

  # Both signal handlers must run; the killer sends them back-to-back so both
  # arrive while the supervision loop is still active. The outer no-op
  # handlers absorb any signal that lands after the loop has already exited.
  local $SIG{INT}  = sub { };
  local $SIG{TERM} = sub { };
  _spawn_killer(0.5, 'TERM', 'INT');
  my $exit = $package->run(
    '--health-file', $health_file, '--log-file', $log_file,
    '--store-file',  '/tmp/store.json',
  );
  is $exit, 0, 'a supervised run exits successfully after SIGINT';
  is _read_health($health_file)->{status}, 'stopped', 'the final health status is stopped';

  open my $fh, '<', $log_file or die "Can't read $log_file: $!";
  my $log = do { local $/ = undef; <$fh> };
  close $fh or die "Can't close $log_file: $!";
  like $log, qr/starting\ authoritative\ IRC\ relay\ service/mxs, 'startup is logged';
  like $log, qr/ready\ relay=/mxs,                                'readiness is logged';
  like $log, qr/stopped\ authoritative\ IRC\ relay\ service/mxs,  'shutdown is logged';
};

subtest 'run stops the child when readiness fails' => sub {
  my $spawner = mock $package => (
    override => [
      _spawn_relay_child    => sub { return _spawn_sleeper() },
      _wait_for_relay_ready => sub { die "relay never came up\n" },
    ],
  );

  like dies { $package->run('--store-file', '/tmp/store.json') }, qr/relay\ never\ came\ up/mxs,
    'a readiness failure is propagated after stopping the child';
};

subtest '_spawn_relay_child forwards each snapshot pubkey as a --snapshot-pubkey argument' => sub {
  my @command;
  my $spawn = mock $package => (override => [_spawn_child => sub { @command = @_; return {pid => 4321} }],);
  Overnet::Program::IRC::Script::AuthorityRelayService::_spawn_relay_child(
    {
      host             => '127.0.0.1',
      port             => 0,
      relay_url        => 'ws://127.0.0.1:0',
      grant_kind       => 14_142,
      store_file       => '/tmp/store.json',
      snapshot_pubkeys => ['a' x 64, 'b' x 64],
    }
  );
  my @forwarded;
  for my $i (0 .. $#command - 1) {
    push @forwarded, $command[$i + 1] if $command[$i] eq '--snapshot-pubkey';
  }
  is \@forwarded, ['a' x 64, 'b' x 64], 'both snapshot pubkeys are forwarded to the relay child';
};

subtest '_fill_defaults replaces an empty relay URL and store file with derived defaults' => sub {
  my $options = {
    host       => '192.0.2.7',
    port       => 7_002,
    relay_url  => q{},
    store_file => q{},
  };
  {
    local $ENV{XDG_STATE_HOME} = $tempdir;
    Overnet::Program::IRC::Script::AuthorityRelayService::_fill_defaults($options);
  }
  is $options->{relay_url}, 'ws://192.0.2.7:7002', 'an empty relay URL is replaced with the derived default';
  is $options->{store_file}, File::Spec->catfile($tempdir, 'irc-server', 'authority-relay-store.json'),
    'an empty store file is replaced with the derived default';
};

subtest 'lifecycle health details report the positive numeric listen port' => sub {
  my $health_file = File::Spec->catfile($tempdir, 'listen-port-health.json');
  my $options     = {
    host      => '127.0.0.1',
    port      => '7448',
    relay_url => 'ws://127.0.0.1:7448',
  };

  Overnet::Program::IRC::Script::AuthorityRelayService::_write_stopping_health($health_file, $options);
  is _read_health($health_file)->{details}{listen_port}, 7_448, 'stopping health reports the positive listen port';

  Overnet::Program::IRC::Script::AuthorityRelayService::_write_stopped_health($health_file, $options);
  is _read_health($health_file)->{details}{listen_port}, 7_448, 'stopped health reports the positive listen port';
};

subtest '_stop_child honours the graceful deadline before force-killing a stubborn child' => sub {
  my $stubborn = _spawn_sleeper(q{$SIG{TERM} = 'IGNORE';});
  sleep 0.2;
  my $pid   = $stubborn->{pid};
  my $start = Time::HiRes::time();
  is Overnet::Program::IRC::Script::AuthorityRelayService::_stop_child($stubborn), 1, 'stop_child returns after killing';
  my $elapsed = Time::HiRes::time() - $start;
  ok $elapsed >= 2, 'stop_child waits the graceful deadline before escalating to SIGKILL';
  is waitpid($pid, POSIX::WNOHANG()), -1, 'the stubborn child was force-killed and reaped';

  # Guard against a mutant that leaves the child running: never leak the sleeper.
  kill 'KILL', $pid;
  waitpid $pid, 0;
};

done_testing;
