use strictures 2;

use Capture::Tiny qw(capture);
use File::Spec;
use File::Temp qw(tempdir);
use JSON ();
use Test2::V0;

use Overnet::Program::IRC::Script::Service;

my $package = 'Overnet::Program::IRC::Script::Service';
my $tempdir = tempdir(CLEANUP => 1);

my $ready_details = {
  listen_host => '127.0.0.1',
  listen_port => 16_667,
  network     => 'overnet',
  server_name => 'irc.overnet.local',
};

sub _ready_notifications {
  return [
    {
      method => 'program.log',
      params => {
        level   => 'info',
        message => 'runtime.init accepted',
      },
    },
    {
      method => 'program.health',
      params => {
        status  => 'ready',
        details => $ready_details,
      },
    },
  ];
}

sub _mock_host {
  my (%behavior) = @_;
  my $notifications = $behavior{notifications} || _ready_notifications();
  return mock 'Overnet::Program::Host' => (
    override => [
      start                  => sub { return 1 },
      observed_notifications => sub { return $notifications },
      pump_until             => sub {
        my ($self, %args) = @_;
        return $args{condition}->($self) ? 1 : 0;
      },
      pump => $behavior{pump} || sub {
        kill 'TERM', $$;
        kill 'INT',  $$;
        return 1;
      },
      has_exited       => $behavior{has_exited}       || sub { return 0 },
      exit_code        => $behavior{exit_code}        || sub { return 0 },
      stderr_output    => $behavior{stderr_output}    || sub { return q{} },
      request_shutdown => $behavior{request_shutdown} || sub { return 1 },
    ],
  );
}

sub _run {
  my (@argv) = @_;
  my ($stdout, $stderr, $exit) = capture {
    local $SIG{INT}  = sub { };
    local $SIG{TERM} = sub { };
    $package->run(@argv);
  };
  return {
    stdout => $stdout,
    stderr => $stderr,
    exit   => $exit,
  };
}

sub _slurp {
  my ($path) = @_;
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $content = do { local $/ = undef; <$fh> };
  close $fh or die "Can't close $path: $!";
  return $content;
}

subtest '--help prints usage to stdout' => sub {
  my $run = _run('--help');
  is $run->{exit}, 0, '--help exits successfully';
  like $run->{stdout}, qr/overnet-irc-server\ service\ \[options\]/mxs, 'usage names the command';
};

subtest 'unknown options print usage to stderr' => sub {
  my $run = _run('--frobnicate');
  is $run->{exit}, 1, 'unknown options fail';
  like $run->{stderr}, qr/overnet-irc-server\ service\ \[options\]/mxs, 'usage goes to stderr';
};

subtest 'an invalid listen port croaks' => sub {
  like dies { $package->run('--listen-port', '65536') }, qr/listen-port\ must\ be/mxs,
    'a port beyond 65535 croaks';
};

subtest 'a malformed channel group croaks' => sub {
  local $ENV{XDG_STATE_HOME} = $tempdir;
  like dies { $package->run('--channel-group', 'missing-separator') },
    qr/--channel-group\ must\ be\ CHANNEL=GROUP_ID/mxs, 'a channel group without = croaks';
};

subtest 'a full service run writes health and log files' => sub {
  local $ENV{XDG_STATE_HOME} = $tempdir;
  my $host        = _mock_host();
  my $health_file = File::Spec->catfile($tempdir, 'service', 'health.json');
  my $log_file    = File::Spec->catfile($tempdir, 'service', 'service.log');

  my $run = _run(
    '--health-file',        $health_file,
    '--log-file',           $log_file,
    '--group-host',         'groups.example.test',
    '--channel-group',      '#overnet=groups.example.test:overnet',
    '--authority-relay-url', 'ws://relay.example.test:1',
    '--authority-relay-query-timeout-ms', '500',
    '--authority-relay-poll-interval-ms', '250',
  );
  is $run->{exit}, 0, 'the service run exits successfully after SIGINT';

  my $health = JSON->new->decode(_slurp($health_file));
  is $health->{status}, 'stopped', 'the final health status is stopped';
  is $health->{details}, $ready_details, 'the stopped health keeps the ready details';

  my $log = _slurp($log_file);
  like $log, qr/starting\ IRC\ service/mxs,                             'startup is logged';
  like $log, qr/ready\ listen=127[.]0[.]0[.]1:16667/mxs,                'readiness is logged';
  like $log, qr/\[program[.]info\]\ runtime[.]init\ accepted/mxs,       'program notifications are logged';
  like $log, qr/shutting\ down\ IRC\ service/mxs,                       'shutdown is logged';
  like $log, qr/stopped\ IRC\ service/mxs,                              'the stop is logged';

  ok -f File::Spec->catfile($tempdir, 'irc-server', 'service-signing-key.pem'), 'a default signing key was created';
};

subtest 'a TLS service run generates certificate material' => sub {
  local $ENV{XDG_STATE_HOME} = $tempdir;
  my $host      = _mock_host();
  my $cert_file = File::Spec->catfile($tempdir, 'service-tls', 'cert.pem');
  my $key_file  = File::Spec->catfile($tempdir, 'service-tls', 'key.pem');

  my $run = _run(
    '--tls',
    '--tls-cert-chain-file',  $cert_file,
    '--tls-private-key-file', $key_file,
    '--tls-ca-file',          $cert_file,
    '--tls-verify-peer',
    '--signing-key-file', File::Spec->catfile($tempdir, 'service-signing-key.pem'),
  );
  is $run->{exit}, 0, 'the TLS service run exits successfully';
  ok -f $cert_file, 'the TLS certificate was generated';
  ok -f $key_file,  'the TLS private key was generated';

  my $defaulted = _run('--tls', '--no-tls-verify-peer');
  is $defaulted->{exit}, 0, 'a TLS run with defaulted material exits successfully';
  ok -f File::Spec->catfile($tempdir, 'irc-server', 'service-tls-cert.pem'), 'the default certificate exists';
  ok -f File::Spec->catfile($tempdir, 'irc-server', 'service-tls-key.pem'),  'the default key exists';
};

subtest 'a host that never becomes ready croaks' => sub {
  local $ENV{XDG_STATE_HOME} = $tempdir;
  my $host = _mock_host(notifications => [],);

  like dies {
    capture { $package->run() };
  }, qr/Program\ did\ not\ publish\ ready\ health\ details/mxs, 'missing readiness croaks';
};

subtest 'a host that exits mid-run reports failed health' => sub {
  local $ENV{XDG_STATE_HOME} = $tempdir;
  my $health_file = File::Spec->catfile($tempdir, 'failed', 'health.json');
  my $host        = _mock_host(
    pump          => sub { return 1 },
    has_exited    => sub { return 1 },
    exit_code     => sub { return 3 },
    stderr_output => sub { return "listener exploded\n" },
  );

  like dies {
    capture { $package->run('--health-file', $health_file) };
  }, qr/IRC\ server\ exited\ unexpectedly\ [(]3[)]\nlistener\ exploded/mxs, 'the exit code and stderr are reported';
  my $health = JSON->new->decode(_slurp($health_file));
  is $health, {status => 'failed', details => {exit_code => 3,},}, 'failed health names the exit code';
};

subtest 'a host killed by a signal reports "signal"' => sub {
  local $ENV{XDG_STATE_HOME} = $tempdir;
  my $host = _mock_host(
    pump          => sub { return 1 },
    has_exited    => sub { return 1 },
    exit_code     => sub { return undef },
    stderr_output => sub { return q{} },
  );

  like dies {
    capture { $package->run() };
  }, qr/IRC\ server\ exited\ unexpectedly\ [(]signal[)]/mxs, 'a signal death is reported';
};

subtest 'a failing shutdown request croaks' => sub {
  local $ENV{XDG_STATE_HOME} = $tempdir;
  my $host = _mock_host(request_shutdown => sub { die "shutdown pipe closed\n" },);

  like dies {
    capture {
      local $SIG{INT}  = sub { };
      local $SIG{TERM} = sub { };
      $package->run();
    };
  }, qr/Failed\ to\ shut\ down\ cleanly:\ shutdown\ pipe\ closed/mxs, 'the shutdown failure is reported';
};

subtest 'a failed adapter registration croaks' => sub {
  local $ENV{XDG_STATE_HOME} = $tempdir;
  my $runtime = mock 'Overnet::Program::Runtime' => (override => [register_adapter_definition => sub { return 0 },],);

  like dies { $package->run() }, qr/Failed\ to\ register\ IRC\ adapter\ definition/mxs,
    'a rejected adapter definition croaks';
};

done_testing;
