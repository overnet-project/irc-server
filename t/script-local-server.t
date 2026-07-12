use strictures 2;

use Capture::Tiny qw(capture);
use File::Spec;
use File::Temp qw(tempdir);
use Test2::V0;

use Overnet::Program::IRC::Script::LocalServer;

my $package = 'Overnet::Program::IRC::Script::LocalServer';
my $tempdir = tempdir(CLEANUP => 1);

my $ready_details = {
  listen_host => '127.0.0.1',
  listen_port => 16_667,
  network     => 'local',
  server_name => 'overnet.irc.local',
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
      start                  => $behavior{start} || sub { return 1 },
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
      has_exited        => $behavior{has_exited}        || sub { return 0 },
      exit_code         => $behavior{exit_code}         || sub { return 0 },
      stderr_output     => $behavior{stderr_output}     || sub { return q{} },
      request_shutdown  => $behavior{request_shutdown}  || sub { return 1 },
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

subtest '--help prints usage to stdout' => sub {
  my $run = _run('--help');
  is $run->{exit}, 0, '--help exits successfully';
  like $run->{stdout}, qr/local-server\ \[options\]/mxs, 'usage names the command';
};

subtest 'unknown options print usage and fail' => sub {
  my $run = _run('--frobnicate');
  is $run->{exit}, 1, 'unknown options fail';
  like $run->{stdout}, qr/local-server\ \[options\]/mxs, 'usage is printed';
};

subtest 'an invalid listen port croaks' => sub {
  like dies { $package->run('--listen-port', '65536') }, qr/listen-port\ must\ be/mxs,
    'a port beyond 65535 croaks';
};

subtest 'a plaintext demo run serves until interrupted' => sub {
  local $ENV{XDG_STATE_HOME} = $tempdir;
  my $host = _mock_host();

  my $run = _run();
  is $run->{exit}, 0, 'the demo run exits successfully after SIGINT';
  like $run->{stdout}, qr/local\ demo\ server\ is\ ready/mxs,     'the ready banner is printed';
  like $run->{stdout}, qr/Listening\ on\ 127[.]0[.]0[.]1:16667/mxs, 'the listen address is printed';
  like $run->{stdout}, qr/chat-client\ --nick\ alice/mxs,         'client instructions are printed';
  like $run->{stdout}, qr/Server\ stopped[.]/mxs,                 'the shutdown message is printed';
  unlike $run->{stdout}, qr/TLS:\ enabled/mxs, 'no TLS details are printed for a plaintext run';
  like $run->{stderr}, qr/\[program[.]info\]\ runtime[.]init\ accepted/mxs, 'program logs are forwarded';
  ok -f File::Spec->catfile($tempdir, 'irc-server', 'local-demo-signing-key.pem'),
    'a default signing key was created';
};

subtest 'a TLS demo run prints TLS and HexChat instructions' => sub {
  local $ENV{XDG_STATE_HOME} = $tempdir;
  my $host      = _mock_host();
  my $cert_file = File::Spec->catfile($tempdir, 'demo-tls', 'cert.pem');
  my $key_file  = File::Spec->catfile($tempdir, 'demo-tls', 'key.pem');

  my $run = _run(
    '--tls',
    '--tls-cert-chain-file',  $cert_file,
    '--tls-private-key-file', $key_file,
    '--tls-ca-file',          $cert_file,
    '--tls-verify-peer',
    '--signing-key-file', File::Spec->catfile($tempdir, 'demo-signing-key.pem'),
  );
  is $run->{exit}, 0, 'the TLS demo run exits successfully after SIGINT';
  like $run->{stdout}, qr/TLS:\ enabled/mxs,          'TLS details are printed';
  like $run->{stdout}, qr/--tls\ --tls-no-verify/mxs, 'client instructions include the TLS flags';
  like $run->{stdout}, qr/HexChat\ can\ connect/mxs,  'HexChat instructions are printed';
  like $run->{stdout}, qr/SSL_CERT_FILE=/mxs,         'the generated certificate is referenced';
  ok -f $cert_file, 'the TLS certificate was generated';
  ok -f $key_file,  'the TLS private key was generated';
};

subtest 'TLS defaults land in the state directory' => sub {
  local $ENV{XDG_STATE_HOME} = $tempdir;
  my $host = _mock_host();

  my $run = _run('--tls', '--no-tls-verify-peer');
  is $run->{exit}, 0, 'the defaulted TLS run exits successfully';
  ok -f File::Spec->catfile($tempdir, 'irc-server', 'local-demo-tls-cert.pem'), 'the default certificate exists';
  ok -f File::Spec->catfile($tempdir, 'irc-server', 'local-demo-tls-key.pem'),  'the default key exists';
};

subtest 'a host that never becomes ready croaks' => sub {
  local $ENV{XDG_STATE_HOME} = $tempdir;
  my $host = _mock_host(notifications => [],);

  like dies {
    capture { $package->run() };
  }, qr/Program\ did\ not\ publish\ ready\ health\ details/mxs, 'missing readiness croaks';
};

subtest 'a host that exits mid-run croaks with its exit code' => sub {
  local $ENV{XDG_STATE_HOME} = $tempdir;
  my $host = _mock_host(
    pump       => sub { return 1 },
    has_exited => sub { return 1 },
    exit_code  => sub { return 3 },
    stderr_output => sub { return "listener exploded\n" },
  );

  like dies {
    capture { $package->run() };
  }, qr/IRC\ server\ exited\ unexpectedly\ [(]3[)]\nlistener\ exploded/mxs, 'the exit code and stderr are reported';
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
