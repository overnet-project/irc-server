use strictures 2;

use Capture::Tiny qw(capture);
use File::Spec;
use File::Temp qw(tempdir);
use IO::Socket::INET;
use IO::Socket::SSL ();
use POSIX qw(_exit);
use Socket qw(AF_UNIX SOCK_STREAM PF_UNSPEC);
use Test2::V0;

use Overnet::Program::IRC::Script::Proxy;
use Overnet::Program::IRC::Script::Util qw(ensure_tls_material);

my $package = 'Overnet::Program::IRC::Script::Proxy';
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

sub _socket_pair {
  socketpair my $near, my $far, AF_UNIX, SOCK_STREAM, PF_UNSPEC
    or die "socketpair failed: $!";
  $near->autoflush(1);
  $far->autoflush(1);
  return ($near, $far);
}

sub _drain {
  my ($handle) = @_;
  my $buffer = q{};
  while (1) {
    my $bytes = sysread($handle, my $chunk, 4_096);
    last if !defined $bytes || $bytes == 0;
    $buffer .= $chunk;
  }
  return $buffer;
}

subtest '--help prints usage to stdout' => sub {
  my $run = _run('--help');
  is $run->{exit}, 0, '--help exits successfully';
  like $run->{stdout}, qr/overnet-irc-server\ proxy\ \[options\]/mxs, 'usage names the command';
};

subtest 'unknown options print usage to stderr' => sub {
  my $run = _run('--frobnicate');
  is $run->{exit}, 1, 'unknown options fail';
  like $run->{stderr}, qr/overnet-irc-server\ proxy\ \[options\]/mxs, 'usage goes to stderr';
};

subtest 'invalid options croak' => sub {
  like dies { $package->run('--listen-port', '65536') }, qr/listen-port\ must\ be/mxs,
    'an out-of-range listen port croaks';
  like dies { $package->run('--server-port', '65536') }, qr/server-port\ must\ be/mxs,
    'an out-of-range server port croaks';
  like dies { $package->run('--listen-host', q{}) }, qr/--listen-host\ is\ required/mxs,
    'an empty listen host croaks';
  like dies { $package->run('--server-host', q{}) }, qr/--server-host\ is\ required/mxs,
    'an empty server host croaks';
  like dies { $package->run('--listen-backlog', '0') }, qr/--listen-backlog\ must\ be\ a\ positive\ integer/mxs,
    'a zero listen backlog croaks';
};

subtest 'run validates, builds the auth client, and serves' => sub {
  my @served;
  my $server_mock = mock $package => (override => [_serve => sub { push @served, [@_]; return 1 },],);

  my $run = _run();
  is $run->{exit}, 0, 'a default run exits successfully';
  is scalar(@served), 1, 'the serve loop ran';
  ok $served[0][1]->isa('Overnet::Auth::Client'), 'an auth client was constructed';

  my $socked = _run('--auth-sock', '/tmp/auth.sock');
  is $socked->{exit}, 0, 'a run with an explicit auth socket exits successfully';
  is scalar(@served), 2, 'the serve loop ran again';
};

subtest '_open_listener listens or croaks' => sub {
  my $options = {
    listen_host    => '127.0.0.1',
    listen_port    => 0,
    listen_backlog => 1,
  };
  my $listener = Overnet::Program::IRC::Script::Proxy::_open_listener($options);
  ok $listener->sockport, 'an ephemeral listener is opened';

  my $taken = {
    listen_host    => '127.0.0.1',
    listen_port    => $listener->sockport,
    listen_backlog => 1,
  };
  like dies { Overnet::Program::IRC::Script::Proxy::_open_listener($taken) },
    qr/Failed\ to\ listen\ on\ 127[.]0[.]0[.]1/mxs, 'an occupied port croaks';
  close $listener or die "Can't close listener: $!";
};

subtest '_open_server_socket connects plain, TLS, or croaks' => sub {
  my $listener = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    Listen    => 2,
    Proto     => 'tcp',
  ) or die "Can't listen: $!";
  my $port = $listener->sockport;

  my $plain = Overnet::Program::IRC::Script::Proxy::_open_server_socket(
    {
      server_host => '127.0.0.1',
      server_port => $port,
    }
  );
  ok $plain, 'a plain upstream connection succeeds';
  close $plain or die "Can't close plain socket: $!";

  like dies {
    Overnet::Program::IRC::Script::Proxy::_open_server_socket(
      {
        server_host => '127.0.0.1',
        server_port => $port,
        server_tls  => 1,
        server_tls_no_verify => 1,
      }
    );
  }, qr/Can't\ connect\ TLS\ to\ 127[.]0[.]0[.]1:$port/mxs, 'a non-TLS upstream fails the TLS connect';
  close $listener or die "Can't close listener: $!";

  like dies {
    Overnet::Program::IRC::Script::Proxy::_open_server_socket(
      {
        server_host => '127.0.0.1',
        server_port => $port,
      }
    );
  }, qr/Can't\ connect\ to\ 127[.]0[.]0[.]1:$port/mxs, 'a refused plain connection croaks';
};

subtest '_open_server_socket completes a TLS handshake' => sub {
  my $cert_file = File::Spec->catfile($tempdir, 'tls', 'cert.pem');
  my $key_file  = File::Spec->catfile($tempdir, 'tls', 'key.pem');
  ensure_tls_material(
    cert_chain_file  => $cert_file,
    private_key_file => $key_file,
    listen_host      => '127.0.0.1',
  );

  my $listener = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    Listen    => 1,
    Proto     => 'tcp',
  ) or die "Can't listen: $!";
  my $port = $listener->sockport;

  my $server_pid = fork;
  die "fork failed: $!" if !defined $server_pid;
  if (!$server_pid) {
    my $plain = $listener->accept or _exit(1);
    my $tls   = IO::Socket::SSL->start_SSL(
      $plain,
      SSL_server    => 1,
      SSL_cert_file => $cert_file,
      SSL_key_file  => $key_file,
    ) or _exit(1);
    my $drained = do { local $/ = undef; <$tls> };
    close $tls;
    _exit(0);
  }

  my $socket = Overnet::Program::IRC::Script::Proxy::_open_server_socket(
    {
      server_host            => '127.0.0.1',
      server_port            => $port,
      server_tls             => 1,
      server_tls_no_verify   => 1,
      server_tls_ca_file     => $cert_file,
      server_tls_name        => '127.0.0.1',
      server_tls_min_version => 'TLSv1.2',
    }
  );
  ok $socket->isa('IO::Socket::SSL'), 'the upstream socket is a TLS socket';
  close $socket or die "Can't close TLS socket: $!";
  waitpid $server_pid, 0;
  close $listener or die "Can't close listener: $!";
};

subtest 'TLS argument helpers select verification settings' => sub {
  my %default = Overnet::Program::IRC::Script::Proxy::_server_tls_args(
    {
      server_host            => 'irc.example.test',
      server_tls_min_version => 'TLSv1.3',
    }
  );
  is $default{SSL_verify_mode}, IO::Socket::SSL::SSL_VERIFY_PEER(), 'verification defaults to peer verification';
  is $default{SSL_hostname},    'irc.example.test',                 'the TLS hostname defaults to the server host';
  is $default{SSL_version},     'TLSv1_3',                          'TLSv1.3 maps to the TLSv1_3 version string';
  ok !exists $default{SSL_ca_file}, 'no CA file is passed by default';

  my %relaxed = Overnet::Program::IRC::Script::Proxy::_server_tls_args(
    {
      server_host            => '127.0.0.1',
      server_tls_no_verify   => 1,
      server_tls_ca_file     => '/tmp/ca.pem',
      server_tls_name        => 'irc.example.test',
      server_tls_min_version => undef,
    }
  );
  is $relaxed{SSL_verify_mode}, IO::Socket::SSL::SSL_VERIFY_NONE(), 'no-verify disables verification';
  is $relaxed{SSL_hostname}, 'irc.example.test', 'an explicit TLS name wins';
  is $relaxed{SSL_ca_file},  '/tmp/ca.pem',      'the CA file is passed through';
  ok !exists $relaxed{SSL_version}, 'an undef minimum version passes no SSL_version';

  like Overnet::Program::IRC::Script::Proxy::_ssl_version_for_min_version('TLSv1.2'), qr/SSLv23/mxs,
    'TLSv1.2 maps to the legacy-disabling version string';
  like dies { Overnet::Program::IRC::Script::Proxy::_ssl_version_for_min_version('TLSv1.1') },
    qr/Unsupported\ --server-tls-min-version:\ TLSv1[.]1/mxs, 'an unsupported minimum version croaks';
};

subtest '_read_ready_lines splits complete lines and reports EOF' => sub {
  my ($near, $far) = _socket_pair();
  my @lines;
  my $buffer = q{};

  syswrite $far, "one\r\ntwo\nthree" or die "Can't write: $!";
  is Overnet::Program::IRC::Script::Proxy::_read_ready_lines($near, \$buffer, sub { push @lines, $_[0] }), 1,
    'a readable handle reports success';
  is \@lines, ["one\r\n", "two\n"], 'complete lines reach the callback';
  is $buffer, 'three', 'the partial line stays buffered';

  close $far or die "Can't close far end: $!";
  is Overnet::Program::IRC::Script::Proxy::_read_ready_lines($near, \$buffer, sub { push @lines, $_[0] }), 0,
    'EOF reports failure';
};

subtest '_write_lines, _write_result, and _same_handle move bytes' => sub {
  my ($near, $far) = _socket_pair();

  is Overnet::Program::IRC::Script::Proxy::_write_lines($near, "a\r\n", "b\r\n"), 1, 'lines are written';
  is Overnet::Program::IRC::Script::Proxy::_write_lines($near), 1, 'writing no lines is a no-op';

  my ($client_near, $client_far) = _socket_pair();
  is Overnet::Program::IRC::Script::Proxy::_write_result(
    $client_near, $near,
    {
      to_server => ["s\r\n"],
      to_client => ["c\r\n"],
    }
  ),
    1, 'a result writes to both sides';
  is Overnet::Program::IRC::Script::Proxy::_write_result($client_near, $near, {}), 1,
    'an empty result writes nothing';

  shutdown $near, 1 or die "Can't shut down: $!";
  close $far or die "Can't close far end: $!";
  {
    local $SIG{PIPE} = 'IGNORE';
    like dies { Overnet::Program::IRC::Script::Proxy::_write_lines($near, "x\r\n") },
      qr/Failed\ to\ write\ IRC\ proxy\ line/mxs, 'a broken pipe croaks';
  }

  is Overnet::Program::IRC::Script::Proxy::_same_handle($client_near, $client_near), 1,
    'a handle matches itself';
  is Overnet::Program::IRC::Script::Proxy::_same_handle($client_near, $client_far), 0,
    'different handles do not match';
  open my $closed, '<', \(my $ignored = q{}) or die "Can't open buffer: $!";
  close $closed or die "Can't close buffer: $!";
  is Overnet::Program::IRC::Script::Proxy::_same_handle($closed,      $client_near), 0, 'a closed left handle fails';
  is Overnet::Program::IRC::Script::Proxy::_same_handle($client_near, $closed),      0, 'a closed right handle fails';
};

subtest '_try_report_client_error reports or swallows failures' => sub {
  my ($near, $far) = _socket_pair();
  is Overnet::Program::IRC::Script::Proxy::_try_report_client_error($near, 'boom'), 1,
    'a healthy client socket receives the error';
  close $near or die "Can't close near end: $!";
  my $received = _drain($far);
  like $received, qr/ERROR\ :Overnet\ IRC\ proxy\ authentication\ failed:\ boom/mxs,
    'the error line reached the client';

  my ($broken_near, $broken_far) = _socket_pair();
  shutdown $broken_near, 1 or die "Can't shut down: $!";
  close $broken_far or die "Can't close far end: $!";
  {
    local $SIG{PIPE} = 'IGNORE';
    is Overnet::Program::IRC::Script::Proxy::_try_report_client_error($broken_near, 'boom'), 0,
      'a broken client socket swallows the failure';
  }
};

subtest '_close_socket ignores undef and croaks on double close' => sub {
  is Overnet::Program::IRC::Script::Proxy::_close_socket(undef, 'missing socket'), 1, 'undef is ignored';

  my ($near, $far) = _socket_pair();
  is Overnet::Program::IRC::Script::Proxy::_close_socket($near, 'near end'), 1, 'a live socket closes';
  like dies {
    no warnings 'unopened';
    Overnet::Program::IRC::Script::Proxy::_close_socket($near, 'near end');
  }, qr/close\ failed\ for\ near\ end/mxs, 'closing again croaks';
  close $far or die "Can't close far end: $!";
};

subtest '_serve_connection proxies lines between client and server' => sub {
  my $upstream_listener = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    Listen    => 1,
    Proto     => 'tcp',
  ) or die "Can't listen: $!";

  my @session_lines;
  my $proxy_mock = mock 'Overnet::Program::IRC::Proxy' => (
    override => [
      start       => sub { return {to_server => ["CAP REQ :sasl\r\n"],} },
      client_line => sub {
        my ($self, $line) = @_;
        push @session_lines, ['client', $line];
        return {to_server => [$line],};
      },
      server_line => sub {
        my ($self, $line) = @_;
        push @session_lines, ['server', $line];
        return {to_client => [$line],};
      },
    ],
  );

  my $options = {
    server_host => '127.0.0.1',
    server_port => $upstream_listener->sockport,
    interactive => 0,
  };

  my ($client_near, $client_far) = _socket_pair();
  syswrite $client_far, "NICK alice\r\n" or die "Can't write: $!";

  my $handled = fork;
  die "fork failed: $!" if !defined $handled;
  if (!$handled) {
    my $upstream = $upstream_listener->accept or _exit(1);
    $upstream->autoflush(1);
    my $expected = "CAP REQ :sasl\r\nNICK alice\r\n";
    my $received = q{};
    while (length($received) < length($expected)) {
      my $bytes = sysread($upstream, my $chunk, 4_096);
      _exit(1) if !defined $bytes || $bytes == 0;
      $received .= $chunk;
    }
    _exit(1) if $received ne $expected;
    syswrite $upstream, ":upstream 001 alice :Welcome\r\n" or _exit(1);
    close $upstream;
    _exit(0);
  }

  my $done = eval {
    Overnet::Program::IRC::Script::Proxy::_serve_connection($options, undef, $client_near);
    1;
  };
  is $done, 1, 'the connection is served until the upstream closes';
  waitpid $handled, 0;
  is $?, 0, 'the upstream child saw the proxied registration lines';
  like _drain($client_far), qr/:upstream\ 001\ alice\ :Welcome/mxs, 'the upstream reply reached the client';
  is \@session_lines,
    [['client', "NICK alice\r\n"], ['server', ":upstream 001 alice :Welcome\r\n"],],
    'the session saw both directions';
  close $client_far or die "Can't close client far end: $!";
  close $upstream_listener or die "Can't close listener: $!";
};

subtest '_serve_connection reports session failures to the client' => sub {
  my $upstream_listener = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    Listen    => 1,
    Proto     => 'tcp',
  ) or die "Can't listen: $!";

  my $proxy_mock = mock 'Overnet::Program::IRC::Proxy' => (
    override => [
      start       => sub { return {to_server => [],} },
      client_line => sub { die "SASL exploded\n" },
    ],
  );

  my $options = {
    server_host => '127.0.0.1',
    server_port => $upstream_listener->sockport,
  };

  my ($client_near, $client_far) = _socket_pair();
  syswrite $client_far, "NICK alice\r\n" or die "Can't write: $!";

  like dies { Overnet::Program::IRC::Script::Proxy::_serve_connection($options, undef, $client_near) },
    qr/SASL\ exploded/mxs, 'the session failure is propagated';
  like _drain($client_far), qr/ERROR\ :Overnet\ IRC\ proxy\ authentication\ failed:\ SASL\ exploded/mxs,
    'the client was told about the failure';
  close $client_far or die "Can't close client far end: $!";
  close $upstream_listener or die "Can't close listener: $!";
};

subtest '_serve accepts connections and survives connection failures' => sub {
  my $listener = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    Listen    => 5,
    Proto     => 'tcp',
    ReuseAddr => 1,
  ) or die "Can't listen: $!";
  my $port = $listener->sockport;

  my $connections = 0;
  my $mock        = mock $package => (
    override => [
      _open_listener    => sub { return $listener },
      _serve_connection => sub {
        my (undef, undef, $client_socket) = @_;
        $connections++;
        close $client_socket;
        die "handshake failed\n" if $connections == 1;
        shutdown $listener, 0;
        return 1;
      },
    ],
  );

  my $first  = IO::Socket::INET->new(PeerHost => '127.0.0.1', PeerPort => $port, Proto => 'tcp')
    or die "Can't connect: $!";
  my $second = IO::Socket::INET->new(PeerHost => '127.0.0.1', PeerPort => $port, Proto => 'tcp')
    or die "Can't connect: $!";

  my ($stdout, $stderr, $died) = capture {
    dies {
      Overnet::Program::IRC::Script::Proxy::_serve(
        {
          listen_host => '127.0.0.1',
          listen_port => $port,
          server_host => '127.0.0.1',
          server_port => 16_667,
        },
        undef,
      );
    };
  };
  like $died, qr/Failed\ to\ accept\ IRC\ proxy\ client\ connection/mxs,
    'a dead listener stops the accept loop';
  like $stdout, qr/Listening\ on\ 127[.]0[.]0[.]1:$port\ and\ proxying/mxs, 'the listening banner is printed';
  like $stderr, qr/connection\ failed:\ handshake\ failed/mxs, 'a failed connection is reported and survived';
  is $connections, 2, 'both queued connections were served';
  close $first  or die "Can't close first client: $!";
  close $second or die "Can't close second client: $!";
};

done_testing;
