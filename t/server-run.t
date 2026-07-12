use strictures 2;

use File::Spec;
use File::Temp qw(tempdir);
use FindBin;
use IO::Socket::INET;
use IO::Socket::SSL        qw(SSL_VERIFY_NONE);
use IO::Socket::SSL::Utils qw(CERT_create PEM_cert2file PEM_key2file);
use JSON ();
use POSIX ();
use Test2::V0;

use lib grep { -d $_ } (
  File::Spec->catdir($FindBin::Bin, 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'lib'),
);

use Net::Nostr::Key;
use Overnet::Program::IRC::Server;

# Devel::Cover slows execution by more than an order of magnitude, so the
# child runtime double scales its watchdog when instrumentation is loaded.
# The scaled value only bounds how long a wait may take; fast runs finish as
# soon as each protocol step completes.
my $TIMEOUT_SCALE = $INC{'Devel/Cover.pm'} ? 30 : 1;

sub _scaled_secs {
  my ($secs) = @_;
  return $secs * $TIMEOUT_SCALE;
}

my $tmpdir   = tempdir(CLEANUP => 1);
my $key_path = File::Spec->catfile($tmpdir, 'signing-key.pem');
Net::Nostr::Key->new->save_privkey($key_path);

sub _frame {
  my ($message) = @_;
  my $json = JSON::encode_json($message);
  return length($json) . "\n" . $json;
}

sub _config {
  my (%overrides) = @_;
  return {
    adapter_id       => 'irc.test',
    network          => 'overnet',
    listen_host      => '127.0.0.1',
    listen_port      => 0,
    server_name      => 'irc.example.test',
    signing_key_file => $key_path,
    adapter_config   => {},
    %overrides,
  };
}

sub _init_request {
  my (%overrides) = @_;
  return {
    type   => 'request',
    id     => 'init-1',
    method => 'runtime.init',
    params => {
      instance_id => 'test-instance',
      config      => _config(),
      %overrides,
    },
  };
}

sub _run_with_input {
  my (@messages) = @_;
  my $in_path = File::Spec->catfile($tmpdir, "run-input-$$-" . int(rand(1_000_000)));
  open my $in_fh, '>', $in_path or die "write $in_path: $!";
  binmode $in_fh;
  print {$in_fh} join q{}, map { _frame($_) } @messages;
  close $in_fh or die "close $in_path: $!";

  my $out_path = "$in_path.out";
  my $server   = Overnet::Program::IRC::Server->new;
  my ($result, $error);
  {
    local (*STDIN, *STDOUT);
    open *STDIN,  '<', $in_path  or die "reopen STDIN: $!";
    open *STDOUT, '>', $out_path or die "reopen STDOUT: $!";
    $result = eval { $server->run };
    $error  = $@;
    close *STDIN;
    close *STDOUT;
  }
  open my $out_fh, '<', $out_path or die "read $out_path: $!";
  my $output = do { local $/ = undef; <$out_fh> };
  close $out_fh;
  return ($result, $error, $output);
}

subtest 'constructor arguments are validated' => sub {
  my $bare = Overnet::Program::IRC::Server->new;
  ok $bare, 'a bare constructor works';
  my $custom = Overnet::Program::IRC::Server->new({program_id => 'custom.id',});
  ok $custom, 'a hashref constructor works';
  like dies { Overnet::Program::IRC::Server->new('odd') },
    qr/must\ be\ a\ hash/mxs, 'odd argument lists are rejected';
  like dies { Overnet::Program::IRC::Server->new(protocol => 'nope',) },
    qr/protocol\ must\ be/mxs, 'a malformed protocol object is rejected';
  like dies { Overnet::Program::IRC::Server->new(program_id => {},) },
    qr/program_id\ is\ required/mxs, 'a malformed program id is rejected';
  like dies { Overnet::Program::IRC::Server->new(program_version => q{},) },
    qr/program_version\ must\ be/mxs, 'an empty program version is rejected';
  like dies { Overnet::Program::IRC::Server->new(supported_protocol_versions => [],) },
    qr/supported_protocol_versions/mxs, 'an empty protocol version list is rejected';
  like dies { Overnet::Program::IRC::Server->new(supported_protocol_versions => [undef],) },
    qr/supported_protocol_versions/mxs, 'an undefined protocol version is rejected';
};

subtest 'runtime config normalization enforces its schema' => sub {
  like dies { Overnet::Program::IRC::Server::_normalized_runtime_config('nope') },
    qr/must\ be\ an\ object/mxs, 'a non-hash config is rejected';
  like dies { Overnet::Program::IRC::Server::_normalized_runtime_config(_config(adapter_id => undef,)) },
    qr/adapter_id\ is\ required/mxs, 'a missing adapter id is rejected';
  like dies { Overnet::Program::IRC::Server::_normalized_runtime_config(_config(network => q{},)) },
    qr/network\ is\ required/mxs, 'a missing network is rejected';
  like dies { Overnet::Program::IRC::Server::_normalized_runtime_config(_config(listen_host => q{},)) },
    qr/listen_host\ is\ required/mxs, 'a missing listen host is rejected';
  like dies { Overnet::Program::IRC::Server::_normalized_runtime_config(_config(server_name => q{},)) },
    qr/server_name\ is\ required/mxs, 'a missing server name is rejected';
  like dies { Overnet::Program::IRC::Server::_normalized_runtime_config(_config(signing_key_file => undef,)) },
    qr/signing_key_file\ is\ required/mxs, 'a missing signing key file is rejected';
  like dies { Overnet::Program::IRC::Server::_normalized_runtime_config(_config(listen_port => 'many',)) },
    qr/listen_port\ must\ be/mxs, 'a malformed listen port is rejected';
  like dies { Overnet::Program::IRC::Server::_normalized_runtime_config(_config(listen_port => 70_000,)) },
    qr/listen_port\ must\ be/mxs, 'an out-of-range listen port is rejected';
  like dies { Overnet::Program::IRC::Server::_normalized_runtime_config(_config(listen_backlog => 0,)) },
    qr/listen_backlog\ must\ be/mxs, 'a malformed listen backlog is rejected';
  like dies { Overnet::Program::IRC::Server::_normalized_runtime_config(_config(adapter_config => 'nope',)) },
    qr/adapter_config\ must\ be/mxs, 'a malformed adapter config is rejected';

  my $config = Overnet::Program::IRC::Server::_normalized_runtime_config(_config());
  is $config->{listen_backlog}, 10, 'the listen backlog defaults';
  ok !exists $config->{authority_relay}, 'no authority relay is configured by default';

  like dies {
    Overnet::Program::IRC::Server::_normalized_runtime_config(_config(authority_relay => 'nope',))
  }, qr/authority_relay\ must\ be/mxs, 'a malformed authority relay is rejected';
  like dies {
    Overnet::Program::IRC::Server::_normalized_runtime_config(_config(authority_relay => {},))
  }, qr/authority_relay\.url\ is\ required/mxs, 'a relay without a url is rejected';
  like dies {
    Overnet::Program::IRC::Server::_normalized_runtime_config(
      _config(authority_relay => {url => 'ws://relay', poll_interval_ms => 'often',},)
    )
  }, qr/poll_interval_ms\ must\ be/mxs, 'a malformed poll interval is rejected';

  my $relayed = Overnet::Program::IRC::Server::_normalized_runtime_config(
    _config(authority_relay => {url => 'ws://relay', query_timeout_ms => 5_000,},)
  );
  is $relayed->{authority_relay}{poll_interval_ms}, 250,   'the poll interval defaults';
  is $relayed->{authority_relay}{query_timeout_ms}, 5_000, 'the query timeout is preserved';

  my $nullrelay = Overnet::Program::IRC::Server::_normalized_runtime_config(
    _config(authority_relay => undef,)
  );
  ok !exists $nullrelay->{authority_relay}, 'an explicit null relay stays absent';

  my $cert_path     = File::Spec->catfile($tmpdir, 'tls-cert.pem');
  my $tls_key_path  = File::Spec->catfile($tmpdir, 'tls-key.pem');
  my ($cert, $tls_key) = CERT_create(subject => {CN => 'irc.example.test',});
  PEM_cert2file($cert, $cert_path);
  PEM_key2file($tls_key, $tls_key_path);
  my $tls_config = Overnet::Program::IRC::Server::_normalized_runtime_config(
    _config(
      tls => {
        enabled          => 1,
        cert_chain_file  => $cert_path,
        private_key_file => $tls_key_path,
      },
    )
  );
  is $tls_config->{tls}{mode}, 'server', 'the TLS mode defaults to server';
  my $server_args = Overnet::Program::IRC::Server::_tls_server_args_for_config($tls_config);
  is $server_args->{SSL_server}, 1, 'the TLS server arguments are built';
  is Overnet::Program::IRC::Server::_tls_server_args_for_config({}), undef,
    'a config without TLS builds no server arguments';
};

subtest 'run handles pre-init protocol failures' => sub {
  my ($result, $error, $output) =
    _run_with_input({type => 'notification', method => 'runtime.fatal', params => {code => 'sad',},});
  like $error, qr/runtime\ fatal:\ sad/mxs, 'a fatal notification before init croaks';

  ($result, $error, $output) =
    _run_with_input({type => 'request', id => 'r-1', method => 'frobnicate', params => {},});
  like $error, qr/Unexpected\ message\ before\ runtime\.init/mxs, 'an unexpected message before init croaks';

  ($result, $error, $output) =
    _run_with_input({type => 'request', id => 's-1', method => 'runtime.shutdown', params => {},});
  is $result, 1, 'a shutdown before init returns cleanly';
  like $output, qr/"id":"s-1"/mxs, 'the shutdown is acknowledged';
  like $output, qr/program\.hello/mxs, 'the hello is sent first';

  ($result, $error, $output) = _run_with_input(
    _init_request(config => _config(adapter_id => undef,)),
    {type => 'request', id => 's-2', method => 'runtime.shutdown', params => {},},
  );
  is $result, 1, 'an invalid init followed by shutdown returns cleanly';
  like $output, qr/program\.operation_failed/mxs, 'the invalid init is answered with an error';
  like $output, qr/adapter_id\ is\ required/mxs,  'the validation reason is included';
};

subtest 'run handles adapter session failures and shutdown' => sub {
  my ($result, $error, $output) = _run_with_input(
    _init_request(),
    {type => 'response', id => 'bogus', ok => JSON::true, result => {},},
  );
  like $error, qr/Unexpected\ response\ id/mxs, 'a mismatched response id croaks';
  like $output, qr/"status":"failed"/mxs, 'the failure is reported through program.health';

  ($result, $error, $output) = _run_with_input(
    _init_request(),
    {
      type  => 'response',
      id    => 'program-1',
      ok    => JSON::false,
      error => {code => 'adapter.unavailable', message => 'no adapters here',},
    },
  );
  like $error, qr/adapters\.open_session\ failed:\ adapter\.unavailable/mxs,
    'a failed session open croaks with the error';

  ($result, $error, $output) = _run_with_input(
    _init_request(),
    {type => 'request', id => 's-3', method => 'runtime.shutdown', params => {},},
  );
  is $result, 1, 'a shutdown during the session open returns cleanly';
  like $output, qr/"id":"s-3"/mxs, 'the mid-request shutdown is acknowledged';

  ($result, $error, $output) = _run_with_input(
    _init_request(),
    {type => 'response', id => 'program-1', ok => JSON::true, result => {adapter_session_id => 'sess-1',},},
    {type => 'request', id => 'r-2', method => 'frobnicate', params => {},},
  );
  like $error, qr/Unexpected\ runtime\ message\ in\ IRC\ server\ loop/mxs,
    'an unexpected loop message croaks';

  ($result, $error, $output) = _run_with_input(
    _init_request(),
    {type => 'response', id => 'program-1', ok => JSON::true, result => {adapter_session_id => 'sess-1',},},
    {type => 'notification', method => 'runtime.subscription_event', params => {item_type => 'mystery',},},
    {type => 'notification', method => 'runtime.fatal', params => {},},
  );
  like $error, qr/runtime\ fatal:\ unknown/mxs, 'a fatal notification in the loop croaks';

  ($result, $error, $output) = _run_with_input(
    _init_request(),
    {type => 'response', id => 'program-1', ok => JSON::true, result => {adapter_session_id => 'sess-1',},},
    {type => 'request', id => 's-4', method => 'runtime.shutdown', params => {},},
    (map { +{type => 'notification', method => 'runtime.subscription_event', params => {item_type => 'mystery',},} }
      1 .. 10),
  );
  is $result, 1, 'a shutdown followed by a burst drains in bounded batches and exits';
  like $output, qr/"status":"ready"/mxs, 'the server reported itself ready first';

  ($result, $error, $output) = _run_with_input(
    _init_request(),
    {type => 'response', id => 'program-1', ok => JSON::true, result => {adapter_session_id => 'sess-1',},},
  );
  like $error, qr/unexpected\ EOF\ on\ runtime\ stdin/mxs, 'runtime EOF in the loop croaks';

  ($result, $error, $output) = _run_with_input(
    _init_request(),
    {type => 'notification', method => 'runtime.subscription_event', params => {item_type => 'mystery',},},
    {type => 'notification', method => 'runtime.fatal', params => {},},
  );
  like $error, qr/runtime\ fatal:\ unknown/mxs,
    'a fatal notification during a request wait croaks after restoring deferrals';

  ($result, $error, $output) = _run_with_input(
    _init_request(),
    {type => 'request', id => 'r-3', method => 'frobnicate', params => {},},
  );
  like $error, qr/Unexpected\ message\ while\ awaiting\ response\ for\ adapters\.open_session/mxs,
    'an unexpected message during a request wait croaks';
};

sub _child_read_frame {
  my ($fh) = @_;
  my $length_line = <$fh>;
  die "runtime stream closed\n" if !defined $length_line;
  chomp $length_line;
  my $json = q{};
  while (length($json) < $length_line) {
    my $read = read $fh, $json, $length_line - length($json), length($json);
    die "runtime stream truncated\n" if !$read;
  }
  return JSON::decode_json($json);
}

sub _child_send_frame {
  my ($fh, $message) = @_;
  print {$fh} _frame($message);
  return 1;
}

sub _child_respond {
  my ($fh, $message) = @_;
  my $result =
    $message->{method} eq 'adapters.open_session'
    ? {adapter_session_id => 'sess-1',}
    : {};
  return _child_send_frame(
    $fh,
    {
      type   => 'response',
      id     => $message->{id},
      ok     => JSON::true,
      result => $result,
    }
  );
}

sub _child_read_socket_until {
  my ($socket, $pattern, $record) = @_;
  while (defined(my $line = <$socket>)) {
    $line =~ s/\r?\n\z//mxs;
    push @{$record}, $line;
    return 1 if $line =~ $pattern;
  }
  die "socket closed before matching $pattern\n";
}

sub _fake_runtime {
  my ($from_server, $to_server, $record) = @_;

  my $hello = _child_read_frame($from_server);
  $record->{hello} = $hello->{params}{program_id};
  _child_send_frame($to_server, _init_request());

  my $port;
  while (!defined $port) {
    my $message = _child_read_frame($from_server);
    if (($message->{type} || q{}) eq 'request') {
      _child_respond($to_server, $message);
      next;
    }
    if ( ($message->{method}         || q{}) eq 'program.health'
      && ($message->{params}{status} || q{}) eq 'ready') {
      $port = $message->{params}{details}{listen_port};
    }
  }
  $record->{listen_port} = $port;

  my $socket = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1',
    PeerPort => $port,
    Proto    => 'tcp',
  ) or die "connect: $!";
  binmode $socket;
  $socket->autoflush(1);

  print {$socket} "NICK eve\r\nUSER eve 0 * :Eve\r\n";
  _child_respond($to_server, _child_read_frame($from_server));
  _child_read_socket_until($socket, qr/\ 001\ /mxs, $record->{irc} = []);

  print {$socket} "PING liveness\r\n";
  _child_read_socket_until($socket, qr/\APONG\ :liveness\z/mxs, $record->{irc});

  print {$socket} "JOIN #overnet\r\n";
  my $channel_subscription = _child_read_frame($from_server);
  $record->{channel_subscription} = $channel_subscription->{params}{subscription_id};
  _child_send_frame(
    $to_server,
    {
      type   => 'notification',
      method => 'runtime.subscription_event',
      params => {item_type => 'mystery',},
    }
  );
  _child_respond($to_server, $channel_subscription);
  my $join_input = _child_read_frame($from_server);
  $record->{join_input} = $join_input->{params}{input}{command};
  _child_respond($to_server, $join_input);
  _child_read_socket_until($socket, qr/\ 366\ /mxs, $record->{irc});

  my $probe = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1',
    PeerPort => $port,
    Proto    => 'tcp',
  ) or die "connect probe: $!";
  binmode $probe;
  $probe->autoflush(1);
  print {$probe} "\x16\x03\x01" . ("\x00" x 13);
  my $log = _child_read_frame($from_server);
  $record->{tls_log} = $log->{params}{message};
  $record->{tls_closed} = defined(<$probe>) ? 0 : 1;
  close $probe;

  print {$socket} "QUIT :done\r\n";
  for (1 .. 3) {
    _child_respond($to_server, _child_read_frame($from_server));
  }
  $record->{quit_closed} = defined(<$socket>) ? 0 : 1;
  close $socket;

  _child_send_frame($to_server, {type => 'request', id => 'shutdown-1', method => 'runtime.shutdown', params => {},},);
  while (1) {
    my $message = _child_read_frame($from_server);
    if (($message->{id} || q{}) eq 'shutdown-1') {
      $record->{shutdown_ok} = $message->{ok} ? 1 : 0;
      last;
    }
  }

  return 1;
}

subtest 'run serves a live IRC session over the runtime protocol' => sub {
  pipe my $server_stdin_read,  my $server_stdin_write  or die "pipe: $!";
  pipe my $server_stdout_read, my $server_stdout_write or die "pipe: $!";
  my $record_path = File::Spec->catfile($tmpdir, 'live-run-record.json');

  my $pid = fork;
  die "fork: $!" if !defined $pid;

  if (!$pid) {
    close $server_stdin_read;
    close $server_stdout_write;
    $server_stdin_write->autoflush(1);
    my %record;
    my $status = 0;
    local $SIG{ALRM} = sub { die "fake runtime timed out\n" };
    alarm(_scaled_secs(60));
    if (!eval { _fake_runtime($server_stdout_read, $server_stdin_write, \%record); 1 }) {
      $record{error} = "$@";
      $status = 1;
    }
    alarm(0);
    if (open my $record_fh, '>', $record_path) {
      print {$record_fh} JSON::encode_json(\%record);
      close $record_fh;
    }
    close $server_stdin_write;
    close $server_stdout_read;
    POSIX::_exit($status);
  }

  close $server_stdin_write;
  close $server_stdout_read;

  my $server = Overnet::Program::IRC::Server->new;
  my $result;
  {
    local (*STDIN, *STDOUT);
    open *STDIN,  '<&=', fileno($server_stdin_read)   or die "dup STDIN: $!";
    open *STDOUT, '>&=', fileno($server_stdout_write) or die "dup STDOUT: $!";
    $result = eval { $server->run };
    diag "run failed: $@" if !defined $result;
    close *STDIN;
    close *STDOUT;
  }
  waitpid $pid, 0;
  my $child_status = $? >> 8;

  is $result, 1, 'run returns cleanly after the runtime shutdown';
  is $child_status, 0, 'the fake runtime completed every step';

  open my $record_fh, '<', $record_path or die "read $record_path: $!";
  my $record = JSON::decode_json(
    do { local $/ = undef; <$record_fh> }
  );
  close $record_fh;

  diag "fake runtime error: $record->{error}" if defined $record->{error};
  is $record->{hello}, 'overnet.program.irc_server', 'the program hello names the program';
  like $record->{listen_port}, qr/\A\d+\z/mxs, 'the health details carry the listen port';
  ok scalar(grep { /\ 001\ .*eve/mxs } @{$record->{irc}}), 'the client registered and saw the prelude';
  ok scalar(grep { /\APONG\ :liveness\z/mxs } @{$record->{irc}}), 'PING was answered over the socket';
  ok scalar(grep { /:eve\ JOIN\ \#overnet/mxs } @{$record->{irc}}), 'the JOIN was echoed over the socket';
  like $record->{channel_subscription}, qr/\Achannel:irc:overnet:\#overnet\z/mxs,
    'the channel subscription was opened';
  is $record->{join_input}, 'JOIN', 'the JOIN was mapped through the adapter';
  like $record->{tls_log}, qr/TLS\ client\ hello/mxs, 'the TLS probe was logged';
  is $record->{tls_closed},  1, 'the TLS probe connection was closed';
  is $record->{quit_closed}, 1, 'the QUIT closed the client connection';
  is $record->{shutdown_ok}, 1, 'the runtime shutdown was acknowledged';
};

my $live_cert_path    = File::Spec->catfile($tmpdir, 'live-tls-cert.pem');
my $live_tls_key_path = File::Spec->catfile($tmpdir, 'live-tls-key.pem');
my ($live_cert, $live_tls_key) = CERT_create(subject => {CN => '127.0.0.1',});
PEM_cert2file($live_cert, $live_cert_path);
PEM_key2file($live_tls_key, $live_tls_key_path);

sub _fake_tls_runtime {
  my ($from_server, $to_server, $record) = @_;

  _child_read_frame($from_server);
  _child_send_frame(
    $to_server,
    _init_request(
      config => _config(
        tls => {
          enabled          => 1,
          cert_chain_file  => $live_cert_path,
          private_key_file => $live_tls_key_path,
        },
      ),
    )
  );

  my $port;
  while (!defined $port) {
    my $message = _child_read_frame($from_server);
    if (($message->{type} || q{}) eq 'request') {
      _child_respond($to_server, $message);
      next;
    }
    if ( ($message->{method}         || q{}) eq 'program.health'
      && ($message->{params}{status} || q{}) eq 'ready') {
      $port = $message->{params}{details}{listen_port};
    }
  }

  # Let the select loop idle through at least one poll interval.
  select undef, undef, undef, 0.25;

  my $socket = IO::Socket::SSL->new(
    PeerAddr        => '127.0.0.1',
    PeerPort        => $port,
    SSL_verify_mode => SSL_VERIFY_NONE,
  ) or die "tls connect: $! $IO::Socket::SSL::SSL_ERROR";
  $socket->autoflush(1);
  print {$socket} "NICK tessa\r\nUSER tessa 0 * :Tessa\r\n";
  _child_respond($to_server, _child_read_frame($from_server));
  _child_read_socket_until($socket, qr/\ 422\ /mxs, $record->{irc} = []);
  $record->{tls_registered} = scalar grep { /\ 001\ /mxs } @{$record->{irc}};

  my $plain = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1',
    PeerPort => $port,
    Proto    => 'tcp',
  ) or die "plain connect: $!";
  $plain->autoflush(1);
  print {$plain} "GARBAGE NOT A HANDSHAKE\r\n";
  my $log = _child_read_frame($from_server);
  $record->{handshake_log} = $log->{params}{message};
  close $plain;

  # Close the registered client without a QUIT: the server must clean it up
  # and close its DM subscription.
  close $socket;
  _child_respond($to_server, _child_read_frame($from_server));
  $record->{abrupt_close_handled} = 1;

  _child_send_frame($to_server, {type => 'request', id => 'shutdown-2', method => 'runtime.shutdown', params => {},},);
  while (1) {
    my $message = _child_read_frame($from_server);
    if (($message->{id} || q{}) eq 'shutdown-2') {
      $record->{shutdown_ok} = $message->{ok} ? 1 : 0;
      last;
    }
  }

  return 1;
}

subtest 'run serves TLS clients and survives handshake failures' => sub {
  pipe my $server_stdin_read,  my $server_stdin_write  or die "pipe: $!";
  pipe my $server_stdout_read, my $server_stdout_write or die "pipe: $!";
  my $record_path = File::Spec->catfile($tmpdir, 'tls-run-record.json');

  my $pid = fork;
  die "fork: $!" if !defined $pid;

  if (!$pid) {
    close $server_stdin_read;
    close $server_stdout_write;
    $server_stdin_write->autoflush(1);
    my %record;
    my $status = 0;
    local $SIG{ALRM} = sub { die "fake TLS runtime timed out\n" };
    alarm(_scaled_secs(60));
    if (!eval { _fake_tls_runtime($server_stdout_read, $server_stdin_write, \%record); 1 }) {
      $record{error} = "$@";
      $status = 1;
    }
    alarm(0);
    if (open my $record_fh, '>', $record_path) {
      print {$record_fh} JSON::encode_json(\%record);
      close $record_fh;
    }
    close $server_stdin_write;
    close $server_stdout_read;
    POSIX::_exit($status);
  }

  close $server_stdin_write;
  close $server_stdout_read;

  my $server = Overnet::Program::IRC::Server->new;
  my $result;
  {
    local (*STDIN, *STDOUT);
    open *STDIN,  '<&=', fileno($server_stdin_read)   or die "dup STDIN: $!";
    open *STDOUT, '>&=', fileno($server_stdout_write) or die "dup STDOUT: $!";
    $result = eval { $server->run };
    diag "run failed: $@" if !defined $result;
    close *STDIN;
    close *STDOUT;
  }
  waitpid $pid, 0;
  my $child_status = $? >> 8;

  is $result, 1, 'run returns cleanly after the TLS session';
  is $child_status, 0, 'the fake TLS runtime completed every step';

  open my $record_fh, '<', $record_path or die "read $record_path: $!";
  my $record = JSON::decode_json(
    do { local $/ = undef; <$record_fh> }
  );
  close $record_fh;

  diag "fake TLS runtime error: $record->{error}" if defined $record->{error};
  is $record->{tls_registered}, 1, 'a TLS client registered over the encrypted socket';
  like $record->{handshake_log}, qr/TLS\ handshake\ failed/mxs, 'the failed handshake was logged';
  is $record->{abrupt_close_handled}, 1, 'an abrupt close tore the client down';
  is $record->{shutdown_ok}, 1, 'the runtime shutdown was acknowledged';
};

done_testing;
