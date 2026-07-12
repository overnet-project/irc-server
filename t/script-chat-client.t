use strictures 2;

use Capture::Tiny qw(capture);
use File::Spec;
use File::Temp qw(tempdir);
use IO::Socket::INET;
use IO::Socket::SSL ();
use POSIX qw(_exit);
use Socket qw(AF_UNIX SOCK_STREAM PF_UNSPEC);
use Time::HiRes qw(sleep);
use Test2::V0;

use Overnet::Program::IRC::Script::ChatClient;
use Overnet::Program::IRC::Script::Util qw(ensure_tls_material);

my $package = 'Overnet::Program::IRC::Script::ChatClient';
my $tempdir = tempdir(CLEANUP => 1);

sub _client_pair {
  my (%args) = @_;
  socketpair my $near, my $far, AF_UNIX, SOCK_STREAM, PF_UNSPEC
    or die "socketpair failed: $!";
  $near->autoflush(1);
  $far->autoflush(1);

  my $output = q{};
  my $error  = q{};
  open my $output_fh, '>', \$output or die "Can't open output buffer: $!";
  open my $error_fh,  '>', \$error  or die "Can't open error buffer: $!";
  $output_fh->autoflush(1);
  $error_fh->autoflush(1);

  my $client = $package->new(
    options => $args{options} || {},
    (exists $args{current_target} ? (current_target => $args{current_target}) : ()),
    output => $output_fh,
    error  => $error_fh,
    (exists $args{input} ? (input => $args{input}) : ()),
  );
  $client->_set_socket($near);

  return {
    client => $client,
    far    => $far,
    output => \$output,
    error  => \$error,
  };
}

sub _read_far {
  my ($pair, $length) = @_;
  my $buffer = q{};
  while (length($buffer) < $length) {
    my $bytes = sysread($pair->{far}, my $chunk, 4_096);
    last if !defined $bytes || $bytes == 0;
    $buffer .= $chunk;
  }
  return $buffer;
}

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

subtest '--help prints usage to stdout' => sub {
  my $run = _run('--help');
  is $run->{exit}, 0, '--help exits successfully';
  like $run->{stdout}, qr/chat-client\ --nick\ NICK/mxs, 'usage names the command';
};

subtest 'unknown options print usage to stderr' => sub {
  my $run = _run('--frobnicate');
  is $run->{exit}, 1, 'unknown options fail';
  like $run->{stderr}, qr/chat-client\ --nick\ NICK/mxs, 'usage goes to stderr';
};

subtest 'invalid options croak' => sub {
  like dies { $package->run() }, qr/--nick\ is\ required/mxs, 'a missing nick croaks';
  like dies { $package->run('--nick', 'alice', '--port', '65536') }, qr/--port\ must\ be/mxs,
    'an out-of-range port croaks';
};

subtest 'a plain connection failure croaks' => sub {
  my $closed = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    Listen    => 1,
    Proto     => 'tcp',
  ) or die "Can't listen: $!";
  my $port = $closed->sockport;
  close $closed or die "Can't close listener: $!";

  like dies {
    capture { $package->run('--nick', 'alice', '--port', $port) };
  }, qr/Can't\ connect\ to\ 127[.]0[.]0[.]1:$port/mxs, 'a refused plain connection croaks';
};

subtest 'a TLS handshake failure croaks' => sub {
  my $listener = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    Listen    => 1,
    Proto     => 'tcp',
  ) or die "Can't listen: $!";
  my $port = $listener->sockport;

  like dies {
    capture { $package->run('--nick', 'alice', '--port', $port, '--tls', '--tls-no-verify') };
  }, qr/Can't\ connect\ TLS\ to\ 127[.]0[.]0[.]1:$port/mxs, 'a non-TLS peer fails the TLS connect';
  close $listener or die "Can't close listener: $!";
};

subtest 'a plain demo session runs until /quit' => sub {
  my $listener = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    Listen    => 1,
    Proto     => 'tcp',
  ) or die "Can't listen: $!";
  my $port = $listener->sockport;

  pipe my $stdin_reader, my $stdin_writer or die "pipe failed: $!";
  $stdin_writer->autoflush(1);

  my $writer_pid = fork;
  die "fork failed: $!" if !defined $writer_pid;
  if (!$writer_pid) {
    close $stdin_reader;
    sleep 0.3;
    print {$stdin_writer} "/quit demo over\n" or _exit(1);
    close $stdin_writer;
    _exit(0);
  }
  close $stdin_writer or die "Can't close writer: $!";

  my $run;
  {
    local *STDIN;
    open STDIN, '<&', $stdin_reader or die "Can't redirect stdin: $!";
    $run = _run('--nick', 'alice', '--port', $port);
    close STDIN;
  }
  waitpid $writer_pid, 0;

  is $run->{exit}, 0, 'the session exits successfully after /quit';
  like $run->{stdout}, qr/Connected\ to\ 127[.]0[.]0[.]1:$port\ as\ alice/mxs, 'the connect banner is printed';
  like $run->{stdout}, qr/Plain\ text\ sends\ to\ [#]overnet/mxs, 'the auto-join target is printed';

  my $server_side = $listener->accept or die "accept failed: $!";
  my $received = do { local $/ = undef; <$server_side> };
  is $received,
    "CAP END\r\n" . "NICK alice\r\n" . "USER alice 0 * :Overnet IRC Demo User\r\n" . "QUIT :demo over\r\n",
    'the registration and quit lines reached the server';
  close $server_side or die "Can't close server side: $!";
  close $listener    or die "Can't close listener: $!";
};

subtest '_open_socket completes a TLS handshake' => sub {
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

  my $client = $package->new(
    options => {
      host            => '127.0.0.1',
      port            => $port,
      tls             => 1,
      tls_no_verify   => 1,
      tls_ca_file     => $cert_file,
      tls_server_name => '127.0.0.1',
      tls_min_version => 'TLSv1.2',
    },
  );
  my $socket = $client->_open_socket;
  ok $socket, 'the TLS handshake succeeded';
  ok $socket->isa('IO::Socket::SSL'), 'the socket is a TLS socket';
  close $socket or die "Can't close TLS socket: $!";
  waitpid $server_pid, 0;
  close $listener or die "Can't close listener: $!";
};

subtest '_tls_socket_args and helpers select verification settings' => sub {
  my $verify = $package->new(options => {host => 'irc.example.test', tls_min_version => 'TLSv1.3',},);
  my %args   = $verify->_tls_socket_args;
  is $args{SSL_verify_mode}, IO::Socket::SSL::SSL_VERIFY_PEER(), 'verification defaults to peer verification';
  is $args{SSL_hostname},    'irc.example.test',                 'the TLS hostname defaults to the host';
  is $args{SSL_version},     'TLSv1_3',                          'TLSv1.3 maps to the TLSv1_3 version string';
  ok !exists $args{SSL_ca_file}, 'no CA file is passed by default';

  my $relaxed = $package->new(
    options => {
      host            => '127.0.0.1',
      tls_no_verify   => 1,
      tls_ca_file     => '/tmp/ca.pem',
      tls_server_name => 'irc.example.test',
      tls_min_version => 'TLSv1.2',
    },
  );
  my %relaxed_args = $relaxed->_tls_socket_args;
  is $relaxed_args{SSL_verify_mode}, IO::Socket::SSL::SSL_VERIFY_NONE(), 'tls-no-verify disables verification';
  is $relaxed_args{SSL_hostname}, 'irc.example.test', 'an explicit server name wins';
  is $relaxed_args{SSL_ca_file},  '/tmp/ca.pem',      'the CA file is passed through';
  like $relaxed_args{SSL_version}, qr/SSLv23/mxs, 'TLSv1.2 maps to the legacy-disabling version string';

  my $unversioned = $package->new(options => {host => '127.0.0.1', tls_min_version => undef,},);
  my %unversioned_args = $unversioned->_tls_socket_args;
  ok !exists $unversioned_args{SSL_version}, 'an undef minimum version passes no SSL_version';

  like dies { Overnet::Program::IRC::Script::ChatClient::_ssl_version_for_min_version('TLSv1.1') },
    qr/Unsupported\ --tls-min-version:\ TLSv1[.]1/mxs, 'an unsupported minimum version croaks';
};

subtest 'server lines are formatted for humans' => sub {
  my %cases = (
    ':alice!a@h PRIVMSG #overnet :hi there'  => '<alice!a@h -> #overnet> hi there',
    ':alice!a@h NOTICE bob :psst'            => '-alice!a@h -> bob- psst',
    ':alice!a@h JOIN #overnet'               => '* alice!a@h joined #overnet',
    ':alice!a@h PART #overnet :bye'          => '* alice!a@h left #overnet (bye)',
    ':alice!a@h PART #overnet'               => '* alice!a@h left #overnet',
    ':alice!a@h QUIT :gone'                  => '* alice!a@h quit (gone)',
    ':alice!a@h QUIT'                        => '* alice!a@h quit',
    ':alice!a@h TOPIC #overnet :new topic'   => '* alice!a@h changed the topic on #overnet to: new topic',
    ':server 353 alice = #overnet :@a +b'    => '* names for #overnet: @a +b',
    ':server 001 alice :Welcome'             => ':server 001 alice :Welcome',
  );
  for my $line (sort keys %cases) {
    is Overnet::Program::IRC::Script::ChatClient::_format_server_line($line), $cases{$line}, "formats: $line";
  }
};

subtest '_handle_server_line answers PING and auto-joins on 001' => sub {
  my $pair   = _client_pair(
    options        => {auto_join => 1, channel => '#overnet',},
    current_target => '#overnet',
  );
  my $client = $pair->{client};

  is $client->_handle_server_line('PING :token-1'), 1, 'PING is handled';
  is _read_far($pair, length("PONG :token-1\r\n")), "PONG :token-1\r\n", 'PING is answered with PONG';

  is $client->_handle_server_line(':server 001 alice :Welcome'), 1, '001 is handled';
  is $client->_registered, 1, 'the 001 numeric marks the client registered';
  is _read_far($pair, length("JOIN #overnet\r\n")), "JOIN #overnet\r\n", 'the auto-join was sent';
  like ${$pair->{output}}, qr/:server\ 001\ alice\ :Welcome/mxs, 'the raw 001 line is printed';

  is $client->_handle_server_line(':server 001 alice :Welcome again'), 1, 'a second 001 is handled';
  is $client->_auto_join_sent, 1, 'the auto-join is only sent once';
};

subtest '_send_auto_join respects the configuration' => sub {
  my $disabled = _client_pair(options => {auto_join => 0, channel => '#overnet',},);
  is $disabled->{client}->_send_auto_join, 1, 'a disabled auto-join returns quietly';
  is $disabled->{client}->_auto_join_sent, 0, 'nothing was sent when auto-join is disabled';

  my $untargeted = _client_pair(options => {auto_join => 1, channel => q{},},);
  is $untargeted->{client}->_send_auto_join, 1, 'a missing channel returns quietly';
  is $untargeted->{client}->_auto_join_sent, 0, 'nothing was sent without a channel';
};

subtest 'user commands map to IRC lines' => sub {
  my $pair   = _client_pair(
    options        => {auto_join => 1, channel => '#overnet',},
    current_target => '#overnet',
  );
  my $client = $pair->{client};

  is $client->_handle_user_input('/help'), 1, '/help is handled';
  like ${$pair->{output}}, qr/Plain\ text\ sends\ a\ PRIVMSG/mxs, '/help prints the command list';

  my %sends = (
    '/join #other'          => "JOIN #other\r\n",
    '/msg bob hello'        => "PRIVMSG bob :hello\r\n",
    '/notice bob psst'      => "NOTICE bob :psst\r\n",
    '/topic #other new one' => "TOPIC #other :new one\r\n",
    '/names #other'         => "NAMES #other\r\n",
    '/names'                => "NAMES #other\r\n",
    '/part #other gone now' => "PART #other :gone now\r\n",
    '/part'                 => "PART #other\r\n",
    '/nick alice2'          => "NICK alice2\r\n",
    '/raw WHOIS bob'        => "WHOIS bob\r\n",
    'plain text here'       => "PRIVMSG #other :plain text here\r\n",
  );
  for my $input (sort keys %sends) {
    is $client->_handle_user_input($input), 1, "$input is handled";
    is _read_far($pair, length $sends{$input}), $sends{$input}, "$input maps to the expected line";
  }

  is $client->_current_target, '#other', '/join updated the current target';

  is $client->_handle_user_input('/target bob'), 1, '/target is handled';
  is $client->_current_target, 'bob', '/target updated the current target';
  like ${$pair->{output}}, qr/Current\ target\ set\ to\ bob/mxs, '/target reports the new target';

  is $client->_handle_user_input('/quit all done'), 1, '/quit is handled';
  is _read_far($pair, length "QUIT :all done\r\n"), "QUIT :all done\r\n", '/quit sends the reason';
  is $client->_done, 1, '/quit marks the session done';
};

subtest 'target-less commands croak' => sub {
  my $pair   = _client_pair(options => {},);
  my $client = $pair->{client};

  like dies { $client->_handle_user_input('hello') }, qr/No\ current\ target/mxs,
    'plain text without a target croaks';
  like dies { $client->_handle_user_input('/names') }, qr/No\ current\ target\ for\ \/names/mxs,
    '/names without a target croaks';
  like dies { $client->_handle_user_input('/part') }, qr/No\ current\ target\ for\ \/part/mxs,
    '/part without a target croaks';
};

subtest '_read_input reads lines, reports errors, and quits on EOF' => sub {
  my $input_text = "/target bob\n\nboom-input\n";
  open my $input_fh, '<', \$input_text or die "Can't open input buffer: $!";
  my $pair   = _client_pair(options => {}, input => $input_fh,);
  my $client = $pair->{client};

  is $client->_read_input, 1, 'a target command line is consumed';
  is $client->_current_target, 'bob', 'the command took effect';

  is $client->_read_input, 1, 'an empty line is ignored';

  $client->_set_current_target(undef);
  is $client->_read_input, 1, 'a failing input line is reported, not fatal';
  like ${$pair->{error}}, qr/error:\ No\ current\ target/mxs, 'the error handle received the message';

  is $client->_read_input, 1, 'EOF is handled';
  is $client->_done, 1, 'EOF marks the session done';
  is _read_far($pair, length "QUIT :stdin closed\r\n"), "QUIT :stdin closed\r\n", 'EOF sends a QUIT';
};

subtest '_read_socket splits lines and detects disconnects' => sub {
  my $pair   = _client_pair(options => {},);
  my $client = $pair->{client};

  syswrite $pair->{far}, "PING :a\r\nPING" or die "Can't write: $!";
  is $client->_read_socket, 1, 'a chunk with a complete and a partial line is consumed';
  is _read_far($pair, length "PONG :a\r\n"), "PONG :a\r\n", 'the complete line was handled';

  syswrite $pair->{far}, " :b\r\n\r\n" or die "Can't write: $!";
  is $client->_read_socket, 1, 'the continuation and an empty line are consumed';
  is _read_far($pair, length "PONG :b\r\n"), "PONG :b\r\n", 'the joined line was handled';

  close $pair->{far} or die "Can't close far end: $!";
  like dies { $client->_read_socket }, qr/Server\ disconnected/mxs, 'EOF on the socket croaks';
};

subtest '_read_socket stops handling lines once done' => sub {
  my $pair   = _client_pair(options => {},);
  my $client = $pair->{client};

  my $quit = mock $package => (
    override => [
      _handle_server_line => sub {
        my ($self) = @_;
        $self->_set_done(1);
        return 1;
      },
    ],
  );
  syswrite $pair->{far}, "PING :a\r\nPING :b\r\n" or die "Can't write: $!";
  is $client->_read_socket, 1, 'reading stops after the handler marks the session done';
  is $client->_done, 1, 'the session is done';
};

subtest '_is_socket_handle compares file descriptors' => sub {
  my $pair   = _client_pair(options => {},);
  my $client = $pair->{client};

  is $client->_is_socket_handle($client->_socket), 1, 'the socket matches itself';
  is $client->_is_socket_handle($pair->{far}),     0, 'another handle does not match';

  open my $closed, '<', \(my $buffer = q{}) or die "Can't open buffer: $!";
  close $closed or die "Can't close buffer: $!";
  is $client->_is_socket_handle($closed), 0, 'a closed handle does not match';

  my $orphan        = _client_pair(options => {},);
  my $orphan_socket = $orphan->{client}->_socket;
  close $orphan_socket or die "Can't close socket: $!";
  is $orphan->{client}->_is_socket_handle(\*STDIN), 0, 'a closed client socket matches nothing';
};

subtest '_send_line croaks when the peer is gone' => sub {
  my $pair   = _client_pair(options => {},);
  my $client = $pair->{client};
  close $pair->{far} or die "Can't close far end: $!";
  shutdown $client->_socket, 1 or die "Can't shut down socket: $!";

  local $SIG{PIPE} = 'IGNORE';
  like dies { $client->_send_line('PING :x') }, qr/Failed\ to\ write\ IRC\ line/mxs,
    'writing to a broken socket croaks';
};

done_testing;
