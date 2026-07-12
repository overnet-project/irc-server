use strictures 2;

use Capture::Tiny qw(capture);
use File::Spec;
use File::Temp qw(tempdir);
use JSON ();
use Test2::V0;

use Overnet::Program::IRC::Script::Util qw(
  append_log
  checked_close
  checked_print
  checked_print_stderr
  checked_print_stdout
  default_state_dir
  ensure_signing_key
  ensure_tls_material
  executable_name
  hexchat_connect_host
  print_new_notifications
  shell_quote
  validate_port
  wait_for_ready_details
  write_health_file
  write_new_notifications
);

my $tempdir = tempdir(CLEANUP => 1);

sub _slurp {
  my ($path) = @_;
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $content = do { local $/ = undef; <$fh> };
  close $fh or die "Can't close $path: $!";
  return $content;
}

subtest 'executable_name reports the running perl' => sub {
  is executable_name(), $^X, 'executable_name returns $EXECUTABLE_NAME';
};

subtest 'checked_print writes or croaks' => sub {
  my $buffer = q{};
  open my $fh, '>', \$buffer or die "Can't open scalar handle: $!";
  is checked_print($fh, 'a', 'b'), 1, 'checked_print returns true on success';
  is $buffer, 'ab', 'checked_print wrote every message';
  close $fh or die "Can't close scalar handle: $!";

  open my $full, '>', '/dev/full' or die "Can't open /dev/full: $!";
  $full->autoflush(1);
  like dies { checked_print($full, 'x' x 65_536) }, qr/print\ failed/mxs,
    'checked_print croaks when the device rejects the write';
  {
    no warnings 'io';
    close $full;
  }
};

subtest 'checked_print_stdout and checked_print_stderr target the right streams' => sub {
  my ($stdout, $stderr, @result) = capture {
    (checked_print_stdout("out\n"), checked_print_stderr("err\n"),);
  };
  is \@result, [1, 1], 'both helpers return true';
  is $stdout, "out\n", 'checked_print_stdout wrote to STDOUT';
  is $stderr, "err\n", 'checked_print_stderr wrote to STDERR';
};

subtest 'checked_close closes or croaks' => sub {
  open my $fh, '>', \(my $buffer) or die "Can't open scalar handle: $!";
  is checked_close($fh, 'scalar handle'), 1, 'checked_close returns true on success';

  like dies {
    no warnings 'unopened';
    checked_close($fh, 'scalar handle');
  }, qr/close\ failed\ for\ scalar\ handle/mxs, 'checked_close croaks on a closed handle';
};

subtest 'validate_port accepts usable ports and rejects everything else' => sub {
  is validate_port(0,       'listen-port'), 0,      'port 0 is allowed';
  is validate_port('6667',  'listen-port'), 6667,   'a numeric string port is numified';
  is validate_port(65_535,  'listen-port'), 65_535, 'the maximum port is allowed';

  like dies { validate_port(65_536, 'listen-port') }, qr/listen-port\ must\ be/mxs, 'ports above 65535 are rejected';
  like dies { validate_port(-1,     'listen-port') }, qr/listen-port\ must\ be/mxs, 'negative ports are rejected';
  like dies { validate_port('01',   'listen-port') }, qr/listen-port\ must\ be/mxs, 'leading-zero ports are rejected';
  like dies { validate_port(undef,  'listen-port') }, qr/listen-port\ must\ be/mxs, 'undef ports are rejected';
  like dies { validate_port([],     'listen-port') }, qr/listen-port\ must\ be/mxs, 'reference ports are rejected';
  like dies { validate_port('abc') },       qr/\Aport\ must\ be/mxs, 'a missing label falls back to "port"';
  like dies { validate_port('abc', q{}) },  qr/\Aport\ must\ be/mxs, 'an empty label falls back to "port"';
  like dies { validate_port('abc', {}) },   qr/\Aport\ must\ be/mxs, 'a reference label falls back to "port"';
};

subtest 'default_state_dir prefers XDG, then HOME, then the temp dir' => sub {
  {
    local $ENV{XDG_STATE_HOME} = '/xdg-state';
    local $ENV{HOME}           = '/home/example';
    is default_state_dir(), File::Spec->catdir('/xdg-state', 'irc-server'), 'XDG_STATE_HOME wins when set';
  }
  {
    local $ENV{XDG_STATE_HOME} = q{};
    local $ENV{HOME}           = '/home/example';
    is default_state_dir(), File::Spec->catdir('/home/example', '.local', 'state', 'irc-server'),
      'HOME is used when XDG_STATE_HOME is unusable';
  }
  {
    local $ENV{XDG_STATE_HOME};
    local $ENV{HOME};
    delete $ENV{XDG_STATE_HOME};
    delete $ENV{HOME};
    is default_state_dir(), File::Spec->catdir(File::Spec->tmpdir, 'irc-server'),
      'the system temp dir is the last resort';
  }
};

subtest 'ensure_signing_key creates a key once' => sub {
  my $key_path = File::Spec->catfile($tempdir, 'keys', 'signing-key.pem');
  is ensure_signing_key($key_path), 1, 'a missing key is created';
  ok -f $key_path, 'the signing key file exists';
  my $mode = (stat $key_path)[2] & 0777;
  is $mode, 0600, 'the signing key is chmod 0600';

  my $before = _slurp($key_path);
  is ensure_signing_key($key_path), 1, 'an existing key is left alone';
  is _slurp($key_path), $before, 'the key contents are unchanged';
};

subtest 'ensure_tls_material creates certificate material once' => sub {
  my $cert_path = File::Spec->catfile($tempdir, 'tls', 'cert.pem');
  my $key_path  = File::Spec->catfile($tempdir, 'tls-keys', 'key.pem');

  is ensure_tls_material(
    cert_chain_file  => $cert_path,
    private_key_file => $key_path,
    listen_host      => '192.0.2.10',
    ),
    1, 'missing TLS material is created for an IP listen host';
  ok -f $cert_path, 'the certificate file exists';
  ok -f $key_path,  'the private key file exists';
  my $mode = (stat $key_path)[2] & 0777;
  is $mode, 0600, 'the TLS private key is chmod 0600';

  is ensure_tls_material(
    cert_chain_file  => $cert_path,
    private_key_file => $key_path,
    listen_host      => '192.0.2.10',
    ),
    1, 'existing TLS material is left alone';

  my $dns_cert = File::Spec->catfile($tempdir, 'tls', 'dns-cert.pem');
  my $dns_key  = File::Spec->catfile($tempdir, 'tls', 'dns-key.pem');
  is ensure_tls_material(
    cert_chain_file  => $dns_cert,
    private_key_file => $dns_key,
    listen_host      => 'irc.example.test',
    ),
    1, 'a DNS listen host is added as a DNS subject alternative name';

  my $local_cert = File::Spec->catfile($tempdir, 'tls', 'local-cert.pem');
  my $local_key  = File::Spec->catfile($tempdir, 'tls', 'local-key.pem');
  is ensure_tls_material(
    cert_chain_file  => $local_cert,
    private_key_file => $local_key,
    listen_host      => 'localhost',
    ),
    1, 'a localhost listen host keeps the default names';

  my $default_cert = File::Spec->catfile($tempdir, 'tls', 'default-cert.pem');
  my $default_key  = File::Spec->catfile($tempdir, 'tls', 'default-key.pem');
  is ensure_tls_material(
    cert_chain_file  => $default_cert,
    private_key_file => $default_key,
    listen_host      => q{},
    ),
    1, 'an empty listen host keeps the default common name';
};

subtest 'wait_for_ready_details returns the ready health details' => sub {
  my $details = {listen_port => 16_667,};
  my $host    = mock {
    notifications => [
      {method => 'program.log',    params => {level  => 'info', message => 'x'}},
      {method => 'program.health', params => {status => 'starting'}},
      {method => 'program.health', params => {status => 'ready', details => 'not-a-hash'}},
      {method => 'program.health', params => {status => 'ready', details => $details}},
      {},
    ],
  };
  my $control = mock $host => (
    add => [
      observed_notifications => sub { return $_[0]->{notifications} },
      pump_until             => sub {
        my ($self, %args) = @_;
        return $args{condition}->($self);
      },
    ],
  );

  is wait_for_ready_details($host), $details, 'ready details with a listen_port are returned';

  my $unready = mock {
    notifications => [
      {method => 'program.health', params => {status => 'starting'}},
      {method => 'program.health', params => {status => 'ready', details => {}}},
    ],
  };
  my $unready_control = mock $unready => (
    add => [
      observed_notifications => sub { return $_[0]->{notifications} },
      pump_until             => sub {
        my ($self, %args) = @_;
        return $args{condition}->($self);
      },
    ],
  );
  is wait_for_ready_details($unready), undef, 'a host that never becomes ready returns nothing';

  my $lying = mock {notifications => [],};
  my $lying_control = mock $lying => (
    add => [
      observed_notifications => sub { return $_[0]->{notifications} },
      pump_until             => sub { return 1 },
    ],
  );
  is wait_for_ready_details($lying), undef, 'a ready signal without a ready notification returns nothing';
};

subtest 'write_new_notifications appends program.log and program.health lines' => sub {
  my $log_path = File::Spec->catfile($tempdir, 'logs', 'service.log');
  my $host     = mock {
    notifications => [
      {method => 'program.log',    params => {level => 'warn', message => 'careful'}},
      {method => 'program.log',    params => {}},
      {method => 'program.health', params => {status => 'ready', message => 'listening'}},
      {method => 'program.health', params => {}},
      {method => 'runtime.other',  params => {}},
      {},
    ],
  };
  my $control = mock $host => (add => [observed_notifications => sub { return $_[0]->{notifications} },],);

  my $cursor = [0];
  is write_new_notifications($host, $cursor, $log_path), 1, 'write_new_notifications returns true';
  is $cursor->[0], 6, 'the cursor advanced past every notification';
  my $log = _slurp($log_path);
  is $log,
    "[program.warn] careful\n"
    . "[program.info] \n"
    . "[program.health] ready: listening\n"
    . "[program.health] unknown\n",
    'log and health notifications were formatted and appended';

  is write_new_notifications($host, $cursor, $log_path), 1, 'a caught-up cursor appends nothing';
  is _slurp($log_path), $log, 'the log is unchanged when there is nothing new';
};

subtest 'print_new_notifications prints to stderr and hides ready health' => sub {
  my $host = mock {
    notifications => [
      {method => 'program.log',    params => {level => 'info', message => 'hello'}},
      {method => 'program.log',    params => {}},
      {method => 'program.health', params => {status => 'ready'}},
      {method => 'program.health', params => {status => 'failed', message => 'boom'}},
      {method => 'program.health', params => {}},
      {method => 'runtime.other',  params => {}},
      {},
    ],
  };
  my $control = mock $host => (add => [observed_notifications => sub { return $_[0]->{notifications} },],);

  my $cursor = [0];
  my ($stdout, $stderr, $result) = capture {
    print_new_notifications($host, $cursor);
  };
  is $result, 1, 'print_new_notifications returns true';
  is $stdout, q{}, 'nothing is written to stdout';
  is $stderr,
    "[program.info] hello\n" . "[program.info] \n" . "[program.health] failed: boom\n" . "[program.health] unknown\n",
    'ready health is suppressed and everything else is printed';
};

subtest 'append_log ignores unusable paths and appends to usable ones' => sub {
  is append_log(undef, "ignored\n"), 1, 'an undef path is ignored';
  is append_log(q{},   "ignored\n"), 1, 'an empty path is ignored';

  my $log_path = File::Spec->catfile($tempdir, 'append', 'log.txt');
  is append_log($log_path, "first\n"),  1, 'a missing directory is created';
  is append_log($log_path, "second\n"), 1, 'appending to an existing log works';
  is _slurp($log_path), "first\nsecond\n", 'both messages were appended in order';

  my $dir_path = File::Spec->catdir($tempdir, 'append-dir');
  mkdir $dir_path or die "Can't mkdir $dir_path: $!";
  like dies { append_log($dir_path, "nope\n") }, qr/Can't\ open\ log\ file/mxs,
    'a path that is a directory croaks';
};

subtest 'write_health_file ignores unusable paths and writes atomic JSON' => sub {
  is write_health_file(undef, {status => 'ready'}), 1, 'an undef path is ignored';
  is write_health_file(q{},   {status => 'ready'}), 1, 'an empty path is ignored';

  my $health_path = File::Spec->catfile($tempdir, 'health', 'health.json');
  is write_health_file($health_path, {status => 'ready', details => {listen_port => 1,},}), 1,
    'a missing directory is created and the payload written';
  is(JSON->new->decode(_slurp($health_path)), {status => 'ready', details => {listen_port => 1,},},
    'the health payload round-trips as JSON');

  my $blocked_tmp = $health_path . '.tmp.' . $$;
  mkdir $blocked_tmp or die "Can't mkdir $blocked_tmp: $!";
  like dies { write_health_file($health_path, {status => 'ready'}) }, qr/Can't\ open\ health\ temp\ file/mxs,
    'a blocked temp path croaks on open';
  rmdir $blocked_tmp or die "Can't rmdir $blocked_tmp: $!";

  my $dir_target = File::Spec->catdir($tempdir, 'health-dir');
  mkdir $dir_target or die "Can't mkdir $dir_target: $!";
  my $inner = File::Spec->catfile($dir_target, 'occupied');
  open my $fh, '>', $inner or die "Can't open $inner: $!";
  close $fh or die "Can't close $inner: $!";
  like dies { write_health_file($dir_target, {status => 'ready'}) }, qr/Can't\ rename\ health\ temp\ file/mxs,
    'a rename over a non-empty directory croaks';
};

subtest 'hexchat_connect_host maps wildcard listen hosts to loopback' => sub {
  is hexchat_connect_host(undef),     '127.0.0.1', 'undef maps to loopback';
  is hexchat_connect_host(q{}),       '127.0.0.1', 'empty maps to loopback';
  is hexchat_connect_host('0.0.0.0'), '127.0.0.1', 'the IPv4 wildcard maps to loopback';
  is hexchat_connect_host(q{::}),     '127.0.0.1', 'the IPv6 wildcard maps to loopback';
  is hexchat_connect_host('192.0.2.9'), '192.0.2.9', 'a concrete host is returned as-is';
};

subtest 'shell_quote wraps values in single quotes' => sub {
  is shell_quote(undef), q{''}, 'undef quotes as the empty string';
  is shell_quote('abc'), q{'abc'}, 'a plain value is wrapped in single quotes';
  is shell_quote(q{a'b}), q{'a'"'"'b'}, 'embedded single quotes are escaped';
};

done_testing;
