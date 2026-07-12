use strictures 2;

use Capture::Tiny qw(capture);
use Test2::V0;

use Overnet::Program::IRC::Script::Auth;

my $package = 'Overnet::Program::IRC::Script::Auth';

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

sub _mock_helper {
  my ($calls) = @_;
  return mock 'Overnet::Program::IRC::Auth::Helper' => (
    override => [
      run => sub {
        my ($class, %args) = @_;
        push @{$calls}, {%args};
        return "helper output\n";
      },
    ],
  );
}

subtest 'a leading --help prints usage to stdout' => sub {
  my $run = _run('--help');
  is $run->{exit}, 0, '--help exits successfully';
  like $run->{stdout}, qr/overnet-irc-server\ auth\ bridge\ \[options\]/mxs, 'usage names the bridge mode';
};

subtest 'unknown options print usage to stderr' => sub {
  my $run = _run('auth', '--frobnicate');
  is $run->{exit}, 1, 'unknown options fail';
  like $run->{stderr}, qr/overnet-irc-server\ auth\ auth\ \[options\]/mxs, 'usage goes to stderr';
};

subtest '--help after a command prints usage to stdout' => sub {
  my $run = _run('auth', '--help');
  is $run->{exit}, 0, 'auth --help exits successfully';
  like $run->{stdout}, qr/Auth-agent\ options:/mxs, 'usage is printed';
};

subtest 'a missing command prints usage and fails' => sub {
  my $run = _run();
  is $run->{exit}, 1, 'no command fails';
  like $run->{stdout}, qr/Usage:/mxs, 'usage is printed to stdout';

  my $empty = _run(q{});
  is $empty->{exit}, 1, 'an empty command fails';
};

subtest 'an unknown command prints usage to stderr' => sub {
  my $run = _run('frobnicate');
  is $run->{exit}, 1, 'an unknown command fails';
  like $run->{stderr}, qr/Usage:/mxs, 'usage goes to stderr';
};

subtest 'the auth command prints the helper output' => sub {
  my @calls;
  my $helper = _mock_helper(\@calls);

  my $run = _run('auth', '--challenge', 'challenge-1', '--scope', 'irc:example');
  is $run->{exit}, 0, 'the auth command exits successfully';
  is $run->{stdout}, "helper output\n", 'the helper output is printed';
  is scalar(@calls), 1, 'the helper ran once';
  is $calls[0]{command},   'auth',        'the helper received the command';
  is $calls[0]{challenge}, 'challenge-1', 'the helper received the challenge';
  is $calls[0]{scope},     'irc:example', 'the helper received the scope';
  ok !exists $calls[0]{input}, 'single-shot mode passes no input handle';
};

subtest 'the delegate command passes its options through' => sub {
  my @calls;
  my $helper = _mock_helper(\@calls);

  my $run = _run(
    'delegate',       '--relay-url', 'ws://relay.example.test:1', '--delegate-pubkey',
    'a' x 64,         '--session-id', 'session-1', '--expires-at',
    '123', '--nick', 'alice',
  );
  is $run->{exit}, 0, 'the delegate command exits successfully';
  is $calls[0]{command},         'delegate',                  'the helper received the command';
  is $calls[0]{relay_url},       'ws://relay.example.test:1', 'the helper received the relay URL';
  is $calls[0]{delegate_pubkey}, 'a' x 64,                    'the helper received the delegate pubkey';
  is $calls[0]{session_id},      'session-1',                 'the helper received the session id';
  is $calls[0]{expires_at},      '123',                       'the helper received the expiry';
  is $calls[0]{nick},            'alice',                     'the helper received the nick';
};

subtest 'an explicit auth socket reaches the auth client' => sub {
  my @calls;
  my $helper       = _mock_helper(\@calls);
  my @client_args;
  my $client_class = mock 'Overnet::Auth::Client' => (
    override => [
      new => sub {
        my ($class, %args) = @_;
        push @client_args, {%args};
        return;
      },
    ],
  );

  my $run = _run('auth', '--auth-sock', '/tmp/auth.sock', '--challenge', 'c');
  is $run->{exit}, 0, 'the auth command exits successfully';
  is \@client_args, [{endpoint => '/tmp/auth.sock',},], 'the auth socket became the client endpoint';
};

subtest 'bridge with an explicit line prints the helper output' => sub {
  my @calls;
  my $helper = _mock_helper(\@calls);

  my $run = _run('bridge', '--line', ':server NOTICE alice :OVERNETAUTH c', '--scope', 'irc:example');
  is $run->{exit}, 0, 'bridge with a line exits successfully';
  is $run->{stdout}, "helper output\n", 'the helper output is printed';
  is $calls[0]{command}, 'bridge', 'the helper received the bridge command';
  is $calls[0]{line}, ':server NOTICE alice :OVERNETAUTH c', 'the helper received the line';
  ok !exists $calls[0]{input}, 'single-line mode passes no input handle';
};

subtest 'bridge without a line streams stdin to stdout' => sub {
  my @calls;
  my $helper = _mock_helper(\@calls);

  my $run = _run('bridge', '--scope', 'irc:example');
  is $run->{exit}, 0, 'continuous bridge mode exits successfully';
  is $run->{stdout}, q{}, 'continuous mode prints nothing itself';
  is $calls[0]{command}, 'bridge', 'the helper received the bridge command';
  ok $calls[0]{input},  'continuous mode passes an input handle';
  ok $calls[0]{output}, 'continuous mode passes an output handle';
};

done_testing;
