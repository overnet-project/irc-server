use strictures 2;

use Capture::Tiny qw(capture);
use Test2::V0;

use Overnet::Program::IRC::Script::AuthorityRelay;

my $package = 'Overnet::Program::IRC::Script::AuthorityRelay';

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
  like $run->{stdout}, qr/authority-relay\ \[options\]/mxs, 'usage names the command';
};

subtest 'unknown options print usage to stderr' => sub {
  my $run = _run('--frobnicate');
  is $run->{exit}, 1, 'unknown options fail';
  like $run->{stderr}, qr/authority-relay\ \[options\]/mxs, 'usage goes to stderr';
};

subtest 'invalid option values croak' => sub {
  like dies { $package->run('--host', q{}) }, qr/--host\ is\ required/mxs, 'an empty host croaks';
  like dies { $package->run('--port=-1') }, qr/--port\ must\ be\ a\ non-negative\ integer/mxs,
    'a negative port croaks';
  like dies { $package->run('--grant-kind', 0) }, qr/--grant-kind\ must\ be\ a\ positive\ integer/mxs,
    'grant-kind zero croaks';
  like dies { $package->run('--store-file', q{}) }, qr/--store-file\ must\ be\ a\ non-empty\ string/mxs,
    'an empty store file croaks';
  like dies { $package->run('--snapshot-pubkey', 'UPPERCASE') },
    qr/--snapshot-pubkey\ must\ be\ a\ 64-char\ lowercase\ hex\ pubkey/mxs, 'a malformed snapshot pubkey croaks';
};

subtest 'a run builds the relay and serves until stopped' => sub {
  my @built;
  my @ran;
  my $stopped = 0;

  my $relay = mock {};
  my $relay_control = mock $relay => (
    add => [
      run => sub {
        my ($self, $host, $port) = @_;
        push @ran, [$host, $port];

        # Exercise the installed signal handlers the way an operator would.
        kill 'INT',  $$;
        kill 'TERM', $$;
        return 1;
      },
      stop => sub { $stopped++; return 1 },
    ],
  );

  my $builder = mock $package => (
    override => [
      build_authoritative_relay => sub {
        my (%args) = @_;
        push @built, {%args};
        return $relay;
      },
    ],
  );

  my $pubkey = 'a' x 64;
  is + ($package->run('--snapshot-pubkey', $pubkey)), 0, 'a default run exits successfully';
  is \@ran, [['127.0.0.1', 7_448]], 'the relay served on the default host and port';
  is $stopped, 2, 'both signal handlers stopped the relay';
  is \@built,
    [
    {
      relay_url        => 'ws://127.0.0.1:7448',
      grant_kind       => 14_142,
      snapshot_pubkeys => [$pubkey],
    },
    ],
    'the relay URL defaults from host and port';

  @built = ();
  @ran   = ();
  is + ($package->run('--relay-url', 'ws://relay.example.test:1', '--store-file', '/tmp/store.json')), 0,
    'an explicit relay URL and store file exit successfully';
  is \@built,
    [
    {
      relay_url        => 'ws://relay.example.test:1',
      grant_kind       => 14_142,
      snapshot_pubkeys => [],
      store_file       => '/tmp/store.json',
    },
    ],
    'explicit relay URL and store file are passed through';
};

done_testing;
