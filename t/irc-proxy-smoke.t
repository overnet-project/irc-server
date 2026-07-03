use strictures 2;

use File::Spec;
use FindBin;
use IO::Handle ();
use IO::Select;
use JSON         ();
use MIME::Base64 qw(decode_base64 encode_base64);
use POSIX        qw(_exit);
use Socket       qw(AF_UNIX PF_UNSPEC SOCK_STREAM);
use Test2::V0;

use lib grep { -d $_ } (
  File::Spec->catdir($FindBin::Bin, 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'lib'),
);

use Overnet::Program::IRC::Script::Proxy;
use t::irc_auth_helper::FakeClient;

my %READ_BUFFERS;

subtest 'proxy runner performs hidden SASL auth between real sockets' => sub {
  my ($client_parent, $client_child) = _socket_pair('client');
  my ($server_parent, $server_child) = _socket_pair('server');

  my $challenge   = '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope       = 'irc://irc.example.test/overnet';
  my $auth_event  = _auth_event(scope => $scope, challenge => $challenge, seed => '1');
  my $auth_client = t::irc_auth_helper::FakeClient->new(response => _artifact_response($auth_event));

  my $pid = fork;
  defined $pid or die "fork failed: $!";
  if ($pid == 0) {
    close $client_parent or die "close parent client socket in child failed: $!";
    close $server_parent or die "close parent server socket in child failed: $!";

    my $ok = eval {
      no warnings qw(redefine once);
      local *Overnet::Program::IRC::Script::Proxy::_open_server_socket = sub {
        return $server_child;
      };

      Overnet::Program::IRC::Script::Proxy::_serve_connection(
        {
          interactive   => 1,
          auto_delegate => 1,
          program_id    => 'irc.proxy',
        },
        $auth_client,
        $client_child,
      );
      1;
    };
    warn $@ if !$ok;
    _exit($ok ? 0 : 1);
  }

  close $client_child or die "close child client socket in parent failed: $!";
  close $server_child or die "close child server socket in parent failed: $!";

  is _read_line($server_parent, 'proxy CAP LS'),  "CAP LS 302\r\n",    'proxy starts upstream CAP discovery';
  is _read_line($server_parent, 'proxy CAP REQ'), "CAP REQ :sasl\r\n", 'proxy requests upstream SASL';

  _write_line($client_parent, "NICK alice\r\n");
  _write_line($client_parent, "USER alice 0 * :Alice Relay\r\n");
  _write_line($client_parent, "JOIN #overnet\r\n");

  is _read_line($server_parent, 'forwarded NICK'), "NICK alice\r\n",                  'proxy forwards NICK before auth';
  is _read_line($server_parent, 'forwarded USER'), "USER alice 0 * :Alice Relay\r\n", 'proxy forwards USER before auth';
  ok !_line_ready($server_parent, 0.2), 'proxy buffers JOIN until auth succeeds';

  _write_line($server_parent, ":server CAP * ACK :sasl\r\n");
  is _read_line($server_parent, 'AUTHENTICATE NOSTR'), "AUTHENTICATE NOSTR\r\n",
    'proxy starts upstream NOSTR SASL after ACK';

  _write_line(
    $server_parent,
    _authenticate_challenge_line(
      {
        challenge => $challenge,
        scope     => $scope,
      }
    )
  );
  is _read_authenticate_response($server_parent), {auth_event => $auth_event,},
    'proxy signs and returns the hidden SASL response';
  ok !_line_ready($client_parent, 0.2), 'hidden SASL traffic is not sent to the local IRC client';

  _write_line($server_parent, ":server 903 alice :SASL authentication successful\r\n");
  is _read_line($server_parent, 'proxy CAP END'), "CAP END\r\n", 'proxy ends upstream CAP negotiation';
  is _read_line($server_parent, 'released buffered JOIN'), "JOIN #overnet\r\n",
    'proxy releases buffered JOIN after auth';

  _write_line($server_parent, ":server 001 alice :Welcome\r\n");
  is _read_line($client_parent, 'forwarded welcome'), ":server 001 alice :Welcome\r\n",
    'proxy forwards normal server traffic after auth';

  _write_line($client_parent, "PRIVMSG #overnet :hello\r\n");
  is _read_line($server_parent, 'forwarded PRIVMSG'), "PRIVMSG #overnet :hello\r\n",
    'proxy forwards normal client traffic after auth';

  close $client_parent or die "close parent client socket failed: $!";
  waitpid $pid, 0;
  is $?, 0, 'proxy child exits cleanly after client disconnect';

  close $server_parent or die "close parent server socket failed: $!";
};

done_testing;

sub _socket_pair {
  my ($name) = @_;
  socketpair(my $left, my $right, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
    or die "socketpair failed for $name sockets: $!";
  for my $socket ($left, $right) {
    binmode($socket, ':raw') or die "binmode failed for $name socket: $!";
    $socket->autoflush(1);
  }
  return ($left, $right);
}

sub _line_ready {
  my ($handle, $timeout) = @_;
  my $fileno = fileno($handle);
  if (defined $fileno && ($READ_BUFFERS{$fileno} || q{}) =~ /\n/mxs) {
    return 1;
  }

  my $selector = IO::Select->new($handle);
  return scalar($selector->can_read($timeout)) ? 1 : 0;
}

sub _read_line {
  my ($handle, $description) = @_;
  my $fileno = fileno($handle);
  defined $fileno or die "handle for $description is closed";
  $READ_BUFFERS{$fileno} = q{} if !defined $READ_BUFFERS{$fileno};

  while (1) {
    if ($READ_BUFFERS{$fileno} =~ s/\A([^\n]*\n)//mxs) {
      return $1;
    }

    ok _line_ready($handle, 2), "$description is available"
      or return;
    my $bytes = sysread($handle, my $chunk, 4_096);
    if (!(defined $bytes && $bytes > 0)) {
      fail "$description read returned EOF";
      return;
    }
    $READ_BUFFERS{$fileno} .= $chunk;
  }
}

sub _write_line {
  my ($handle, $line) = @_;
  print {$handle} $line or die "write failed: $!";
  return 1;
}

sub _authenticate_challenge_line {
  my ($payload) = @_;
  my $encoded = encode_base64(JSON::encode_json($payload), '');
  return ":server AUTHENTICATE $encoded\r\n";
}

sub _read_authenticate_response {
  my ($handle) = @_;
  my @chunks;

  while (1) {
    my $line = _read_line($handle, 'AUTHENTICATE response');
    my ($chunk) = $line =~ /\AAUTHENTICATE\s+(\S+)\r?\n\z/mxs;
    ok defined $chunk, 'proxy response is an AUTHENTICATE line';
    last if !defined $chunk;
    push @chunks, $chunk if $chunk ne '+';
    last if $chunk eq '+' || length($chunk) < 400;
  }

  return JSON::decode_json(decode_base64(join q{}, @chunks));
}

sub _auth_event {
  my (%args) = @_;
  return {
    id         => ($args{seed} x 64),
    pubkey     => ('a' x 64),
    created_at => 1744301600,
    kind       => 22242,
    tags       => [[relay => $args{scope}], [challenge => $args{challenge}],],
    content    => '',
    sig        => ('b' x 128),
  };
}

sub _artifact_response {
  my ($event) = @_;
  return {
    type   => 'response',
    id     => 'auth-1',
    ok     => JSON::true,
    result => {
      artifacts => [
        {
          type   => 'nostr.event',
          format => 'nostr.event',
          value  => $event,
        },
      ],
    },
  };
}
