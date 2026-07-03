use strictures 2;

use File::Spec;
use FindBin;
use JSON         ();
use MIME::Base64 qw(decode_base64 encode_base64);
use Test2::V0;

use lib grep { -d $_ } (
  File::Spec->catdir($FindBin::Bin, 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'lib'),
);

use Overnet::Program::IRC::Proxy;
use t::irc_auth_helper::FakeClient;

subtest 'proxy hides upstream SASL NOSTR auth from a plain IRC client' => sub {
  my $challenge  = '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope      = 'irc://irc.example.test/overnet';
  my $auth_event = _auth_event(scope => $scope, challenge => $challenge, seed => '1');
  my $client     = t::irc_auth_helper::FakeClient->new(response => _artifact_response($auth_event));
  my $proxy      = Overnet::Program::IRC::Proxy->new(
    client      => $client,
    interactive => 1,
  );

  is $proxy->start,
    {
    to_server => ["CAP LS 302\r\n", "CAP REQ :sasl\r\n"],
    to_client => [],
    },
    'proxy starts its own upstream capability negotiation';

  is $proxy->client_line("CAP LS 302\r\n"),
    {
    to_server => [],
    to_client => [":overnet-irc-proxy CAP * LS :\r\n"],
    },
    'client CAP LS is answered locally while hidden upstream auth is in progress';

  is $proxy->client_line("CAP REQ :sasl\r\n"),
    {
    to_server => [],
    to_client => [":overnet-irc-proxy CAP * NAK :sasl\r\n"],
    },
    'client SASL requests are not forwarded because the proxy owns upstream SASL';

  is $proxy->client_line("NICK alice\r\n"),
    {
    to_server => ["NICK alice\r\n"],
    to_client => [],
    },
    'NICK is forwarded early so upstream SASL success can name the client';

  is $proxy->client_line("USER alice 0 * :Alice Relay\r\n"),
    {
    to_server => ["USER alice 0 * :Alice Relay\r\n"],
    to_client => [],
    },
    'USER is forwarded early while upstream registration is held in CAP negotiation';

  is $proxy->client_line("JOIN #overnet\r\n"),
    {
    to_server => [],
    to_client => [],
    },
    'non-registration traffic is buffered until hidden auth completes';

  is $proxy->server_line(":server CAP * ACK :sasl\r\n"),
    {
    to_server => ["AUTHENTICATE NOSTR\r\n"],
    to_client => [],
    },
    'upstream SASL ACK starts NOSTR authentication';

  my @auth_response = _drive_server_lines(
    $proxy,
    _authenticate_server_lines(
      {
        challenge => $challenge,
        scope     => $scope,
      }
    )
  );
  ok @auth_response, 'proxy emits an upstream SASL response';
  like $auth_response[0], qr/\AAUTHENTICATE\ \S+\r\n\z/mx, 'proxy response uses raw IRC AUTHENTICATE lines';
  is _decode_authenticate_output(@auth_response),
    {auth_event => $auth_event,},
    'proxy preserves the auth event returned by the auth agent';

  is $client->calls->[0]{params}{program_id},  'irc.proxy',            'proxy identifies itself to the auth agent';
  is $client->calls->[0]{params}{action},      'session.authenticate', 'proxy requests session authentication';
  is $client->calls->[0]{params}{interactive}, JSON::true,             'proxy honors interactive auth by default';
  is $client->calls->[0]{params}{scope},       $scope,                 'proxy uses the server-provided scope';
  is $client->calls->[0]{params}{service}, {locators => [$scope],}, 'proxy uses scope as the default locator';
  is $client->calls->[0]{params}{challenge},
    {
    type  => 'opaque',
    value => $challenge,
    },
    'proxy forwards the server-provided challenge';

  is $proxy->server_line(":server 903 alice :SASL authentication successful\r\n"),
    {
    to_server => ["CAP END\r\n", "JOIN #overnet\r\n"],
    to_client => [],
    },
    'SASL success is hidden from the client and releases buffered traffic';
  ok $proxy->authenticated, 'proxy records that hidden upstream auth succeeded';

  is $proxy->server_line(":server 001 alice :Welcome\r\n"),
    {
    to_server => [],
    to_client => [":server 001 alice :Welcome\r\n"],
    },
    'normal server traffic is forwarded after hidden auth completes';

  is $proxy->client_line("PRIVMSG #overnet :hello\r\n"),
    {
    to_server => ["PRIVMSG #overnet :hello\r\n"],
    to_client => [],
    },
    'normal client traffic is forwarded after hidden auth completes';
};

subtest 'proxy can auto-delegate from relay-backed SASL challenges' => sub {
  my $challenge       = '7cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope           = 'irc://irc.example.test/overnet';
  my $delegate_pubkey = ('f' x 64);
  my $auth_event      = _auth_event(scope => $scope, challenge => $challenge, seed => '2');
  my $delegate_event  = {
    id         => ('3' x 64),
    pubkey     => ('4' x 64),
    created_at => 1744301800,
    kind       => 24142,
    tags       => [
      [relay      => 'ws://127.0.0.1:7448'],
      [server     => $scope],
      [delegate   => $delegate_pubkey],
      [session    => 'session-123'],
      [expires_at => '1744304600'],
    ],
    content => '',
    sig     => ('5' x 128),
  };
  my $client = t::irc_auth_helper::FakeClient->new(
    responses => [_artifact_response($auth_event), _artifact_response($delegate_event),],);
  my $proxy = Overnet::Program::IRC::Proxy->new(
    client      => $client,
    interactive => 1,
  );

  $proxy->start;
  $proxy->server_line(":server CAP * ACK :sasl\r\n");
  my @auth_response = _drive_server_lines(
    $proxy,
    _authenticate_server_lines(
      {
        challenge       => $challenge,
        scope           => $scope,
        relay_url       => 'ws://127.0.0.1:7448',
        grant_kind      => 24142,
        delegate_pubkey => $delegate_pubkey,
        session_id      => 'session-123',
        expires_at      => '1744304600',
      }
    )
  );

  is _decode_authenticate_output(@auth_response),
    {
    auth_event     => $auth_event,
    delegate_event => $delegate_event,
    },
    'relay-backed SASL responses include both auth and delegation events';
  is scalar(@{$client->calls}),           2, 'proxy calls the auth agent once for auth and once for delegation';
  is $client->calls->[1]{params}{action}, 'session.delegate', 'proxy requests relay delegation second';
  is $client->calls->[1]{params}{artifacts}[0]{params}{kind}, 24142,
    'proxy preserves the server-provided delegation kind';
};

subtest 'proxy refuses relay-backed SASL challenges when auto-delegation is disabled' => sub {
  my $challenge       = '8cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope           = 'irc://irc.example.test/overnet';
  my $delegate_pubkey = ('f' x 64);
  my $auth_event      = _auth_event(scope => $scope, challenge => $challenge, seed => '6');
  my $client          = t::irc_auth_helper::FakeClient->new(response => _artifact_response($auth_event));
  my $proxy           = Overnet::Program::IRC::Proxy->new(
    client        => $client,
    auto_delegate => 0,
  );

  $proxy->start;
  $proxy->server_line(":server CAP * ACK :sasl\r\n");
  my $error = eval {
    _drive_server_lines(
      $proxy,
      _authenticate_server_lines(
        {
          challenge       => $challenge,
          scope           => $scope,
          relay_url       => 'ws://127.0.0.1:7448',
          grant_kind      => 24142,
          delegate_pubkey => $delegate_pubkey,
          session_id      => 'session-123',
          expires_at      => '1744304600',
        }
      )
    );
    1;
  } ? undef : $@;

  like $error, qr/SASL\ NOSTR\ delegation\ is\ disabled/mx,
    'relay-backed SASL challenges fail loudly when auto-delegation is disabled';
  is scalar(@{$client->calls}), 1, 'the proxy does not request delegation when auto-delegation is disabled';
};

sub _drive_server_lines {
  my ($proxy, $input) = @_;
  my @lines = grep {length} split /\r\n/mx, $input;
  my @to_server;
  for my $line (@lines) {
    my $result = $proxy->server_line("$line\r\n");
    is $result->{to_client}, [], 'hidden SASL challenge line is not sent to the local client';
    push @to_server, @{$result->{to_server}};
  }
  return @to_server;
}

sub _authenticate_server_lines {
  my ($payload) = @_;
  my $encoded = encode_base64(JSON::encode_json($payload), '');
  my @chunks;
  while (length($encoded) > 400) {
    push @chunks, substr($encoded, 0, 400, '');
  }
  push @chunks, $encoded if length $encoded;

  return join '', map {":server AUTHENTICATE $_\r\n"} @chunks;
}

sub _decode_authenticate_output {
  my (@lines) = @_;
  my $payload = join '', map {
    my $line = $_;
    $line =~ s/\r?\n\z//mx;
    $line =~ s/\AAUTHENTICATE\s+//mx;
    $line eq '+' ? () : $line;
  } @lines;

  return JSON::decode_json(decode_base64($payload));
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

done_testing;
