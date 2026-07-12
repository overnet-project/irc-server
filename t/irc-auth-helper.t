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

use Overnet::Program::IRC::Auth::Helper;
use t::irc_auth_helper::FakeClient;

subtest 'auth mode uses the auth agent and emits a paste-ready OVERNETAUTH AUTH line' => sub {
  my $challenge = '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope     = 'irc://irc.example.test/overnet';
  my $event     = {
    id         => ('a' x 64),
    pubkey     => ('b' x 64),
    created_at => 1744301000,
    kind       => 22242,
    tags       => [[relay => $scope], [challenge => $challenge],],
    content    => '',
    sig        => ('c' x 128),
  };
  my $client = t::irc_auth_helper::FakeClient->new(
    response => {
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
    },
  );

  my $output = Overnet::Program::IRC::Auth::Helper->run(
    client      => $client,
    command     => 'auth',
    identity_id => 'default',
    challenge   => $challenge,
    scope       => $scope,
    quote       => 1,
    interactive => 1,
  );

  my ($payload) = $output =~ qr{\A/quote\ OVERNETAUTH\ AUTH\ (\S+)\n\z}mx;
  ok defined $payload, 'the helper prints a paste-ready OVERNETAUTH AUTH command';
  is JSON::decode_json(decode_base64($payload)), $event,
    'the helper preserves the signed auth event returned by the auth agent';

  is $client->calls,
    [
    {
      method => 'sessions.authorize',
      params => {
        program_id  => 'irc.bridge',
        identity_id => 'default',
        service     => {
          locators => [$scope],
        },
        scope       => $scope,
        action      => 'session.authenticate',
        interactive => JSON::true,
        challenge   => {
          type  => 'opaque',
          value => $challenge,
        },
        artifacts => [
          {
            type   => 'nostr.event',
            params => {
              kind => 22242,
              tags => [[relay => $scope], [challenge => $challenge],],
            },
          },
        ],
      },
    },
    ],
    'auth mode sends the expected sessions.authorize request';
};

subtest 'delegate mode uses the auth agent and emits a paste-ready OVERNETAUTH DELEGATE line' => sub {
  my $scope = 'irc://irc.example.test/overnet';
  my $event = {
    id         => ('d' x 64),
    pubkey     => ('e' x 64),
    created_at => 1744301100,
    kind       => 14142,
    tags       => [
      [relay      => 'ws://127.0.0.1:7448'],
      [server     => $scope],
      [delegate   => ('f' x 64)],
      [session    => 'session-123'],
      [expires_at => '1744304600'],
      [nick       => 'alice'],
    ],
    content => '',
    sig     => ('1' x 128),
  };
  my $client = t::irc_auth_helper::FakeClient->new(
    response => {
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
    },
  );

  my $output = Overnet::Program::IRC::Auth::Helper->run(
    client          => $client,
    command         => 'delegate',
    identity_id     => 'default',
    relay_url       => 'ws://127.0.0.1:7448',
    scope           => $scope,
    delegate_pubkey => ('f' x 64),
    session_id      => 'session-123',
    expires_at      => '1744304600',
    nick            => 'alice',
    quote           => 1,
    interactive     => 1,
  );

  my ($payload) = $output =~ qr{\A/quote\ OVERNETAUTH\ DELEGATE\ (\S+)\n\z}mx;
  ok defined $payload, 'the helper prints a paste-ready OVERNETAUTH DELEGATE command';
  is JSON::decode_json(decode_base64($payload)), $event,
    'the helper preserves the signed delegate event returned by the auth agent';

  is $client->calls,
    [
    {
      method => 'sessions.authorize',
      params => {
        program_id  => 'irc.bridge',
        identity_id => 'default',
        service     => {
          locators => [$scope],
        },
        scope       => $scope,
        action      => 'session.delegate',
        interactive => JSON::true,
        artifacts   => [
          {
            type   => 'nostr.event',
            params => {
              kind => 14142,
              tags => [
                [relay      => 'ws://127.0.0.1:7448'],
                [server     => $scope],
                [delegate   => ('f' x 64)],
                [session    => 'session-123'],
                [expires_at => '1744304600'],
                [nick       => 'alice'],
              ],
            },
          },
        ],
      },
    },
    ],
    'delegate mode sends the expected sessions.authorize request';
};

subtest 'bridge mode parses OVERNETAUTH CHALLENGE lines and requests auth artifacts' => sub {
  my $challenge = '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope     = 'irc://irc.example.test/overnet';
  my $client    = t::irc_auth_helper::FakeClient->new(
    response => {
      type   => 'response',
      id     => 'auth-1',
      ok     => JSON::true,
      result => {
        artifacts => [
          {
            type   => 'nostr.event',
            format => 'nostr.event',
            value  => {
              id         => ('2' x 64),
              pubkey     => ('3' x 64),
              created_at => 1744301200,
              kind       => 22242,
              tags       => [[relay => $scope], [challenge => $challenge],],
              content    => '',
              sig        => ('4' x 128),
            },
          },
        ],
      },
    },
  );

  my $output = Overnet::Program::IRC::Auth::Helper->run(
    client      => $client,
    command     => 'bridge',
    scope       => $scope,
    line        => "-server- OVERNETAUTH CHALLENGE $challenge",
    quote       => 1,
    interactive => 1,
  );

  like $output, qr{\A/quote\ OVERNETAUTH\ AUTH\ \S+\n\z}mx, 'bridge mode emits an OVERNETAUTH AUTH command';
  is $client->calls->[0]{params}{action}, 'session.authenticate',
    'bridge mode maps challenge lines to session.authenticate';
  is $client->calls->[0]{params}{challenge}{value}, $challenge, 'bridge mode extracts the challenge token';
};

subtest 'bridge mode parses OVERNETAUTH DELEGATE lines and requests delegate artifacts' => sub {
  my $scope           = 'irc://irc.example.test/overnet';
  my $delegate_pubkey = ('f' x 64);
  my $client          = t::irc_auth_helper::FakeClient->new(
    response => {
      type   => 'response',
      id     => 'auth-1',
      ok     => JSON::true,
      result => {
        artifacts => [
          {
            type   => 'nostr.event',
            format => 'nostr.event',
            value  => {
              id         => ('5' x 64),
              pubkey     => ('6' x 64),
              created_at => 1744301300,
              kind       => 14142,
              tags       => [
                [relay      => 'ws://127.0.0.1:7448'],
                [server     => $scope],
                [delegate   => $delegate_pubkey],
                [session    => 'session-123'],
                [expires_at => '1744304600'],
              ],
              content => '',
              sig     => ('7' x 128),
            },
          },
        ],
      },
    },
  );

  my $output = Overnet::Program::IRC::Auth::Helper->run(
    client      => $client,
    command     => 'bridge',
    scope       => $scope,
    line        => "-server- OVERNETAUTH DELEGATE $delegate_pubkey session-123 ws://127.0.0.1:7448 1744304600",
    quote       => 1,
    interactive => 1,
  );

  like $output, qr{\A/quote\ OVERNETAUTH\ DELEGATE\ \S+\n\z}mx, 'bridge mode emits an OVERNETAUTH DELEGATE command';
  is $client->calls->[0]{params}{action}, 'session.delegate', 'bridge mode maps delegate lines to session.delegate';
  is $client->calls->[0]{params}{artifacts}[0]{params}{tags},
    [
    [relay      => 'ws://127.0.0.1:7448'],
    [server     => $scope],
    [delegate   => $delegate_pubkey],
    [session    => 'session-123'],
    [expires_at => '1744304600'],
    ],
    'bridge mode extracts the delegate parameters from the IRC line';
};

subtest 'bridge mode processes a continuous stdin stream and emits quote commands for matching lines only' => sub {
  my $challenge       = '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope           = 'irc://irc.example.test/overnet';
  my $delegate_pubkey = ('f' x 64);
  my $client          = t::irc_auth_helper::FakeClient->new(
    responses => [
      {
        type   => 'response',
        id     => 'auth-1',
        ok     => JSON::true,
        result => {
          artifacts => [
            {
              type   => 'nostr.event',
              format => 'nostr.event',
              value  => {
                id         => ('2' x 64),
                pubkey     => ('3' x 64),
                created_at => 1744301200,
                kind       => 22242,
                tags       => [[relay => $scope], [challenge => $challenge],],
                content    => '',
                sig        => ('4' x 128),
              },
            },
          ],
        },
      },
      {
        type   => 'response',
        id     => 'auth-2',
        ok     => JSON::true,
        result => {
          artifacts => [
            {
              type   => 'nostr.event',
              format => 'nostr.event',
              value  => {
                id         => ('5' x 64),
                pubkey     => ('6' x 64),
                created_at => 1744301300,
                kind       => 14142,
                tags       => [
                  [relay      => 'ws://127.0.0.1:7448'],
                  [server     => $scope],
                  [delegate   => $delegate_pubkey],
                  [session    => 'session-123'],
                  [expires_at => '1744304600'],
                ],
                content => '',
                sig     => ('7' x 128),
              },
            },
          ],
        },
      },
    ],
  );

  my $input = join '',
    ":server 001 alice :welcome\r\n",
    "-server- OVERNETAUTH CHALLENGE $challenge\r\n",
    ":server NOTICE alice :ignored\r\n",
    "-server- OVERNETAUTH DELEGATE $delegate_pubkey session-123 ws://127.0.0.1:7448 1744304600\r\n";
  my $output = '';
  open my $in,  '<', \$input  or die "open input failed: $!";
  open my $out, '>', \$output or die "open output failed: $!";

  my $count = Overnet::Program::IRC::Auth::Helper->run(
    client      => $client,
    command     => 'bridge',
    scope       => $scope,
    input       => $in,
    output      => $out,
    quote       => 1,
    interactive => 1,
  );

  close $out or die "close output failed: $!";
  is $count, 2, 'bridge mode reports the number of emitted auth commands';
  like $output,
    qr{\A/quote\ OVERNETAUTH\ AUTH\ \S+\n/quote\ OVERNETAUTH\ DELEGATE\ \S+\n\z}mx,
    'bridge mode emits one quote command per matching auth line';
  is scalar(@{$client->calls}),                     2,          'only matching OVERNETAUTH lines reach the auth agent';
  is $client->calls->[0]{params}{challenge}{value}, $challenge, 'stream mode extracted the challenge';
  is $client->calls->[1]{params}{action},           'session.delegate', 'stream mode extracted the delegate request';
};

subtest 'bridge mode returns zero for streams with no matching auth lines' => sub {
  my $client = t::irc_auth_helper::FakeClient->new(
    response => {
      type   => 'response',
      id     => 'auth-1',
      ok     => JSON::true,
      result => {artifacts => []},
    },
  );

  my $input  = ":server 001 alice :welcome\r\n:server NOTICE alice :ignored\r\n";
  my $output = '';
  open my $in,  '<', \$input  or die "open input failed: $!";
  open my $out, '>', \$output or die "open output failed: $!";

  my $count = Overnet::Program::IRC::Auth::Helper->run(
    client      => $client,
    command     => 'bridge',
    scope       => 'irc://irc.example.test/overnet',
    input       => $in,
    output      => $out,
    quote       => 1,
    interactive => 1,
  );

  close $out or die "close output failed: $!";
  is $count,                    0,  'bridge mode reports no generated commands';
  is $output,                   '', 'bridge mode stays silent for non-auth lines';
  is scalar(@{$client->calls}), 0,  'non-auth lines do not call the auth agent';
};

subtest 'bridge mode stream can emit payloads without /quote prefixes' => sub {
  my $challenge = '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope     = 'irc://irc.example.test/overnet';
  my $client    = t::irc_auth_helper::FakeClient->new(
    response => {
      type   => 'response',
      id     => 'auth-1',
      ok     => JSON::true,
      result => {
        artifacts => [
          {
            type   => 'nostr.event',
            format => 'nostr.event',
            value  => {
              id         => ('2' x 64),
              pubkey     => ('3' x 64),
              created_at => 1744301200,
              kind       => 22242,
              tags       => [[relay => $scope], [challenge => $challenge],],
              content    => '',
              sig        => ('4' x 128),
            },
          },
        ],
      },
    },
  );

  my $input  = "-server- OVERNETAUTH CHALLENGE $challenge\r\n";
  my $output = '';
  open my $in,  '<', \$input  or die "open input failed: $!";
  open my $out, '>', \$output or die "open output failed: $!";

  my $count = Overnet::Program::IRC::Auth::Helper->run(
    client      => $client,
    command     => 'bridge',
    scope       => $scope,
    input       => $in,
    output      => $out,
    quote       => 0,
    interactive => 1,
  );

  close $out or die "close output failed: $!";
  is $count, 1, 'bridge mode reports one generated payload';
  unlike $output, qr{\A/quote\ }mx, 'bridge mode omits /quote when quote output is disabled';
  like $output,   qr{\A\S+\n\z}mx,  'bridge mode still emits the auth payload on its own line';
};

subtest 'bridge mode processes SASL NOSTR AUTHENTICATE streams without relay delegation' => sub {
  my $challenge  = '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope      = 'irc://irc.example.test/overnet';
  my $auth_event = {
    id         => ('1' x 64),
    pubkey     => ('2' x 64),
    created_at => 1744301600,
    kind       => 22242,
    tags       => [[relay => $scope], [challenge => $challenge],],
    content    => '',
    sig        => ('3' x 128),
  };
  my $client = t::irc_auth_helper::FakeClient->new(
    response => {
      type   => 'response',
      id     => 'auth-1',
      ok     => JSON::true,
      result => {
        artifacts => [
          {
            type   => 'nostr.event',
            format => 'nostr.event',
            value  => $auth_event,
          },
        ],
      },
    },
  );

  my $input = _authenticate_input_lines(
    {
      challenge => $challenge,
      scope     => $scope,
    }
  );
  my $output = '';
  open my $in,  '<', \$input  or die "open input failed: $!";
  open my $out, '>', \$output or die "open output failed: $!";

  my $count = Overnet::Program::IRC::Auth::Helper->run(
    client      => $client,
    command     => 'bridge',
    input       => $in,
    output      => $out,
    quote       => 1,
    interactive => 1,
  );

  close $out or die "close output failed: $!";
  my @lines = grep {length} split /\n/mx, $output;
  ok @lines >= 1, 'sasl bridge emitted AUTHENTICATE lines';
  is $count, scalar(@lines), 'sasl bridge count matches emitted AUTHENTICATE lines';
  like $lines[0], qr{\A/quote\ AUTHENTICATE\ \S+\z}mx, 'sasl bridge emits AUTHENTICATE commands';

  my $response = _decode_authenticate_output($output);
  is $response, {auth_event => $auth_event,}, 'sasl bridge preserves the auth event in the response payload';

  is $client->calls,
    [
    {
      method => 'sessions.authorize',
      params => {
        program_id => 'irc.bridge',
        service    => {
          locators => [$scope],
        },
        scope       => $scope,
        action      => 'session.authenticate',
        interactive => JSON::true,
        challenge   => {
          type  => 'opaque',
          value => $challenge,
        },
        artifacts => [
          {
            type   => 'nostr.event',
            params => {
              kind => 22242,
              tags => [[relay => $scope], [challenge => $challenge],],
            },
          },
        ],
      },
    },
    ],
    'sasl bridge requests only the auth artifact when delegation is absent';
};

subtest 'bridge mode processes relay-backed SASL NOSTR AUTHENTICATE streams' => sub {
  my $challenge       = '7cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope           = 'irc://irc.example.test/overnet';
  my $delegate_pubkey = ('f' x 64);
  my $auth_event      = {
    id         => ('4' x 64),
    pubkey     => ('5' x 64),
    created_at => 1744301700,
    kind       => 22242,
    tags       => [[relay => $scope], [challenge => $challenge],],
    content    => '',
    sig        => ('6' x 128),
  };
  my $delegate_event = {
    id         => ('7' x 64),
    pubkey     => ('8' x 64),
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
    sig     => ('9' x 128),
  };
  my $client = t::irc_auth_helper::FakeClient->new(
    responses => [
      {
        type   => 'response',
        id     => 'auth-1',
        ok     => JSON::true,
        result => {
          artifacts => [
            {
              type   => 'nostr.event',
              format => 'nostr.event',
              value  => $auth_event,
            },
          ],
        },
      },
      {
        type   => 'response',
        id     => 'auth-2',
        ok     => JSON::true,
        result => {
          artifacts => [
            {
              type   => 'nostr.event',
              format => 'nostr.event',
              value  => $delegate_event,
            },
          ],
        },
      },
    ],
  );

  my $input = _authenticate_input_lines(
    {
      challenge       => $challenge,
      scope           => $scope,
      relay_url       => 'ws://127.0.0.1:7448',
      grant_kind      => 24142,
      delegate_pubkey => $delegate_pubkey,
      session_id      => 'session-123',
      expires_at      => '1744304600',
      padding         => ('x' x 700),
    }
  );
  my $output = '';
  open my $in,  '<', \$input  or die "open input failed: $!";
  open my $out, '>', \$output or die "open output failed: $!";

  my $count = Overnet::Program::IRC::Auth::Helper->run(
    client      => $client,
    command     => 'bridge',
    input       => $in,
    output      => $out,
    quote       => 0,
    interactive => 1,
  );

  close $out or die "close output failed: $!";
  my @lines = grep {length} split /\n/mx, $output;
  ok @lines >= 1, 'relay-backed sasl bridge emitted AUTHENTICATE lines';
  is $count, scalar(@lines), 'relay-backed sasl bridge count matches emitted AUTHENTICATE lines';
  like $lines[0],   qr{\AAUTHENTICATE\ \S+\z}mx, 'relay-backed sasl bridge can emit raw AUTHENTICATE lines';
  unlike $lines[0], qr{\A/quote\ }mx,            'relay-backed sasl bridge omits /quote when disabled';

  my $response = _decode_authenticate_output($output);
  is $response,
    {
    auth_event     => $auth_event,
    delegate_event => $delegate_event,
    },
    'relay-backed sasl bridge preserves both returned events in the response payload';

  is scalar(@{$client->calls}),           2, 'relay-backed sasl bridge makes two auth-agent requests';
  is $client->calls->[0]{params}{action}, 'session.authenticate', 'relay-backed sasl bridge requests auth first';
  is $client->calls->[0]{params}{challenge}{value}, $challenge,
    'relay-backed sasl bridge forwards the server challenge';
  is $client->calls->[1]{params}{action}, 'session.delegate', 'relay-backed sasl bridge requests delegation second';
  is $client->calls->[1]{params}{artifacts}[0]{params}{tags},
    [
    [relay      => 'ws://127.0.0.1:7448'],
    [server     => $scope],
    [delegate   => $delegate_pubkey],
    [session    => 'session-123'],
    [expires_at => '1744304600'],
    ],
    'relay-backed sasl bridge forwards the delegate challenge parameters';
  is $client->calls->[1]{params}{artifacts}[0]{params}{kind}, 24142,
    'relay-backed sasl bridge honors grant_kind from the server challenge';
};

subtest 'auth mode forwards locator and service identity descriptors to the auth agent' => sub {
  my $challenge = '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope     = 'irc://irc.example.test/overnet';
  my $locator   = 'wss://relay.example.test/auth';
  my $client    = t::irc_auth_helper::FakeClient->new(
    response => {
      type   => 'response',
      id     => 'auth-1',
      ok     => JSON::true,
      result => {
        artifacts => [
          {
            type   => 'nostr.event',
            format => 'nostr.event',
            value  => {
              id         => ('8' x 64),
              pubkey     => ('9' x 64),
              created_at => 1744301400,
              kind       => 22242,
              tags       => [[relay => $scope], [challenge => $challenge],],
              content    => '',
              sig        => ('a' x 128),
            },
          },
        ],
      },
    },
  );

  my $output = Overnet::Program::IRC::Auth::Helper->run(
    client                   => $client,
    command                  => 'auth',
    identity_id              => 'default',
    challenge                => $challenge,
    scope                    => $scope,
    locator                  => $locator,
    service_identity_scheme  => 'nostr.pubkey',
    service_identity_value   => ('b' x 64),
    service_identity_display => 'relay.example.test authority',
    interactive              => 1,
  );

  like $output, qr{\A\S+\n\z}mx, 'auth mode still returns a wire payload';
  is $client->calls->[0]{params}{service},
    {
    locators         => [$locator],
    service_identity => {
      scheme  => 'nostr.pubkey',
      value   => ('b' x 64),
      display => 'relay.example.test authority',
    },
    },
    'auth mode forwards locator and service identity descriptors';
};

subtest 'service identity flags require both scheme and value' => sub {
  my $client = t::irc_auth_helper::FakeClient->new(
    response => {
      type   => 'response',
      id     => 'auth-1',
      ok     => JSON::true,
      result => {
        artifacts => [
          {
            type   => 'nostr.event',
            format => 'nostr.event',
            value  => {
              id         => ('c' x 64),
              pubkey     => ('d' x 64),
              created_at => 1744301500,
              kind       => 22242,
              tags       => [],
              content    => '',
              sig        => ('e' x 128),
            },
          },
        ],
      },
    },
  );

  my $error = eval {
    Overnet::Program::IRC::Auth::Helper->run(
      client                  => $client,
      command                 => 'auth',
      challenge               => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
      scope                   => 'irc://irc.example.test/overnet',
      service_identity_scheme => 'nostr.pubkey',
      interactive             => 1,
    );
    1;
  } ? undef : $@;

  like $error,
    qr/--service-identity-scheme\ and\ --service-identity-value\ are\ required\ together/mx,
    'partial service identity descriptors are rejected';
  is scalar @{$client->calls}, 0, 'the auth agent is not called on invalid service identity input';
};

subtest 'run rejects unsupported commands and missing arguments' => sub {
  my $client = t::irc_auth_helper::FakeClient->new(response => _ok_response(),);

  like dies { Overnet::Program::IRC::Auth::Helper->run(command => 'frobnicate') },
    qr/unsupported\ command:\ frobnicate/mx, 'an unsupported command croaks';
  like dies { Overnet::Program::IRC::Auth::Helper->run() },
    qr/unsupported\ command:/mx, 'a missing command croaks';

  like dies {
    Overnet::Program::IRC::Auth::Helper->run(client => $client, command => 'auth', challenge => q{}, scope => 's',);
  }, qr/--challenge\ is\ required/mx, 'auth without a challenge croaks';
  like dies {
    Overnet::Program::IRC::Auth::Helper->run(client => $client, command => 'auth', challenge => 'c', scope => q{},);
  }, qr/--scope\ is\ required/mx, 'auth without a scope croaks';

  my %delegate = (
    client          => $client,
    command         => 'delegate',
    relay_url       => 'ws://relay.example.test:1',
    scope           => 'irc://irc.example.test/overnet',
    delegate_pubkey => ('f' x 64),
    session_id      => 'session-1',
    expires_at      => '1744304600',
  );
  for my $field (qw(relay_url scope delegate_pubkey session_id expires_at)) {
    my %missing = (%delegate, $field => q{},);
    (my $flag = $field) =~ tr/_/-/;
    like dies { Overnet::Program::IRC::Auth::Helper->run(%missing) }, qr/--$flag\ is\ required/mx,
      "delegate without $field croaks";
  }

  my $delegated = Overnet::Program::IRC::Auth::Helper->run(%delegate, nick => q{},);
  like $delegated, qr/\S/mx, 'a delegate request with an unusable nick still succeeds without the nick tag';

  like dies { Overnet::Program::IRC::Auth::Helper->_bridge_line(line => q{},) },
    qr/--line\ is\ required/mx, 'a bridge line command without a line croaks';
  like dies {
    Overnet::Program::IRC::Auth::Helper->run(
      client  => $client,
      command => 'bridge',
      line    => ':server NOTICE alice :nothing to see',
    );
  }, qr/unsupported\ OVERNETAUTH\ bridge\ line/mx, 'an unparseable bridge line croaks';

  like dies { Overnet::Program::IRC::Auth::Helper->consume_sasl_challenge_line(client => $client, line => q{},) },
    qr/line\ is\ required/mx, 'consume_sasl_challenge_line without a line croaks';

  my $mechanism = Overnet::Program::IRC::Auth::Helper->consume_sasl_challenge_line(
    client => $client,
    state  => {},
    line   => 'AUTHENTICATE NOSTR',
  );
  is $mechanism, {handled => 0, lines => [],}, 'the NOSTR mechanism announcement is not a challenge chunk';

  my $empty_marker = Overnet::Program::IRC::Auth::Helper->consume_sasl_challenge_line(
    client => $client,
    state  => {},
    line   => 'AUTHENTICATE +',
  );
  is $empty_marker, {handled => 1, lines => [],}, 'an empty-payload marker flushes an empty buffer quietly';
};

subtest 'auth agent failures are reported with usable messages' => sub {
  my %auth = (
    command   => 'auth',
    challenge => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
    scope     => 'irc://irc.example.test/overnet',
  );

  like dies { Overnet::Program::IRC::Auth::Helper->run(%auth) }, qr/client\ is\ required/mx,
    'a missing auth client croaks';

  my $undef_response = t::irc_auth_helper::FakeClient->new();
  like dies { Overnet::Program::IRC::Auth::Helper->run(%auth, client => $undef_response,) },
    qr/auth\ agent\ request\ failed/mx, 'an undef response reports a generic failure';

  my $no_error = t::irc_auth_helper::FakeClient->new(response => {type => 'response', ok => JSON::false,},);
  like dies { Overnet::Program::IRC::Auth::Helper->run(%auth, client => $no_error,) },
    qr/auth\ agent\ request\ failed/mx, 'a failure without an error object reports a generic failure';

  my $bare_error =
    t::irc_auth_helper::FakeClient->new(response => {type => 'response', ok => JSON::false, error => {},},);
  like dies { Overnet::Program::IRC::Auth::Helper->run(%auth, client => $bare_error,) },
    qr/unknown_error:\ unknown\ auth-agent\ failure/mx, 'an empty error object gets default code and message';

  my $named_error = t::irc_auth_helper::FakeClient->new(
    response => {
      type  => 'response',
      ok    => JSON::false,
      error => {
        code    => 'auth.denied',
        message => 'the user said no',
      },
    },
  );
  like dies { Overnet::Program::IRC::Auth::Helper->run(%auth, client => $named_error,) },
    qr/auth[.]denied:\ the\ user\ said\ no/mx, 'error code and message are surfaced';

  my $no_artifacts = t::irc_auth_helper::FakeClient->new(
    response => {
      type   => 'response',
      ok     => JSON::true,
      result => {artifacts => [],},
    },
  );
  like dies { Overnet::Program::IRC::Auth::Helper->run(%auth, client => $no_artifacts,) },
    qr/auth\ agent\ did\ not\ return\ any\ artifacts/mx, 'a response without artifacts croaks';

  my $no_result = t::irc_auth_helper::FakeClient->new(response => {type => 'response', ok => JSON::true,},);
  like dies { Overnet::Program::IRC::Auth::Helper->run(%auth, client => $no_result,) },
    qr/auth\ agent\ did\ not\ return\ any\ artifacts/mx, 'a response without a result croaks';
};

subtest 'undecodable SASL buffers are dropped instead of answered' => sub {
  my $client = t::irc_auth_helper::FakeClient->new(response => _ok_response(),);

  my @not_json = Overnet::Program::IRC::Auth::Helper->_flush_sasl_chunk_state(
    client => $client,
    state  => {buffer => encode_base64('not json', q{})},
  );
  is \@not_json, [], 'a buffer that is not JSON is dropped';

  my @not_hash = Overnet::Program::IRC::Auth::Helper->_flush_sasl_chunk_state(
    client => $client,
    state  => {buffer => encode_base64('[1,2]', q{})},
  );
  is \@not_hash, [], 'a JSON array payload is dropped';

  my @no_challenge = Overnet::Program::IRC::Auth::Helper->_flush_sasl_chunk_state(
    client => $client,
    state  => {buffer => encode_base64(JSON::encode_json({scope => 's',}), q{})},
  );
  is \@no_challenge, [], 'a payload without a challenge is dropped';

  my @no_scope = Overnet::Program::IRC::Auth::Helper->_flush_sasl_chunk_state(
    client => $client,
    state  => {buffer => encode_base64(JSON::encode_json({challenge => 'c',}), q{})},
  );
  is \@no_scope, [], 'a payload without a scope is dropped';

  my @ref_challenge = Overnet::Program::IRC::Auth::Helper->_flush_sasl_chunk_state(
    client => $client,
    state  => {buffer => encode_base64(JSON::encode_json({challenge => {}, scope => 's',}), q{})},
  );
  is \@ref_challenge, [], 'a payload with a reference challenge is dropped';

  my @not_hash_payload = Overnet::Program::IRC::Auth::Helper->_render_sasl_response(
    client            => $client,
    challenge_payload => [],
  );
  is \@not_hash_payload, [], 'a non-hash challenge payload renders nothing';

  is Overnet::Program::IRC::Auth::Helper::_sasl_delegate_required([]), 0,
    'a non-hash payload never requires delegation';

  is scalar @{$client->calls}, 0, 'no auth agent calls were made for dropped buffers';
};

subtest 'bridge stream output failures croak at every write site' => sub {
  my $challenge = 'bcf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope     = 'irc://irc.example.test/overnet';
  my $sasl_line = 'AUTHENTICATE ' . encode_base64(
    JSON::encode_json(
      {
        challenge => $challenge,
        scope     => $scope,
      }
    ),
    q{}
  );
  my $padded = _padded_sasl_payload(
    {
      challenge => $challenge,
      scope     => $scope,
    },
    800,
  );
  my @padded_chunks = ($padded =~ /(.{1,400})/gmxs);

  my %streams = (
    'an OVERNETAUTH line write failure' => "-server- OVERNETAUTH CHALLENGE $challenge\r\n",
    'a SASL response write failure'     => "$sasl_line\r\n",
    'a mid-stream flush write failure'  =>
      join(q{}, (map {"AUTHENTICATE $_\r\n"} @padded_chunks), ":server NOTICE alice :interrupt\r\n"),
    'an EOF flush write failure' => join(q{}, map {"AUTHENTICATE $_\r\n"} @padded_chunks),
  );

  for my $case (sort keys %streams) {
    my $input_text = $streams{$case};
    open my $in,  '<', \$input_text or die "open input failed: $!";
    open my $out, '>', '/dev/full'  or die "open /dev/full failed: $!";
    $out->autoflush(1);

    my $client = t::irc_auth_helper::FakeClient->new(response => _ok_response(),);
    my $error  = eval {
      Overnet::Program::IRC::Auth::Helper->run(
        client  => $client,
        command => 'bridge',
        line    => q{},
        scope   => $scope,
        input   => $in,
        output  => $out,
        quote   => 0,
      );
      1;
    } ? undef : $@;
    like $error, qr/write\ bridge\ output\ failed/mx, "$case croaks";
    {
      no warnings 'io';
      close $out;
    }
  }
};

subtest 'service identity descriptor branch corners' => sub {
  my $client = t::irc_auth_helper::FakeClient->new(response => _ok_response(),);
  my %auth   = (
    command   => 'auth',
    challenge => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
    scope     => 'irc://irc.example.test/overnet',
  );

  like dies {
    Overnet::Program::IRC::Auth::Helper->run(
      %auth,
      client                   => $client,
      service_identity_display => 'Display Only',
    );
  }, qr/--service-identity-scheme\ and\ --service-identity-value\ are\ required\ together/mx,
    'a display without scheme and value croaks';

  like dies {
    Overnet::Program::IRC::Auth::Helper->run(
      %auth,
      client                  => $client,
      service_identity_scheme => q{},
      service_identity_value  => 'value-1',
    );
  }, qr/--service-identity-scheme\ and\ --service-identity-value\ are\ required\ together/mx,
    'an empty scheme croaks even with a value';

  my $output = Overnet::Program::IRC::Auth::Helper->run(
    %auth,
    client                   => $client,
    service_identity_scheme  => 'nostr.pubkey',
    service_identity_value   => ('a' x 64),
    service_identity_display => q{},
  );
  like $output, qr/\S/mx, 'an empty display is dropped from the descriptor';
  is $client->calls->[-1]{params}{service}{service_identity},
    {
    scheme => 'nostr.pubkey',
    value  => ('a' x 64),
    },
    'the descriptor carries scheme and value without a display';
};

subtest 'malformed relay-backed SASL payloads croak after auth' => sub {
  my $client = t::irc_auth_helper::FakeClient->new(response => _ok_response(),);
  my $error  = eval {
    Overnet::Program::IRC::Auth::Helper->consume_sasl_challenge_line(
      client => $client,
      state  => {},
      line   => 'AUTHENTICATE '
        . encode_base64(
        JSON::encode_json(
          {
            challenge => ('9' x 64),
            scope     => 'irc://irc.example.test/overnet',
            relay_url => q{},
          }
        ),
        q{}
        ),
    );
    1;
  } ? undef : $@;

  like $error, qr/malformed\ SASL\ NOSTR\ challenge\ payload/mx,
    'a relay-backed payload with an empty field croaks';
  is scalar @{$client->calls}, 1, 'the auth artifact was requested before the malformed delegation was found';
};

subtest 'bridge streams flush pending SASL buffers mid-stream and at EOF' => sub {
  my $challenge = 'acf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';
  my $scope     = 'irc://irc.example.test/overnet';
  my $payload   = _padded_sasl_payload(
    {
      challenge => $challenge,
      scope     => $scope,
    },
    800,
  );

  my @chunks = ($payload =~ /(.{1,400})/gmxs);
  is [map { length } @chunks], [400, 400], 'the padded payload splits into two full chunks';

  my $input_text = join q{}, (map {"AUTHENTICATE $_\r\n"} @chunks), ":server NOTICE alice :interrupting line\r\n";
  my $output     = '';
  open my $in,  '<', \$input_text or die "open input failed: $!";
  open my $out, '>', \$output     or die "open output failed: $!";

  my $client = t::irc_auth_helper::FakeClient->new(response => _ok_response(),);
  my $count  = Overnet::Program::IRC::Auth::Helper->run(
    client  => $client,
    command => 'bridge',
    input   => $in,
    output  => $out,
    quote   => 0,
  );
  close $out or die "close output failed: $!";
  ok $count > 0, 'the interrupted stream still produced SASL responses';
  like $output, qr/\AAUTHENTICATE\ \S+/mx, 'the mid-stream flush answered the challenge';
  is scalar @{$client->calls}, 1, 'the auth agent was called once for the mid-stream flush';

  my $eof_text   = join q{}, map {"AUTHENTICATE $_\r\n"} @chunks;
  my $eof_output = '';
  open my $eof_in,  '<', \$eof_text   or die "open input failed: $!";
  open my $eof_out, '>', \$eof_output or die "open output failed: $!";

  my $eof_client = t::irc_auth_helper::FakeClient->new(response => _ok_response(),);
  my $eof_count  = Overnet::Program::IRC::Auth::Helper->run(
    client  => $eof_client,
    command => 'bridge',
    input   => $eof_in,
    output  => $eof_out,
    quote   => 0,
  );
  close $eof_out or die "close output failed: $!";
  ok $eof_count > 0, 'a stream ending in a full chunk flushes at EOF';
  like $eof_output, qr/\AAUTHENTICATE\ \S+/mx, 'the EOF flush answered the challenge';
};

sub _ok_response {
  return {
    type   => 'response',
    id     => 'auth-1',
    ok     => JSON::true,
    result => {
      artifacts => [
        {
          type   => 'nostr.event',
          format => 'nostr.event',
          value  => {
            id         => ('1' x 64),
            pubkey     => ('2' x 64),
            created_at => 1744301000,
            kind       => 22242,
            tags       => [],
            content    => '',
            sig        => ('3' x 128),
          },
        },
      ],
    },
  };
}

sub _padded_sasl_payload {
  my ($payload, $wanted_length) = @_;
  for my $pad_length (0 .. $wanted_length) {
    my %padded  = (%{$payload}, pad => ('x' x $pad_length),);
    my $encoded = encode_base64(JSON::encode_json(\%padded), q{});
    return $encoded if length($encoded) == $wanted_length;
  }
  die "Can't pad a SASL payload to $wanted_length base64 bytes";
}

sub _authenticate_input_lines {
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
  my ($output) = @_;
  my $payload  = join '', map {
    my $line = $_;
    $line =~ s/\A\/quote\s+//mx;
    $line =~ s/\AAUTHENTICATE\s+//mx;
    $line eq '+' ? () : $line;
    }
    grep {length}
    split /\n/mx, $output;

  return JSON::decode_json(decode_base64($payload));
}

done_testing;
