use strictures 2;

use File::Spec;
use FindBin;
use JSON         ();
use MIME::Base64 qw(encode_base64);
use Test2::V0;

use lib grep { -d $_ } (
  File::Spec->catdir($FindBin::Bin, 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'lib'),
);

use Overnet::Authority::Delegation;
use Overnet::Core::Nostr;
use Overnet::Program::IRC::Command::Auth;
use TestIRCServer;

my $package = 'Overnet::Program::IRC::Command::Auth';
my $scope   = 'irc://irc.example.test/overnet';

sub _server {
  my (%overrides) = @_;
  my $server = TestIRCServer->new;
  $server->configure(%overrides);
  return $server;
}

sub _encoded_event {
  my ($event) = @_;
  return encode_base64(JSON::encode_json($event), q{});
}

sub _last_notice {
  my ($server, $client_id) = @_;
  my ($line) = reverse @{$server->lines_for($client_id)};
  return $line;
}

sub _feed_sasl_payload {
  my ($server, $client_id, $payload) = @_;
  my $encoded = encode_base64(JSON::encode_json($payload), q{});
  my @chunks;
  while (length($encoded) > 400) {
    push @chunks, substr($encoded, 0, 400, q{});
  }
  push @chunks, length($encoded) ? $encoded : q{+};
  for my $chunk (@chunks) {
    Overnet::Program::IRC::Command::Auth::handle_authenticate($server, $client_id, [$chunk]);
  }
  if (length($chunks[-1]) == 400) {
    Overnet::Program::IRC::Command::Auth::handle_authenticate($server, $client_id, ['+']);
  }
  return 1;
}

subtest 'handle_cap negotiates capabilities' => sub {
  my $server = _server();
  my $client = $server->add_client(1);

  is Overnet::Program::IRC::Command::Auth::handle_cap($server, 99, ['LS']), 0, 'an unknown client is rejected';

  is Overnet::Program::IRC::Command::Auth::handle_cap($server, 1, ['LS', '302']), 1, 'CAP LS is handled';
  is $client->{cap_negotiation_active}, 1, 'CAP LS starts negotiation for unregistered clients';
  like _last_notice($server, 1), qr/CAP\ [*]\ LS\ :.*\bsasl\b/mxs, 'the LS reply advertises sasl under nip29';

  is Overnet::Program::IRC::Command::Auth::handle_cap($server, 1, ['REQ']), 1, 'CAP REQ without params is handled';
  like _last_notice($server, 1), qr/461 .* CAP/mxs, 'CAP REQ without capabilities asks for more parameters';

  is Overnet::Program::IRC::Command::Auth::handle_cap($server, 1, ['REQ', 'sasl server-time']), 1,
    'CAP REQ is handled';
  like _last_notice($server, 1), qr/CAP\ [*]\ ACK\ :sasl\ server-time/mxs, 'supported capabilities are ACKed';
  is $client->{capabilities}{sasl},           1, 'the sasl capability is recorded';
  is $client->{capabilities}{'message-tags'}, 1, 'server-time implies message-tags';

  is Overnet::Program::IRC::Command::Auth::handle_cap($server, 1, ['REQ', 'frobnicate']), 1,
    'an unsupported CAP REQ is handled';
  like _last_notice($server, 1), qr/CAP\ [*]\ NAK\ :frobnicate/mxs, 'unsupported capabilities are NAKed';

  is Overnet::Program::IRC::Command::Auth::handle_cap($server, 1, ['FROB']), 1, 'an unknown subcommand is handled';
  like _last_notice($server, 1), qr/421 .* CAP/mxs, 'unknown CAP subcommands report unknown command';

  is Overnet::Program::IRC::Command::Auth::handle_cap($server, 1, ['END']), 1, 'CAP END is handled';
  is $client->{cap_negotiation_active}, 0, 'CAP END finishes negotiation';

  my $registered = $server->add_client(
    2,
    registered => 1,
    nick       => 'bob',
    username   => 'bob',
  );
  is Overnet::Program::IRC::Command::Auth::handle_cap($server, 2, ['LS']), 1, 'CAP LS after registration is handled';
  ok !$registered->{cap_negotiation_active}, 'CAP LS after registration does not restart negotiation';
  is Overnet::Program::IRC::Command::Auth::handle_cap($server, 2, ['REQ', 'account-tag']), 1,
    'CAP REQ after registration is handled';
  ok !$registered->{cap_negotiation_active}, 'CAP REQ after registration does not restart negotiation';
  is $registered->{capabilities}{'message-tags'}, 1, 'account-tag implies message-tags';
};

subtest 'handle_authenticate rejects unusable SASL attempts' => sub {
  my $server = _server();
  my $client = $server->add_client(1, nick => 'alice', username => 'alice',);

  is Overnet::Program::IRC::Command::Auth::handle_authenticate($server, 99, ['NOSTR']), 0,
    'an unknown client is rejected';

  is Overnet::Program::IRC::Command::Auth::handle_authenticate($server, 1, []), 1,
    'AUTHENTICATE without params is handled';
  like _last_notice($server, 1), qr/461 .* AUTHENTICATE/mxs, 'a missing argument asks for more parameters';

  is Overnet::Program::IRC::Command::Auth::handle_authenticate($server, 1, ['NOSTR']), 1,
    'AUTHENTICATE without the sasl capability is handled';
  like _last_notice($server, 1), qr/904/mxs, 'a client without the sasl capability fails';

  $client->{capabilities}{sasl} = 1;
  is Overnet::Program::IRC::Command::Auth::handle_authenticate($server, 1, ['PLAIN']), 1,
    'an unsupported mechanism is handled';
  like _last_notice($server, 1), qr/904/mxs, 'non-NOSTR mechanisms fail';

  my $plain_server = _server(adapter_config => {authority_profile => q{}, network => 'overnet',},);
  my $plain_client = $plain_server->add_client(1, capabilities => {sasl => 1,},);
  is Overnet::Program::IRC::Command::Auth::handle_authenticate($plain_server, 1, ['NOSTR']), 1,
    'NOSTR without nip29 is handled';
  like _last_notice($plain_server, 1), qr/904/mxs, 'NOSTR without an nip29 authority profile fails';

  my $failed_exchange = mock $package => (override => [start_sasl_nostr_exchange => sub { return },],);
  is Overnet::Program::IRC::Command::Auth::handle_authenticate($server, 1, ['NOSTR']), 1,
    'a failed exchange start is handled';
  like _last_notice($server, 1), qr/904/mxs, 'a failed exchange start fails the authentication';
};

subtest 'a SASL NOSTR exchange succeeds without relay delegation' => sub {
  my $server = _server(authority_relay => undef,);
  my $client = $server->add_client(
    1,
    nick         => 'alice',
    username     => 'alice',
    capabilities => {sasl => 1,},
  );

  is Overnet::Program::IRC::Command::Auth::handle_authenticate($server, 1, ['NOSTR']), 1,
    'the NOSTR mechanism starts an exchange';
  is $client->{sasl_mechanism}, 'NOSTR', 'the mechanism is recorded';
  my $payload = $client->{sasl_challenge_payload};
  is ref($payload), 'HASH', 'a challenge payload was stored';
  is $payload->{scope}, $scope, 'the challenge payload names the scope';
  ok !exists $payload->{relay_url}, 'no relay fields are offered without authority_relay';
  like $server->lines_for(1)->[-1], qr/\AAUTHENTICATE\ \S+\z/mxs, 'the challenge is sent as AUTHENTICATE lines';

  my $key        = Overnet::Core::Nostr->generate_key;
  my $auth_event = Overnet::Authority::Delegation->create_auth_event(
    key       => $key,
    challenge => $payload->{challenge},
    scope     => $scope,
  );
  $server->clear_sent_lines;
  _feed_sasl_payload($server, 1, {auth_event => $auth_event,});

  like join("\n", @{$server->lines_for(1)}), qr/903 .* :SASL\ authentication\ successful/mxs,
    'the exchange succeeds';
  is $client->{authority_pubkey}, $key->pubkey_hex, 'the authenticated pubkey is bound to the client';
  is $client->{registered},       1,                'the client registers once SASL completes';
  ok !defined $client->{sasl_mechanism}, 'the SASL state is reset';
};

subtest 'SASL NOSTR aborts and failures reset the exchange' => sub {
  my $server = _server(authority_relay => undef,);
  my $client = $server->add_client(1, capabilities => {sasl => 1,},);

  Overnet::Program::IRC::Command::Auth::handle_authenticate($server, 1, ['NOSTR']);
  is Overnet::Program::IRC::Command::Auth::handle_authenticate($server, 1, ['*']), 1, 'an abort is handled';
  like _last_notice($server, 1), qr/904/mxs, 'an abort fails the exchange';
  ok !defined $client->{sasl_mechanism}, 'an abort resets the mechanism';

  Overnet::Program::IRC::Command::Auth::handle_authenticate($server, 1, ['NOSTR']);
  is Overnet::Program::IRC::Command::Auth::handle_authenticate($server, 1, ['+']), 1,
    'an empty response is handled';
  like _last_notice($server, 1), qr/904/mxs, 'an empty response fails the exchange';

  Overnet::Program::IRC::Command::Auth::handle_authenticate($server, 1, ['NOSTR']);
  my $garbage = encode_base64('[]', q{});
  is Overnet::Program::IRC::Command::Auth::handle_authenticate($server, 1, [$garbage]), 1,
    'a non-hash payload is handled';
  like _last_notice($server, 1), qr/904/mxs, 'a non-hash payload fails the exchange';

  Overnet::Program::IRC::Command::Auth::handle_authenticate($server, 1, ['NOSTR']);
  my $key       = Overnet::Core::Nostr->generate_key;
  my $bad_event = Overnet::Authority::Delegation->create_auth_event(
    key       => $key,
    challenge => '0' x 64,
    scope     => $scope,
  );
  $server->clear_sent_lines;
  _feed_sasl_payload($server, 1, {auth_event => $bad_event,});
  like join("\n", @{$server->lines_for(1)}), qr/904/mxs, 'a wrong-challenge auth event fails the exchange';

  is Overnet::Program::IRC::Command::Auth::complete_sasl_exchange($server, 99), 0,
    'completing an unknown client fails quietly';
};

subtest 'a relay-backed SASL NOSTR exchange delegates and publishes' => sub {
  my $server = _server();
  my $client = $server->add_client(
    1,
    nick         => 'alice',
    username     => 'alice',
    capabilities => {sasl => 1,},
  );

  Overnet::Program::IRC::Command::Auth::handle_authenticate($server, 1, ['NOSTR']);
  my $payload = $client->{sasl_challenge_payload};
  is $payload->{relay_url},  'ws://127.0.0.1:7448', 'the challenge offers the relay URL';
  is $payload->{grant_kind}, 14_142,                'the challenge offers the grant kind';
  like $payload->{delegate_pubkey}, qr/\A[0-9a-f]{64}\z/mxs, 'the challenge offers a delegate pubkey';

  my $key        = Overnet::Core::Nostr->generate_key;
  my $auth_event = Overnet::Authority::Delegation->create_auth_event(
    key       => $key,
    challenge => $payload->{challenge},
    scope     => $scope,
  );
  my $delegate_event = Overnet::Authority::Delegation->create_delegation_grant_event(
    key             => $key,
    relay_url       => $payload->{relay_url},
    scope           => $scope,
    delegate_pubkey => $payload->{delegate_pubkey},
    session_id      => $payload->{session_id},
    expires_at      => $payload->{expires_at},
    kind            => $payload->{grant_kind},
  );

  $server->clear_sent_lines;
  _feed_sasl_payload(
    $server, 1,
    {
      auth_event     => $auth_event,
      delegate_event => $delegate_event,
    }
  );
  like join("\n", @{$server->lines_for(1)}), qr/903/mxs, 'the relay-backed exchange succeeds';
  my ($publish) = grep { $_->{method} eq 'nostr.publish_event' } @{$server->requests};
  ok $publish, 'the delegation grant was published to the relay';
  is $publish->{params}{relay_url}, 'ws://127.0.0.1:7448', 'the grant went to the configured relay';
};

subtest 'a relay-backed SASL NOSTR exchange fails without a delegate event' => sub {
  my $server = _server();
  my $client = $server->add_client(1, capabilities => {sasl => 1,},);

  Overnet::Program::IRC::Command::Auth::handle_authenticate($server, 1, ['NOSTR']);
  my $payload = $client->{sasl_challenge_payload};

  my $key        = Overnet::Core::Nostr->generate_key;
  my $auth_event = Overnet::Authority::Delegation->create_auth_event(
    key       => $key,
    challenge => $payload->{challenge},
    scope     => $scope,
  );
  $server->clear_sent_lines;
  _feed_sasl_payload($server, 1, {auth_event => $auth_event,});
  like join("\n", @{$server->lines_for(1)}), qr/904/mxs, 'a missing delegate event fails the exchange';
  ok !defined $client->{authority_pubkey}, 'the authoritative binding is cleared';

  Overnet::Program::IRC::Command::Auth::handle_authenticate($server, 1, ['NOSTR']);
  my $retry_payload = $client->{sasl_challenge_payload};
  my $retry_auth    = Overnet::Authority::Delegation->create_auth_event(
    key       => $key,
    challenge => $retry_payload->{challenge},
    scope     => $scope,
  );
  my $wrong_delegate = Overnet::Authority::Delegation->create_delegation_grant_event(
    key             => $key,
    relay_url       => $retry_payload->{relay_url},
    scope           => $scope,
    delegate_pubkey => $retry_payload->{delegate_pubkey},
    session_id      => 'wrong-session',
    expires_at      => $retry_payload->{expires_at},
    kind            => $retry_payload->{grant_kind},
  );
  $server->clear_sent_lines;
  _feed_sasl_payload(
    $server, 1,
    {
      auth_event     => $retry_auth,
      delegate_event => $wrong_delegate,
    }
  );
  like join("\n", @{$server->lines_for(1)}), qr/904/mxs, 'a mismatched delegation grant fails the exchange';
};

subtest 'handle_overnetauth CHALLENGE and AUTH bind an account' => sub {
  my $server = _server(authority_relay => undef,);
  my $client = $server->add_client(1, nick => 'alice',);

  is Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, 99, ['CHALLENGE']), 0,
    'an unknown client is rejected';
  is Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, 1, []), 1,
    'OVERNETAUTH without params is handled';
  like _last_notice($server, 1), qr/461 .* OVERNETAUTH/mxs, 'a missing subcommand asks for more parameters';
  is Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, 1, ['FROB']), 1,
    'an unknown subcommand is handled';
  like _last_notice($server, 1), qr/421 .* OVERNETAUTH/mxs, 'an unknown subcommand reports unknown command';

  is Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, 1, ['CHALLENGE']), 1,
    'CHALLENGE is handled';
  my ($challenge) = _last_notice($server, 1) =~ /OVERNETAUTH\ CHALLENGE\ ([0-9a-f]{64})/mxs;
  ok $challenge, 'a challenge is issued in a server notice';
  is $client->{authority_challenge}, $challenge, 'the challenge is stored on the client';

  is Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, 1, ['AUTH']), 1,
    'AUTH without an event is handled';
  like _last_notice($server, 1), qr/461 .* OVERNETAUTH/mxs, 'AUTH without an event asks for more parameters';

  is Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, 1, ['AUTH', '%%%not-base64%%%']), 1,
    'AUTH with undecodable input is handled';
  like _last_notice($server, 1), qr/requires\ a\ base64-encoded\ event\ object/mxs,
    'undecodable AUTH input is reported';

  my $key         = Overnet::Core::Nostr->generate_key;
  my $wrong_kind  = $key->create_event_hash(
    kind       => 1,
    created_at => int(time()),
    content    => q{},
    tags       => [['relay', $scope], ['challenge', $challenge],],
  );
  is Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, 1, ['AUTH', _encoded_event($wrong_kind)]), 1,
    'AUTH with the wrong kind is handled';
  like _last_notice($server, 1), qr/requires\ kind\ 22242/mxs, 'the wrong kind is reported';

  my $wrong_challenge = Overnet::Authority::Delegation->create_auth_event(
    key       => $key,
    challenge => '0' x 64,
    scope     => $scope,
  );
  is Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, 1, ['AUTH', _encoded_event($wrong_challenge)]),
    1, 'AUTH with the wrong challenge is handled';
  like _last_notice($server, 1), qr/challenge\ does\ not\ match/mxs, 'the challenge mismatch is reported';

  my $wrong_scope = Overnet::Authority::Delegation->create_auth_event(
    key       => $key,
    challenge => $challenge,
    scope     => 'irc://other.example.test/overnet',
  );
  is Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, 1, ['AUTH', _encoded_event($wrong_scope)]), 1,
    'AUTH with the wrong scope is handled';
  like _last_notice($server, 1), qr/relay\ scope\ does\ not\ match/mxs, 'the scope mismatch is reported';

  my $valid = Overnet::Authority::Delegation->create_auth_event(
    key       => $key,
    challenge => $challenge,
    scope     => $scope,
  );
  is Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, 1, ['AUTH', _encoded_event($valid)]), 1,
    'a valid AUTH is handled';
  like _last_notice($server, 1), qr/OVERNETAUTH\ AUTH\ @{[$key->pubkey_hex]}/mxs,
    'the bound pubkey is confirmed in a notice';
  is $client->{authority_pubkey}, $key->pubkey_hex, 'the account is bound to the client';
  ok !exists $client->{authority_challenge}, 'the challenge is consumed';
};

subtest 'handle_overnetauth DELEGATE offers and accepts grants' => sub {
  my $no_relay = _server(authority_relay => undef,);
  $no_relay->add_client(1, nick => 'alice',);
  is Overnet::Program::IRC::Command::Auth::handle_overnetauth($no_relay, 1, ['DELEGATE']), 1,
    'DELEGATE without a relay is handled';
  like _last_notice($no_relay, 1), qr/requires\ authority_relay/mxs, 'DELEGATE requires the relay';

  my $server = _server();
  my $client = $server->add_client(1, nick => 'alice',);

  is Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, 1, ['DELEGATE']), 1,
    'DELEGATE before AUTH is handled';
  like _last_notice($server, 1), qr/requires\ a\ prior\ AUTH/mxs, 'DELEGATE requires a prior AUTH';

  my $key = Overnet::Core::Nostr->generate_key;
  Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, 1, ['CHALLENGE']);
  my ($challenge) = _last_notice($server, 1) =~ /OVERNETAUTH\ CHALLENGE\ ([0-9a-f]{64})/mxs;
  my $auth_event = Overnet::Authority::Delegation->create_auth_event(
    key       => $key,
    challenge => $challenge,
    scope     => $scope,
  );
  Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, 1, ['AUTH', _encoded_event($auth_event)]);

  my $grant_event = Overnet::Authority::Delegation->create_delegation_grant_event(
    key             => $key,
    relay_url       => 'ws://127.0.0.1:7448',
    scope           => $scope,
    delegate_pubkey => 'a' x 64,
    session_id      => 'session-1',
    expires_at      => int(time()) + 3600,
    kind            => 14_142,
  );
  is Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, 1, ['DELEGATE', _encoded_event($grant_event)]),
    1, 'DELEGATE before an offer is handled';
  like _last_notice($server, 1), qr/requires\ a\ prior\ parameter\ request/mxs,
    'DELEGATE requires the offer first';

  is Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, 1, ['DELEGATE']), 1,
    'a DELEGATE offer request is handled';
  my ($delegate_pubkey, $session_id, $relay_url, $expires_at) =
    _last_notice($server, 1) =~ /OVERNETAUTH\ DELEGATE\ ([0-9a-f]{64})\ (\S+)\ (\S+)\ (\d+)/mxs;
  ok $delegate_pubkey, 'the offer includes a delegate pubkey';
  is $relay_url, 'ws://127.0.0.1:7448', 'the offer includes the relay URL';

  is Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, 1, ['DELEGATE', '%%%not-base64%%%']), 1,
    'DELEGATE with undecodable input is handled';
  like _last_notice($server, 1), qr/requires\ a\ base64-encoded\ event\ object/mxs,
    'undecodable DELEGATE input is reported';

  my $wrong_session = Overnet::Authority::Delegation->create_delegation_grant_event(
    key             => $key,
    relay_url       => $relay_url,
    scope           => $scope,
    delegate_pubkey => $delegate_pubkey,
    session_id      => 'not-the-offer',
    expires_at      => $expires_at,
    kind            => 14_142,
  );
  is Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, 1,
    ['DELEGATE', _encoded_event($wrong_session)]), 1, 'DELEGATE with a session mismatch is handled';
  like _last_notice($server, 1), qr/session\ does\ not\ match/mxs, 'the session mismatch is reported';

  my $valid_grant = Overnet::Authority::Delegation->create_delegation_grant_event(
    key             => $key,
    relay_url       => $relay_url,
    scope           => $scope,
    delegate_pubkey => $delegate_pubkey,
    session_id      => $session_id,
    expires_at      => $expires_at,
    kind            => 14_142,
  );
  is Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, 1, ['DELEGATE', _encoded_event($valid_grant)]),
    1, 'a valid DELEGATE is handled';
  is _last_notice($server, 1), ':irc.example.test NOTICE alice :OVERNETAUTH DELEGATE',
    'a valid DELEGATE is confirmed';
  my ($publish) = grep { $_->{method} eq 'nostr.publish_event' } @{$server->requests};
  ok $publish, 'the delegation grant was published';

  my $rejecting = _server();
  $rejecting->request_handler(
    sub {
      my (%args) = @_;
      return {accepted => 0,} if $args{method} eq 'nostr.publish_event';
      return;
    }
  );
  my $rejected_client = $rejecting->add_client(1, nick => 'alice',);
  Overnet::Program::IRC::Command::Auth::handle_overnetauth($rejecting, 1, ['CHALLENGE']);
  my ($rejected_challenge) = _last_notice($rejecting, 1) =~ /OVERNETAUTH\ CHALLENGE\ ([0-9a-f]{64})/mxs;
  my $rejected_auth = Overnet::Authority::Delegation->create_auth_event(
    key       => $key,
    challenge => $rejected_challenge,
    scope     => $scope,
  );
  Overnet::Program::IRC::Command::Auth::handle_overnetauth($rejecting, 1, ['AUTH', _encoded_event($rejected_auth)]);
  Overnet::Program::IRC::Command::Auth::handle_overnetauth($rejecting, 1, ['DELEGATE']);
  my ($r_pubkey, $r_session, $r_relay, $r_expires) =
    _last_notice($rejecting, 1) =~ /OVERNETAUTH\ DELEGATE\ ([0-9a-f]{64})\ (\S+)\ (\S+)\ (\d+)/mxs;
  my $rejected_grant = Overnet::Authority::Delegation->create_delegation_grant_event(
    key             => $key,
    relay_url       => $r_relay,
    scope           => $scope,
    delegate_pubkey => $r_pubkey,
    session_id      => $r_session,
    expires_at      => $r_expires,
    kind            => 14_142,
  );
  is Overnet::Program::IRC::Command::Auth::handle_overnetauth($rejecting, 1,
    ['DELEGATE', _encoded_event($rejected_grant)]), 1, 'a rejected publish is handled';
  like _last_notice($rejecting, 1), qr/relay\ publish\ failed/mxs, 'a rejected publish is reported';
};

subtest 'failure notices map validation reasons to stable texts' => sub {
  is Overnet::Program::IRC::Command::Auth::_auth_failure_notice('auth event requires kind 22242'),
    'OVERNETAUTH AUTH requires kind 22242', 'kind failures map to the kind notice';
  is Overnet::Program::IRC::Command::Auth::_auth_failure_notice('auth event challenge does not match'),
    'OVERNETAUTH AUTH challenge does not match', 'challenge failures map to the challenge notice';
  is Overnet::Program::IRC::Command::Auth::_auth_failure_notice('auth event relay scope does not match'),
    'OVERNETAUTH AUTH relay scope does not match', 'scope failures map to the scope notice';
  is Overnet::Program::IRC::Command::Auth::_auth_failure_notice(undef),
    'OVERNETAUTH AUTH requires a valid signed Nostr event', 'unknown reasons map to the generic notice';

  my %delegate_notices = (
    'delegation event uses the wrong event kind'                => 'uses the wrong event kind',
    'delegation event pubkey does not match authenticated user' => 'pubkey does not match the authenticated user',
    'delegation relay does not match'                           => 'relay does not match',
    'delegation server scope does not match'                    => 'server scope does not match',
    'delegation delegate pubkey does not match'                 => 'delegate pubkey does not match',
    'delegation session does not match'                         => 'session does not match',
    'delegation expiration does not match'                      => 'expiration does not match',
    'delegation relay publish failed'                           => 'relay publish failed',
  );
  for my $reason (sort keys %delegate_notices) {
    like Overnet::Program::IRC::Command::Auth::_delegate_failure_notice($reason),
      qr/\AOVERNETAUTH\ DELEGATE\ .*\Q$delegate_notices{$reason}\E\z/mxs, "'$reason' maps to its notice";
  }
  is Overnet::Program::IRC::Command::Auth::_delegate_failure_notice(undef),
    'OVERNETAUTH DELEGATE requires a valid signed Nostr event', 'unknown delegate reasons map to the generic notice';
};

subtest 'small helpers validate their inputs' => sub {
  is Overnet::Program::IRC::Command::Auth::_has_param('not-an-array', 0), 0, 'a non-array fails';
  is Overnet::Program::IRC::Command::Auth::_has_param([],      0), 0, 'a short array fails';
  is Overnet::Program::IRC::Command::Auth::_has_param([undef], 0), 0, 'an undef entry fails';
  is Overnet::Program::IRC::Command::Auth::_has_param([[]],    0), 0, 'a reference entry fails';
  is Overnet::Program::IRC::Command::Auth::_has_param([q{}],   0), 0, 'an empty entry fails';
  is Overnet::Program::IRC::Command::Auth::_has_param(['x'],   0), 1, 'a usable entry passes';

  is Overnet::Program::IRC::Command::Auth::_client_has_authority_pubkey('nope'), 0, 'a non-hash client fails';
  is Overnet::Program::IRC::Command::Auth::_client_has_authority_pubkey({}), 0, 'a missing pubkey fails';
  is Overnet::Program::IRC::Command::Auth::_client_has_authority_pubkey({authority_pubkey => {},}), 0,
    'a reference pubkey fails';
  is Overnet::Program::IRC::Command::Auth::_client_has_authority_pubkey({authority_pubkey => q{},}), 0,
    'an empty pubkey fails';
  is Overnet::Program::IRC::Command::Auth::_client_has_authority_pubkey({authority_pubkey => 'a' x 64,}), 1,
    'a usable pubkey passes';

  my $key = Overnet::Core::Nostr->generate_key;
  is Overnet::Program::IRC::Command::Auth::_delegate_offer_state({}), undef, 'a missing key yields no offer state';
  is Overnet::Program::IRC::Command::Auth::_delegate_offer_state({authority_delegate_key => $key,}), undef,
    'a missing session yields no offer state';
  is Overnet::Program::IRC::Command::Auth::_delegate_offer_state(
    {
      authority_delegate_key        => $key,
      authority_delegate_session_id => {},
    }
    ),
    undef, 'a reference session yields no offer state';
  is Overnet::Program::IRC::Command::Auth::_delegate_offer_state(
    {
      authority_delegate_key        => $key,
      authority_delegate_session_id => q{},
    }
    ),
    undef, 'an empty session yields no offer state';
  is Overnet::Program::IRC::Command::Auth::_delegate_offer_state(
    {
      authority_delegate_key        => $key,
      authority_delegate_session_id => 'session-1',
    }
    ),
    undef, 'a missing expiry yields no offer state';
  is Overnet::Program::IRC::Command::Auth::_delegate_offer_state(
    {
      authority_delegate_key        => $key,
      authority_delegate_session_id => 'session-1',
      authority_delegate_expires_at => 123,
    }
    ),
    {
    key        => $key,
    session_id => 'session-1',
    expires_at => 123,
    },
    'a complete offer state is returned';

  is Overnet::Program::IRC::Command::Auth::reset_sasl_state(undef, 'not-a-hash'), 0,
    'resetting a non-hash client fails quietly';
  is Overnet::Program::IRC::Command::Auth::start_sasl_nostr_exchange(undef, 'not-a-hash'), undef,
    'starting an exchange for a non-hash client fails quietly';
  is Overnet::Program::IRC::Command::Auth::ensure_authoritative_delegate_offer(undef, 'not-a-hash'), undef,
    'offering delegation for a non-hash client fails quietly';
  is Overnet::Program::IRC::Command::Auth::apply_authoritative_auth_validation(undef, 'not-a-hash', {valid => 1,}), 0,
    'applying validation to a non-hash client fails quietly';
  is Overnet::Program::IRC::Command::Auth::apply_authoritative_auth_validation(undef, {}, {valid => 0,}), 0,
    'applying an invalid validation fails quietly';
  is Overnet::Program::IRC::Command::Auth::clear_authoritative_binding(undef, 'not-a-hash'), 0,
    'clearing a non-hash client fails quietly';
  is Overnet::Program::IRC::Command::Auth::set_authoritative_account(undef, 'not-a-hash'), 0,
    'setting an account on a non-hash client fails quietly';
  is Overnet::Program::IRC::Command::Auth::_clear_authoritative_delegate_state(undef, 'not-a-hash'), 0,
    'clearing delegate state on a non-hash client fails quietly';
};

subtest 'set_authoritative_account tracks changes and notifies watchers' => sub {
  my $client = {id => 7,};
  is Overnet::Program::IRC::Command::Auth::set_authoritative_account(undef, $client), 1,
    'clearing an already-clear account is a no-op';
  is Overnet::Program::IRC::Command::Auth::set_authoritative_account(undef, $client, account => 'a' x 64,), 1,
    'an account can be bound without a server';
  is $client->{authority_pubkey}, 'a' x 64, 'the account is stored';
  is Overnet::Program::IRC::Command::Auth::set_authoritative_account(undef, $client, account => 'a' x 64,), 1,
    'rebinding the same account is a no-op';
  is Overnet::Program::IRC::Command::Auth::set_authoritative_account(undef, $client), 1, 'the account can be cleared';
  ok !exists $client->{authority_pubkey}, 'the account is removed';

  my $server = _server();
  my $alice  = $server->add_client(
    1,
    nick         => 'alice',
    username     => 'alice',
    registered   => 1,
  );
  my $bob = $server->add_client(
    2,
    nick         => 'bob',
    username     => 'bob',
    registered   => 1,
    capabilities => {'account-notify' => 1,},
  );
  my $carol = $server->add_client(
    3,
    nick       => 'carol',
    username   => 'carol',
    registered => 1,
  );
  my $dave = $server->add_client(
    4,
    nick         => 'dave',
    username     => 'dave',
    registered   => 0,
    capabilities => {'account-notify' => 1,},
  );
  $server->_add_client_to_channel($_, '#overnet') for 1 .. 4;

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Auth::set_authoritative_account($server, $alice, account => 'b' x 64,), 1,
    'binding an account with watchers succeeds';
  like $server->lines_for(2), [qr/\A:alice!alice\@\S+\ ACCOUNT\ b{64}\z/mxs],
    'account-notify watchers hear about the binding';
  is $server->lines_for(3), [], 'clients without account-notify hear nothing';
  is $server->lines_for(4), [], 'unregistered clients hear nothing';

  my $unregistered = {id => 9,};
  is Overnet::Program::IRC::Command::Auth::_send_account_notify($server, $unregistered, 'x'), 1,
    'an unregistered client sends no notify';
  is Overnet::Program::IRC::Command::Auth::_send_account_notify($server, {id => 9, registered => 1,}, 'x'), 1,
    'a nickless client sends no notify';
  is Overnet::Program::IRC::Command::Auth::_send_account_notify($server, 'not-a-hash', 'x'), 1,
    'a non-hash client sends no notify';
  is Overnet::Program::IRC::Command::Auth::_send_account_notify(
    $server,
    {
      id         => 3,
      registered => 1,
      nick       => 'carol',
    },
    'x'
    ),
    1, 'a client with no interested watchers sends no notify';
};

done_testing;
