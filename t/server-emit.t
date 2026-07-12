use strictures 2;

use File::Spec;
use FindBin;
use JSON ();
use Test2::V0;

use lib grep { -d $_ } (
  File::Spec->catdir($FindBin::Bin, 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'lib'),
);

use Overnet::Core::Nostr;
use TestIRCServer;

my $channel = '#overnet';

sub _server {
  my (%overrides) = @_;
  my $server = TestIRCServer->new;
  $server->configure(
    adapter_config => {
      authority_profile => q{},
      network           => 'overnet',
    },
    authority_relay => undef,
    %overrides,
  );
  $server->{signing_key}        = Overnet::Core::Nostr->generate_key;
  $server->{adapter_session_id} = 'adapter-session-1';
  return $server;
}

sub _client {
  my ($server, $client_id, $nick, %fields) = @_;
  my $client = $server->add_client(
    $client_id,
    nick       => $nick,
    username   => $nick,
    registered => 1,
    %fields,
  );
  $server->{nick_to_client_id}{$server->_nick_key($nick)} = $client_id;
  return $client;
}

sub _lines {
  my ($server, $client_id) = @_;
  return join "\n", @{$server->lines_for($client_id)};
}

sub _channel_candidate {
  my (%fields) = @_;
  return {
    kind       => 1,
    created_at => 1_000,
    content    => JSON::encode_json({body => {text => 'hi',},}),
    tags       => [
      ['overnet_ot',  'chat.channel'],
      ['overnet_oid', 'irc:overnet:' . $channel],
      ['overnet_et',  'chat.message'],
    ],
    %fields,
  };
}

sub _dm_candidate {
  my (%fields) = @_;
  my $content = delete $fields{content};
  $content = JSON::encode_json(
    {
      provenance => {external_identity => 'alice',},
      body       => {text => 'secret hello',},
    }
  ) if !defined $content;
  return {
    kind       => 1,
    created_at => 1_000,
    content    => $content,
    tags       => delete($fields{tags}) || [
      ['overnet_ot',  'chat.dm'],
      ['overnet_oid', 'irc:overnet:dm:bob'],
      ['overnet_et',  'chat.dm_message'],
    ],
    %fields,
  };
}

subtest 'mapped results emit events, state, and capabilities' => sub {
  my $server = _server();
  my $alice  = _client($server, 1, 'alice');
  $server->_add_client_to_channel(1, $channel);
  $server->request_handler(
    sub {
      my (%args) = @_;
      return {
        events => [_channel_candidate(), _channel_candidate(tags => [['overnet_ot', 'chat.channel'], ['overnet_oid', 'irc:overnet:' . $channel], ['overnet_et', 'chat.join'],],),],
        state  => [_channel_candidate(tags => [['overnet_ot', 'chat.channel'], ['overnet_oid', 'irc:overnet:' . $channel], ['overnet_et', 'chat.topic'],],),],
        capabilities => [{name => 'chat',}, {name => 'presence',},],
      } if $args{method} eq 'adapters.map_input';
      return;
    }
  );

  ok $server->_emit_client_input(
    $alice,
    {command => 'PRIVMSG', target => $channel, text => 'hi',},
    suppress_render_event_types => {'chat.join' => 1,},
  ), 'a mapped input emits';

  my @emitted = grep { $_->{method} eq 'overnet.emit_event' } @{$server->requests};
  is scalar(@emitted), 2, 'both mapped events are emitted';
  like $emitted[0]{params}{event}{sig}, qr/\A[0-9a-f]+\z/mxs, 'emitted events are signed';
  my ($state) = grep { $_->{method} eq 'overnet.emit_state' } @{$server->requests};
  ok $state, 'mapped state is emitted';
  my ($capabilities) = grep { $_->{method} eq 'overnet.emit_capabilities' } @{$server->requests};
  is scalar(@{$capabilities->{params}{capabilities}}), 2, 'mapped capabilities are emitted';
  is $server->{events_emitted},       2, 'the event counter advances';
  is $server->{state_emitted},        1, 'the state counter advances';
  is $server->{capabilities_emitted}, 2, 'the capabilities counter advances';

  is scalar(keys %{$server->{subscription_event_origin_client_ids}}), 1,
    'the originating channel message is tracked';
  is scalar(keys %{$server->{suppress_subscription_event_ids}}), 1,
    'the suppressed event type is remembered';

  like dies { $server->_sign_candidate_event('nope') }, qr/must\ be\ an\ object/mxs,
    'a non-hash candidate cannot be signed';
  like dies { $server->_sign_candidate_event({}) }, qr/kind\ is\ required/mxs,
    'a kindless candidate cannot be signed';
  like dies { $server->_sign_candidate_event({kind => 1,}) }, qr/created_at\ is\ required/mxs,
    'an undated candidate cannot be signed';
  like dies { $server->_sign_candidate_event({kind => 1, created_at => 1,}) }, qr/tags\ must\ be\ an\ array/mxs,
    'a tagless candidate cannot be signed';
  like dies { $server->_sign_candidate_event({kind => 1, created_at => 1, tags => [],}) },
    qr/content\ is\ required/mxs, 'a contentless candidate cannot be signed';
};

subtest 'wrapped private-message candidates are encrypted and emitted' => sub {
  my $server = _server();
  my $alice  = _client($server, 1, 'alice');
  my $bob    = _client($server, 2, 'bob');

  ok $server->_emit_private_message_candidate(_dm_candidate(), originating_client_id => 1,),
    'a DM candidate emits';
  my ($emitted) = grep { $_->{method} eq 'overnet.emit_private_message' } @{$server->requests};
  like $emitted->{params}{message}{source}{line}, qr/:alice\ PRIVMSG\ bob\ :secret\ hello/mxs,
    'the source line mirrors the IRC form';
  ok $emitted->{params}{message}{transport}{decrypted_rumor}, 'the transport carries the decrypted rumor';
  is $server->{private_messages_emitted}, 1, 'the private message counter advances';

  my $notice = _dm_candidate(
    tags => [
      ['overnet_ot',  'chat.dm'],
      ['overnet_oid', 'irc:overnet:dm:bob'],
      ['overnet_et',  'chat.dm_notice'],
    ],
  );
  ok $server->_emit_private_message_candidate($notice, originating_client_id => 1,), 'a DM notice emits';

  like dies { $server->_emit_private_message_candidate('nope', originating_client_id => 1,) },
    qr/must\ be\ an\ object/mxs, 'a non-hash candidate croaks';
  like dies { $server->_emit_private_message_candidate(_dm_candidate()) },
    qr/originating_client_id\ is\ required/mxs, 'a missing originator croaks';
  like dies { $server->_emit_private_message_candidate(_dm_candidate(), originating_client_id => 99,) },
    qr/Unknown\ originating_client_id/mxs, 'an unknown originator croaks';

  my $unregistered = $server->add_client(3, nick => 'carol',);
  like dies { $server->_emit_private_message_candidate(_dm_candidate(), originating_client_id => 3,) },
    qr/must\ be\ registered/mxs, 'an unregistered originator croaks';

  like dies {
    $server->_emit_private_message_candidate(
      _dm_candidate(tags => [['overnet_ot', 'chat.channel'],],),
      originating_client_id => 1,
    )
  }, qr/must\ target\ chat\.dm/mxs, 'a non-DM candidate croaks';

  like dies {
    $server->_emit_private_message_candidate(
      _dm_candidate(tags => [['overnet_ot', 'chat.dm'], ['overnet_et', 'chat.frob'],],),
      originating_client_id => 1,
    )
  }, qr/dm_message\ or\ chat\.dm_notice/mxs, 'an unknown DM event type croaks';

  like dies {
    $server->_emit_private_message_candidate(_dm_candidate(content => 'not-json',), originating_client_id => 1,)
  }, qr/must\ decode\ to\ an\ object/mxs, 'undecodable content croaks';

  like dies {
    $server->_emit_private_message_candidate(
      _dm_candidate(content => JSON::encode_json({body => 'nope',}),),
      originating_client_id => 1,
    )
  }, qr/body\ must\ be\ an\ object/mxs, 'a malformed body croaks';

  like dies {
    $server->_emit_private_message_candidate(
      _dm_candidate(content => JSON::encode_json({body => {},}),),
      originating_client_id => 1,
    )
  }, qr/body\.text\ must\ be\ a\ string/mxs, 'a textless body croaks';

  like dies {
    $server->_emit_private_message_candidate(
      _dm_candidate(
        tags => [
          ['overnet_ot',  'chat.dm'],
          ['overnet_oid', 'not-a-dm-object'],
          ['overnet_et',  'chat.dm_message'],
        ],
      ),
      originating_client_id => 1,
    )
  }, qr/must\ target\ an\ IRC\ nick/mxs, 'a malformed object id croaks';

  like dies {
    $server->_emit_private_message_candidate(
      _dm_candidate(
        tags => [
          ['overnet_ot',  'chat.dm'],
          ['overnet_oid', 'irc:overnet:dm:ghost'],
          ['overnet_et',  'chat.dm_message'],
        ],
      ),
      originating_client_id => 1,
    )
  }, qr/not\ connected/mxs, 'an unconnected recipient croaks';

  $server->add_client(4, nick => 'dave',);
  $server->{nick_to_client_id}{$server->_nick_key('dave')} = 4;
  like dies {
    $server->_emit_private_message_candidate(
      _dm_candidate(
        tags => [
          ['overnet_ot',  'chat.dm'],
          ['overnet_oid', 'irc:overnet:dm:dave'],
          ['overnet_et',  'chat.dm_message'],
        ],
      ),
      originating_client_id => 1,
    )
  }, qr/recipient\ must\ be\ registered/mxs, 'an unregistered recipient croaks';
};

subtest 'private subscription items render decrypted and opaque messages' => sub {
  my $server = _server();
  my $alice  = _client($server, 1, 'alice');
  my $bob    = _client(
    $server, 2, 'bob',
    capabilities => {'overnet-e2ee' => 1,},
    e2ee_pubkey  => 'd' x 64,
  );

  my $render = $server->_render_subscription_item(
    item_type => 'private_message',
    data      => {
      private_type    => 'chat.dm_message',
      object_id       => 'irc:overnet:dm:bob',
      decrypted_rumor => {
        content => {
          provenance => {external_identity => 'alice',},
          body       => {text => 'plain secret',},
        },
      },
    },
  );
  like $render->{line}, qr/:alice\ PRIVMSG\ bob\ :plain\ secret/mxs, 'a decrypted rumor renders as PRIVMSG';
  is $render->{client_ids}, [2], 'the rumor goes to the recipient';

  is $server->_render_subscription_item(
    item_type => 'private_message',
    data      => {
      private_type    => 'chat.dm_message',
      object_id       => 'irc:overnet:dm:bob',
      decrypted_rumor => {content => 'nope',},
    },
  ), undef, 'a rumor with malformed content renders nothing';

  my $notice = $server->_render_subscription_item(
    item_type => 'private_message',
    data      => {
      private_type    => 'chat.dm_notice',
      object_id       => 'irc:overnet:dm:bob',
      sender_identity => 'alice',
      transport       => {kind => 1059, content => 'opaque',},
    },
  );
  like $notice->{line}, qr/:alice\ NOTICE\ bob\ :\+overnet-e2ee-v1\ /mxs,
    'an opaque transport renders with the e2ee body prefix';
  is $notice->{client_ids}, [2], 'the opaque message goes to the capable recipient';

  is $server->_render_opaque_private_message_item(
    event_type      => 'chat.dm_message',
    object_id       => 'irc:overnet:dm:alice',
    sender_identity => 'bob',
    transport       => {kind => 1059,},
  ), undef, 'an incapable recipient renders nothing';
  is $server->_render_opaque_private_message_item(
    event_type      => 'chat.dm_message',
    object_id       => 'bad-object',
    sender_identity => 'bob',
    transport       => {},
  ), undef, 'a malformed object id renders nothing';
  is $server->_render_opaque_private_message_item(
    event_type      => 'chat.dm_message',
    object_id       => 'irc:overnet:dm:bob',
    sender_identity => q{},
    transport       => {},
  ), undef, 'a missing sender identity renders nothing';
  is $server->_render_opaque_private_message_item(
    event_type      => 'chat.dm_message',
    object_id       => 'irc:overnet:dm:bob',
    sender_identity => 'alice',
    transport       => 'nope',
  ), undef, 'a malformed transport renders nothing';
  is $server->_render_opaque_private_message_item(
    event_type      => 'chat.frob',
    object_id       => 'irc:overnet:dm:bob',
    sender_identity => 'alice',
    transport       => {},
  ), undef, 'an unknown opaque event type renders nothing';

  is $server->_render_private_message_item(
    event_type => 'chat.dm_message',
    object_id  => 'bad-object',
    provenance => {external_identity => 'alice',},
    body       => {text => 'x',},
  ), undef, 'a malformed DM object id renders nothing';
  is $server->_render_private_message_item(
    event_type => 'chat.dm_message',
    object_id  => 'irc:overnet:dm:bob',
    provenance => 'nope',
    body       => {text => 'x',},
  ), undef, 'malformed provenance renders nothing';
  is $server->_render_private_message_item(
    event_type => 'chat.dm_message',
    object_id  => 'irc:overnet:dm:bob',
    provenance => {},
    body       => {text => 'x',},
  ), undef, 'a missing external identity renders nothing';
  is $server->_render_private_message_item(
    event_type => 'chat.dm_message',
    object_id  => 'irc:overnet:dm:bob',
    provenance => {external_identity => 'alice',},
    body       => 'nope',
  ), undef, 'a malformed body renders nothing';
  is $server->_render_private_message_item(
    event_type => 'chat.dm_message',
    object_id  => 'irc:overnet:dm:bob',
    provenance => {external_identity => 'alice',},
    body       => {},
  ), undef, 'a textless body renders nothing';
  is $server->_render_private_message_item(
    event_type => 'chat.frob',
    object_id  => 'irc:overnet:dm:bob',
    provenance => {external_identity => 'alice',},
    body       => {text => 'x',},
  ), undef, 'an unknown DM event type renders nothing';
  is $server->_render_private_message_item(
    event_type => 'chat.dm_message',
    object_id  => 'irc:overnet:dm:ghost',
    provenance => {external_identity => 'alice',},
    body       => {text => 'x',},
  ), undef, 'a DM to an unconnected nick renders nothing';
};

subtest 'network nick subscription items rename visible nicks' => sub {
  my $server = _server();
  my $alice  = _client($server, 1, 'alice');
  $server->_add_client_to_channel(1, $channel);
  $server->_add_visible_nick($channel, 'roamer');

  my $event = $server->{signing_key}->create_event_hash(
    kind       => 1,
    created_at => 1_000,
    content    => JSON::encode_json(
      {
        body => {
          old_nick => 'roamer',
          new_nick => 'wanderer',
        },
      }
    ),
    tags => [
      ['overnet_ot', 'irc.network'],
      ['overnet_oid', 'irc:overnet'],
      ['overnet_et', 'irc.nick'],
    ],
  );
  is $server->_handle_subscription_event({item_type => 'event', data => $event,}), 1,
    'a network nick event fans out';
  like _lines($server, 1), qr/:roamer\ NICK\ :wanderer/mxs, 'the rename is announced';
  my $state = $server->{channels}{$server->_channel_key($channel)};
  ok $state->{visible_nicks}{$server->_nick_key('wanderer')}, 'the visible nick is renamed';

  my $wrong_scope = $server->{signing_key}->create_event_hash(
    kind       => 1,
    created_at => 1_001,
    content    => JSON::encode_json({body => {old_nick => 'a', new_nick => 'b',},}),
    tags       => [
      ['overnet_ot', 'irc.network'],
      ['overnet_oid', 'irc:elsewhere'],
      ['overnet_et', 'irc.nick'],
    ],
  );
  is $server->_handle_subscription_event({item_type => 'event', data => $wrong_scope,}), 0,
    'a nick event for another network renders nothing';

  my $missing_nicks = $server->{signing_key}->create_event_hash(
    kind       => 1,
    created_at => 1_002,
    content    => JSON::encode_json({body => {old_nick => 'a',},}),
    tags       => [
      ['overnet_ot', 'irc.network'],
      ['overnet_oid', 'irc:overnet'],
      ['overnet_et', 'irc.nick'],
    ],
  );
  is $server->_handle_subscription_event({item_type => 'event', data => $missing_nicks,}), 0,
    'a nick event without both nicks renders nothing';

  my $unwatched = $server->{signing_key}->create_event_hash(
    kind       => 1,
    created_at => 1_003,
    content    => JSON::encode_json({body => {old_nick => 'nobody', new_nick => 'somebody',},}),
    tags       => [
      ['overnet_ot', 'irc.network'],
      ['overnet_oid', 'irc:overnet'],
      ['overnet_et', 'irc.nick'],
    ],
  );
  is $server->_handle_subscription_event({item_type => 'event', data => $unwatched,}), 0,
    'a nick rename with no shared watchers renders nothing';
};

subtest 'topic and part subscription items update channel state' => sub {
  my $server = _server();
  my $alice  = _client($server, 1, 'alice');
  $server->_add_client_to_channel(1, $channel);
  $server->_add_visible_nick($channel, 'roamer');

  my $topic = $server->{signing_key}->create_event_hash(
    kind       => 1,
    created_at => 1_000,
    content    => JSON::encode_json(
      {
        provenance => {external_identity => 'roamer',},
        body       => {topic => 'from the network',},
      }
    ),
    tags => [
      ['overnet_ot',  'chat.channel'],
      ['overnet_oid', 'irc:overnet:' . $channel],
      ['overnet_et',  'chat.topic'],
    ],
  );
  is $server->_handle_subscription_event({item_type => 'state', data => $topic,}), 1,
    'a topic state item fans out';
  like _lines($server, 1), qr/:roamer\ TOPIC\ \Q$channel\E\ :from\ the\ network/mxs,
    'the topic line is rendered';
  is $server->{channels}{$server->_channel_key($channel)}{topic_text}, 'from the network',
    'the channel topic state is updated';

  my $part = $server->{signing_key}->create_event_hash(
    kind       => 1,
    created_at => 1_001,
    content    => JSON::encode_json(
      {
        provenance => {external_identity => 'roamer',},
        body       => {reason => 'done',},
      }
    ),
    tags => [
      ['overnet_ot',  'chat.channel'],
      ['overnet_oid', 'irc:overnet:' . $channel],
      ['overnet_et',  'chat.part'],
    ],
  );
  is $server->_handle_subscription_event({item_type => 'event', data => $part,}), 1,
    'a part event fans out';
  like _lines($server, 1), qr/:roamer\ PART\ \Q$channel\E\ :done/mxs, 'the part line carries the reason';
  ok !$server->{channels}{$server->_channel_key($channel)}{visible_nicks}{$server->_nick_key('roamer')},
    'the visible nick is removed on part';

  my $quit = $server->{signing_key}->create_event_hash(
    kind       => 1,
    created_at => 1_002,
    content    => JSON::encode_json({provenance => {external_identity => 'ghost',}, body => {},}),
    tags       => [
      ['overnet_ot',  'chat.channel'],
      ['overnet_oid', 'irc:overnet:' . $channel],
      ['overnet_et',  'chat.quit'],
    ],
  );
  is $server->_handle_subscription_event({item_type => 'event', data => $quit,}), 1, 'a quit event fans out';
  like _lines($server, 1), qr/:ghost\ QUIT/mxs, 'the quit line is rendered';

  my $unknown_type = $server->{signing_key}->create_event_hash(
    kind       => 1,
    created_at => 1_003,
    content    => JSON::encode_json({provenance => {external_identity => 'ghost',}, body => {},}),
    tags       => [
      ['overnet_ot',  'chat.channel'],
      ['overnet_oid', 'irc:overnet:' . $channel],
      ['overnet_et',  'chat.frob'],
    ],
  );
  is $server->_handle_subscription_event({item_type => 'event', data => $unknown_type,}), 0,
    'an unknown channel event type renders nothing';

  my $foreign_channel = $server->{signing_key}->create_event_hash(
    kind       => 1,
    created_at => 1_004,
    content    => JSON::encode_json({provenance => {external_identity => 'ghost',}, body => {text => 'x',},}),
    tags       => [
      ['overnet_ot',  'chat.channel'],
      ['overnet_oid', 'irc:overnet:#empty'],
      ['overnet_et',  'chat.message'],
    ],
  );
  is $server->_handle_subscription_event({item_type => 'event', data => $foreign_channel,}), 0,
    'a message for a memberless channel renders nothing';

  my $nameless = $server->{signing_key}->create_event_hash(
    kind       => 1,
    created_at => 1_005,
    content    => JSON::encode_json({provenance => {}, body => {text => 'x',},}),
    tags       => [
      ['overnet_ot',  'chat.channel'],
      ['overnet_oid', 'irc:overnet:' . $channel],
      ['overnet_et',  'chat.message'],
    ],
  );
  is $server->_handle_subscription_event({item_type => 'event', data => $nameless,}), 0,
    'a message without an external identity renders nothing';
};

subtest 'small server helpers answer directly' => sub {
  my $server = _server();
  my $alice  = _client($server, 1, 'alice', authority_pubkey => 'a' x 64,);

  like $server->_server_description, qr/Overnet\ IRC/mxs, 'the server describes itself';
  is $server->_client_account_name($alice), 'a' x 64, 'the account name is the authority pubkey';
  is $server->_client_account_name({}),     undef,    'a client without a pubkey has no account name';
  is $server->_authority_relay_poll_interval_ms, undef, 'a relayless server has no poll interval';
  ok $server->_maybe_poll_authoritative_relay, 'polling the relay is a no-op';
  ok !$server->_has_authoritative_relay_poll_interest, 'there is no poll interest';

  is $server->_cached_authoritative_channel_view('nochannel'), undef,
    'an invalid channel has no cached view';
  is $server->_cached_authoritative_channel_view($channel), undef, 'an unprimed channel has no cached view';
  ok !$server->_authoritative_channel_is_known($channel), 'a plain server knows no authoritative channels';

  my $relay = TestIRCServer->new;
  $relay->configure;
  $relay->{authoritative_channel_cache}{$channel} = {events => [{}], view => {members => [],},};
  ok $relay->_authoritative_channel_is_known($channel), 'cached events mark a channel as known';
  is $relay->_cached_authoritative_channel_view($channel), {members => [],}, 'the cached view is returned';
  is $relay->_authority_relay_poll_interval_ms, 250, 'a configured relay reports its poll interval';

  ok !$relay->_is_authoritative_nip29_event(channel => $channel, event => 'nope',),
    'a non-hash event is not authoritative';
  ok !$relay->_is_authoritative_nip29_event(channel => $channel, event => {kind => 1, tags => [],},),
    'a foreign kind is not authoritative';
  ok !$relay->_is_authoritative_nip29_event(channel => $channel, event => {kind => 9021, tags => [],},),
    'a missing group tag is not authoritative';
  ok !$relay->_is_authoritative_nip29_event(channel => 'nochannel', event => {kind => 9021, tags => [],},),
    'an invalid channel is not authoritative';

  is $server->_emit_nick_change_input($alice, undef, 'new'), 1, 'a nick change without an old nick is a no-op';

  is [$server->_shared_client_ids_for_nick(',bad')], [], 'an invalid nick shares no clients';
  is [$server->_shared_client_ids_for_client(99)],   [], 'an unknown client shares no clients';

  ok $server->_close_listen_socket, 'closing a missing listener succeeds';
  ok $server->_close_socket(undef), 'closing an undefined socket succeeds';
  ok !$server->_is_listener_socket(\*STDIN), 'STDIN is not the listener';
  ok $server->_is_runtime_stdin(\*STDIN), 'STDIN is the runtime handle';
  ok !$server->_is_runtime_stdin(undef),  'an undefined handle is not the runtime handle';
  is $server->_client_id_for_handle(undef), undef, 'an undefined handle maps to no client';
  is $server->_client_id_for_handle(\*STDIN), undef, 'a socketless client map finds nothing';

  ok $server->_close_all_clients, 'closing all clients succeeds';
  is $server->{clients}, {}, 'all clients are removed';

  like dies { Overnet::Program::IRC::Server::_validate_runtime_request_args(undef, {}) },
    qr/method\ is\ required/mxs, 'a request without a method croaks';
  like dies { Overnet::Program::IRC::Server::_validate_runtime_request_args('overnet.emit_event', 'nope') },
    qr/params\ must\ be\ an\ object/mxs, 'a request with malformed params croaks';

  require File::Temp;
  my $capture_file = File::Temp->new;
  {
    local *STDOUT;
    open *STDOUT, '>', $capture_file->filename or die "reopen STDOUT: $!";
    $server->_log(level => 'info', message => 'hello', context => {a => 1,},);
    $server->_log;
    $server->_health(status => 'ready', message => 'up', details => {ok => 1,},);
    close *STDOUT;
  }
  open my $captured_fh, '<', $capture_file->filename or die "read capture: $!";
  my $captured = do { local $/ = undef; <$captured_fh> };
  close $captured_fh;
  like $captured, qr/program\.log/mxs,    'log notifications are framed to stdout';
  like $captured, qr/program\.health/mxs, 'health notifications are framed to stdout';

  ok !$server->_looks_like_tls_client_hello(undef), 'undefined buffers are not TLS hellos';
  ok !$server->_looks_like_tls_client_hello('ab'),  'short buffers are not TLS hellos';
  ok !$server->_looks_like_tls_client_hello("\x15\x03\x01"), 'non-handshake records are not TLS hellos';
  ok !$server->_looks_like_tls_client_hello("\x16\x02\x01"), 'wrong major versions are not TLS hellos';
  ok !$server->_looks_like_tls_client_hello("\x16\x03\x09"), 'wrong minor versions are not TLS hellos';
  ok $server->_looks_like_tls_client_hello("\x16\x03\x01\x00"), 'a TLS client hello is recognized';

  ok Overnet::Program::IRC::Server::_is_shutdown_sentinel_error("__shutdown__ at foo line 1\n"),
    'the shutdown sentinel is recognized with a location';
  ok Overnet::Program::IRC::Server::_is_shutdown_sentinel_error('__shutdown__'),
    'the bare shutdown sentinel is recognized';
  ok !Overnet::Program::IRC::Server::_is_shutdown_sentinel_error('boom'), 'other errors are not sentinels';
  ok !Overnet::Program::IRC::Server::_is_shutdown_sentinel_error({}), 'references are not sentinels';
};

done_testing;
