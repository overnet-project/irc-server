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

use Overnet::Authority::HostedChannel;
use Overnet::Core::Nostr;
use TestIRCServer;

my $channel  = '#overnet';
my $group_id = Overnet::Authority::HostedChannel::authoritative_group_id(
  network => 'overnet',
  channel => $channel,
);

sub _server {
  my (%overrides) = @_;
  my $server = TestIRCServer->new;
  $server->configure(%overrides);
  $server->{signing_key}        = Overnet::Core::Nostr->generate_key;
  $server->{adapter_session_id} = 'adapter-session-1';
  return $server;
}

sub _plain_server {
  my (%overrides) = @_;
  return _server(
    adapter_config  => {authority_profile => q{}, network => 'overnet',},
    authority_relay => undef,
    %overrides,
  );
}

sub _local_authority_server {
  my (%overrides) = @_;
  return _server(authority_relay => undef, %overrides,);
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

sub _group_event {
  my (%fields) = @_;
  return {
    id         => delete($fields{id}) || ('e' x 64),
    kind       => delete($fields{kind}) || 39_000,
    created_at => delete($fields{created_at}) || 100,
    pubkey     => 'c' x 64,
    content    => q{},
    tags       => delete($fields{tags}) || [['d', $group_id],],
    %fields,
  };
}

sub _local_authority_handler {
  my ($server, %responses) = @_;
  $server->request_handler(
    sub {
      my (%args) = @_;
      if ($args{method} eq 'events.read') {
        return {entries => [map { +{event => $_} } @{$responses{events} || [_group_event()]}],};
      }
      if ($args{method} eq 'adapters.derive') {
        my $operation = $args{params}{operation};
        my $response  = $responses{$operation};
        return ref($response) eq 'CODE' ? $response->(%args) : $response if defined $response;
        return {view => [$responses{view} || {members => [],},],}
          if $operation eq 'authoritative_channel_view';
        return {};
      }
      if ($args{method} eq 'adapters.map_input' && defined $responses{map_input}) {
        my $response = $responses{map_input};
        return ref($response) eq 'CODE' ? $response->(%args) : $response;
      }
      return;
    }
  );
  return $server;
}

subtest 'reply senders guard unknown clients and unusable lines' => sub {
  my $server = _plain_server();
  is $server->_send_rendered_lines(1, 'not-an-array'), 0, 'non-array lines send nothing';

  my $alice = _client($server, 1, 'alice');
  is $server->_send_rendered_lines(1, [undef, [], 'plain line',]), 1, 'unusable lines are skipped';
  is scalar(@{$server->lines_for(1)}), 1, 'only the usable line is sent';

  my @unknown_client_senders = (
    [_send_unknown_command             => 'FROB'],
    [_send_registration_prelude        => ()],
    [_send_nonickname_given            => ()],
    [_send_need_more_params            => 'FROB'],
    [_send_server_notice               => 'text'],
    [_send_no_such_nick                => 'ghost'],
    [_send_no_such_channel             => $channel],
    [_send_not_on_channel              => $channel],
    [_send_cannot_send_to_channel      => $channel],
    [_send_chan_op_privs_needed        => $channel],
    [_send_cannot_join_channel         => $channel],
    [_send_ban_list_entry              => $channel, 'x!*@*'],
    [_send_end_of_ban_list             => $channel],
    [_send_exception_list_entry        => $channel, 'x!*@*'],
    [_send_end_of_exception_list       => $channel],
    [_send_invite_exception_list_entry => $channel, 'x!*@*'],
    [_send_end_of_invite_exception_list => $channel],
    [_send_inviting                     => 'ghost', $channel],
    [_send_channel_mode_is              => $channel],
    [_send_user_mode_is                 => ()],
    [_send_lusers_reply                 => ()],
    [_send_list_reply                   => undef],
    [_send_authoritative_invite_list_reply       => $channel, []],
    [_send_authoritative_join_request_list_reply => $channel, []],
    [_send_topic_reply                           => $channel],
    [_send_userhost_reply                        => []],
    [_send_who_list                              => $channel],
    [_send_whois_reply                           => {}],
    [_send_sasl_success                          => ()],
    [_send_sasl_fail                             => ()],
  );
  for my $sender (@unknown_client_senders) {
    my ($method, @args) = @{$sender};
    is $server->$method(99, @args), 0, "$method rejects an unknown client";
  }

  my $nickless = $server->add_client(2);
  is $server->_send_server_notice(2, 'text'), 0, 'a nickless client gets no server notice';
  is $server->_send_whois_reply(1, 'not-a-hash'), 0, 'a malformed whois entry sends nothing';
  is $server->_send_topic_reply(1, ',bad'), 0, 'an invalid topic channel sends nothing';
  is $server->_send_who_list(1, ',bad'), 0, 'an invalid WHO channel sends nothing';
  is $server->_send_channel_mode_is(1, ',bad'), 0, 'an invalid MODE channel sends nothing';

  $server->clear_sent_lines;
  $server->_send_whois_reply(1, {nick => 'x', username => 'x', host => 'h', realname => 'r', account => 'a' x 64,});
  like _lines($server, 1), qr/330 .* a{64}/mxs, 'a whois entry with an account renders the account line';
};

subtest 'topic replies and channel modes read authoritative views' => sub {
  my $server = _local_authority_server();
  my $alice  = _client($server, 1, 'alice');
  $server->_add_client_to_channel(1, $channel);
  _local_authority_handler(
    $server,
    view => {
      members       => [],
      topic         => 'derived topic',
      channel_modes => 'ntk',
      channel_key   => 'sekrit',
      user_limit    => 12,
    },
  );

  ok $server->_send_topic_reply(1, $channel), 'an authoritative topic reply renders';
  like _lines($server, 1), qr/332 .* derived\ topic/mxs, 'the derived topic is reported';

  $server->clear_sent_lines;
  ok $server->_send_channel_mode_is(1, $channel), 'an authoritative mode reply renders';
  like _lines($server, 1), qr/324 .* ntk\ sekrit\ 12/mxs, 'the derived modes, key, and limit are reported';

  my $topicless = _local_authority_server();
  _client($topicless, 1, 'alice');
  $topicless->_add_client_to_channel(1, $channel);
  _local_authority_handler($topicless, view => {members => [],},);
  ok $topicless->_send_topic_reply(1, $channel), 'a topicless authoritative reply renders';
  like _lines($topicless, 1), qr/331/mxs, 'the no-topic numeric is reported';

  my $plain = _plain_server();
  _client($plain, 1, 'alice');
  $plain->_channel_state($channel)->{topic_text} = 'local topic';
  ok $plain->_send_topic_reply(1, $channel), 'a local topic reply renders';
  like _lines($plain, 1), qr/332 .* local\ topic/mxs, 'the local topic is reported';
};

subtest 'presentation helpers cloak and resolve identities' => sub {
  my $server = _plain_server();
  my $alice  = _client($server, 1, 'alice');

  is $server->_client_numeric_target('nope'), q{*}, 'a malformed client targets the asterisk';
  is $server->_irc_casefold(undef),           undef, 'undefined values do not casefold';
  is $server->_irc_casefold('Nick[a]{b}'), $server->_irc_casefold('nick{a}[b]'),
    'IRC casefolding maps the bracket pairs';

  is $server->_presentational_host_for_client('nope'), $server->_default_presentational_host,
    'a malformed client presents the default host';
  is $server->_presentational_host_for_client({presentational_host => 'vanity.host',}), 'vanity.host',
    'an assigned vhost is presented verbatim';
  like $server->_presentational_host_for_client({peerhost => '203.0.113.7',}), qr/\.users\.overnet\z/mxs,
    'a raw address is cloaked';
  is $server->_presentational_host_for_client({}), $server->_default_presentational_host,
    'an addressless client presents the default host';

  my $configured = _plain_server(cloak_secret => 'stable-secret',);
  my $cloak_a    = $configured->_cloak_host_for_address('203.0.113.7');
  is $configured->_cloak_host_for_address('203.0.113.7'), $cloak_a, 'configured cloaks are stable';

  is $server->_canonical_current_nick(',bad'), undef, 'an invalid nick has no canonical form';
  is $server->_canonical_current_nick('ghost'), undef, 'an unknown nick has no canonical form';
  is $server->_client_for_current_nick(',bad'), undef, 'an invalid nick has no client';
  is $server->_client_for_current_nick('ghost'), undef, 'an unknown nick has no client';

  ok !$server->_client_has_capability('nope', 'sasl'), 'a malformed client has no capabilities';
  ok !$server->_client_has_capability($alice, q{}),    'an empty capability is never present';
  is $server->_client_account_name('nope'), undef, 'a malformed client has no account name';

  is $server->_generate_authoritative_auth_challenge('not-a-hash'), D(),
    'a challenge can be generated without a client hash';
  is $server->_generate_authoritative_delegate_session_id('not-a-hash'), D(),
    'a session id can be generated without a client hash';
};

subtest 'authoritative channel discovery lists configured and joined channels' => sub {
  my $server = _server(
    adapter_config => {
      authority_profile => 'nip29',
      group_host        => 'groups.example.test',
      network           => 'overnet',
      channel_groups    => {
        '#configured' => 'irc-group-1',
        'not a chan'  => 'irc-group-2',
      },
    },
  );
  my $alice = _client($server, 1, 'alice');
  $server->_add_client_to_channel(1, '#joined');
  $server->{authoritative_discovered_channels}{'#found'} = {channel_name => '#found', group_id => 'g',};
  $server->{authoritative_discovered_channels}{'bad name'} = {};

  is [$server->_authoritative_channels], ['#configured', '#found', '#joined'],
    'configured, discovered, and joined channels are merged';

  is $server->_authoritative_grant_subscription_id,     'irc.authority.grants:overnet',    'the grant id wrapper delegates';
  is $server->_authoritative_discovery_subscription_id, 'irc.authority.discovery:overnet', 'the discovery id wrapper delegates';
  my @subscription_ids = $server->_authoritative_channel_subscription_ids($channel);
  is scalar(@subscription_ids), 2, 'the channel id wrapper delegates';
  is $server->_ensure_authoritative_grant_subscription, 'irc.authority.grants:overnet', 'the grant ensure wrapper delegates';
  is $server->_read_nostr_subscription_snapshot('sub-x'), [], 'the snapshot wrapper delegates';

  my $plain = _plain_server();
  is [$plain->_authoritative_channels], [], 'a plain server has no authoritative channels';
};

subtest 'derive helpers guard their inputs' => sub {
  my $server = _server();
  is $server->_derive_authoritative_view_from_events(undef, $channel, []), undef,
    'a missing operation derives nothing';
  is $server->_derive_authoritative_view_from_events('op', 'nochannel', []), undef,
    'an invalid channel derives nothing';
  is $server->_derive_authoritative_view_from_events('op', $channel, 'nope'), undef,
    'malformed events derive nothing';
  is $server->_derive_authoritative_join_admission_from_events('nochannel', []), undef,
    'an invalid admission channel derives nothing';
  is $server->_derive_authoritative_join_admission_from_events($channel, 'nope'), undef,
    'malformed admission events derive nothing';
  is $server->_derive_authoritative_permission_from_events(undef, $channel, []), undef,
    'a missing permission operation derives nothing';
  is $server->_derive_authoritative_permission_from_events('op', 'nochannel', []), undef,
    'an invalid permission channel derives nothing';
  is $server->_derive_authoritative_permission_from_events('op', $channel, 'nope'), undef,
    'malformed permission events derive nothing';
  is $server->_derive_authoritative_view('op', 'nochannel'), undef,
    'an invalid view channel derives nothing';
  is $server->_derive_authoritative_view(q{}, $channel), undef,
    'an empty view operation derives nothing';
  is $server->_derive_authoritative_channel_view('nochannel'), undef,
    'an invalid channel has no channel view';
  is $server->_derive_authoritative_join_admission('nochannel'), undef,
    'an invalid channel has no join admission';
  is $server->_derive_authoritative_speak_permission('nochannel'), undef,
    'an invalid channel has no speak permission';
  is $server->_derive_authoritative_topic_permission('nochannel'), undef,
    'an invalid channel has no topic permission';
  is $server->_derive_authoritative_mode_write_permission('nochannel'), undef,
    'an invalid channel has no mode permission';
  is $server->_derive_authoritative_channel_action_permission('nochannel'), undef,
    'an invalid channel has no action permission';

  my $failing = _server();
  $failing->request_handler(sub { die "derive unavailable\n" });
  is $failing->_derive_authoritative_view_from_events('op', $channel, [_group_event()]), undef,
    'a failed derive request derives nothing';
  is $failing->_derive_authoritative_join_admission_from_events($channel, [_group_event()]), undef,
    'a failed admission request derives nothing';
  is $failing->_derive_authoritative_permission_from_events('op', $channel, [_group_event()]), undef,
    'a failed permission request derives nothing';

  my $with_actor = _server();
  $with_actor->request_handler(
    sub {
      my (%args) = @_;
      return {view => [{actor => $args{params}{input}{actor_pubkey},},],}
        if $args{method} eq 'adapters.derive';
      return;
    }
  );
  is $with_actor->_derive_authoritative_view_from_events(
    'op', $channel, [],
    actor_pubkey => 'a' x 64,
    actor_mask   => 'alice!alice@host',
    extra_input  => {join_key => 'k',},
  ), {actor => 'a' x 64,}, 'actor arguments ride into the derive input';
  is $with_actor->_derive_authoritative_join_admission_from_events(
    $channel, [],
    actor_pubkey => 'a' x 64,
    actor_mask   => 'alice!alice@host',
    extra_input  => {join_key => 'k',},
  ), undef, 'admission responses without admissions derive nothing';
  is $with_actor->_derive_authoritative_permission_from_events(
    'op', $channel, [],
    actor_pubkey => 'a' x 64,
    actor_mask   => 'alice!alice@host',
    extra_input  => {mode => '+m',},
  ), undef, 'permission responses without permissions derive nothing';
};

subtest 'view state extraction copies every optional field' => sub {
  my $server = _server();
  is $server->_authoritative_channel_state_from_view('nope'), undef, 'a malformed view has no state';

  my $state = $server->_authoritative_channel_state_from_view(
    {
      authority_profile      => 'nip29',
      object_type            => 'chat.channel',
      object_id              => 'irc:overnet:#overnet',
      channel_modes          => 'imtkl',
      ban_masks              => ['b!*@*'],
      exception_masks        => ['e!*@*'],
      invite_exception_masks => ['i!*@*'],
      channel_key            => 'sekrit',
      user_limit             => 5,
      topic                  => 'topical',
      topic_actor_pubkey     => 'a' x 64,
      private                => 1,
      restricted             => 1,
      hidden                 => 1,
      tombstoned             => 1,
      supported_roles        => ['irc.operator'],
      members                => [{pubkey => 'a' x 64, roles => ['irc.operator'], presentational_prefix => '@',},],
      retained_members       => [{pubkey => 'a' x 64, roles => ['irc.operator'],},],
    }
  );
  is $state->{ban_masks},   ['b!*@*'], 'ban masks are copied';
  is $state->{channel_key}, 'sekrit',  'the channel key is copied';
  is $state->{user_limit},  5,         'the user limit is copied';
  is $state->{topic},       'topical', 'the topic is copied';
  is $state->{private},     1,         'the private flag is copied';
  is $state->{hidden},      1,         'the hidden flag is copied';
  is $state->{tombstoned},  1,         'the tombstone flag is copied';
  is scalar(@{$state->{retained_members}}), 1, 'retained members are copied';

  my $metadata = $server->_authoritative_group_metadata_from_state($state);
  is $metadata->{closed},                 1,         'the metadata reflects invite-only';
  is $metadata->{exception_masks},        ['e!*@*'], 'exception masks are copied to metadata';
  is $metadata->{invite_exception_masks}, ['i!*@*'], 'invite exception masks are copied to metadata';
  is $metadata->{channel_key},            'sekrit',  'the channel key is copied to metadata';
  is $metadata->{user_limit},             5,         'the user limit is copied to metadata';
  is $metadata->{private},                1,         'the private flag is copied to metadata';
  is $metadata->{restricted},             1,         'the restricted flag is copied to metadata';
  is $metadata->{hidden},                 1,         'the hidden flag is copied to metadata';
  is $metadata->{topic},                  'topical', 'the topic is copied to metadata';

  ok !$server->_channel_mode_enabled($state, undef), 'an undefined mode letter is never enabled';
  ok !$server->_channel_mode_enabled($state, 'im'),  'multi-letter modes are never enabled';
  ok !$server->_channel_mode_enabled('nope', 'i'),   'a malformed state has no modes';
};

subtest 'admission and permission population checks accept every field' => sub {
  my $server = _server();
  for my $field (
    qw(allowed member present invite_code deleted create_channel auth_required request_join pending_request reason)) {
    ok $server->_authoritative_join_admission_is_populated({$field => 0,}), "$field populates an admission";
  }
  ok !$server->_authoritative_join_admission_is_populated({}),     'an empty admission is unpopulated';
  ok !$server->_authoritative_join_admission_is_populated('nope'), 'a malformed admission is unpopulated';

  for my $field (qw(allowed reason roles presentational_prefix)) {
    ok $server->_authoritative_permission_is_populated({$field => 0,}), "$field populates a permission";
  }
  ok !$server->_authoritative_permission_is_populated({}), 'an empty permission is unpopulated';

  my $normalized = Overnet::Program::IRC::Server::_normalized_authoritative_join_admission(
    {
      allowed         => 1,
      member          => 1,
      present         => 0,
      invite_code     => 'f' x 64,
      deleted         => 0,
      create_channel  => 1,
      auth_required   => 0,
      request_join    => 0,
      pending_request => 0,
      reason          => '+i',
    },
    'a' x 64,
  );
  is $normalized->{invite_code},    'f' x 64, 'the invite code is normalized through';
  is $normalized->{create_channel}, 1,        'the create flag is normalized through';
  is $normalized->{reason},         '+i',     'the reason is normalized through';

  my $mode_permission = Overnet::Program::IRC::Server::_normalized_authoritative_mode_permission(
    {
      allowed                          => 1,
      target_pubkey                    => 'b' x 64,
      current_roles                    => ['irc.voice'],
      normalized_ban_mask              => 'b!*@*',
      normalized_exception_mask        => 'e!*@*',
      normalized_invite_exception_mask => 'i!*@*',
      channel_key                      => 'sekrit',
      user_limit                       => 5,
      group_metadata                   => {name => $channel,},
    }
  );
  is $mode_permission->{normalized_exception_mask},        'e!*@*', 'the exception mask is normalized through';
  is $mode_permission->{normalized_invite_exception_mask}, 'i!*@*', 'the invite exception mask is normalized through';
  is $mode_permission->{channel_key},                      'sekrit', 'the key is normalized through';
  is $mode_permission->{user_limit},                       5,        'the limit is normalized through';
  is $mode_permission->{group_metadata}{name},             $channel, 'the metadata is normalized through';

  my $action_permission = Overnet::Program::IRC::Server::_normalized_authoritative_channel_action_permission(
    {
      allowed        => 0,
      target_pubkey  => 'b' x 64,
      group_metadata => {name => $channel,},
    }
  );
  is $action_permission->{target_pubkey}, 'b' x 64, 'the action target is normalized through';
};

subtest 'actor pubkeys, roles, and grants guard their inputs' => sub {
  my $server = _server();
  is $server->_effective_authoritative_actor_pubkey_from_event('nope'), undef,
    'a malformed event has no actor';
  is $server->_effective_authoritative_actor_pubkey_from_event({tags => [['overnet_actor', '9' x 64],],}),
    '9' x 64, 'the overnet_actor tag wins';
  is $server->_effective_authoritative_actor_pubkey_from_event(
    {tags => [['overnet_actor', 'nothex'],], pubkey => '8' x 64,}
  ), '8' x 64, 'a malformed actor tag falls back to the event pubkey';
  is $server->_effective_authoritative_actor_pubkey_from_event({tags => [], pubkey => 'nothex',}), undef,
    'a malformed event pubkey has no actor';

  my $unregistered = $server->add_client(1, nick => 'sleepy', authority_pubkey => 'a' x 64,);
  my $nickless     = $server->add_client(2, registered => 1, authority_pubkey => 'b' x 64,);
  $server->request_handler(sub { return {events => [],} });
  is $server->_authoritative_nick_for_pubkey('a' x 64), undef,
    'an unregistered client does not answer nick lookups';
  is $server->_authoritative_nick_for_pubkey('b' x 64), undef,
    'a nickless client does not answer nick lookups';

  is $server->_authoritative_member_for_pubkey('nope', 'a' x 64), undef,
    'a malformed state has no members';
  is $server->_authoritative_member_for_pubkey({members => [],}, q{}), undef,
    'an empty pubkey matches no member';
  is $server->_authoritative_member_for_pubkey({members => ['nope', {roles => [],},],}, 'a' x 64), undef,
    'malformed members never match';

  is [$server->_authoritative_roles_for_client($channel, {})], [],
    'a client without a pubkey has no roles';
  is [$server->_authoritative_retained_roles_for_client($channel, {})], [],
    'a client without a pubkey has no retained roles';

  my $stateless = _server();
  $stateless->request_handler(sub { return {} });
  my $keyed = $stateless->add_client(1, nick => 'keyed', registered => 1, authority_pubkey => 'a' x 64,);
  is [$stateless->_authoritative_roles_for_client($channel, $keyed)], [],
    'a stateless channel grants no roles';
  is [$stateless->_authoritative_retained_roles_for_client($channel, $keyed)], [],
    'a stateless channel grants no retained roles';
  ok !$stateless->_client_has_authoritative_voice($channel, $keyed), 'a stateless channel grants no voice';
  ok !$stateless->_channel_is_moderated_for_client($channel, $keyed),
    'a stateless channel is not moderated';
  ok !$stateless->_channel_is_topic_restricted_for_client($channel, $keyed),
    'a stateless channel is not topic restricted';

  my $voiced = _local_authority_server();
  my $vclient = _client($voiced, 1, 'vicky', authority_pubkey => 'a' x 64,);
  _local_authority_handler(
    $voiced,
    view => {
      members => [
        {pubkey => 'a' x 64, roles => ['irc.voice'],},
        {pubkey => 'b' x 64, roles => ['irc.operator'],},
      ],
      channel_modes => 'mt',
    },
  );
  ok $voiced->_client_has_authoritative_voice($channel, $vclient), 'a voiced member has voice';
  ok !$voiced->_channel_is_moderated_for_client($channel, $vclient),
    'a voiced member is not muted by moderation';
  ok $voiced->_channel_is_topic_restricted_for_client($channel, $vclient),
    'a non-operator is topic restricted under +t';

  my $muted = _local_authority_server();
  my $mclient = _client($muted, 1, 'mute', authority_pubkey => 'c' x 64,);
  _local_authority_handler($muted, view => {members => [], channel_modes => 'm',},);
  ok $muted->_channel_is_moderated_for_client($channel, $mclient), 'a plain member is muted under +m';

  is $server->_authoritative_irc_mask_for_client('nope'), undef, 'a malformed client has no mask';
  is $server->_authoritative_irc_mask_for_client({}),     undef, 'a nickless client has no mask';
  like $server->_authoritative_irc_mask_for_client({nick => 'solo',}), qr/\Asolo!solo@/mxs,
    'a userless client masks with its nick';
};

subtest 'authoritative commands run against the local runtime stream' => sub {
  my $view = {
    members => [{pubkey => 'a' x 64, roles => ['irc.operator'], presentational_prefix => '@',},],
    channel_modes => 'nt',
  };
  my $server = _local_authority_server();
  my $alice  = _client($server, 1, 'alice', authority_pubkey => 'a' x 64,);
  my $bob    = _client($server, 2, 'bob',   authority_pubkey => 'b' x 64,);
  $server->_add_client_to_channel($_, $channel) for 1, 2;
  _local_authority_handler(
    $server,
    view                                    => $view,
    authoritative_topic_permission          => {permission => [{allowed => 1, reason => q{},},],},
    authoritative_mode_write_permission     => {permission => [{allowed => 1, reason => q{},},],},
    authoritative_channel_action_permission => {
      permission => [{allowed => 1, reason => q{}, target_pubkey => 'b' x 64, group_metadata => {},},],
    },
    map_input => {},
  );

  ok $server->_handle_authoritative_topic_command(client_id => 1, channel => $channel, text => 'set locally',),
    'a local authoritative topic write is handled';
  like _lines($server, 2), qr/:alice\ TOPIC\ \Q$channel\E\ :set\ locally/mxs, 'the topic write is broadcast';
  is $server->{channels}{$server->_channel_key($channel)}{topic_text}, 'set locally',
    'the local topic state follows the write';

  $server->clear_sent_lines;
  ok $server->_handle_authoritative_delete_command(client_id => 1, channel => $channel,),
    'a local authoritative delete is handled';
  like _lines($server, 1), qr/OVERNETCHANNEL\ DELETE/mxs, 'the delete is confirmed';

  ok $server->_handle_authoritative_undelete_command(client_id => 1, channel => $channel,),
    'a local authoritative undelete is handled';

  $server->clear_sent_lines;
  ok $server->_handle_authoritative_kick_command(client_id => 1, channel => $channel, params => [$channel, 'bob'],),
    'a local authoritative kick is handled';
  like _lines($server, 1), qr/KICK\ \Q$channel\E\ bob/mxs, 'the kick is broadcast';

  $server->_add_client_to_channel(2, $channel);
  $server->clear_sent_lines;
  ok $server->_handle_authoritative_invite_command(
    client_id   => 1,
    channel     => $channel,
    target_nick => 'bob',
  ), 'a local authoritative invite is handled';
  like _lines($server, 2), qr/INVITE\ bob/mxs, 'the invite reaches the target';

  $server->clear_sent_lines;
  ok $server->_handle_authoritative_part_command(client_id => 1, channel => $channel, reason => 'off',),
    'a local authoritative part is handled';
  like _lines($server, 2), qr/:alice\ PART\ \Q$channel\E\ :off/mxs, 'the part is broadcast';

  ok $server->_handle_authoritative_mode_command(
    client_id => 1,
    channel   => $channel,
    params    => [$channel, '+m'],
  ), 'a local authoritative mode write is handled';

  is $server->_handle_authoritative_mode_command(client_id => 1, channel => $channel, params => [$channel],), 1,
    'a mode write without a mode asks for more parameters';

  is $server->_handle_authoritative_part_command(client_id => 99, channel => $channel,), 0,
    'an unknown part client is rejected';
  is $server->_handle_authoritative_topic_command(client_id => 99, channel => $channel, text => 'x',), 0,
    'an unknown topic client is rejected';
  is $server->_handle_authoritative_delete_command(client_id => 99, channel => $channel,), 0,
    'an unknown delete client is rejected';
  is $server->_handle_authoritative_undelete_command(client_id => 99, channel => $channel,), 0,
    'an unknown undelete client is rejected';
  is $server->_handle_authoritative_kick_command(client_id => 99, channel => $channel, params => [],), 0,
    'an unknown kick client is rejected';
  is $server->_handle_authoritative_invite_command(client_id => 99, channel => $channel, target_nick => 'x',), 0,
    'an unknown invite client is rejected';
  is $server->_handle_authoritative_invites_command(client_id => 99, channel => $channel,), 0,
    'an unknown invites client is rejected';
  is $server->_handle_authoritative_requests_command(client_id => 99, channel => $channel,), 0,
    'an unknown requests client is rejected';

  my $stateless = _local_authority_server();
  _client($stateless, 1, 'alice', authority_pubkey => 'a' x 64,);
  $stateless->_add_client_to_channel(1, $channel);
  $stateless->request_handler(sub { return {} });
  is $stateless->_handle_authoritative_topic_command(client_id => 1, channel => $channel, text => 'x',), 1,
    'a stateless topic write needs privileges';
  like _lines($stateless, 1), qr/482/mxs, 'the stateless topic write is refused';
  $stateless->clear_sent_lines;
  is $stateless->_handle_authoritative_mode_command(
    client_id => 1,
    channel   => $channel,
    params    => [$channel, '+m'],
  ), 1, 'a stateless mode write needs privileges';
  like _lines($stateless, 1), qr/482/mxs, 'the stateless mode write is refused';

  my $anonymous = _local_authority_server();
  _client($anonymous, 1, 'alice');
  $anonymous->_add_client_to_channel(1, $channel);
  _local_authority_handler($anonymous, view => $view,);
  is $anonymous->_handle_authoritative_topic_command(client_id => 1, channel => $channel, text => 'x',), 1,
    'an unauthenticated topic write needs privileges';
};

subtest 'publish and emit guard their payload shapes' => sub {
  my $server = _server();
  my $key    = Overnet::Core::Nostr->generate_key;
  my $client = _client(
    $server, 1, 'alice',
    authority_pubkey            => 'a' x 64,
    authority_delegate_key      => $key,
    authority_delegate_event_id => 'b' x 64,
  );

  is $server->_publish_authoritative_input('nope', {}), 0, 'a malformed client publishes nothing';
  is $server->_publish_authoritative_input($client, 'nope'), 0, 'malformed input publishes nothing';

  $server->request_handler(
    sub {
      my (%args) = @_;
      return 'not-a-hash' if $args{method} eq 'adapters.map_input';
      return;
    }
  );
  is $server->_publish_authoritative_input($client, {command => 'JOIN', target => $channel,}), 0,
    'a malformed mapping fails the publish';
  is $server->{authoritative_publish_error}, 'authoritative relay mapping failed',
    'the mapping failure is recorded';

  $server->request_handler(sub { return {} });
  is $server->_publish_authoritative_input($client, {command => 'JOIN', target => $channel,}), 0,
    'a mapping without drafts fails the publish';
  is $server->{authoritative_publish_error}, 'authoritative relay mapping produced no event drafts',
    'the missing drafts are recorded';

  my $listy = _server();
  my $listy_client = _client(
    $listy, 1, 'alice',
    authority_pubkey            => 'a' x 64,
    authority_delegate_key      => $key,
    authority_delegate_event_id => 'b' x 64,
  );
  $listy->request_handler(
    sub {
      my (%args) = @_;
      if ($args{method} eq 'adapters.map_input') {
        return {
          events => [
            {kind => 9021, created_at => 1, content => q{}, tags => [['h', $group_id],],},
            'not-a-hash',
          ],
        };
      }
      if ($args{method} eq 'adapters.derive') {
        return {view => [{members => [],},],};
      }
      return;
    }
  );
  is $listy->_publish_authoritative_input($listy_client, {command => 'JOIN', target => $channel,}), 1,
    'mapped event lists publish each draft';

  my $mapped_result = _local_authority_server();
  my $mapped_client = _client($mapped_result, 1, 'alice', authority_pubkey => 'a' x 64,);
  $mapped_result->_add_client_to_channel(1, $channel);
  _local_authority_handler(
    $mapped_result,
    map_input => {
      events => [{kind => 9021, created_at => 1, content => q{}, tags => [['h', $group_id],],},],
    },
  );
  ok $mapped_result->_emit_client_input($mapped_client, {command => 'JOIN', target => $channel,}),
    'authoritative mapped events append to the runtime stream';
  ok scalar(grep { $_->{method} eq 'events.append' } @{$mapped_result->requests}),
    'the mapped event was appended';

  is $mapped_result->_handle_authoritative_mapped_result(
    client => $mapped_client,
    target => $channel,
    mapped => {events => [{kind => 1, created_at => 1, content => q{}, tags => [],},],},
  ), 0, 'non-authoritative mapped events are not intercepted';
  is $mapped_result->_handle_authoritative_mapped_result(
    client => $mapped_client,
    target => $channel,
    mapped => {event => {kind => 9021, tags => [['h', $group_id],],}, state => [],},
  ), 0, 'mapped results with state are not intercepted';
  is $mapped_result->_handle_authoritative_mapped_result(
    client => $mapped_client,
    target => $channel,
    mapped => 'nope',
  ), 0, 'malformed mapped results are not intercepted';
  is $mapped_result->_handle_authoritative_mapped_result(
    client => $mapped_client,
    target => 'bob',
    mapped => {},
  ), 0, 'non-channel targets are not intercepted';

  my $failing_append = _local_authority_server();
  my $failing_client = _client($failing_append, 1, 'alice', authority_pubkey => 'a' x 64,);
  $failing_append->_add_client_to_channel(1, $channel);
  $failing_append->request_handler(
    sub {
      my (%args) = @_;
      if ($args{method} eq 'adapters.map_input') {
        return {event => {kind => 9021, created_at => 1, content => q{}, tags => [['h', $group_id],],},};
      }
      if ($args{method} eq 'events.append') {
        die "stream unavailable\n";
      }
      if ($args{method} eq 'adapters.derive') {
        return {view => [{members => [],},],};
      }
      return;
    }
  );
  my $result = eval { $failing_append->_emit_client_input($failing_client, {command => 'JOIN', target => $channel,}) };
  ok !$result, 'a failed authoritative append fails the emit';

  is $server->_next_authoritative_delegate_sequence('nope'), undef,
    'a malformed client has no delegate sequence';
  my $keyless = {id => q{},};
  is $server->_next_authoritative_delegate_sequence($keyless), 1,
    'a client without a usable id still sequences';
  is $server->_next_authoritative_delegate_sequence($keyless), 2, 'the fallback sequence advances';
  is $server->_next_authoritative_created_at('nope'), D(), 'a malformed client still gets a timestamp';
  is $server->_next_authoritative_created_at({id => q{},}), D(),
    'a client without a usable id still gets a timestamp';
  my $first  = $server->_next_authoritative_created_at($client);
  my $second = $server->_next_authoritative_created_at($client);
  ok $second > $first, 'created_at values are strictly increasing per client';
};

subtest 'join admission edges refresh and reconcile' => sub {
  my $known = _server();
  $known->{authoritative_discovered_channels}{$channel} = {channel_name => $channel, group_id => 'g',};
  $known->request_handler(sub { return {events => [],} });
  my $client    = _client($known, 1, 'alice', authority_pubkey => 'a' x 64,);
  my $admission = $known->_authoritative_join_admission_for_client($channel, $client);
  is $admission->{allowed}, 0, 'a known channel without events denies the join';
  is $admission->{reason}, 'authoritative state unavailable', 'the unavailable state is reported';

  my $relay_invite = _server();
  my $invited = _client($relay_invite, 1, 'alice', authority_pubkey => 'a' x 64,);
  my @admissions = (
    {admission => [{allowed => 0, reason => '+i',},]},
    {admission => [{allowed => 1, member => 1, invite_code => 'f' x 64,},]},
  );
  $relay_invite->request_handler(
    sub {
      my (%args) = @_;
      if ($args{method} eq 'nostr.read_subscription_snapshot' || $args{method} eq 'nostr.query_events') {
        return {events => [_group_event()],};
      }
      if ($args{method} eq 'adapters.derive') {
        my $operation = $args{params}{operation};
        return {view => [{members => [],},]} if $operation eq 'authoritative_channel_view';
        return @admissions > 1 ? shift @admissions : $admissions[0]
          if $operation eq 'authoritative_join_admission';
        return {};
      }
      return;
    }
  );
  my $refreshed = $relay_invite->_authoritative_join_admission_for_client($channel, $invited);
  is $refreshed->{allowed},     1,        'an invite-only denial is refreshed against the relay';
  is $refreshed->{invite_code}, 'f' x 64, 'the refreshed admission carries the invite code';

  ok !$relay_invite->_needs_relay_invite_join_refresh({allowed => 1,}, 'a' x 64),
    'an allowed admission needs no refresh';
  ok !$relay_invite->_needs_relay_invite_join_refresh({allowed => 0, reason => 'other',}, 'a' x 64),
    'other denial reasons need no refresh';
  ok !$relay_invite->_needs_relay_invite_join_refresh(
    {allowed => 0, reason => '+i', invite_code => 'f' x 64,}, 'a' x 64,
  ), 'an admission with an invite code needs no refresh';
  ok !$relay_invite->_needs_relay_invite_join_refresh({allowed => 0, reason => '+i',}, undef),
    'an anonymous admission needs no refresh';
};

subtest 'list machinery falls back through view, state, and discovery' => sub {
  my $server = _server();
  is $server->_authoritative_list_visible_users($channel, {visible_users => 9,}, undef, undef), 9,
    'the list view count wins';
  is $server->_authoritative_list_visible_users($channel, {}, {present_members => [{}, {},],}, undef), 2,
    'the present members count follows';
  is $server->_authoritative_list_visible_users($channel, undef, undef, {members => {},}), 0,
    'the channel state count follows';
  is $server->_authoritative_list_visible_users($channel, undef, undef, undef), 0,
    'no sources count zero users';

  is $server->_authoritative_list_display_channel($channel, {channel => '#Pretty',}, undef), '#Pretty',
    'the list view name wins';
  is $server->_authoritative_list_display_channel($channel, {}, {channel_name => '#State',}), '#State',
    'the state name follows';
  $server->{authoritative_discovered_channels}{$channel} = {channel_name => '#Found',};
  is $server->_authoritative_list_display_channel($channel, undef, undef), '#Found',
    'the discovered name follows';
  is $server->_authoritative_list_display_channel('#other', undef, undef), '#other',
    'the raw channel name is the last resort';

  is $server->_authoritative_list_topic({topic => 'lv',}, undef, undef), 'lv', 'the list view topic wins';
  is $server->_authoritative_list_topic({}, {topic => 'v',}, undef), 'v', 'the view topic follows';
  is $server->_authoritative_list_topic(undef, undef, {topic_text => 's',}), 's', 'the state topic follows';
  is $server->_authoritative_list_topic(undef, undef, undef), q{}, 'no sources yield an empty topic';

  is $server->_local_list_entry_for_channel('nope'), undef, 'a malformed local state lists nothing';
  ok !Overnet::Program::IRC::Server::_list_member_client_is_visible({registered => 1,}),
    'a nickless member is invisible';

  my $plain = _plain_server();
  my $alice = _client($plain, 1, 'alice');
  $plain->_add_client_to_channel(1, $channel);
  $plain->{channels}{'#nameless'} = {channel_name => q{},};
  is [$plain->_list_channels('nochannel')], [$channel], 'malformed channel states are skipped';
  is [$plain->_list_channels($channel)],    [$channel], 'the target filter matches by key';
  is [$plain->_list_channels('#other')],    [],         'the target filter excludes other channels';
};

subtest 'subscription rendering and DM subscriptions cover their edges' => sub {
  my $server = _plain_server();
  my $alice  = _client($server, 1, 'alice');
  $server->_add_client_to_channel(1, $channel);

  is $server->_render_subscription_item(item_type => 'event', data => 'nope',), undef,
    'malformed data renders nothing';
  is $server->_render_subscription_item(item_type => 'event', data => {kind => 1,},), undef,
    'an invalid wire event renders nothing';

  my $dm_event = $server->{signing_key}->create_event_hash(
    kind       => 1,
    created_at => 1_000,
    content    => JSON::encode_json(
      {
        provenance => {external_identity => 'bob',},
        body       => {text => 'direct',},
      }
    ),
    tags => [
      ['overnet_ot',  'chat.dm'],
      ['overnet_oid', 'irc:overnet:dm:alice'],
      ['overnet_et',  'chat.dm_message'],
    ],
  );
  my $render = $server->_render_subscription_item(item_type => 'event', data => $dm_event,);
  like $render->{line}, qr/:bob\ PRIVMSG\ alice\ :direct/mxs, 'a DM wire event renders for the recipient';

  my $unroutable = $server->{signing_key}->create_event_hash(
    kind       => 1,
    created_at => 1_001,
    content    => JSON::encode_json({body => {},}),
    tags       => [['overnet_ot', 'mystery.object'],],
  );
  is $server->_render_subscription_item(item_type => 'event', data => $unroutable,), undef,
    'an unknown object type renders nothing';

  is Overnet::Program::IRC::Server::_channel_text_line('PRIVMSG', 'a', $channel, undef), undef,
    'a textless channel line renders nothing';
  is $server->_channel_topic_subscription_line('a', $channel, {}), undef,
    'a malformed topic renders nothing';

  is $server->_ensure_client_dm_subscription(99), undef, 'an unknown client opens no DM subscription';
  is $server->_ensure_client_dm_subscription(2), undef, 'a missing client opens no DM subscription';
  my $sleepy = $server->add_client(3, nick => 'sleepy',);
  is $server->_ensure_client_dm_subscription(3), undef,
    'an unregistered client opens no DM subscription';
  my $nickless = $server->add_client(4, registered => 1,);
  is $server->_ensure_client_dm_subscription(4), undef, 'a nickless client opens no DM subscription';

  my $first = $server->_ensure_client_dm_subscription(1);
  is $server->_ensure_client_dm_subscription(1), $first, 'a stable nick reuses the DM subscription';
  $alice->{nick} = 'newalice';
  my $second = $server->_ensure_client_dm_subscription(1);
  is $second, $first, 'the subscription id is stable per client';
  my @closes = grep { $_->{method} eq 'subscriptions.close' } @{$server->requests};
  is scalar(@closes), 1, 'the old DM subscription is closed on rename';

  is $server->_close_client_dm_subscription(99), 1, 'closing an unknown client subscription is a no-op';
  is $server->_close_client_dm_subscription(3),  1, 'closing an unopened subscription is a no-op';
  is $server->_close_channel_subscription(',bad'), 1, 'closing an invalid channel is a no-op';
  is $server->_close_channel_subscription('#empty'), 1, 'closing an unknown channel is a no-op';
  $server->{channels}{$server->_channel_key('#quiet')} = {channel_name => '#quiet', members => {},};
  is $server->_close_channel_subscription('#quiet'), 1, 'closing an unsubscribed channel is a no-op';

  is $server->_add_client_to_channel(99, $channel), 0, 'an unknown client joins nothing';
  is $server->_add_client_to_channel(1, ',bad'),    0, 'an invalid channel joins nothing';
  is $server->_remove_client_from_channel(1, ',bad'), 0, 'an invalid channel removes nothing';
  is $server->_remove_client_from_channel(1, '#empty'), 0, 'an unknown channel removes nothing';
  is $server->_disconnect_client(99), 1, 'disconnecting an unknown client is a no-op';

  is $server->_channel_object_id(',bad'), undef, 'an invalid channel has no object id';
  is $server->_client_joined_channel_name('nope', $channel), undef,
    'a malformed client joins no channels';
  is $server->_client_joined_channel_name($alice, ',bad'), undef,
    'an invalid channel name is never joined';
  is $server->_channel_state(',bad'), undef, 'an invalid channel has no state';
  is $server->_add_visible_nick($channel, undef), 0, 'an undefined nick is never visible';
  is $server->_remove_visible_nick($channel, undef), 0, 'an undefined nick is never removed';
  is $server->_remove_visible_nick(',bad', 'x'),      0, 'an invalid channel removes no nicks';
  is $server->_remove_visible_nick('#empty', 'x'),    0, 'an unknown channel removes no nicks';
  is $server->_remove_visible_nick($channel, 'ghost'), 0, 'an untracked nick removes nothing';
  is $server->_rename_visible_nick($channel, old_nick => undef, new_nick => 'x',), 0,
    'an undefined old nick renames nothing';
  is $server->_rename_visible_nick($channel, old_nick => 'x', new_nick => undef,), 0,
    'an undefined new nick renames nothing';
  is $server->_rename_visible_nick(',bad', old_nick => 'x', new_nick => 'y',), 0,
    'an invalid channel renames nothing';
  is $server->_rename_visible_nick('#empty', old_nick => 'x', new_nick => 'y',), 0,
    'an unknown channel renames nothing';
  is $server->_rename_visible_nick($channel, old_nick => 'ghost', new_nick => 'y',), 0,
    'an untracked nick renames nothing';
  is $server->_rename_client_channels('nope', old_nick => 'x', new_nick => 'y',), 0,
    'a malformed client renames nothing';
  is [$server->_visible_nicks_for_channel(',bad')], [], 'an invalid channel has no visible nicks';
  is [$server->_visible_nicks_for_channel('#empty')], [], 'an unknown channel has no visible nicks';

  is $server->_send_names_list(99, $channel), 0, 'an unknown client gets no names list';
  is $server->_send_names_list(1, ',bad'),    0, 'an invalid channel gets no names list';
  is $server->_send_join_bootstrap(1, ',bad'), 0, 'an invalid channel gets no bootstrap';
  is $server->_send_join_bootstrap(1, '#empty'), 0, 'an unknown channel gets no bootstrap';

  is $server->_channel_name_from_object_id(undef), undef, 'undefined object ids name no channel';
  is $server->_channel_name_from_object_id('other:prefix'), undef,
    'foreign object ids name no channel';
  is $server->_channel_name_from_object_id('irc:overnet:notachannel'), undef,
    'non-channel object ids name no channel';
  is $server->_dm_nick_from_object_id(undef), undef, 'undefined object ids name no nick';
  is $server->_dm_nick_from_object_id('other:prefix'), undef, 'foreign object ids name no nick';
  is $server->_dm_nick_from_object_id('irc:overnet:dm:,bad'), undef,
    'invalid nicks in object ids name no nick';

  is $server->_broadcast_channel_line(',bad', 'line'), 0, 'an invalid channel broadcasts nothing';
  is $server->_broadcast_channel_line('#empty', 'line'), 0, 'an unknown channel broadcasts nothing';
  is [$server->_shared_client_ids_for_channels([',bad', '#empty'],)], [],
    'invalid channels share no clients';
  is $server->_send_line_to_client_ids([99], 'line'), 0, 'unknown clients receive no lines';
};

subtest 'nick assignment and release guard their inputs' => sub {
  my $server = _plain_server();
  my $alice  = _client($server, 1, 'alice');

  ok !$server->_nick_in_use(',bad'), 'an invalid nick is never in use';
  ok !$server->_nick_in_use('ghost'), 'an unknown nick is not in use';
  is $server->_assign_client_nick(99, 'x'), 0, 'an unknown client gets no nick';
  is $server->_assign_client_nick(1, undef), 0, 'an undefined nick is never assigned';
  is $server->_release_client_nick(99, nick => 'x',), 0, 'an unknown client releases nothing';
  is $server->_send_nick_in_use(99, 'x'), 0, 'an unknown client gets no collision notice';

  my $bob = $server->add_client(2);
  is $server->_release_client_nick(2, nick => undef,), 0, 'a nickless client releases nothing';
  is $server->_release_client_nick(2, nick => ',bad',), 0, 'an invalid nick releases nothing';
  $server->{nick_to_client_id}{$server->_nick_key('alice')} = 1;
  is $server->_release_client_nick(2, nick => 'alice',), 0,
    'a nick owned by another client is not released';
};

subtest 'opaque transport and e2ee body guards reject bad shapes' => sub {
  my $server = _plain_server();
  my $alice  = _client(
    $server, 1, 'alice',
    capabilities => {'overnet-e2ee' => 1,},
    e2ee_pubkey  => 'a' x 64,
  );
  my $bob = _client(
    $server, 2, 'bob',
    capabilities => {'overnet-e2ee' => 1,},
    e2ee_pubkey  => 'd' x 64,
  );
  my $plainuser = _client($server, 3, 'carol');

  like dies {
    $server->_emit_opaque_private_message_transport(
      client => 'nope', command => 'PRIVMSG', target_nick => 'bob', body_text => 'x', transport => {},
    )
  }, qr/client\ is\ required/mxs, 'a malformed client croaks';
  like dies {
    $server->_emit_opaque_private_message_transport(
      client => $alice, command => 'FROB', target_nick => 'bob', body_text => 'x', transport => {},
    )
  }, qr/command\ must\ be/mxs, 'a malformed command croaks';
  like dies {
    $server->_emit_opaque_private_message_transport(
      client => $alice, command => 'PRIVMSG', target_nick => q{}, body_text => 'x', transport => {},
    )
  }, qr/target_nick\ is\ required/mxs, 'a missing target croaks';
  like dies {
    $server->_emit_opaque_private_message_transport(
      client => $alice, command => 'PRIVMSG', target_nick => 'bob', body_text => 'x', transport => 'nope',
    )
  }, qr/transport\ must\ be/mxs, 'a malformed transport croaks';
  like dies {
    $server->_emit_opaque_private_message_transport(
      client => $alice, command => 'PRIVMSG', target_nick => 'bob', body_text => q{}, transport => {},
    )
  }, qr/body_text\ is\ required/mxs, 'a missing body croaks';

  is $server->_emit_opaque_private_message_transport(
    client => $plainuser, command => 'PRIVMSG', target_nick => 'bob', body_text => 'x', transport => {},
  ), 0, 'an incapable sender is refused';
  like _lines($server, 3), qr/require\ CAP\ overnet-e2ee/mxs, 'the sender requirement is reported';

  is $server->_emit_opaque_private_message_transport(
    client => $alice, command => 'PRIVMSG', target_nick => 'carol', body_text => 'x', transport => {},
  ), 0, 'an incapable recipient is refused';
  like _lines($server, 1), qr/not\ E2EE-capable/mxs, 'the recipient requirement is reported';

  is $server->_emit_opaque_private_message_transport(
    client => $alice, command => 'PRIVMSG', target_nick => 'bob', body_text => 'x', transport => {kind => 1059,},
  ), 0, 'an unvalidatable transport is refused';
  like _lines($server, 1), qr/Malformed\ overnet-e2ee\ transport/mxs, 'the malformed transport is reported';

  my $sender_key = Overnet::Core::Nostr->generate_key;
  my $wrong_kind = $sender_key->create_event_hash(
    kind       => 1,
    created_at => 1,
    content    => 'x',
    tags       => [['p', 'd' x 64],],
  );
  $server->clear_sent_lines;
  is $server->_emit_opaque_private_message_transport(
    client => $alice, command => 'PRIVMSG', target_nick => 'bob', body_text => 'x', transport => $wrong_kind,
  ), 0, 'a non-1059 transport is refused';
  like _lines($server, 1), qr/kind\ 1059/mxs, 'the wrong kind is reported';

  my $wrong_recipient = $sender_key->create_event_hash(
    kind       => 1059,
    created_at => 1,
    content    => 'x',
    tags       => [['p', 'f' x 64],],
  );
  $server->clear_sent_lines;
  is $server->_emit_opaque_private_message_transport(
    client => $alice, command => 'PRIVMSG', target_nick => 'bob', body_text => 'x', transport => $wrong_recipient,
  ), 0, 'a mismatched recipient is refused';
  like _lines($server, 1), qr/does\ not\ match\ the\ target\ nick/mxs, 'the recipient mismatch is reported';

  my ($undef_transport, $error, $flag) = $server->_decode_e2ee_dm_body(undef);
  is $flag, 0, 'an undefined body is not e2ee';
  ($undef_transport, $error, $flag) = $server->_decode_e2ee_dm_body('plain text');
  is $flag, 0, 'a plain body is not e2ee';
  ($undef_transport, $error, $flag) = $server->_decode_e2ee_dm_body('+overnet-e2ee-v1 ');
  like $error, qr/missing\ transport\ payload/mxs, 'an empty payload is reported';
  ($undef_transport, $error, $flag) = $server->_decode_e2ee_dm_body('+overnet-e2ee-v1 aGk=');
  like $error, qr/transport\ JSON\ is\ invalid/mxs, 'non-JSON payloads are reported';
  like dies { $server->_encode_e2ee_dm_body('nope') }, qr/transport\ must\ be\ an\ object/mxs,
    'encoding a malformed transport croaks';

  ok !$server->_is_private_message_candidate({tags => [],}), 'untagged events are not DM candidates';
  ok !$server->_is_private_message_candidate(
    {tags => [['overnet_ot', 'chat.dm'], ['overnet_et', 'chat.message'],],}
  ), 'non-DM event types are not DM candidates';
  ok $server->_is_private_message_candidate(
    {tags => [['overnet_ot', 'chat.dm'], ['overnet_et', 'chat.dm_notice'],],}
  ), 'DM notices are DM candidates';

  my $mapped_dm = _plain_server();
  my $sender = _client($mapped_dm, 1, 'alice');
  my $friend = _client($mapped_dm, 2, 'bob');
  $mapped_dm->request_handler(
    sub {
      my (%args) = @_;
      if ($args{method} eq 'adapters.map_input') {
        return {
          events => [
            {
              kind       => 1,
              created_at => 1,
              content    => JSON::encode_json(
                {
                  provenance => {external_identity => 'alice',},
                  body       => {text => 'hi',},
                }
              ),
              tags => [
                ['overnet_ot',  'chat.dm'],
                ['overnet_oid', 'irc:overnet:dm:bob'],
                ['overnet_et',  'chat.dm_message'],
              ],
            },
          ],
        };
      }
      return;
    }
  );
  ok $mapped_dm->_emit_client_input($sender, {command => 'PRIVMSG', target => 'bob', text => 'hi',}),
    'a mapped DM candidate emits through the input pipeline';
  ok scalar(grep { $_->{method} eq 'overnet.emit_private_message' } @{$mapped_dm->requests}),
    'the mapped DM candidate is emitted as a private message';
};

subtest 'outbound decoration and tag parsing cover their corners' => sub {
  my $server = _plain_server();
  my $alice  = _client(
    $server, 1, 'alice',
    capabilities => {'account-tag' => 1, 'message-tags' => 1,},
  );
  my $bob = _client($server, 2, 'bob', authority_pubkey => 'b' x 64,);

  my $tagged = $server->_decorate_outbound_line_for_client($alice, ':bob PRIVMSG alice :hi');
  like $tagged, qr/\A\@account=b{64}\ :bob/mxs, 'account tags decorate without server-time';

  is $server->_decorate_outbound_line_for_client($alice, 'PING :x'), 'PING :x',
    'unprefixed lines carry no account tag';
  like $server->_decorate_outbound_line_for_client($alice, ':bob!x@y QUIT'), qr/account=b{64}/mxs,
    'full-mask prefixes from known senders carry the account tag';

  is {$server->_first_tag_values([['a'], 'nope', ['b', 1], ['b', 2],])},
    {b => 1,}, 'first tag values skip malformed tags and keep the first value';

  my $nip29 = _server();
  ok scalar(grep { $_ eq 'sasl' } $nip29->_supported_capabilities),
    'the nip29 capability set advertises sasl';
  ok !scalar(grep { $_ eq 'sasl' } $server->_supported_capabilities),
    'plain profiles do not advertise sasl';
  like $server->_isupport_tokens, qr/NETWORK=overnet/mxs, 'isupport tokens name the network';
};

done_testing;
