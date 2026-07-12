use strictures 2;

use File::Spec;
use FindBin;
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
my $alice_pubkey = 'a' x 64;
my $bob_pubkey   = 'b' x 64;
my $carol_pubkey = 'c' x 64;
my $ghost_pubkey = 'd' x 64;

sub _server {
  my (%overrides) = @_;
  my $server = TestIRCServer->new;
  $server->configure(%overrides);
  $server->{signing_key}        = Overnet::Core::Nostr->generate_key;
  $server->{adapter_session_id} = 'adapter-session-1';
  return $server;
}

sub _joined_server {
  my $server = _server();
  $server->add_client(
    1,
    nick             => 'alice',
    username         => 'alice',
    registered       => 1,
    authority_pubkey => $alice_pubkey,
  );
  $server->add_client(
    2,
    nick             => 'bob',
    username         => 'bob',
    registered       => 1,
    authority_pubkey => $bob_pubkey,
  );
  $server->add_client(
    3,
    nick             => 'carol',
    username         => 'carol',
    registered       => 1,
    authority_pubkey => $carol_pubkey,
  );
  $server->{nick_to_client_id}{$server->_nick_key('alice')} = 1;
  $server->{nick_to_client_id}{$server->_nick_key('bob')}   = 2;
  $server->{nick_to_client_id}{$server->_nick_key('carol')} = 3;
  $server->_add_client_to_channel($_, $channel) for 1 .. 3;
  return $server;
}

sub _apply {
  my ($server, $event, $old_view, $new_view) = @_;
  return $server->_apply_authoritative_channel_cache_update(
    channel   => $channel,
    event     => $event,
    old_view  => $old_view,
    new_view  => $new_view,
    old_state => $server->_authoritative_channel_state_from_view($old_view),
    new_state => $server->_authoritative_channel_state_from_view($new_view),
  );
}

sub _lines {
  my ($server, $client_id) = @_;
  return join "\n", @{$server->lines_for($client_id)};
}

sub _grant_event {
  my (%fields) = @_;
  return {
    id         => delete($fields{id}) || ('e' x 64),
    kind       => 14_142,
    created_at => delete($fields{created_at}) || 100,
    pubkey     => delete($fields{pubkey}) || $ghost_pubkey,
    content    => q{},
    tags       => delete($fields{tags}) || [
      ['relay', 'ws://127.0.0.1:7448'],
      ['nick',  'zoe'],
    ],
    %fields,
  };
}

subtest 'grant events map pubkeys to nicks' => sub {
  my $server = _joined_server();
  $server->request_handler(
    sub {
      my (%args) = @_;
      return {
        events => [
          _grant_event(id => '1' x 64, created_at => 100, tags => [['relay', 'ws://127.0.0.1:7448'], ['nick', 'zoe'],],),
          _grant_event(id => '2' x 64, created_at => 300, tags => [['relay', 'ws://127.0.0.1:7448'], ['nick', 'zoey'],],),
          _grant_event(id => '3' x 64, created_at => 200, tags => [['relay', 'ws://127.0.0.1:7448'], ['nick', 'stale'],],),
          _grant_event(id => '4' x 64, tags => [['relay', 'ws://other.example'], ['nick', 'wrong'],],),
          _grant_event(id => '5' x 64, tags => [['relay', 'ws://127.0.0.1:7448'],],),
          _grant_event(
            id   => '6' x 64,
            tags => [['relay', 'ws://127.0.0.1:7448'], ['nick', 'gone'], ['expires_at', 10],],
          ),
          _grant_event(id => '7' x 64, kind   => 1,),
          _grant_event(id => '8' x 64, pubkey => 'nothex',),
          bless({created_at => 1,}, 'NotAPlainHash'),
        ],
      } if $args{method} eq 'nostr.read_subscription_snapshot';
      return;
    }
  );

  is $server->_authoritative_nick_for_pubkey(undef),    undef, 'an undefined pubkey has no nick';
  is $server->_authoritative_nick_for_pubkey('nothex'), undef, 'a malformed pubkey has no nick';
  is $server->_authoritative_nick_for_pubkey($alice_pubkey), 'alice', 'a local client wins the nick lookup';
  is $server->_authoritative_nick_for_pubkey($ghost_pubkey), 'zoey',
    'the newest usable grant names a remote pubkey';
  is $server->_authoritative_nick_for_pubkey('f' x 64), undef, 'an unknown pubkey has no nick';
  is $server->_authoritative_nick_for_pubkey($ghost_pubkey), 'zoey', 'the grant nick map is cached';

  ok !Overnet::Program::IRC::Server::_authoritative_grant_is_expired('soon'),
    'a non-numeric expiry never expires';
  ok Overnet::Program::IRC::Server::_authoritative_grant_is_expired(10), 'a past expiry is expired';
  ok !Overnet::Program::IRC::Server::_hex_pubkey([]), 'a reference is not a hex pubkey';
};

subtest 'topic lines and topic state track the authoritative view' => sub {
  my $server = _joined_server();
  is $server->_authoritative_topic_line_from_view($channel, 'nope'), undef,
    'a malformed view renders no topic line';
  is $server->_authoritative_topic_line_from_view($channel, {}), undef,
    'a view without a topic renders no topic line';
  is $server->_authoritative_topic_line_from_view('nochannel', {topic => 'x',}), undef,
    'an invalid channel renders no topic line';

  is $server->_authoritative_topic_line_from_view($channel, {topic => 'greetings',}),
    ":irc.example.test TOPIC $channel :greetings", 'a topic without an actor comes from the server';
  is $server->_authoritative_topic_line_from_view(
    $channel,
    {
      topic              => 'greetings',
      topic_actor_pubkey => $alice_pubkey,
    }
  ), ":alice TOPIC $channel :greetings", 'a topic actor resolves to the local nick';

  is $server->_sync_authoritative_topic_state_from_view('nochannel', {}), 0,
    'an invalid channel syncs nothing';
  ok $server->_sync_authoritative_topic_state_from_view($channel, {topic => 'greetings',}),
    'a topic view syncs the channel state';
  my $state = $server->{channels}{$server->_channel_key($channel)};
  is $state->{topic_text}, 'greetings', 'the topic text is stored';
  ok $server->_sync_authoritative_topic_state_from_view($channel, {}), 'a topicless view syncs the state';
  is $state->{topic_text}, undef, 'the topic text is cleared';
  ok $server->_sync_authoritative_topic_state_from_view($channel, {tombstoned => 1,}),
    'a tombstoned view syncs the state';
  is $state->{topic_line}, undef, 'a tombstoned view clears the topic line';
};

subtest 'cache updates broadcast mode, ban, invite, and topic changes' => sub {
  my $server = _joined_server();

  is $server->_apply_authoritative_channel_cache_update(channel => 'nochannel', event => {},), 0,
    'an invalid channel applies nothing';
  is $server->_apply_authoritative_channel_cache_update(channel => $channel, event => 'nope',), 0,
    'a malformed event applies nothing';

  my $mode_event = {
    id         => '1' x 64,
    kind       => 9_002,
    created_at => 100,
    pubkey     => $alice_pubkey,
    content    => q{},
    tags       => [['h', $group_id],],
  };
  ok _apply(
    $server, $mode_event,
    {channel_modes => '+n',  members => [],},
    {channel_modes => 'imt', members => [], ban_masks => ['bad!*@*'],},
  ), 'a mode event applies';
  like _lines($server, 2), qr/:alice\ MODE\ \Q$channel\E\ [+]i/mxs, 'the +i flag is broadcast';
  like _lines($server, 2), qr/[+]m/mxs, 'the +m flag is broadcast';
  like _lines($server, 2), qr/[+]t/mxs, 'the +t flag is broadcast';
  like _lines($server, 2), qr/MODE\ \Q$channel\E\ [+]b\ bad!\*@\*/mxs, 'the new ban mask is broadcast';

  $server->clear_sent_lines;
  ok _apply(
    $server, $mode_event,
    {channel_modes => 'imt', members => [], ban_masks => ['bad!*@*'],},
    {channel_modes => 'n',   members => [],},
  ), 'a mode removal applies';
  like _lines($server, 2), qr/-i/mxs, 'the -i flag is broadcast';
  like _lines($server, 2), qr/MODE\ \Q$channel\E\ -b\ bad!\*@\*/mxs, 'the removed ban mask is broadcast';

  $server->clear_sent_lines;
  my $invite_event = {
    id         => '2' x 64,
    kind       => 9009,
    created_at => 200,
    pubkey     => $alice_pubkey,
    content    => q{},
    tags       => [['h', $group_id], ['code', 'f' x 64], ['p', $bob_pubkey],],
  };
  my $invite_view = {
    members         => [],
    pending_invites => [{code => 'f' x 64, target_pubkey => $bob_pubkey,},],
  };
  ok _apply($server, $invite_event, {members => [],}, $invite_view), 'an invite event applies';
  like _lines($server, 2), qr/:alice\ INVITE\ bob\ :\Q$channel\E/mxs, 'the invited client hears the invite';
  is _lines($server, 3), q{}, 'other clients hear nothing';
  $server->clear_sent_lines;
  ok _apply($server, $invite_event, {members => [],}, $invite_view), 'a repeated invite event applies';
  is _lines($server, 2), q{}, 'a repeated invite code is not resent';
  ok _apply($server, $invite_event, $invite_view, $invite_view), 'an already-pending invite applies';
  ok _apply(
    $server,
    {%{$invite_event}, tags => [['h', $group_id],],},
    {members => [],},
    $invite_view,
  ), 'an invite event without a code applies';

  $server->clear_sent_lines;
  my $meta_event = {
    id         => '3' x 64,
    kind       => 39_000,
    created_at => 300,
    pubkey     => $alice_pubkey,
    content    => q{},
    tags       => [['d', $group_id],],
  };
  ok _apply(
    $server, $meta_event,
    {members => [],},
    {
      members            => [],
      topic              => 'brand new',
      topic_actor_pubkey => $alice_pubkey,
    },
  ), 'a topic change applies';
  like _lines($server, 2), qr/:alice\ TOPIC\ \Q$channel\E\ :brand\ new/mxs, 'the topic change is broadcast';
};

subtest 'cache updates broadcast joins, kicks, parts, and tombstones' => sub {
  my $server = _joined_server();

  my $join_event = {
    id         => '4' x 64,
    kind       => 9021,
    created_at => 400,
    pubkey     => $ghost_pubkey,
    content    => q{},
    tags       => [['h', $group_id],],
  };
  ok _apply(
    $server, $join_event,
    {members => [], present_members => [],},
    {members => [], present_members => [{pubkey => $ghost_pubkey,},],},
  ), 'a remote join event applies';
  like _lines($server, 1), qr/:irc\.example\.test\ JOIN\ \Q$channel\E/mxs,
    'a remote join without a known nick is announced by the server';

  $server->clear_sent_lines;
  ok _apply(
    $server,
    {%{$join_event}, id => '5' x 64, pubkey => $alice_pubkey,},
    {members => [], present_members => [],},
    {members => [], present_members => [{pubkey => $alice_pubkey,},],},
  ), 'a local join event applies';
  is _lines($server, 2), q{}, 'a join by a local client is not rebroadcast';

  $server->clear_sent_lines;
  my $kick_event = {
    id         => '6' x 64,
    kind       => 9001,
    created_at => 500,
    pubkey     => $alice_pubkey,
    content    => 'flooding',
    tags       => [['h', $group_id], ['p', $bob_pubkey],],
  };
  ok _apply(
    $server, $kick_event,
    {members => [], present_members => [{pubkey => $bob_pubkey,},],},
    {members => [], present_members => [],},
  ), 'a kick event applies';
  like _lines($server, 3), qr/:alice\ KICK\ \Q$channel\E\ bob\ :flooding/mxs, 'the kick is broadcast';
  ok !$server->{clients}{2}{joined_channels}{$server->_channel_key($channel)}, 'the kicked client is removed';

  $server->clear_sent_lines;
  my $part_event = {
    id         => '7' x 64,
    kind       => 9022,
    created_at => 600,
    pubkey     => $carol_pubkey,
    content    => q{},
    tags       => [['h', $group_id],],
  };
  ok _apply(
    $server, $part_event,
    {members => [], present_members => [{pubkey => $carol_pubkey,},],},
    {members => [], present_members => [],},
  ), 'a part event applies';
  like _lines($server, 1), qr/:carol\ PART\ \Q$channel\E/mxs, 'the part is broadcast';
  ok !$server->{clients}{3}{joined_channels}{$server->_channel_key($channel)}, 'the parted client is removed';

  $server->clear_sent_lines;
  ok _apply(
    $server,
    {%{$part_event}, id => '8' x 64, pubkey => $ghost_pubkey,},
    {members => [], present_members => [{pubkey => $ghost_pubkey,},],},
    {members => [], present_members => [],},
  ), 'a remote part event applies';
  like _lines($server, 1), qr/PART\ \Q$channel\E/mxs, 'the remote part is broadcast';

  ok _apply(
    $server,
    {id => '9' x 64, kind => 39_000, created_at => 700, content => q{}, tags => [['d', $group_id],],},
    {members => [],},
    {members => [], tombstoned => 1,},
  ), 'a tombstone view applies';
  like _lines($server, 1), qr/PART\ \Q$channel\E\ :channel\ deleted/mxs, 'the tombstone parts the members';
  ok !$server->{channels}{$server->_channel_key($channel)}, 'the channel state is removed';

  is $server->_apply_authoritative_channel_tombstone('nochannel'), 0,
    'an invalid channel cannot be tombstoned';
  ok $server->_apply_authoritative_channel_tombstone($channel), 'tombstoning a stateless channel succeeds';
};

subtest 'join admissions fall back to the authoritative view' => sub {
  my %view_case = (
    'view admission' => {
      view => {
        admission       => {allowed => 1, member => 1, request_join => 0, pending_request => 0, deleted => 0,},
        present_members => [{pubkey => $alice_pubkey,},],
      },
      check => {allowed => 1, member => 1, present => 1,},
    },
    'tombstoned view' => {
      view  => {tombstoned => 1,},
      check => {allowed => 0, deleted => 1,},
    },
    'invite-only state' => {
      view  => {members => [], channel_modes => 'i',},
      check => {allowed => 0, reason => '+i',},
    },
    'open state' => {
      view  => {members => [], channel_modes => 'n',},
      check => {allowed => 1,},
    },
  );
  for my $case (sort keys %view_case) {
    my $server = _joined_server();
    my $view   = $view_case{$case}{view};
    $server->request_handler(
      sub {
        my (%args) = @_;
        if ($args{method} eq 'nostr.read_subscription_snapshot' || $args{method} eq 'nostr.query_events') {
          return {
            events => [
              {
                id         => 'e' x 64,
                kind       => 39_000,
                created_at => 100,
                pubkey     => $carol_pubkey,
                content    => q{},
                tags       => [['d', $group_id],],
              },
            ],
          };
        }
        if ($args{method} eq 'adapters.derive') {
          my $operation = $args{params}{operation};
          return {view => [$view]} if $operation eq 'authoritative_channel_view';
          return {};
        }
        return;
      }
    );
    my $admission = $server->_authoritative_join_admission_for_client($channel, $server->{clients}{1});
    for my $field (sort keys %{$view_case{$case}{check}}) {
      is $admission->{$field}, $view_case{$case}{check}{$field}, "the $case admission reports $field";
    }
  }

  my $anonymous = _joined_server();
  $anonymous->request_handler(
    sub {
      my (%args) = @_;
      if ($args{method} eq 'nostr.read_subscription_snapshot' || $args{method} eq 'nostr.query_events') {
        return {
          events => [
            {
              id         => 'e' x 64,
              kind       => 39_000,
              created_at => 100,
              pubkey     => $carol_pubkey,
              content    => q{},
              tags       => [['d', $group_id],],
            },
          ],
        };
      }
      if ($args{method} eq 'adapters.derive') {
        return {view => [{members => [], channel_modes => 'n',},]}
          if $args{params}{operation} eq 'authoritative_channel_view';
        return {};
      }
      return;
    }
  );
  my $admission =
    $anonymous->_authoritative_join_admission_for_client($channel, $anonymous->add_client(9, nick => 'newbie',));
  is $admission->{allowed}, 1, 'an anonymous client falls back to the plain view';
};

subtest 'mode and action permissions fall back to derived state' => sub {
  my $operator_view = {
    members => [
      {pubkey => $alice_pubkey, roles => ['irc.operator'],},
      {pubkey => $bob_pubkey,   roles => ['irc.voice'],},
    ],
    retained_members => [{pubkey => $alice_pubkey, roles => ['irc.operator'],},],
    channel_modes    => 'nt',
    ban_masks        => ['bad!*@*'],
  };

  my $viewless = _joined_server();
  $viewless->request_handler(sub { return {} });
  is $viewless->_authoritative_mode_write_permission_for_client($channel, $viewless->{clients}{1}, mode => '+m',),
    {allowed => 0, reason => 'state_unavailable',}, 'missing state blocks mode writes';
  is $viewless->_authoritative_channel_action_permission_for_client(
    $channel, $viewless->{clients}{1}, action => 'delete',
  ), {allowed => 0, reason => 'state_unavailable',}, 'missing state blocks channel actions';

  my $server = _joined_server();
  $server->request_handler(
    sub {
      my (%args) = @_;
      if ($args{method} eq 'nostr.read_subscription_snapshot' || $args{method} eq 'nostr.query_events') {
        return {
          events => [
            {
              id         => 'e' x 64,
              kind       => 39_000,
              created_at => 100,
              pubkey     => $carol_pubkey,
              content    => q{},
              tags       => [['d', $group_id],],
            },
          ],
        };
      }
      if ($args{method} eq 'adapters.derive') {
        return {view => [$operator_view]} if $args{params}{operation} eq 'authoritative_channel_view';
        return {};
      }
      return;
    }
  );

  my $alice = $server->{clients}{1};
  my $carol = $server->{clients}{3};

  my $role_permission = $server->_authoritative_mode_write_permission_for_client(
    $channel, $alice,
    mode      => '+o',
    mode_args => [$bob_pubkey],
  );
  is $role_permission->{allowed},       1,             'an operator may write role modes';
  is $role_permission->{target_pubkey}, $bob_pubkey,   'the role target pubkey is attached';
  is $role_permission->{current_roles}, ['irc.voice'], 'the current roles are attached';

  my $mask_permission = $server->_authoritative_mode_write_permission_for_client(
    $channel, $alice,
    mode      => '+b',
    mode_args => ['lurker!*@*'],
  );
  is $mask_permission->{normalized_ban_mask}, 'lurker!*@*', 'the ban mask is attached';
  is $mask_permission->{group_metadata}{topic_restricted}, 1, 'the group metadata reflects the modes';

  my $key_permission = $server->_authoritative_mode_write_permission_for_client(
    $channel, $alice,
    mode      => '+k',
    mode_args => ['sekrit'],
  );
  is $key_permission->{channel_key}, 'sekrit', 'the channel key is attached';

  my $limit_permission = $server->_authoritative_mode_write_permission_for_client(
    $channel, $alice,
    mode      => '+l',
    mode_args => ['25'],
  );
  is $limit_permission->{user_limit}, 25, 'the user limit is attached';

  my $clear_permission = $server->_authoritative_mode_write_permission_for_client(
    $channel, $alice,
    mode      => '-k',
    mode_args => [],
  );
  ok $clear_permission->{group_metadata}, 'clearing a key attaches the group metadata';

  is $server->_authoritative_mode_write_permission_for_client($channel, $carol, mode => '+m',)->{reason},
    'not_operator', 'a non-operator may not write modes';

  my $delete_permission =
    $server->_authoritative_channel_action_permission_for_client($channel, $alice, action => 'delete',);
  is $delete_permission->{allowed}, 1, 'an operator may delete the channel';
  ok $delete_permission->{group_metadata}, 'the delete permission carries the group metadata';

  my $kick_permission = $server->_authoritative_channel_action_permission_for_client(
    $channel, $alice,
    action        => 'kick',
    target_pubkey => $bob_pubkey,
  );
  is $kick_permission->{target_pubkey}, $bob_pubkey, 'the kick permission carries the target';

  is $server->_authoritative_channel_action_permission_for_client($channel, $carol, action => 'kick',)->{reason},
    'not_operator', 'a non-operator may not act on the channel';
  is $server->_authoritative_channel_action_permission_for_client($channel, $alice, action => 'undelete',)->{reason},
    'not_deleted', 'a live channel cannot be undeleted';

  my $tombstoned = _joined_server();
  $tombstoned->request_handler(
    sub {
      my (%args) = @_;
      if ($args{method} eq 'nostr.read_subscription_snapshot' || $args{method} eq 'nostr.query_events') {
        return {
          events => [
            {
              id         => 'e' x 64,
              kind       => 39_000,
              created_at => 100,
              pubkey     => $carol_pubkey,
              content    => q{},
              tags       => [['d', $group_id],],
            },
          ],
        };
      }
      if ($args{method} eq 'adapters.derive') {
        return {view => [{%{$operator_view}, tombstoned => 1,},]}
          if $args{params}{operation} eq 'authoritative_channel_view';
        return {};
      }
      return;
    }
  );
  is $tombstoned->_authoritative_mode_write_permission_for_client(
    $channel, $tombstoned->{clients}{1}, mode => '+m',
  )->{reason}, 'deleted', 'a tombstoned channel blocks mode writes';
  is $tombstoned->_authoritative_channel_action_permission_for_client(
    $channel, $tombstoned->{clients}{1}, action => 'delete',
  )->{reason}, 'deleted', 'a tombstoned channel blocks deletion';
  my $undelete = $tombstoned->_authoritative_channel_action_permission_for_client(
    $channel, $tombstoned->{clients}{1}, action => 'undelete',
  );
  is $undelete->{allowed}, 1, 'a retained operator may undelete';
  ok $undelete->{group_metadata}, 'the undelete permission carries the group metadata';
  is $tombstoned->_authoritative_channel_action_permission_for_client(
    $channel, $tombstoned->{clients}{3}, action => 'undelete',
  )->{reason}, 'not_operator', 'a non-retained client may not undelete';
};

subtest 'authoritative NAMES and LIST entries blend local and remote members' => sub {
  my $view = {
    members => [
      {pubkey => $alice_pubkey, roles => ['irc.operator'], presentational_prefix => '@',},
      {pubkey => $ghost_pubkey, roles => [],},
    ],
    present_members => [{pubkey => $alice_pubkey,}, {pubkey => $ghost_pubkey,},],
    topic           => 'authoritative topic',
  };
  my $server = _joined_server();
  $server->request_handler(
    sub {
      my (%args) = @_;
      if ($args{method} eq 'nostr.read_subscription_snapshot' || $args{method} eq 'nostr.query_events') {
        return {
          events => [
            {
              id         => 'e' x 64,
              kind       => 39_000,
              created_at => 100,
              pubkey     => $carol_pubkey,
              content    => q{},
              tags       => [['d', $group_id],],
            },
            _grant_event(id => 'f' x 64,),
          ],
        };
      }
      if ($args{method} eq 'adapters.derive') {
        my $operation = $args{params}{operation};
        return {view => [$view]} if $operation eq 'authoritative_channel_view';
        return {view => [{visible_in_list => 1, visible_users => 7, channel => $channel, topic => 'listed',},]}
          if $operation eq 'authoritative_list_entry_view';
        return {};
      }
      return;
    }
  );
  $server->_add_visible_nick($channel, 'watcher');

  ok $server->_send_join_bootstrap(1, $channel), 'the join bootstrap renders';
  like _lines($server, 1), qr/TOPIC\ \Q$channel\E\ :authoritative\ topic/mxs,
    'the bootstrap sends the authoritative topic';
  like _lines($server, 1), qr/353 .* \@alice/mxs, 'the local operator keeps the presentational prefix';
  like _lines($server, 1), qr/353 .* zoe/mxs,     'a present remote member is named through the grants';
  like _lines($server, 1), qr/353 .* watcher/mxs, 'visible nicks fill in the rest';

  $server->clear_sent_lines;
  ok $server->_send_list_reply(1, undef), 'the list reply renders';
  like _lines($server, 1), qr/322 .* \Q$channel\E\ 7\ :listed/mxs, 'the list entry uses the list view';
  like _lines($server, 1), qr/323/mxs, 'the list is terminated';

  my $hidden = _joined_server();
  $hidden->request_handler(
    sub {
      my (%args) = @_;
      if ($args{method} eq 'nostr.read_subscription_snapshot' || $args{method} eq 'nostr.query_events') {
        return {events => [],};
      }
      if ($args{method} eq 'adapters.derive') {
        my $operation = $args{params}{operation};
        return {view => [{members => [], present_members => [],},]}
          if $operation eq 'authoritative_channel_view';
        return {view => [{visible_in_list => 0,},]}
          if $operation eq 'authoritative_list_entry_view';
        return {};
      }
      return;
    }
  );
  $hidden->clear_sent_lines;
  ok $hidden->_send_list_reply(1, $channel), 'a hidden-channel list reply renders';
  unlike _lines($hidden, 1), qr/322/mxs, 'a hidden channel is not listed';

  my $empty = _joined_server();
  $empty->request_handler(sub { return {} });
  is [$empty->_authoritative_name_entries_for_channel('nope', $channel)], [],
    'a malformed client yields no name entries';
  is [$empty->_authoritative_name_entries_for_channel($empty->{clients}{1}, $channel)], [],
    'a missing view yields no name entries';
  is [
    $empty->_authoritative_name_entries_for_channel(
      $empty->{clients}{1}, $channel, view => {members => [], present_members => [],},
    )
  ], ['alice', 'bob', 'carol'], 'local members appear without authoritative state';

  my $solo = _server();
  my $me   = $solo->add_client(1, nick => 'me', username => 'me', registered => 1,);
  $solo->{channels}{$solo->_channel_key($channel)} = {
    channel_name  => $channel,
    members       => {},
    visible_nicks => {},
  };
  $me->{joined_channels}{$solo->_channel_key($channel)} = $channel;
  is [$solo->_authoritative_name_entries_for_channel($me, $channel, view => {members => [],},)], ['me'],
    'a joined client with no other entries names itself';
};

subtest 'WHO entries cover remote visible nicks' => sub {
  my $server = _joined_server();
  $server->_add_visible_nick($channel, 'watcher');
  my @entries = $server->_who_entries_for_channel($channel);
  my ($watcher) = grep { $_->{nick} eq 'watcher' } @entries;
  is $watcher->{username}, 'overnet', 'a remote visible nick uses the placeholder username';
  is scalar(@entries), 4, 'local clients and remote nicks are all listed';

  my $whois = $server->_whois_entry_for_nick('alice');
  is $whois->{account}, $alice_pubkey, 'the whois entry carries the authoritative account';
  is $server->_whois_entry_for_nick(',bad'), undef, 'an invalid nick has no whois entry';
  is $server->_whois_entry_for_nick('ghost'), undef, 'an unknown nick has no whois entry';
  is $server->_userhost_entry_for_nick(',bad'), undef, 'an invalid nick has no userhost entry';
  is $server->_userhost_entry_for_nick('ghost'), undef, 'an unknown nick has no userhost entry';
};

done_testing;
