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

use Overnet::Authority::HostedChannel;
use Overnet::Core::Nostr;
use Overnet::Program::IRC::Command::Channel;
use TestIRCServer;

my $package  = 'Overnet::Program::IRC::Command::Channel';
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
    adapter_config => {
      authority_profile => q{},
      network           => 'overnet',
    },
    authority_relay => undef,
    %overrides,
  );
}

sub _registered_client {
  my ($server, $client_id, %fields) = @_;
  my $nick   = delete($fields{nick}) || 'alice';
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

sub _delegated_client {
  my ($server, $client_id, %fields) = @_;
  return _registered_client(
    $server, $client_id,
    authority_pubkey            => 'a' x 64,
    authority_delegate_key      => Overnet::Core::Nostr->generate_key,
    authority_delegate_event_id => 'b' x 64,
    %fields,
  );
}

sub _group_metadata_event {
  my (%fields) = @_;
  return {
    id         => $fields{id} || ('e' x 64),
    kind       => 39_000,
    created_at => $fields{created_at} || 1_000,
    pubkey     => 'c' x 64,
    content    => q{},
    tags       => [['d', $group_id], ['name', $channel],],
    %{$fields{extra} || {}},
  };
}

sub _install_handler {
  my ($server, %responses) = @_;
  $server->request_handler(
    sub {
      my (%args) = @_;
      my $method = $args{method};
      if ($method eq 'nostr.read_subscription_snapshot' || $method eq 'nostr.query_events') {
        return {events => [@{$responses{events} || []}]};
      }
      if ($method eq 'events.read') {
        return {entries => [map { +{event => $_} } @{$responses{events} || []}]};
      }
      if ($method eq 'adapters.derive') {
        my $operation = $args{params}{operation};
        my $response  = $responses{$operation};
        return ref($response) eq 'CODE' ? $response->(%args) : $response
          if defined $response;
        return {};
      }
      if ($method eq 'adapters.map_input' && defined $responses{map_input}) {
        my $response = $responses{map_input};
        return ref($response) eq 'CODE' ? $response->(%args) : $response;
      }
      if ($method eq 'nostr.publish_event' && defined $responses{publish}) {
        my $response = $responses{publish};
        return ref($response) eq 'CODE' ? $response->(%args) : $response;
      }
      return;
    }
  );
  return 1;
}

sub _authoritative_mode_event_draft {
  return {
    kind       => 9_002,
    created_at => 1_500,
    content    => q{},
    tags       => [['h', $group_id],],
  };
}

sub _lines {
  my ($server, $client_id) = @_;
  return join "\n", @{$server->lines_for($client_id)};
}

subtest 'handle_overnetchannel validates its inputs' => sub {
  my $server = _server();
  my $client = _registered_client($server, 1);

  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($server, 1, undef), 1,
    'missing params are handled';
  like _lines($server, 1), qr/461 .* OVERNETCHANNEL/mxs, 'missing params ask for more parameters';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($server, 1, ['DELETE']), 1,
    'a missing channel argument is handled';
  like _lines($server, 1), qr/461/mxs, 'a missing channel argument asks for more parameters';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($server, 1, [q{}, $channel]), 1,
    'an empty subcommand is handled';
  like _lines($server, 1), qr/461/mxs, 'an empty subcommand asks for more parameters';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($server, 1, ['FROB', $channel]), 1,
    'an unknown subcommand is handled';
  like _lines($server, 1), qr/421 .* OVERNETCHANNEL/mxs, 'an unknown subcommand reports unknown command';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($server, 1, ['DELETE', 'nochannel']), 1,
    'a non-channel target is handled';
  like _lines($server, 1), qr/403/mxs, 'a non-channel DELETE target reports no such channel';

  my $plain = _plain_server();
  _registered_client($plain, 1);
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($plain, 1, ['UNDELETE', $channel]), 1,
    'a non-authoritative UNDELETE target is handled';
  like _lines($plain, 1), qr/403/mxs, 'a non-authoritative UNDELETE target reports no such channel';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($server, 1, ['INVITES', 'bad name']), 1,
    'an invalid INVITES channel is handled';
  like _lines($server, 1), qr/403/mxs, 'an invalid INVITES channel reports no such channel';

  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($server, 99, ['INVITES', $channel]), 1,
    'an unknown INVITES client is handled quietly';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($server, 1, ['REQUESTS', $channel]), 1,
    'REQUESTS while not joined is handled';
  like _lines($server, 1), qr/442/mxs, 'REQUESTS while not joined reports not on channel';
};

subtest 'OVERNETCHANNEL DELETE and UNDELETE bridge to channel actions' => sub {
  my $server = _server();
  my $client = _delegated_client($server, 1);
  _install_handler(
    $server,
    events                                    => [_group_metadata_event()],
    authoritative_channel_view                => {view => [{members => [],},],},
    authoritative_channel_action_permission   => {
      permission => [
        {
          allowed        => 1,
          reason         => q{},
          group_metadata => {name => $channel,},
        },
      ],
    },
    map_input => {event => _authoritative_mode_event_draft(),},
  );

  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($server, 1, ['DELETE', $channel]), 1,
    'DELETE with permission is handled';
  like _lines($server, 1), qr/OVERNETCHANNEL\ DELETE\ \Q$channel\E/mxs, 'DELETE is confirmed in a notice';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($server, 1, ['UNDELETE', $channel]), 1,
    'UNDELETE with permission is handled';
  like _lines($server, 1), qr/OVERNETCHANNEL\ UNDELETE\ \Q$channel\E/mxs, 'UNDELETE is confirmed in a notice';

  my $denied = _server();
  _delegated_client($denied, 1);
  _install_handler(
    $denied,
    events                                  => [_group_metadata_event()],
    authoritative_channel_action_permission => {permission => [{allowed => 0, reason => 'not_operator',},],},
  );
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($denied, 1, ['DELETE', $channel]), 1,
    'a denied DELETE is handled';
  like _lines($denied, 1), qr/482/mxs, 'a denied DELETE reports chanop privileges needed';

  my $deleted = _server();
  _delegated_client($deleted, 1);
  _install_handler(
    $deleted,
    events                                  => [_group_metadata_event()],
    authoritative_channel_action_permission => {permission => [{allowed => 0, reason => 'deleted',},],},
  );
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($deleted, 1, ['DELETE', $channel]), 1,
    'a deleted-channel DELETE is handled';
  like _lines($deleted, 1), qr/403/mxs, 'a deleted-channel DELETE reports no such channel';

  my $not_deleted = _server();
  _delegated_client($not_deleted, 1);
  _install_handler(
    $not_deleted,
    events                                  => [_group_metadata_event()],
    authoritative_channel_action_permission => {permission => [{allowed => 0, reason => 'not_deleted',},],},
  );
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($not_deleted, 1, ['UNDELETE', $channel]), 1,
    'an UNDELETE of a live channel is handled';
  like _lines($not_deleted, 1), qr/403/mxs, 'an UNDELETE of a live channel reports no such channel';

  my $undelegated = _server();
  _registered_client($undelegated, 1, authority_pubkey => 'a' x 64,);
  _install_handler(
    $undelegated,
    events                                  => [_group_metadata_event()],
    authoritative_channel_action_permission => {permission => [{allowed => 1, reason => q{},},],},
  );
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($undelegated, 1, ['DELETE', $channel]), 1,
    'DELETE without delegation is handled';
  like _lines($undelegated, 1), qr/OVERNETAUTH\ DELEGATE\ is\ required/mxs, 'DELETE without delegation is refused';
  $undelegated->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($undelegated, 1, ['UNDELETE', $channel]), 1,
    'UNDELETE without delegation is handled';
  like _lines($undelegated, 1), qr/OVERNETAUTH\ DELEGATE\ is\ required/mxs, 'UNDELETE without delegation is refused';

  my $rejected = _server();
  _delegated_client($rejected, 1);
  _install_handler(
    $rejected,
    events                                  => [_group_metadata_event()],
    authoritative_channel_action_permission => {permission => [{allowed => 1, reason => q{},},],},
    map_input                               => {event => _authoritative_mode_event_draft(),},
    publish                                 => {accepted => 0,},
  );
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($rejected, 1, ['DELETE', $channel]), 1,
    'a rejected DELETE publish is handled';
  like _lines($rejected, 1), qr/rejected\ event/mxs, 'a rejected DELETE publish is reported';
  $rejected->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($rejected, 1, ['UNDELETE', $channel]), 1,
    'a rejected UNDELETE publish is handled';
  like _lines($rejected, 1), qr/rejected\ event/mxs, 'a rejected UNDELETE publish is reported';
};

subtest 'OVERNETCHANNEL INVITES and REQUESTS list channel views' => sub {
  my $server = _server();
  my $client = _delegated_client($server, 1);
  $server->_add_client_to_channel(1, $channel);
  _install_handler(
    $server,
    events                     => [_group_metadata_event()],
    authoritative_channel_view => {
      view => [
        {
          members         => [],
          pending_invites       => [{code => 'f' x 64, target_pubkey => 'd' x 64,},],
          pending_join_requests => [{pubkey => 'd' x 64, actor_mask => 'dave!dave@example.test',},],
        },
      ],
    },
    authoritative_channel_action_permission => {permission => [{allowed => 1, reason => q{},},],},
  );

  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($server, 1, ['INVITES', $channel]), 1,
    'INVITES is handled';
  like _lines($server, 1), qr/336 .* 337/mxs, 'INVITES lists the pending invites and ends the list';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($server, 1, ['REQUESTS', $channel]), 1,
    'REQUESTS is handled';
  like _lines($server, 1), qr/338 .* 339/mxs, 'REQUESTS lists the pending join requests and ends the list';

  my $denied = _server();
  _delegated_client($denied, 1);
  $denied->_add_client_to_channel(1, $channel);
  _install_handler(
    $denied,
    events                                  => [_group_metadata_event()],
    authoritative_channel_action_permission => {permission => [{allowed => 0, reason => 'not_operator',},],},
  );
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($denied, 1, ['INVITES', $channel]), 1,
    'a denied INVITES is handled';
  like _lines($denied, 1), qr/482/mxs, 'a denied INVITES reports chanop privileges needed';
  $denied->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($denied, 1, ['REQUESTS', $channel]), 1,
    'a denied REQUESTS is handled';
  like _lines($denied, 1), qr/482/mxs, 'a denied REQUESTS reports chanop privileges needed';

  my $deleted = _server();
  _delegated_client($deleted, 1);
  $deleted->_add_client_to_channel(1, $channel);
  _install_handler(
    $deleted,
    events                                  => [_group_metadata_event()],
    authoritative_channel_action_permission => {permission => [{allowed => 0, reason => 'deleted',},],},
  );
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($deleted, 1, ['INVITES', $channel]), 1,
    'INVITES on a deleted channel is handled';
  like _lines($deleted, 1), qr/403/mxs, 'INVITES on a deleted channel reports no such channel';
  $deleted->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_overnetchannel($deleted, 1, ['REQUESTS', $channel]), 1,
    'REQUESTS on a deleted channel is handled';
  like _lines($deleted, 1), qr/403/mxs, 'REQUESTS on a deleted channel reports no such channel';
};

subtest 'handle_mode routes user and channel mode queries' => sub {
  my $server = _plain_server();
  my $client = _registered_client($server, 1);

  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 99, ['#x']), 0, 'an unknown client is rejected';

  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, []), 1, 'missing params are handled';
  like _lines($server, 1), qr/461 .* MODE/mxs, 'missing params ask for more parameters';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, ['alice']), 1, 'own-nick MODE is handled';
  like _lines($server, 1), qr/221/mxs, 'own-nick MODE reports user modes';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, ['bob']), 1, 'other-nick MODE is handled';
  like _lines($server, 1), qr/403/mxs, 'other-nick MODE reports no such channel';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, [$channel]), 1,
    'MODE while not joined is handled';
  like _lines($server, 1), qr/442/mxs, 'MODE while not joined reports not on channel';

  $server->_add_client_to_channel(1, $channel);
  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, [$channel]), 1,
    'a joined non-authoritative MODE query is handled';
  like _lines($server, 1), qr/324/mxs, 'a joined MODE query reports channel modes';
};

subtest 'authoritative MODE commands enforce permissions and lists' => sub {
  my $server = _server();
  my $client = _delegated_client($server, 1);
  my $target = _delegated_client($server, 2, nick => 'bob',);
  $server->_add_client_to_channel($_, $channel) for 1, 2;
  my $view = {
    members => [{pubkey => 'a' x 64, roles => ['irc.operator'],},],
    ban_masks              => ['spammer!*@*'],
    exception_masks        => ['friend!*@*'],
    invite_exception_masks => ['pal!*@*'],
    channel_modes          => 'nt',
  };
  _install_handler(
    $server,
    events                              => [_group_metadata_event()],
    authoritative_channel_view          => {view => [$view]},
    authoritative_ban_list_view         => {view => [{ban_masks => ['spammer!*@*'],},],},
    authoritative_mode_write_permission => {permission => [{allowed => 1, reason => q{},},],},
    map_input                           => {event => _authoritative_mode_event_draft(),},
  );

  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, [$channel, '+b']), 1,
    'a +b list query is handled';
  like _lines($server, 1), qr/367 .* spammer/mxs,  'the ban list is sent';
  like _lines($server, 1), qr/368/mxs,             'the ban list is terminated';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, [$channel, '+e']), 1,
    'a +e list query is handled';
  like _lines($server, 1), qr/348 .* friend/mxs, 'the exception list is sent';
  like _lines($server, 1), qr/349/mxs,           'the exception list is terminated';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, [$channel, '+I']), 1,
    'a +I list query is handled';
  like _lines($server, 1), qr/346 .* pal/mxs, 'the invite exception list is sent';
  like _lines($server, 1), qr/347/mxs,        'the invite exception list is terminated';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, [$channel, '+o', 'bob']), 1,
    'a role mode change is handled';
  like _lines($server, 1), qr/MODE\ \Q$channel\E\ [+]o\ bob/mxs, 'the role mode change is broadcast';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, [$channel, '+o']), 1,
    'a role mode change without a target is handled';
  like _lines($server, 1), qr/461/mxs, 'a missing role target asks for more parameters';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, [$channel, '+v', 'ghost']), 1,
    'a role mode change for an unknown nick is handled';
  like _lines($server, 1), qr/401/mxs, 'an unknown role target reports no such nick';

  my $plainuser = _registered_client($server, 3, nick => 'carol',);
  $server->_add_client_to_channel(3, $channel);
  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, [$channel, '-o', 'carol']), 1,
    'a role mode change for an unauthenticated nick is handled';
  like _lines($server, 1), qr/401/mxs, 'an unauthenticated role target reports no such nick';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, [$channel, '+b', 'lurker!*@*']), 1,
    'a ban mask mode change is handled';
  like _lines($server, 1), qr/MODE\ \Q$channel\E\ [+]b\ lurker/mxs, 'the ban mask change is broadcast';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, [$channel, '+k', 'sekrit']), 1,
    'a channel key mode change is handled';
  like _lines($server, 1), qr/MODE\ \Q$channel\E\ [+]k\ sekrit/mxs, 'the key change is broadcast';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, [$channel, '+k']), 1,
    'a key mode change without a key is handled';
  like _lines($server, 1), qr/461/mxs, 'a missing key asks for more parameters';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, [$channel, '+l', '25']), 1,
    'a user limit mode change is handled';
  like _lines($server, 1), qr/MODE\ \Q$channel\E\ [+]l\ 25/mxs, 'the limit change is broadcast';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, [$channel, '+l', 'many']), 1,
    'a malformed user limit is handled';
  like _lines($server, 1), qr/461/mxs, 'a malformed limit asks for more parameters';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, [$channel, '+m']), 1,
    'a flag mode change is handled';
  like _lines($server, 1), qr/MODE\ \Q$channel\E\ [+]m/mxs, 'the flag change is broadcast';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_mode($server, 1, [$channel, '+z']), 1,
    'an unsupported mode letter is handled';
  like _lines($server, 1), qr/421/mxs, 'an unsupported mode letter reports unknown command';

  my $denied = _server();
  _delegated_client($denied, 1);
  $denied->_add_client_to_channel(1, $channel);
  _install_handler(
    $denied,
    events                              => [_group_metadata_event()],
    authoritative_channel_view          => {view => [$view]},
    authoritative_mode_write_permission => {permission => [{allowed => 0, reason => 'not_operator',},],},
  );
  is Overnet::Program::IRC::Command::Channel::handle_mode($denied, 1, [$channel, '+m']), 1,
    'a denied mode change is handled';
  like _lines($denied, 1), qr/482/mxs, 'a denied mode change reports chanop privileges needed';

  my $deleted = _server();
  _delegated_client($deleted, 1);
  $deleted->_add_client_to_channel(1, $channel);
  _install_handler(
    $deleted,
    events                              => [_group_metadata_event()],
    authoritative_channel_view          => {view => [$view]},
    authoritative_mode_write_permission => {permission => [{allowed => 0, reason => 'deleted',},],},
  );
  is Overnet::Program::IRC::Command::Channel::handle_mode($deleted, 1, [$channel, '+m']), 1,
    'a deleted-channel mode change is handled';
  like _lines($deleted, 1), qr/403/mxs, 'a deleted-channel mode change reports no such channel';

  my $undelegated = _server();
  _registered_client($undelegated, 1, authority_pubkey => 'a' x 64,);
  $undelegated->_add_client_to_channel(1, $channel);
  _install_handler(
    $undelegated,
    events                              => [_group_metadata_event()],
    authoritative_channel_view          => {view => [$view]},
    authoritative_mode_write_permission => {permission => [{allowed => 1, reason => q{},},],},
  );
  is Overnet::Program::IRC::Command::Channel::handle_mode($undelegated, 1, [$channel, '+m']), 1,
    'a mode change without delegation is handled';
  like _lines($undelegated, 1), qr/OVERNETAUTH\ DELEGATE\ is\ required/mxs,
    'a mode change without delegation is refused';
};

subtest 'handle_kick enforces authoritative permissions' => sub {
  my $server = _server();
  my $client = _delegated_client($server, 1);
  my $target = _delegated_client($server, 2, nick => 'bob', authority_pubkey => 'd' x 64,);
  $server->_add_client_to_channel($_, $channel) for 1, 2;
  _install_handler(
    $server,
    events                                  => [_group_metadata_event()],
    authoritative_channel_view              => {view => [{members => [],},],},
    authoritative_channel_action_permission => {
      permission => [{allowed => 1, reason => q{}, target_pubkey => 'd' x 64,},],
    },
    map_input => {event => _authoritative_mode_event_draft(),},
  );

  is Overnet::Program::IRC::Command::Channel::handle_kick($server, 99, [$channel, 'bob']), 0,
    'an unknown client is rejected';

  is Overnet::Program::IRC::Command::Channel::handle_kick($server, 1, [$channel]), 1,
    'missing params are handled';
  like _lines($server, 1), qr/461 .* KICK/mxs, 'missing params ask for more parameters';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_kick($server, 1, ['nochannel', 'bob']), 1,
    'a non-channel KICK target is handled';
  like _lines($server, 1), qr/403/mxs, 'a non-channel KICK target reports no such channel';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_kick($server, 1, ['#elsewhere', 'bob']), 1,
    'a KICK while not joined is handled';
  like _lines($server, 1), qr/442/mxs, 'a KICK while not joined reports not on channel';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_kick($server, 1, [$channel, 'ghost']), 1,
    'a KICK of an unknown nick is handled';
  like _lines($server, 1), qr/401/mxs, 'a KICK of an unknown nick reports no such nick';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_kick($server, 1, [$channel, 'bob', 'flooding']), 1,
    'an allowed KICK is handled';
  like _lines($server, 1), qr/KICK\ \Q$channel\E\ bob\ :flooding/mxs, 'the KICK is broadcast with the reason';
  ok !exists $target->{joined_channels}{$server->_channel_key($channel)}, 'the target left the channel';

  my $plain = _plain_server();
  _registered_client($plain, 1);
  $plain->_add_client_to_channel(1, $channel);
  is Overnet::Program::IRC::Command::Channel::handle_kick($plain, 1, [$channel, 'bob']), 1,
    'a non-authoritative KICK is handled';
  like _lines($plain, 1), qr/421 .* KICK/mxs, 'a non-authoritative KICK reports unknown command';
};

subtest 'handle_invite offers authoritative invites' => sub {
  my $server = _server();
  my $client = _delegated_client($server, 1);
  my $target = _delegated_client($server, 2, nick => 'bob', authority_pubkey => 'd' x 64,);
  $server->_add_client_to_channel(1, $channel);
  _install_handler(
    $server,
    events                                  => [_group_metadata_event()],
    authoritative_channel_view              => {view => [{members => [],},],},
    authoritative_channel_action_permission => {
      permission => [{allowed => 1, reason => q{}, target_pubkey => 'd' x 64,},],
    },
    map_input => {event => _authoritative_mode_event_draft(),},
  );

  is Overnet::Program::IRC::Command::Channel::handle_invite($server, 99, ['bob', $channel]), 0,
    'an unknown client is rejected';

  is Overnet::Program::IRC::Command::Channel::handle_invite($server, 1, ['bob']), 1, 'missing params are handled';
  like _lines($server, 1), qr/461 .* INVITE/mxs, 'missing params ask for more parameters';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_invite($server, 1, ['bob', 'nochannel']), 1,
    'a non-channel INVITE target is handled';
  like _lines($server, 1), qr/403/mxs, 'a non-channel INVITE target reports no such channel';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_invite($server, 1, ['bob', '#elsewhere']), 1,
    'an INVITE while not joined is handled';
  like _lines($server, 1), qr/442/mxs, 'an INVITE while not joined reports not on channel';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_invite($server, 1, ['ghost', $channel]), 1,
    'an INVITE of an unknown nick is handled';
  like _lines($server, 1), qr/401/mxs, 'an INVITE of an unknown nick reports no such nick';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_invite($server, 1, ['bob', $channel]), 1,
    'an allowed INVITE is handled';
  like _lines($server, 1), qr/341/mxs, 'the inviter sees the inviting numeric';
  like _lines($server, 2), qr/INVITE\ bob\ :\Q$channel\E/mxs, 'the target receives the INVITE line';
  ok scalar keys %{$target->{authority_seen_invites}{$channel} || {}}, 'the invite code is remembered';

  my $plain = _plain_server();
  _registered_client($plain, 1);
  _registered_client($plain, 2, nick => 'bob',);
  $plain->_add_client_to_channel(1, $channel);
  is Overnet::Program::IRC::Command::Channel::handle_invite($plain, 1, ['bob', $channel]), 1,
    'a non-authoritative INVITE is handled';
  like _lines($plain, 1), qr/421 .* INVITE/mxs, 'a non-authoritative INVITE reports unknown command';
};

subtest 'handle_join validates and completes non-authoritative joins' => sub {
  my $server = _plain_server();
  my $client = _registered_client($server, 1);

  is Overnet::Program::IRC::Command::Channel::handle_join($server, 99, [$channel]), 0,
    'an unknown client is rejected';

  is Overnet::Program::IRC::Command::Channel::handle_join($server, 1, []), 1, 'missing params are handled';
  like _lines($server, 1), qr/461 .* JOIN/mxs, 'missing params ask for more parameters';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_join($server, 1, ['nochannel']), 1,
    'a non-channel JOIN target is handled';
  like _lines($server, 1), qr/403/mxs, 'a non-channel JOIN target reports no such channel';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_join($server, 1, [$channel]), 1, 'a JOIN is handled';
  like _lines($server, 1), qr/JOIN\ \Q$channel\E/mxs, 'the JOIN is echoed to the client';
  ok $client->{joined_channels}{$server->_channel_key($channel)}, 'the channel is recorded as joined';
  my ($open) = grep { $_->{method} eq 'subscriptions.open' } @{$server->requests};
  ok $open, 'a channel subscription is opened';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_join($server, 1, [$channel]), 1,
    'a repeated JOIN is handled';
  is _lines($server, 1), q{}, 'a repeated JOIN is a no-op';
};

subtest 'handle_join walks the authoritative admission branches' => sub {
  my %admission_case = (
    'auth required' => {
      admission => {allowed => 0, auth_required => 1,},
      pattern   => qr/OVERNETAUTH\ AUTH\ is\ required/mxs,
    },
    'deleted channel' => {
      admission => {allowed => 0, deleted => 1,},
      pattern   => qr/403/mxs,
    },
    'pending request' => {
      admission => {allowed => 0, pending_request => 1,},
      pattern   => qr/Join\ request\ already\ pending/mxs,
    },
    'denial reason' => {
      admission => {allowed => 0, reason => '+i',},
      pattern   => qr/473/mxs,
    },
  );
  for my $case (sort keys %admission_case) {
    my $server = _server();
    my $client = _delegated_client($server, 1);
    _install_handler(
      $server,
      events                        => [_group_metadata_event()],
      authoritative_channel_view    => {view => [{members => [],},],},
      authoritative_join_admission  => {admission => [$admission_case{$case}{admission}],},
    );
    is Overnet::Program::IRC::Command::Channel::handle_join($server, 1, [$channel]), 1, "a $case JOIN is handled";
    like _lines($server, 1), $admission_case{$case}{pattern}, "a $case JOIN reports its outcome";
  }

  my $requestable = _server();
  _delegated_client($requestable, 1);
  _install_handler(
    $requestable,
    events                       => [_group_metadata_event()],
    authoritative_channel_view   => {view => [{members => [],},],},
    authoritative_join_admission => {admission => [{allowed => 0, request_join => 1,},],},
    map_input                    => {event => _authoritative_mode_event_draft(),},
  );
  is Overnet::Program::IRC::Command::Channel::handle_join($requestable, 1, [$channel]), 1,
    'a request_join JOIN is handled';
  like _lines($requestable, 1), qr/Join\ request\ submitted/mxs, 'a join request is submitted';

  my $allowed = _server();
  my $member  = _delegated_client($allowed, 1);
  _install_handler(
    $allowed,
    events                       => [_group_metadata_event()],
    authoritative_channel_view   => {view => [{members => [],},],},
    authoritative_join_admission => {
      admission => [{allowed => 1, member => 0, present => 0, invite_code => 'f' x 64,},],
    },
    map_input => {event => _authoritative_mode_event_draft(),},
  );
  is Overnet::Program::IRC::Command::Channel::handle_join($allowed, 1, [$channel, 'sekrit']), 1,
    'an allowed JOIN with an invite code and key is handled';
  like _lines($allowed, 1), qr/JOIN\ \Q$channel\E/mxs, 'the allowed JOIN completes';
  my ($map) = grep { $_->{method} eq 'adapters.map_input' } @{$allowed->requests};
  is $map->{params}{input}{join_key},    'sekrit', 'the join key rides in the mapped input';
  is $map->{params}{input}{invite_code}, 'f' x 64, 'the invite code rides in the mapped input';

  my $present = _server();
  my $joined  = _delegated_client($present, 1);
  $present->_add_client_to_channel(1, $channel);
  _install_handler(
    $present,
    events                       => [_group_metadata_event()],
    authoritative_channel_view   => {view => [{members => [],},],},
    authoritative_join_admission => {admission => [{allowed => 1, member => 1, present => 1,},],},
  );
  is Overnet::Program::IRC::Command::Channel::handle_join($present, 1, [$channel]), 1,
    'a JOIN while already present is handled';
  is _lines($present, 1), q{}, 'a JOIN while already present is a no-op';

  my $stale = _server();
  _delegated_client($stale, 1);
  $stale->_add_client_to_channel(1, $channel);
  _install_handler(
    $stale,
    events                       => [_group_metadata_event()],
    authoritative_channel_view   => {view => [{members => [],},],},
    authoritative_join_admission => {admission => [{allowed => 0, deleted => 1,},],},
  );
  is Overnet::Program::IRC::Command::Channel::handle_join($stale, 1, [$channel]), 1,
    'a stale local join is reconciled';
  ok !$stale->{clients}{1}{joined_channels}{$stale->_channel_key($channel)},
    'the stale local join is removed';

  my $undelegated = _server();
  _registered_client($undelegated, 1, authority_pubkey => 'a' x 64,);
  _install_handler(
    $undelegated,
    events                       => [_group_metadata_event()],
    authoritative_channel_view   => {view => [{members => [],},],},
    authoritative_join_admission => {admission => [{allowed => 1, member => 0, present => 0,},],},
  );
  is Overnet::Program::IRC::Command::Channel::handle_join($undelegated, 1, [$channel]), 1,
    'a JOIN without delegation is handled';
  like _lines($undelegated, 1), qr/OVERNETAUTH\ DELEGATE\ is\ required/mxs,
    'a JOIN without delegation is refused';

  my $rejected = _server();
  _delegated_client($rejected, 1);
  _install_handler(
    $rejected,
    events                       => [_group_metadata_event()],
    authoritative_channel_view   => {view => [{members => [],},],},
    authoritative_join_admission => {admission => [{allowed => 1, member => 0, present => 0,},],},
    map_input                    => {event => _authoritative_mode_event_draft(),},
    publish                      => {accepted => 0, message => 'relay says no',},
  );
  is Overnet::Program::IRC::Command::Channel::handle_join($rejected, 1, [$channel]), 1,
    'a rejected JOIN publish is handled';
  like _lines($rejected, 1), qr/rejected\ event:\ relay\ says\ no/mxs, 'the relay rejection reason is reported';

  my $settled = _server();
  _delegated_client($settled, 1);
  _install_handler(
    $settled,
    events                       => [_group_metadata_event()],
    authoritative_channel_view   => {view => [{members => [],},],},
    authoritative_join_admission => {admission => [{allowed => 1, member => 1, present => 1,},],},
  );
  is Overnet::Program::IRC::Command::Channel::handle_join($settled, 1, [$channel]), 1,
    'an allowed member-present JOIN is handled';
  like _lines($settled, 1), qr/JOIN\ \Q$channel\E/mxs, 'an allowed member-present JOIN completes locally';
};

subtest 'handle_part covers authoritative and plain channels' => sub {
  my $server = _plain_server();
  my $client = _registered_client($server, 1);
  $server->_add_client_to_channel(1, $channel);

  is Overnet::Program::IRC::Command::Channel::handle_part($server, 99, [$channel]), 0,
    'an unknown client is rejected';

  is Overnet::Program::IRC::Command::Channel::handle_part($server, 1, []), 1, 'missing params are handled';
  like _lines($server, 1), qr/461 .* PART/mxs, 'missing params ask for more parameters';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_part($server, 1, ['nochannel']), 1,
    'a non-channel PART target is handled';
  like _lines($server, 1), qr/403/mxs, 'a non-channel PART target reports no such channel';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_part($server, 1, ['#elsewhere']), 1,
    'a PART while not joined is handled';
  like _lines($server, 1), qr/442/mxs, 'a PART while not joined reports not on channel';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_part($server, 1, [$channel, 'gone fishing']), 1,
    'a PART with a reason is handled';
  like _lines($server, 1), qr/PART\ \Q$channel\E\ :gone\ fishing/mxs, 'the PART is broadcast with the reason';
  ok !$client->{joined_channels}{$server->_channel_key($channel)}, 'the channel is no longer joined';

  my $auth = _server();
  my $delegated = _delegated_client($auth, 1);
  $auth->_add_client_to_channel(1, $channel);
  _install_handler(
    $auth,
    events                     => [_group_metadata_event()],
    authoritative_channel_view => {view => [{members => [],},],},
    map_input                  => {event => _authoritative_mode_event_draft(),},
  );
  is Overnet::Program::IRC::Command::Channel::handle_part($auth, 1, [$channel, 'bye']), 1,
    'an authoritative PART is handled';
  like _lines($auth, 1), qr/PART\ \Q$channel\E\ :bye/mxs, 'the authoritative PART is broadcast';

  my $anonymous = _server();
  _registered_client($anonymous, 1);
  $anonymous->_add_client_to_channel(1, $channel);
  is Overnet::Program::IRC::Command::Channel::handle_part($anonymous, 1, [$channel]), 1,
    'an unauthenticated authoritative PART is handled';
  like _lines($anonymous, 1), qr/OVERNETAUTH\ AUTH\ is\ required/mxs,
    'an unauthenticated authoritative PART is refused';

  my $undelegated = _server();
  _registered_client($undelegated, 1, authority_pubkey => 'a' x 64,);
  $undelegated->_add_client_to_channel(1, $channel);
  is Overnet::Program::IRC::Command::Channel::handle_part($undelegated, 1, [$channel]), 1,
    'an undelegated authoritative PART is handled';
  like _lines($undelegated, 1), qr/OVERNETAUTH\ DELEGATE\ is\ required/mxs,
    'an undelegated authoritative PART is refused';

  my $rejected = _server();
  _delegated_client($rejected, 1);
  $rejected->_add_client_to_channel(1, $channel);
  _install_handler(
    $rejected,
    events                     => [_group_metadata_event()],
    authoritative_channel_view => {view => [{members => [],},],},
    map_input                  => {event => _authoritative_mode_event_draft(),},
    publish                    => {accepted => 0,},
  );
  is Overnet::Program::IRC::Command::Channel::handle_part($rejected, 1, [$channel]), 1,
    'a rejected authoritative PART publish is handled';
  like _lines($rejected, 1), qr/rejected\ event/mxs, 'the rejected PART publish is reported';
};

subtest 'handle_privmsg_or_notice routes channels and private messages' => sub {
  my $server = _plain_server();
  my $client = _registered_client(
    $server, 1,
    capabilities => {'overnet-e2ee' => 1,},
    e2ee_pubkey  => 'c' x 64,
  );
  my $friend = _registered_client(
    $server, 2,
    nick         => 'bob',
    capabilities => {'overnet-e2ee' => 1,},
  );
  $server->_add_client_to_channel(1, $channel);

  is Overnet::Program::IRC::Command::Channel::handle_privmsg_or_notice($server, 99, 'PRIVMSG', [$channel, 'hi']),
    0, 'an unknown client is rejected';

  is Overnet::Program::IRC::Command::Channel::handle_privmsg_or_notice($server, 1, 'PRIVMSG', [$channel]), 1,
    'missing params are handled';
  like _lines($server, 1), qr/461 .* PRIVMSG/mxs, 'missing params ask for more parameters';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_privmsg_or_notice($server, 1, 'PRIVMSG', ['#elsewhere', 'hi']),
    1, 'a message to an unjoined channel is handled';
  like _lines($server, 1), qr/442/mxs, 'a message to an unjoined channel reports not on channel';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_privmsg_or_notice($server, 1, 'PRIVMSG', [$channel, 'hi all']),
    1, 'a channel message is handled';
  my ($map) = grep { $_->{method} eq 'adapters.map_input' } @{$server->requests};
  is $map->{params}{input}{text}, 'hi all', 'the channel message is mapped as input';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_privmsg_or_notice($server, 1, 'PRIVMSG', [',bad', 'hi']), 1,
    'an invalid nick target is handled';
  like _lines($server, 1), qr/401/mxs, 'an invalid nick target reports no such nick';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_privmsg_or_notice($server, 1, 'PRIVMSG', ['ghost', 'hi']), 1,
    'an unknown nick target is handled';
  like _lines($server, 1), qr/401/mxs, 'an unknown nick target reports no such nick';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_privmsg_or_notice($server, 1, 'NOTICE', ['bob', 'psst']), 1,
    'a direct notice is handled';
  my ($dm) = grep { $_->{method} eq 'adapters.map_input' && ($_->{params}{input}{target} || q{}) eq 'bob' }
    @{$server->requests};
  ok $dm, 'the direct message is mapped as input';

  $server->clear_sent_lines;
  my $garbled = '+overnet-e2ee-v1 %%%';
  is Overnet::Program::IRC::Command::Channel::handle_privmsg_or_notice($server, 1, 'PRIVMSG', ['bob', $garbled]),
    1, 'a malformed e2ee body is handled';
  like _lines($server, 1), qr/Malformed\ overnet-e2ee\ body/mxs, 'the malformed e2ee body is reported';

  $friend->{e2ee_pubkey} = 'd' x 64;
  my $sender_key = Overnet::Core::Nostr->generate_key;
  my $wrap       = $sender_key->create_event_hash(
    kind       => 1059,
    created_at => 1_000,
    content    => 'opaque',
    tags       => [['p', 'd' x 64],],
  );
  my $valid = '+overnet-e2ee-v1 ' . encode_base64(JSON::encode_json($wrap), q{});
  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_privmsg_or_notice($server, 1, 'PRIVMSG', ['bob', $valid]), 1,
    'a valid e2ee body is handled';
  my ($opaque) = grep { $_->{method} eq 'overnet.emit_private_message' } @{$server->requests};
  ok $opaque, 'the opaque private message is emitted';

  my $auth = _server();
  _delegated_client($auth, 1);
  $auth->_add_client_to_channel(1, $channel);
  _install_handler(
    $auth,
    events                        => [_group_metadata_event()],
    authoritative_channel_view    => {view => [{members => [],},],},
    authoritative_speak_permission => {permission => [{allowed => 0, reason => '+m',},],},
  );
  is Overnet::Program::IRC::Command::Channel::handle_privmsg_or_notice($auth, 1, 'PRIVMSG', [$channel, 'hi']), 1,
    'a muted authoritative message is handled';
  like _lines($auth, 1), qr/404/mxs, 'a muted authoritative message reports cannot send';

  my $moderated = _plain_server();
  _registered_client($moderated, 1);
  $moderated->_add_client_to_channel(1, $channel);
  my $mock = mock 'TestIRCServer' => (override => [_channel_is_moderated_for_client => sub {1},],);
  is Overnet::Program::IRC::Command::Channel::handle_privmsg_or_notice($moderated, 1, 'PRIVMSG', [$channel, 'hi']),
    1, 'a moderated plain-channel message is handled';
  like _lines($moderated, 1), qr/404/mxs, 'a moderated plain-channel message reports cannot send';
};

subtest 'handle_topic reads and writes topics' => sub {
  my $server = _plain_server();
  my $client = _registered_client($server, 1);
  $server->_add_client_to_channel(1, $channel);

  is Overnet::Program::IRC::Command::Channel::handle_topic($server, 99, [$channel]), 0,
    'an unknown client is rejected';

  is Overnet::Program::IRC::Command::Channel::handle_topic($server, 1, []), 1, 'missing params are handled';
  like _lines($server, 1), qr/461 .* TOPIC/mxs, 'missing params ask for more parameters';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_topic($server, 1, ['nochannel']), 1,
    'a non-channel TOPIC target is handled';
  like _lines($server, 1), qr/403/mxs, 'a non-channel TOPIC target reports no such channel';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_topic($server, 1, ['#elsewhere']), 1,
    'a TOPIC while not joined is handled';
  like _lines($server, 1), qr/442/mxs, 'a TOPIC while not joined reports not on channel';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_topic($server, 1, [$channel]), 1, 'a TOPIC query is handled';
  like _lines($server, 1), qr/331|332/mxs, 'a TOPIC query reports the topic state';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_topic($server, 1, [$channel, 'fresh topic']), 1,
    'a plain TOPIC change is handled';
  my ($map) = grep { $_->{method} eq 'adapters.map_input' } @{$server->requests};
  is $map->{params}{input}{text}, 'fresh topic', 'the topic change is mapped as input';

  my $restricted = _plain_server();
  _registered_client($restricted, 1);
  $restricted->_add_client_to_channel(1, $channel);
  my $mock = mock 'TestIRCServer' => (override => [_channel_is_topic_restricted_for_client => sub {1},],);
  is Overnet::Program::IRC::Command::Channel::handle_topic($restricted, 1, [$channel, 'nope']), 1,
    'a restricted plain TOPIC change is handled';
  like _lines($restricted, 1), qr/482/mxs, 'a restricted plain TOPIC change reports chanop privileges needed';
  $mock = undef;

  my $view = {
    members       => [{pubkey => 'a' x 64, roles => ['irc.operator'],},],
    channel_modes => 'nt',
  };
  my $auth = _server();
  _delegated_client($auth, 1);
  $auth->_add_client_to_channel(1, $channel);
  _install_handler(
    $auth,
    events                          => [_group_metadata_event()],
    authoritative_channel_view      => {view => [$view]},
    authoritative_topic_permission  => {permission => [{allowed => 1, reason => q{},},],},
    map_input                       => {event => _authoritative_mode_event_draft(),},
  );
  is Overnet::Program::IRC::Command::Channel::handle_topic($auth, 1, [$channel, 'set by op']), 1,
    'an authoritative TOPIC change is handled';
  my ($topic_map) = grep { $_->{method} eq 'adapters.map_input' } @{$auth->requests};
  is $topic_map->{params}{input}{text}, 'set by op', 'the authoritative topic rides in the mapped input';

  my $denied = _server();
  _delegated_client($denied, 1);
  $denied->_add_client_to_channel(1, $channel);
  _install_handler(
    $denied,
    events                         => [_group_metadata_event()],
    authoritative_channel_view     => {view => [$view]},
    authoritative_topic_permission => {permission => [{allowed => 0, reason => '+t',},],},
  );
  is Overnet::Program::IRC::Command::Channel::handle_topic($denied, 1, [$channel, 'nope']), 1,
    'a denied authoritative TOPIC change is handled';
  like _lines($denied, 1), qr/482/mxs, 'a denied authoritative TOPIC change reports chanop privileges needed';

  my $deleted = _server();
  _delegated_client($deleted, 1);
  $deleted->_add_client_to_channel(1, $channel);
  _install_handler(
    $deleted,
    events                         => [_group_metadata_event()],
    authoritative_channel_view     => {view => [$view]},
    authoritative_topic_permission => {permission => [{allowed => 0, reason => 'deleted',},],},
  );
  is Overnet::Program::IRC::Command::Channel::handle_topic($deleted, 1, [$channel, 'nope']), 1,
    'a deleted-channel TOPIC change is handled';
  like _lines($deleted, 1), qr/403/mxs, 'a deleted-channel TOPIC change reports no such channel';
};

subtest 'handle_list replies with the list numerics' => sub {
  my $server = _plain_server();
  my $client = _registered_client($server, 1);
  $server->_add_client_to_channel(1, $channel);

  is Overnet::Program::IRC::Command::Channel::handle_list($server, 1, []), 1, 'LIST without a target is handled';
  like _lines($server, 1), qr/323/mxs, 'LIST ends with the end-of-list numeric';

  $server->clear_sent_lines;
  is Overnet::Program::IRC::Command::Channel::handle_list($server, 1, [$channel]), 1,
    'LIST with a target is handled';
  like _lines($server, 1), qr/323/mxs, 'a targeted LIST ends with the end-of-list numeric';
};

done_testing;
