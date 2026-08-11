use strictures 2;

use File::Spec;
use FindBin;
use JSON         ();
use Scalar::Util qw(isweak refaddr);
use Test2::V0;

use lib grep { -d $_ } (
  File::Spec->catdir($FindBin::Bin, 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'lib'),
);

use Overnet::Authority::HostedChannel;
use Overnet::Core::Nostr;
use Overnet::Program::IRC::Authority::Coordinator;
use TestIRCServer;

my $package  = 'Overnet::Program::IRC::Authority::Coordinator';
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

sub _coordinator {
  my ($server) = @_;
  return Overnet::Program::IRC::Authority::Coordinator->new(server => $server,);
}

{

  package Local::DispatchingAuthorityCoordinator;

  use Moo;
  extends 'Overnet::Program::IRC::Authority::Coordinator';

  has grant_id_calls => (is => 'rw', default => sub {0});

  no Moo;

  sub authoritative_grant_subscription_id {
    my ($self) = @_;
    $self->grant_id_calls($self->grant_id_calls + 1);
    return 'custom-grant-subscription';
  }
}

subtest 'the server owns one authority coordinator collaborator' => sub {
  my $server      = _server();
  my $coordinator = $server->_authority_coordinator;

  isa_ok $coordinator, ['Overnet::Program::IRC::Authority::Coordinator'];
  is refaddr($coordinator->server), refaddr($server), 'the coordinator holds a weak server dependency';
  ok isweak($coordinator->{server}), 'the coordinator cannot keep its owning server alive';
};

subtest 'internal coordinator calls use method dispatch' => sub {
  my $server      = _server();
  my $coordinator = Local::DispatchingAuthorityCoordinator->new(server => $server,);

  is $coordinator->ensure_authoritative_grant_subscription,
    'custom-grant-subscription', 'the override supplies the opened subscription id';
  is $coordinator->grant_id_calls, 1, 'the coordinator dispatches its subscription-id helper as a method';
};

sub _group_event {
  my (%fields) = @_;
  return {
    id         => delete($fields{id}) || ('e' x 64),
    kind       => 39_000,
    created_at => delete($fields{created_at}) || 1_000,
    pubkey     => 'c' x 64,
    content    => q{},
    tags       => delete($fields{tags}) || [['d', $group_id], ['name', $channel],],
    %fields,
  };
}

sub _failing_open_handler {
  return sub {
    my (%args) = @_;
    die "relay unavailable\n" if $args{method} eq 'nostr.open_subscription';
    return;
  };
}

sub _with_view_handler {
  my ($server, $inner) = @_;
  $server->request_handler(
    sub {
      my (%args) = @_;
      if ($args{method} eq 'adapters.derive'
        && ($args{params}{operation} || q{}) eq 'authoritative_channel_view') {
        return {view => [{members => [],},],};
      }
      return $inner ? $inner->(%args) : ();
    }
  );
  return $server;
}

subtest 'subscription id helpers name the network and group' => sub {
  my $server = _server();
  is _coordinator($server)->authoritative_grant_subscription_id(),
    'irc.authority.grants:overnet', 'the grant subscription id names the network';
  is _coordinator($server)->authoritative_discovery_subscription_id(),
    'irc.authority.discovery:overnet', 'the discovery subscription id names the network';

  my @ids = _coordinator($server)->authoritative_channel_subscription_ids($channel);
  is scalar(@ids), 2, 'a bound channel yields meta and control subscription ids';
  like $ids[0], qr/\Airc[.]authority[.]meta:overnet:/mxs,    'the meta id is namespaced';
  like $ids[1], qr/\Airc[.]authority[.]control:overnet:/mxs, 'the control id is namespaced';

  my $unbound = _server(adapter_config => {authority_profile => 'nip29', network => 'overnet',},);
  is [_coordinator($unbound)->authoritative_channel_subscription_ids($channel)],
    [], 'a channel without a group binding yields no subscription ids';
};

subtest 'ensure_authoritative_grant_subscription opens once' => sub {
  my $disabled = _server(authority_relay => undef,);
  is _coordinator($disabled)->ensure_authoritative_grant_subscription(), undef, 'a disabled relay opens nothing';

  my $server = _server();
  my $id     = _coordinator($server)->ensure_authoritative_grant_subscription();
  is $id, 'irc.authority.grants:overnet', 'the subscription is opened';
  is _coordinator($server)->ensure_authoritative_grant_subscription(), $id,
    'a second call reuses the stored subscription id';
  my @opens = grep { $_->{method} eq 'nostr.open_subscription' } @{$server->requests};
  is scalar(@opens), 1, 'the subscription is opened only once';

  my $failing = _server();
  $failing->request_handler(_failing_open_handler());
  is _coordinator($failing)->ensure_authoritative_grant_subscription(), undef, 'a failed open reports no subscription';
};

subtest 'ensure_authoritative_discovery_subscription requires nip29' => sub {
  my $disabled = _server(authority_relay => undef,);
  is _coordinator($disabled)->ensure_authoritative_discovery_subscription(), undef, 'a disabled relay opens nothing';

  my $plain = _server(adapter_config => {authority_profile => q{}, network => 'overnet',},);
  is _coordinator($plain)->ensure_authoritative_discovery_subscription(), undef, 'a non-nip29 profile opens nothing';

  my $server = _server();
  my $id     = _coordinator($server)->ensure_authoritative_discovery_subscription();
  is $id, 'irc.authority.discovery:overnet', 'the discovery subscription is opened';
  is _coordinator($server)->ensure_authoritative_discovery_subscription(), $id,
    'a second call reuses the stored subscription id';

  my $failing = _server();
  $failing->request_handler(_failing_open_handler());
  is _coordinator($failing)->ensure_authoritative_discovery_subscription(), undef,
    'a failed open reports no subscription';
};

subtest 'ensure_authoritative_channel_subscription opens meta and control' => sub {
  my $disabled = _server(authority_relay => undef,);
  is _coordinator($disabled)->ensure_authoritative_channel_subscription($channel),
    undef, 'a disabled relay opens nothing';

  my $plain = _server(adapter_config => {authority_profile => q{}, network => 'overnet',},);
  is _coordinator($plain)->ensure_authoritative_channel_subscription($channel),
    undef, 'a non-authoritative channel opens nothing';

  my $server = _server();
  my $ids    = _coordinator($server)->ensure_authoritative_channel_subscription($channel);
  is scalar(@{$ids}), 2, 'both channel subscriptions are opened';
  is _coordinator($server)->ensure_authoritative_channel_subscription($channel),
    $ids, 'a second call reuses the opened subscriptions';
  my @opens = grep { $_->{method} eq 'nostr.open_subscription' } @{$server->requests};
  is scalar(@opens), 2, 'the channel subscriptions are opened only once';

  my $failing = _server();
  $failing->request_handler(_failing_open_handler());
  is _coordinator($failing)->ensure_authoritative_channel_subscription($channel),
    [], 'failed opens yield no subscription ids';
};

subtest 'read_nostr_subscription_snapshot guards its inputs' => sub {
  my $server = _server();
  is _coordinator($server)->read_nostr_subscription_snapshot(undef), [], 'an undefined subscription id reads nothing';
  is _coordinator($server)->read_nostr_subscription_snapshot(q{}),   [], 'an empty subscription id reads nothing';

  $server->request_handler(
    sub {
      my (%args) = @_;
      return {events => [_group_event()],} if $args{method} eq 'nostr.read_subscription_snapshot';
      return;
    }
  );
  my $events = _coordinator($server)->read_nostr_subscription_snapshot('sub-1', refresh => 1,);
  is scalar(@{$events}), 1, 'snapshot events are returned';
  my ($read) = grep { $_->{method} eq 'nostr.read_subscription_snapshot' } @{$server->requests};
  is $read->{params}{refresh}, 1, 'the refresh flag is forwarded';

  is _coordinator($server)->read_nostr_subscription_snapshot('sub-1', refresh => 0,),
    [_group_event()], 'a false refresh flag is forwarded as zero';

  my $failing = _server();
  $failing->request_handler(sub { die "runtime gone\n" });
  is _coordinator($failing)->read_nostr_subscription_snapshot('sub-1'), [], 'a failed read reports no events';

  my $malformed = _server();
  $malformed->request_handler(sub { return {events => 'nope',} });
  is _coordinator($malformed)->read_nostr_subscription_snapshot('sub-1'), [], 'a malformed snapshot reports no events';
};

subtest 'discovered channels are remembered, forgotten, and recorded' => sub {
  my $server = _server();
  is $server->_remember_authoritative_discovered_channel(channel => 'nochannel', group_id => $group_id,), 0,
    'an invalid channel is not remembered';
  is $server->_remember_authoritative_discovered_channel(channel => $channel, group_id => q{},), 0,
    'an empty group id is not remembered';
  is $server->_remember_authoritative_discovered_channel(channel => $channel, group_id => $group_id,), 1,
    'a valid discovery is remembered';
  ok $server->{authoritative_discovered_channels}{$channel}, 'the discovery is cached';

  is $server->_forget_authoritative_discovered_channel('nochannel'), 0, 'an invalid channel is not forgotten';
  is $server->_forget_authoritative_discovered_channel($channel),    1, 'the discovery is forgotten';
  ok !$server->{authoritative_discovered_channels}{$channel}, 'the cache entry is removed';

  is $server->_record_authoritative_discovery_event('nope'), 0, 'a non-hash event records nothing';
  is $server->_record_authoritative_discovery_event({kind => 39_000, tags => [],}), 0,
    'an event without a derivable channel records nothing';
  is $server->_record_authoritative_discovery_event(_group_event()), 1, 'a group event records its channel';
  ok $server->{authoritative_discovered_channels}{$channel}, 'the recorded channel is discovered';

  my $tombstone = _group_event(
    id         => 'f' x 64,
    tags       => [['d', $group_id], ['name', $channel], ['status', 'tombstoned'],],
    created_at => 2_000,
  );
  is $server->_record_authoritative_discovery_event($tombstone), 1, 'a tombstone event is recorded';
  ok !$server->{authoritative_discovered_channels}{$channel}, 'a tombstoned channel is no longer discovered';

  $server->{authoritative_discovery_event_cache}{'#weird'} = 'not-an-array';
  is $server->_record_authoritative_discovery_event(_group_event(id => 'a1' . ('0' x 62),)), 1,
    'recording tolerates malformed cache entries';
};

subtest 'event merging and discovery bucketing skip malformed input' => sub {
  my $server       = _server();
  my $unidentified = _group_event();
  delete $unidentified->{id};
  my $merged = _coordinator($server)
    ->_merge_authoritative_events('not-a-list', [_group_event(), 'not-a-hash', $unidentified, _group_event(),],);
  is scalar(@{$merged}), 2, 'non-lists, non-hashes, and duplicates are dropped while unidentified events stay';

  my $count =
    _coordinator($server)
    ->_set_authoritative_discovery_events(
    [bless({created_at => 1,}, 'NotAPlainHash'), {kind => 39_000, tags => [],}, _group_event(),],);
  is $count, 1, 'only plain-hash events with a derivable channel are bucketed';
  ok $server->{authoritative_discovered_channels}{$channel}, 'the derivable channel is discovered';
};

subtest 'an invalid channel_groups binding disables group-bound helpers' => sub {
  my $server = _server(
    adapter_config => {
      authority_profile => 'nip29',
      group_host        => 'groups.example.test',
      network           => 'overnet',
      channel_groups    => {$channel => [],},
    },
  );
  is _coordinator($server)->ensure_authoritative_channel_subscription($channel),
    undef, 'an unresolvable binding opens no channel subscriptions';
  is $server->_load_authoritative_nip29_events($channel, refresh => 1), [],
    'an unresolvable binding loads no refreshed events';

  my $local = _server(
    authority_relay => undef,
    adapter_config  => {
      authority_profile => 'nip29',
      group_host        => 'groups.example.test',
      network           => 'overnet',
      channel_groups    => {$channel => [],},
    },
  );
  my $client = $local->add_client(1, nick => 'alice',);
  is $local->_publish_authoritative_nip29_event(
    channel => $channel,
    client  => $client,
    event   => {kind => 9021, created_at => 1, content => q{}, tags => [],},
    ),
    0, 'an unresolvable binding fails the no-relay publish through append';
};

subtest 'refresh_authoritative_discovery_cache merges snapshots' => sub {
  my $disabled = _server(authority_relay => undef,);
  is $disabled->_refresh_authoritative_discovery_cache, 0, 'a disabled relay refreshes nothing';

  my $plain = _server(adapter_config => {authority_profile => q{}, network => 'overnet',},);
  is $plain->_refresh_authoritative_discovery_cache, 0, 'a non-nip29 profile refreshes nothing';

  my $failing = _server();
  $failing->request_handler(_failing_open_handler());
  is $failing->_refresh_authoritative_discovery_cache, 0, 'a failed discovery open refreshes nothing';

  my $server = _server();
  $server->request_handler(
    sub {
      my (%args) = @_;
      return {events => [_group_event(), 'not-a-hash', _group_event(),],}
        if $args{method} eq 'nostr.read_subscription_snapshot';
      return;
    }
  );
  is $server->_refresh_authoritative_discovery_cache(refresh => 1), 1, 'the discovery cache is refreshed';
  ok $server->{authoritative_discovered_channels}{$channel}, 'the discovered channel is cached';
  is $server->_refresh_authoritative_discovery_cache, 1, 'a refresh without arguments rereads the snapshot';
};

subtest 'query_nostr_events guards its inputs' => sub {
  my $server = _server();
  is $server->_query_nostr_events(filters => [{}],), [], 'a missing relay url queries nothing';
  is $server->_query_nostr_events(relay_url => [], filters => [{}],), [], 'a reference relay url queries nothing';
  is $server->_query_nostr_events(relay_url => 'ws://relay', filters => [],),     [], 'empty filters query nothing';
  is $server->_query_nostr_events(relay_url => 'ws://relay', filters => 'nope',), [], 'malformed filters query nothing';

  $server->request_handler(
    sub {
      my (%args) = @_;
      return {events => [_group_event()],} if $args{method} eq 'nostr.query_events';
      return;
    }
  );
  my $events = $server->_query_nostr_events(
    relay_url  => 'ws://relay',
    filters    => [{kinds => [39_000],}],
    timeout_ms => 250,
  );
  is scalar(@{$events}), 1, 'query events are returned';
  my ($query) = grep { $_->{method} eq 'nostr.query_events' } @{$server->requests};
  is $query->{params}{timeout_ms}, 250, 'the timeout is forwarded';

  my $failing = _server();
  $failing->request_handler(sub { die "runtime gone\n" });
  is $failing->_query_nostr_events(relay_url => 'ws://relay', filters => [{}],), [], 'a failed query reports no events';

  my $malformed = _server();
  $malformed->request_handler(sub { return {events => 'nope',} });
  is $malformed->_query_nostr_events(relay_url => 'ws://relay', filters => [{}],), [],
    'a malformed query result reports no events';
};

subtest 'runtime NIP-29 event streams are read and appended' => sub {
  my $plain = _server(adapter_config => {authority_profile => q{}, network => 'overnet',},);
  is $plain->_read_authoritative_nip29_events_from_runtime($channel), [], 'a channel without a stream reads nothing';

  my $server = _server(authority_relay => undef,);
  $server->request_handler(
    sub {
      my (%args) = @_;
      return {entries => [{event => _group_event(),}, 'not-a-hash', {event => 'nope',},],}
        if $args{method} eq 'events.read';
      return;
    }
  );
  my $events = $server->_read_authoritative_nip29_events_from_runtime($channel);
  is scalar(@{$events}), 1, 'only well-formed entries are returned';

  my $failing = _server(authority_relay => undef,);
  $failing->request_handler(sub { die "runtime gone\n" });
  is $failing->_read_authoritative_nip29_events_from_runtime($channel), [], 'a failed runtime read reports no events';

  my $malformed = _server(authority_relay => undef,);
  $malformed->request_handler(sub { return {entries => 'nope',} });
  is $malformed->_read_authoritative_nip29_events_from_runtime($channel), [],
    'a malformed runtime read reports no events';

  is $server->_append_authoritative_nip29_event($channel, 'nope'),         0, 'a non-hash event is not appended';
  is $plain->_append_authoritative_nip29_event($channel, _group_event()),  0, 'an unbound channel appends nothing';
  is $server->_append_authoritative_nip29_event($channel, _group_event()), 1, 'a valid event is appended';
  my ($append) = grep { $_->{method} eq 'events.append' } @{$server->requests};
  like $append->{params}{stream}, qr/\Airc[.]authority[.]nip29:overnet:/mxs, 'the append targets the stream';
};

subtest 'load_authoritative_nip29_events covers relay and runtime paths' => sub {
  my $plain = _server(adapter_config => {authority_profile => q{}, network => 'overnet',},);
  is $plain->_load_authoritative_nip29_events($channel), [], 'a non-authoritative channel loads nothing';

  my $duplicate = _group_event();
  my $server    = _server();
  $server->request_handler(
    sub {
      my (%args) = @_;
      return {events => [$duplicate, 'not-a-hash', $duplicate, _group_event(id => 'f' x 64,),],}
        if $args{method} eq 'nostr.read_subscription_snapshot'
        || $args{method} eq 'nostr.query_events';
      return;
    }
  );
  my $snapshot_events = $server->_load_authoritative_nip29_events($channel);
  is scalar(@{$snapshot_events}), 2, 'subscription snapshot events are deduplicated';

  my $refreshed = $server->_load_authoritative_nip29_events($channel, refresh => 1);
  is scalar(@{$refreshed}), 2, 'refresh queries are deduplicated';
  ok scalar(grep { $_->{method} eq 'nostr.query_events' } @{$server->requests}), 'a refresh queries the relay directly';

  my $failing = _server();
  $failing->request_handler(_failing_open_handler());
  is $failing->_load_authoritative_nip29_events($channel), [], 'failed subscription opens load nothing';

  my $runtime = _server(authority_relay => undef,);
  $runtime->request_handler(
    sub {
      my (%args) = @_;
      return {entries => [{event => _group_event(),},],} if $args{method} eq 'events.read';
      return;
    }
  );
  is scalar(@{$runtime->_load_authoritative_nip29_events($channel)}), 1, 'the runtime stream backs the no-relay path';
};

subtest 'the channel cache refreshes, reads, and reconciles' => sub {
  my $plain = _server(adapter_config => {authority_profile => q{}, network => 'overnet',},);
  is $plain->_refresh_authoritative_nip29_channel_cache($channel), [], 'a non-authoritative channel refreshes nothing';
  is $plain->_read_authoritative_nip29_events($channel),           [], 'a non-authoritative channel reads nothing';

  my $invite_event = {
    id         => 'd' x 64,
    kind       => 9009,
    created_at => 3_000,
    pubkey     => 'c' x 64,
    content    => q{},
    tags       => [['h', $group_id],],
  };
  my $server    = _server();
  my @snapshots = ([_group_event()], [_group_event(), $invite_event],);
  $server->request_handler(
    sub {
      my (%args) = @_;
      if ($args{method} eq 'nostr.read_subscription_snapshot' || $args{method} eq 'nostr.query_events') {
        my $events = @snapshots > 1 ? $snapshots[0] : $snapshots[-1];
        return {events => [@{$events}],};
      }
      if ($args{method} eq 'adapters.derive' && $args{params}{operation} eq 'authoritative_channel_view') {
        return {view => [{members => [], pending_invites => [],},],};
      }
      return;
    }
  );

  my $events = $server->_read_authoritative_nip29_events($channel);
  is scalar(@{$events}),                                             1, 'the first read fills the cache';
  is scalar(@{$server->_read_authoritative_nip29_events($channel)}), 1, 'a second read hits the cache';

  shift @snapshots;
  my $forced = $server->_read_authoritative_nip29_events($channel, force => 1);
  is scalar(@{$forced}), 2, 'a forced read refreshes and merges the cache';

  is $server->_reconcile_authoritative_pending_invites_from_refresh(
    channel    => $channel,
    old_view   => {},
    old_events => [_group_event()],
    new_view   => {pending_invites => [],},
    new_events => [_group_event(), $invite_event, 'not-a-hash', {kind => 9009,},],
    ),
    1, 'new invite events are reconciled';

  is $server->_reconcile_authoritative_pending_invites_from_refresh(
    channel    => $channel,
    old_view   => undef,
    old_events => [_group_event()],
    new_view   => {pending_invites => [],},
    new_events => [_group_event(), {%{$invite_event}, id => 'f' x 64,},],
    ),
    1, 'a refresh without a prior view still reconciles new invites';

  is $server->_reconcile_authoritative_pending_invites_from_refresh(
    channel    => $channel,
    old_view   => {},
    old_events => [$invite_event],
    new_view   => {pending_invites => [],},
    new_events => [$invite_event],
    ),
    0, 'already-seen invite events are not reconciled again';

  is $server->_reconcile_authoritative_pending_invites_from_refresh(
    channel    => $channel,
    old_view   => {},
    old_events => [],
    new_view   => 'nope',
    new_events => [],
    ),
    0, 'a malformed new view reconciles nothing';

  is $server->_reconcile_authoritative_pending_invites_from_refresh(
    channel    => $channel,
    old_view   => {},
    old_events => 'nope',
    new_view   => {},
    new_events => [],
    ),
    0, 'malformed event lists reconcile nothing';

  is $plain->_reconcile_authoritative_pending_invites_from_refresh(
    channel    => $channel,
    old_view   => {},
    old_events => [],
    new_view   => {},
    new_events => [],
    ),
    0, 'a non-authoritative channel reconciles nothing';

  my %coordinator_guard_case = (
    'a non-authoritative channel' => [$plain, channel => $channel, new_view => {}, old_events => [], new_events => [],],
    'a malformed new view'  => [$server, channel => $channel, new_view => 'nope', old_events => [], new_events => [],],
    'malformed event lists' => [$server, channel => $channel, new_view => {}, old_events => 'nope', new_events => [],],
    'idless and non-hash events' => [
      $server,
      channel    => $channel,
      new_view   => {pending_invites => [],},
      old_events => [$invite_event],
      new_events => ['nope', {kind => 9009,}, {kind => 1, id => 'a' x 64,}, $invite_event,],
    ],
  );

  for my $case (sort keys %coordinator_guard_case) {
    my ($guarded, %args) = @{$coordinator_guard_case{$case}};
    is _coordinator($guarded)->reconcile_authoritative_pending_invites_from_refresh(
      old_view => {},
      %args,
      ),
      0, "$case reconciles nothing through the coordinator";
  }
};

subtest 'read_authoritative_grant_events caches grant snapshots' => sub {
  my $disabled = _server(authority_relay => undef,);
  is $disabled->_read_authoritative_grant_events, [], 'a disabled relay reads no grants';

  my $server = _server();
  $server->request_handler(
    sub {
      my (%args) = @_;
      return {events => [_group_event(created_at => 2_000,), _group_event(id => 'f' x 64, created_at => 1_000,),],}
        if $args{method} eq 'nostr.read_subscription_snapshot';
      return;
    }
  );
  my $events = $server->_read_authoritative_grant_events;
  is scalar(@{$events}),                                   2,        'grant events are read';
  is $events->[0]{id},                                     'f' x 64, 'grant events are sorted by created_at';
  is scalar(@{$server->_read_authoritative_grant_events}), 2,        'a second read hits the cache';
  my @reads = grep { $_->{method} eq 'nostr.read_subscription_snapshot' } @{$server->requests};
  is scalar(@reads),                                                   1, 'the cache avoids a second snapshot read';
  is scalar(@{$server->_read_authoritative_grant_events(force => 1)}), 2, 'a forced read refreshes the cache';
};

subtest 'publish_authoritative_nip29_event covers relay publishing' => sub {
  my $server = _with_view_handler(_server());
  my $key    = Overnet::Core::Nostr->generate_key;
  my $client = $server->add_client(
    1,
    nick                        => 'alice',
    username                    => 'alice',
    registered                  => 1,
    authority_pubkey            => 'a' x 64,
    authority_delegate_key      => $key,
    authority_delegate_event_id => 'b' x 64,
  );
  my $draft = {
    kind       => 9021,
    created_at => 1_000,
    content    => q{},
    tags       => [['h', $group_id],],
  };

  is $server->_publish_authoritative_nip29_event(channel => 'nochannel', client => $client, event => $draft,), 0,
    'a non-authoritative channel publishes nothing';
  is $server->_publish_authoritative_nip29_event(channel => $channel, client => $client, event => 'nope',), 0,
    'a non-hash event publishes nothing';

  my $undelegated = $server->add_client(2, nick => 'bob',);
  is $server->_publish_authoritative_nip29_event(channel => $channel, client => $undelegated, event => $draft,), 0,
    'a client without delegation publishes nothing';

  is $server->_publish_authoritative_nip29_event(channel => $channel, client => $client, event => $draft,), 1,
    'a delegated publish succeeds';
  my ($publish) = grep { $_->{method} eq 'nostr.publish_event' } @{$server->requests};
  is $publish->{params}{relay_url}, 'ws://127.0.0.1:7448', 'the publish targets the relay';

  my $expired = $server->add_client(
    3,
    nick                          => 'carol',
    authority_delegate_key        => $key,
    authority_delegate_event_id   => 'b' x 64,
    authority_delegate_expires_at => 1,
  );
  is $server->_publish_authoritative_nip29_event(channel => $channel, client => $expired, event => $draft,), 0,
    'an expired delegation publishes nothing';

  my $suppressing       = _server();
  my $suppressed_client = $suppressing->add_client(
    1,
    nick                        => 'alice',
    authority_delegate_key      => $key,
    authority_delegate_event_id => 'b' x 64,
  );
  _with_view_handler(
    $suppressing,
    sub {
      my (%args) = @_;
      return {accepted => 1, event_id => '9' x 64,} if $args{method} eq 'nostr.publish_event';
      return;
    }
  );
  is $suppressing->_publish_authoritative_nip29_event(
    channel => $channel,
    client  => $suppressed_client,
    event   => $draft,
    ),
    1, 'an accepted publish with an event id succeeds';
  ok $suppressing->{suppress_subscription_event_ids}{'9' x 64}, 'the published event id is suppressed';

  my $rejecting       = _server();
  my $rejected_client = $rejecting->add_client(
    1,
    nick                        => 'alice',
    authority_delegate_key      => $key,
    authority_delegate_event_id => 'b' x 64,
  );
  _with_view_handler(
    $rejecting,
    sub {
      my (%args) = @_;
      return {accepted => 0, message => 'nope',} if $args{method} eq 'nostr.publish_event';
      return;
    }
  );
  is $rejecting->_publish_authoritative_nip29_event(channel => $channel, client => $rejected_client, event => $draft,),
    0, 'a rejected publish fails';
  like $rejecting->{authoritative_publish_error}, qr/rejected\ event:\ nope/mxs, 'the rejection message is preserved';

  my $erroring     = _server();
  my $error_client = $erroring->add_client(
    1,
    nick                        => 'alice',
    authority_delegate_key      => $key,
    authority_delegate_event_id => 'b' x 64,
  );
  _with_view_handler(
    $erroring,
    sub {
      my (%args) = @_;
      die "relay gone\n" if $args{method} eq 'nostr.publish_event';
      return;
    }
  );
  is $erroring->_publish_authoritative_nip29_event(channel => $channel, client => $error_client, event => $draft,),
    0, 'a failed publish request fails';
  is $erroring->{authoritative_publish_error}, 'authoritative relay publish failed', 'the publish failure is recorded';

  my $unsignable        = _server();
  my $unsignable_client = $unsignable->add_client(
    1,
    nick                        => 'alice',
    authority_delegate_key      => $key,
    authority_delegate_event_id => 'b' x 64,
  );
  my $dying_key = mock 'Overnet::Core::Nostr::Key' => (override => [sign_event_hash => sub { die "no\n" },],);
  is $unsignable->_publish_authoritative_nip29_event(
    channel => $channel,
    client  => $unsignable_client,
    event   => $draft,
    ),
    0, 'a signing failure fails the publish';
  is $unsignable->{authoritative_publish_error}, 'authoritative relay signing failed',
    'the signing failure is recorded';
  $dying_key = mock 'Overnet::Core::Nostr::Key' => (override => [sign_event_hash => sub {'not-an-event'},],);
  is $unsignable->_publish_authoritative_nip29_event(
    channel => $channel,
    client  => $unsignable_client,
    event   => $draft,
    ),
    0, 'an invalid signing result fails the publish';
  is $unsignable->{authoritative_publish_error}, 'authoritative relay signing returned an invalid event',
    'the invalid signing result is recorded';
  $dying_key = mock 'Overnet::Core::Nostr::Key' =>
    (override => [sign_event_hash => sub { return {%{$draft}, id => '8' x 64,} },],);
  _with_view_handler($unsignable);
  is $unsignable->_publish_authoritative_nip29_event(
    channel => $channel,
    client  => $unsignable_client,
    event   => $draft,
    ),
    1, 'a signing result that is already a hash publishes as-is';
  $dying_key = undef;

  my $local        = _with_view_handler(_server(authority_relay => undef,));
  my $local_client = $local->add_client(1, nick => 'alice',);
  is $local->_publish_authoritative_nip29_event(channel => $channel, client => $local_client, event => $draft,), 1,
    'a no-relay publish appends to the runtime stream';
  ok scalar(grep { $_->{method} eq 'events.append' } @{$local->requests}), 'the event is appended';

  my $unappendable = _server(
    authority_relay => undef,
    adapter_config  => {authority_profile => 'nip29', network => 'overnet',},
  );
  my $unappendable_client = $unappendable->add_client(1, nick => 'alice',);
  is $unappendable->_publish_authoritative_nip29_event(
    channel => $channel,
    client  => $unappendable_client,
    event   => $draft,
    ),
    0, 'an unbound no-relay channel publishes nothing';
};

subtest 'handle_subscription_event renders and fans out runtime items' => sub {
  my $server = _server(adapter_config => {authority_profile => q{}, network => 'overnet',},);
  my $alice  = $server->add_client(1, nick => 'alice', username => 'alice', registered => 1,);
  my $bob    = $server->add_client(2, nick => 'bob',   username => 'bob',   registered => 1,);
  $server->_add_client_to_channel($_, $channel) for 1, 2;

  is $server->_handle_subscription_event('nope'), 0, 'non-hash params are ignored';
  is $server->_handle_subscription_event({item_type => 'mystery',}),               0, 'unknown item types are ignored';
  is $server->_handle_subscription_event({item_type => 'event', data => 'nope',}), 0, 'non-hash data is ignored';

  my $message = $server->{signing_key}->create_event_hash(
    kind       => 1,
    created_at => 1_000,
    content    => JSON::encode_json(
      {
        provenance => {external_identity => 'carol',},
        body       => {text              => 'hello channel',},
      }
    ),
    tags =>
      [['overnet_ot', 'chat.channel'], ['overnet_oid', 'irc:overnet:' . $channel], ['overnet_et', 'chat.message'],],
  );

  is $server->_handle_subscription_event({item_type => 'event', data => $message,}), 2,
    'a channel message fans out to the joined clients';
  like $server->lines_for(1)->[-1], qr/:carol\ PRIVMSG\ \Q$channel\E\ :hello\ channel/mxs,
    'the rendered line reaches the members';

  is $server->_handle_subscription_event({item_type => 'event', data => $message,}), 0,
    'a repeated event id is not rendered twice';

  my $suppressed = $server->{signing_key}->create_event_hash(
    kind       => 1,
    created_at => 1_001,
    content    => JSON::encode_json(
      {
        provenance => {external_identity => 'carol',},
        body       => {text              => 'suppressed',},
      }
    ),
    tags =>
      [['overnet_ot', 'chat.channel'], ['overnet_oid', 'irc:overnet:' . $channel], ['overnet_et', 'chat.message'],],
  );
  $server->{suppress_subscription_event_ids}{$suppressed->{id}} = 1;
  is $server->_handle_subscription_event({item_type => 'event', data => $suppressed,}), 0,
    'a suppressed event id is not rendered';

  my $origin = $server->{signing_key}->create_event_hash(
    kind       => 1,
    created_at => 1_002,
    content    => JSON::encode_json(
      {
        provenance => {external_identity => 'alice',},
        body       => {text              => 'from alice',},
      }
    ),
    tags =>
      [['overnet_ot', 'chat.channel'], ['overnet_oid', 'irc:overnet:' . $channel], ['overnet_et', 'chat.message'],],
  );
  $server->{subscription_event_origin_client_ids}{$origin->{id}} = 1;
  $server->clear_sent_lines;
  is $server->_handle_subscription_event({item_type => 'event', data => $origin,}), 1,
    'an originating client is excluded from the fan-out';
  is $server->lines_for(1), [], 'the originating client hears nothing';
  like $server->lines_for(2)->[-1], qr/from\ alice/mxs, 'other members still hear the line';

  my $unrenderable = $server->{signing_key}->create_event_hash(
    kind       => 1,
    created_at => 1_003,
    content    => 'not-json',
    tags       => [['overnet_ot', 'chat.channel'],],
  );
  is $server->_handle_subscription_event({item_type => 'event', data => $unrenderable,}), 0,
    'an unrenderable event is ignored';
};

subtest 'handle_nostr_subscription_event routes by subscription' => sub {
  my $server = _with_view_handler(_server());
  is $server->_handle_nostr_subscription_event({data => 'nope',}), 0, 'non-hash data is ignored';
  is $server->_handle_nostr_subscription_event({data => {},}),     0, 'a missing subscription id is ignored';
  is $server->_handle_nostr_subscription_event({data => {}, subscription_id => [],}), 0,
    'a reference subscription id is ignored';

  my $suppressed_event = _group_event(id => '1' x 64,);
  $server->{suppress_subscription_event_ids}{'1' x 64} = 1;
  is $server->_handle_nostr_subscription_event(
    {
      item_type       => 'nostr.event',
      subscription_id => 'sub-x',
      data            => $suppressed_event,
    }
    ),
    0, 'a suppressed nostr event id is ignored';

  $server->{rendered_subscription_event_ids}{'2' x 64} = 1;
  is $server->_handle_nostr_subscription_event(
    {
      subscription_id => 'sub-x',
      data            => _group_event(id => '2' x 64,),
    }
    ),
    0, 'an already-rendered nostr event id is ignored';

  $server->{authoritative_grant_subscription_id} = 'grants-sub';
  is $server->_handle_subscription_event(
    {
      item_type       => 'nostr.event',
      subscription_id => 'grants-sub',
      data            => _group_event(id => '3' x 64,),
    }
    ),
    1, 'a grant subscription event refreshes the grant cache';
  ok $server->{authoritative_grant_cache}, 'the grant cache is rebuilt';

  $server->{authoritative_discovery_subscription_id} = 'discovery-sub';
  is $server->_handle_nostr_subscription_event(
    {
      subscription_id => 'discovery-sub',
      data            => _group_event(id => '4' x 64,),
    }
    ),
    1, 'a discovery subscription event records the channel';

  is $server->_handle_nostr_subscription_event(
    {
      subscription_id => 'unknown-sub',
      data            => _group_event(id => '5' x 64,),
    }
    ),
    0, 'an unknown subscription id is ignored';

  $server->{authoritative_subscription_channels}{'channel-sub'} = $channel;
  is $server->_handle_nostr_subscription_event(
    {
      subscription_id => 'channel-sub',
      data            => _group_event(id => '6' x 64,),
    }
    ),
    1, 'a channel subscription event updates the channel cache';
  ok $server->{rendered_subscription_event_ids}{'6' x 64}, 'the applied event id is remembered';

  $server->{authoritative_subscription_channels}{'weird-sub'} = 'nochannel';
  is $server->_handle_nostr_subscription_event(
    {
      subscription_id => 'weird-sub',
      data            => _group_event(id => '7' x 64,),
    }
    ),
    0, 'a subscription bound to an invalid channel updates nothing';
  ok !$server->{rendered_subscription_event_ids}{'7' x 64}, 'the unapplied event id is not remembered';
};

subtest 'rendered event ids are capped' => sub {
  my $server = _server();
  is _coordinator($server)->_remember_rendered_subscription_event_id(undef), 0,
    'an undefined event id is not remembered';
  is _coordinator($server)->_remember_rendered_subscription_event_id('seen'), 1, 'an event id is remembered';
  is _coordinator($server)->_remember_rendered_subscription_event_id('seen'), 1, 'a repeated event id stays remembered';
  is scalar(@{$server->{rendered_subscription_event_id_order}}),              1, 'repeats are not queued twice';

  _coordinator($server)->_remember_rendered_subscription_event_id("id-$_")
    for 1 .. 4_096;
  ok !$server->{rendered_subscription_event_ids}{seen}, 'the oldest event id is evicted at the cap';
  is scalar(@{$server->{rendered_subscription_event_id_order}}), 4_096, 'the order queue stays at the cap';
};

done_testing;
