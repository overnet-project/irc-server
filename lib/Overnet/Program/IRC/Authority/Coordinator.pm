package Overnet::Program::IRC::Authority::Coordinator;

use strictures 2;

use English qw(-no_match_vars);
use Overnet::Authority::HostedChannel;

our $VERSION = '0.001';
my $MAX_RENDERED_SUBSCRIPTION_EVENT_IDS = 4_096;

sub _event_id {
  my ($event) = @_;
  if (!(ref($event) eq 'HASH')) {
    return;
  }

  if (!(defined($event->{id}) && !ref($event->{id}) && length($event->{id}))) {
    return;
  }

  return $event->{id};
}

sub _merge_authoritative_events {
  my ($server, @lists) = @_;
  my @events;
  my %seen_ids;

  for my $list (@lists) {
    if (!(ref($list) eq 'ARRAY')) {
      next;
    }

    for my $event (@{$list}) {
      if (!(ref($event) eq 'HASH')) {
        next;
      }

      my $event_id = _event_id($event);
      next if defined($event_id) && $seen_ids{$event_id}++;
      push @events, $event;
    }
  }

  return $server->_sort_authoritative_events(\@events);
}

sub _all_authoritative_discovery_events {
  my ($server) = @_;
  my @events;

  for my $events (values %{$server->{authoritative_discovery_event_cache} || {}}) {
    if (!(ref($events) eq 'ARRAY')) {
      next;
    }

    push @events, @{$events};
  }

  return \@events;
}

sub _set_authoritative_discovery_events {
  my ($server, $events) = @_;
  my %by_channel;

  for my $event (@{$server->_sort_authoritative_events($events || []) || []}) {
    if (!(ref($event) eq 'HASH')) {
      next;
    }

    my $channel = Overnet::Authority::HostedChannel::channel_name_from_group_event(
      network => $server->{config}{network},
      event   => $event,
    );
    if (!(defined $channel)) {
      next;
    }

    my $canonical = $server->_canonical_channel_name($channel);
    if (!(defined $canonical)) {
      next;
    }

    push @{$by_channel{$canonical}}, $event;
  }

  $server->{authoritative_discovery_event_cache} = {};
  $server->{authoritative_discovered_channels}   = {};

  for my $canonical (sort keys %by_channel) {
    my $sorted = $server->_sort_authoritative_events($by_channel{$canonical});
    $server->{authoritative_discovery_event_cache}{$canonical} = $sorted;

    my $active;
    for my $event (@{$sorted}) {
      my %tags     = $server->_first_tag_values($event->{tags});
      my $group_id = $tags{d} || $tags{h};
      if (!(defined $group_id && !ref($group_id) && length($group_id))) {
        next;
      }

      if (
        Overnet::Authority::HostedChannel::group_event_is_tombstoned(
          event => $event
        )
      ) {
        $active = undef;
        next;
      }
      $active = {
        channel_name  => $canonical,
        group_id      => $group_id,
        discovered_at => time(),
      };
    }

    if (ref($active) eq 'HASH') {
      $server->{authoritative_discovered_channels}{$canonical} = $active;
    }

  }

  return scalar keys %{$server->{authoritative_discovered_channels} || {}};
}

sub authoritative_grant_subscription_id {
  my ($server) = @_;
  return 'irc.authority.grants:' . $server->{config}{network};
}

sub authoritative_discovery_subscription_id {
  my ($server) = @_;
  return 'irc.authority.discovery:' . $server->{config}{network};
}

sub authoritative_channel_subscription_ids {
  my ($server,     $channel)  = @_;
  my ($group_host, $group_id) = $server->_authoritative_group_binding($channel);
  if (!(defined $group_host && defined $group_id)) {
    return ();
  }

  return (
    join(q{:}, q{irc.authority.meta},    $server->{config}{network}, $group_host, $group_id),
    join(q{:}, q{irc.authority.control}, $server->{config}{network}, $group_host, $group_id),
  );
}

sub ensure_authoritative_grant_subscription {
  my ($server) = @_;
  if (!($server->_authority_relay_enabled)) {
    return;
  }

  my $subscription_id = $server->{authoritative_grant_subscription_id}
    || authoritative_grant_subscription_id($server);
  return $subscription_id
    if $server->{authoritative_grant_subscription_id};

  my $opened = eval {
    $server->_request(
      method => 'nostr.open_subscription',
      params => {
        subscription_id => $subscription_id,
        relay_url       => $server->_authority_relay_url,
        timeout_ms      => $server->_authority_relay_query_timeout_ms,
        filters         => [
          {
            kinds => [$server->_authority_grant_kind],
            limit => 200,
          },
        ],
      },
    );
    1;
  };
  if (!($opened)) {
    return;
  }

  $server->{authoritative_grant_subscription_id} = $subscription_id;
  return $subscription_id;
}

sub ensure_authoritative_discovery_subscription {
  my ($server) = @_;
  if (!($server->_authority_relay_enabled)) {
    return;
  }

  if (!($server->_authority_profile eq 'nip29')) {
    return;
  }

  my $subscription_id = $server->{authoritative_discovery_subscription_id}
    || authoritative_discovery_subscription_id($server);
  return $subscription_id
    if $server->{authoritative_discovery_subscription_id};

  my $opened = eval {
    $server->_request(
      method => 'nostr.open_subscription',
      params => {
        subscription_id => $subscription_id,
        relay_url       => $server->_authority_relay_url,
        timeout_ms      => $server->_authority_relay_query_timeout_ms,
        filters         => [
          {
            kinds => [39_000, 9_002],
            limit => 1_000,
          },
        ],
      },
    );
    1;
  };
  if (!($opened)) {
    return;
  }

  $server->{authoritative_discovery_subscription_id} = $subscription_id;
  return $subscription_id;
}

sub ensure_authoritative_channel_subscription {
  my ($server, $channel) = @_;
  if (!($server->_authority_relay_enabled)) {
    return;
  }

  if (!($server->_is_authoritative_channel($channel))) {
    return;
  }

  my $canonical = $server->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    return;
  }

  my (undef, $group_id) = $server->_authoritative_group_binding($canonical);
  if (!(defined $group_id)) {
    return;
  }

  my @subscription_specs = (
    [
      (authoritative_channel_subscription_ids($server, $canonical))[0],
      [
        {
          kinds => [39_000, 39_001, 39_002, 39_003],
          '#d'  => [$group_id],
          limit => 200,
        },
      ],
    ],
    [
      (authoritative_channel_subscription_ids($server, $canonical))[1],
      [
        {
          kinds => [9000, 9001, 9_002, 9009, 9021, 9022],
          '#h'  => [$group_id],
          limit => 200,
        },
      ],
    ],
  );

  my @subscription_ids;
  for my $spec (@subscription_specs) {
    my ($subscription_id, $filters) = @{$spec};
    if (!(defined $subscription_id)) {
      next;
    }

    if (!$server->{authoritative_subscription_channels}{$subscription_id}) {
      my $opened = eval {
        $server->_request(
          method => 'nostr.open_subscription',
          params => {
            subscription_id => $subscription_id,
            relay_url       => $server->_authority_relay_url,
            timeout_ms      => $server->_authority_relay_query_timeout_ms,
            filters         => $filters,
          },
        );
        1;
      };
      if (!($opened)) {
        next;
      }

      $server->{authoritative_subscription_channels}{$subscription_id} = $canonical;
    }
    push @subscription_ids, $subscription_id;
  }

  return \@subscription_ids;
}

sub read_nostr_subscription_snapshot {
  my ($server, $subscription_id, %args) = @_;
  if (!(defined $subscription_id && !ref($subscription_id) && length($subscription_id))) {
    return [];
  }

  my $result = eval {
    $server->_request(
      method => 'nostr.read_subscription_snapshot',
      params => {
        subscription_id => $subscription_id,
        (
          defined $args{refresh}
          ? (refresh => $args{refresh} ? 1 : 0)
          : ()
        ),
      },
    );
  };
  return [] if $EVAL_ERROR;
  if (!(ref($result->{events}) eq 'ARRAY')) {
    return [];
  }

  return [@{$result->{events}}];
}

sub remember_authoritative_discovered_channel {
  my ($server, %args) = @_;
  my $channel  = $args{channel};
  my $group_id = $args{group_id};
  if (!($server->_is_channel_name($channel))) {
    return 0;
  }

  if (!(defined $group_id && !ref($group_id) && length($group_id))) {
    return 0;
  }

  my $canonical = $server->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    return 0;
  }

  $server->{authoritative_discovered_channels}{$canonical} = {
    channel_name  => $channel,
    group_id      => $group_id,
    discovered_at => time(),
  };
  return 1;
}

sub forget_authoritative_discovered_channel {
  my ($server, $channel) = @_;
  my $canonical = $server->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    return 0;
  }

  delete $server->{authoritative_discovered_channels}{$canonical};
  return 1;
}

sub record_authoritative_discovery_event {
  my ($server, $event) = @_;
  if (!(ref($event) eq 'HASH')) {
    return 0;
  }

  my $channel = Overnet::Authority::HostedChannel::channel_name_from_group_event(
    network => $server->{config}{network},
    event   => $event,
  );
  if (!(defined $channel)) {
    return 0;
  }

  my $merged = _merge_authoritative_events($server, _all_authoritative_discovery_events($server), [$event],);
  _set_authoritative_discovery_events($server, $merged);
  return 1;
}

sub refresh_authoritative_discovery_cache {
  my ($server, %args) = @_;
  if (!($server->_authority_relay_enabled)) {
    return 0;
  }

  if (!($server->_authority_profile eq 'nip29')) {
    return 0;
  }

  my $subscription_id = ensure_authoritative_discovery_subscription($server);
  if (!(defined $subscription_id)) {
    return 0;
  }

  my $events = read_nostr_subscription_snapshot($server, $subscription_id, ($args{refresh} ? (refresh => 1) : ()),);
  my $merged = _merge_authoritative_events($server, _all_authoritative_discovery_events($server), $events,);
  return _set_authoritative_discovery_events($server, $merged);
}

sub query_nostr_events {
  my ($server, %args) = @_;
  my $relay_url = $args{relay_url};
  my $filters   = $args{filters};
  if (!(defined $relay_url && !ref($relay_url) && length($relay_url))) {
    return [];
  }

  if (!(ref($filters) eq 'ARRAY' && @{$filters})) {
    return [];
  }

  my $result = eval {
    $server->_request(
      method => 'nostr.query_events',
      params => {
        relay_url => $relay_url,
        filters   => $filters,
        (
          defined $args{timeout_ms}
          ? (timeout_ms => $args{timeout_ms})
          : ()
        ),
      },
    );
  };
  return [] if $EVAL_ERROR;
  if (!(ref($result->{events}) eq 'ARRAY')) {
    return [];
  }

  return [@{$result->{events}}];
}

sub read_authoritative_nip29_events_from_runtime {
  my ($server, $channel) = @_;
  my $stream = $server->_authoritative_nip29_stream_name($channel);
  if (!(defined $stream)) {
    return [];
  }

  my $result = eval { $server->_request(method => 'events.read', params => {stream => $stream,},); };
  return [] if $EVAL_ERROR;
  if (!(ref($result->{entries}) eq 'ARRAY')) {
    return [];
  }

  return [
    map  { $_->{event} }
    grep { ref eq 'HASH' && ref($_->{event}) eq 'HASH' } @{$result->{entries}}
  ];
}

sub load_authoritative_nip29_events {
  my ($server, $channel, %args) = @_;
  if (!($server->_is_authoritative_channel($channel))) {
    return [];
  }

  my $canonical = $server->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    return [];
  }

  if ($server->_authority_relay_enabled) {
    if ($args{refresh}) {
      my (undef, $group_id) = $server->_authoritative_group_binding($canonical);
      if (!(defined $group_id)) {
        return [];
      }

      my @events;
      my %seen_ids;
      for my $filters (
        [
          {
            kinds => [39_000, 39_001, 39_002, 39_003],
            '#d'  => [$group_id],
            limit => 200,
          },
        ],
        [
          {
            kinds => [9000, 9001, 9_002, 9009, 9021, 9022],
            '#h'  => [$group_id],
            limit => 200,
          },
        ],
      ) {
        my $queried = query_nostr_events(
          $server,
          relay_url  => $server->_authority_relay_url,
          filters    => $filters,
          timeout_ms => $server->_authority_relay_query_timeout_ms,
        );
        for my $event (@{$queried || []}) {
          if (!(ref($event) eq 'HASH')) {
            next;
          }

          next
            if defined($event->{id}) && $seen_ids{$event->{id}}++;
          push @events, $event;
        }
      }

      return \@events;
    }

    my $subscription_ids = ensure_authoritative_channel_subscription($server, $canonical);
    if (!(ref($subscription_ids) eq 'ARRAY' && @{$subscription_ids})) {
      return [];
    }

    my @events;
    my %seen_ids;
    for my $subscription_id (@{$subscription_ids}) {
      my $subscription_events = read_nostr_subscription_snapshot($server, $subscription_id);
      for my $event (@{$subscription_events || []}) {
        if (!(ref($event) eq 'HASH')) {
          next;
        }

        next if defined($event->{id}) && $seen_ids{$event->{id}}++;
        push @events, $event;
      }
    }
    return \@events;
  }

  return read_authoritative_nip29_events_from_runtime($server, $canonical);
}

sub refresh_authoritative_nip29_channel_cache {
  my ($server, $channel, %args) = @_;
  if (!($server->_is_authoritative_channel($channel))) {
    return [];
  }

  my $canonical = $server->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    return [];
  }

  my $cache = ($server->{authoritative_channel_cache}{$canonical} ||= {});
  my $old_events =
    ref($cache->{events}) eq 'ARRAY'
    ? $cache->{events}
    : [];
  my $events =
    load_authoritative_nip29_events($server, $canonical, (defined $args{refresh} ? (refresh => $args{refresh}) : ()),);
  $events = _merge_authoritative_events($server, $old_events, $events);
  my $view = $server->_derive_authoritative_channel_view_from_events($canonical, $events);
  $cache->{events}       = $events;
  $cache->{view}         = $view;
  $cache->{state}        = $server->_authoritative_channel_state_from_view($view);
  $cache->{refreshed_at} = time();
  $server->_sync_authoritative_topic_state_from_view($canonical, $view);

  return $events;
}

sub read_authoritative_nip29_events {
  my ($server, $channel, %args) = @_;
  if (!($server->_is_authoritative_channel($channel))) {
    return [];
  }

  my $canonical = $server->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    return [];
  }

  my $cache = $server->{authoritative_channel_cache}{$canonical};
  if ( !$args{force}
    && ref($cache) eq 'HASH'
    && ref($cache->{events}) eq 'ARRAY') {
    return [@{$cache->{events}}];
  }

  my $old_view = ref($cache) eq 'HASH' ? $cache->{view} : undef;
  my $old_events =
    ref($cache) eq 'HASH' && ref($cache->{events}) eq 'ARRAY'
    ? [@{$cache->{events}}]
    : [];
  my $events    = refresh_authoritative_nip29_channel_cache($server, $canonical, refresh => $args{force} ? 1 : 0,);
  my $new_cache = $server->{authoritative_channel_cache}{$canonical};
  if ($args{force} && ref($new_cache) eq 'HASH') {
    reconcile_authoritative_pending_invites_from_refresh(
      $server,
      channel    => $canonical,
      old_view   => $old_view,
      old_events => $old_events,
      new_view   => $new_cache->{view},
      new_events => $new_cache->{events},
    );
  }
  return [@{$events}];
}

sub read_authoritative_grant_events {
  my ($server, %args) = @_;
  if (!($server->_authority_relay_enabled)) {
    return [];
  }

  my $cache = $server->{authoritative_grant_cache};
  if (!$args{force} && $cache && ref($cache->{events}) eq 'ARRAY') {
    return [@{$cache->{events}}];
  }

  my $subscription_id = ensure_authoritative_grant_subscription($server);
  my $events = read_nostr_subscription_snapshot($server, $subscription_id, ($args{force} ? (refresh => 1) : ()),);
  $events = $server->_sort_authoritative_events($events);

  $server->{authoritative_grant_cache} = {
    events         => $events,
    refreshed_at   => time(),
    nick_by_pubkey => undef,
  };

  return [@{$events}];
}

sub publish_authoritative_nip29_event {
  my ($server, %args) = @_;
  my $channel = $args{channel};
  my $client  = $args{client};
  my $event   = $args{event};
  if (!($server->_is_authoritative_channel($channel))) {
    return 0;
  }

  if (!(ref($event) eq 'HASH')) {
    return 0;
  }

  if ($server->_authority_relay_enabled) {
    if (!($server->_client_has_authoritative_delegation($client))) {
      return 0;
    }

    my $signed = eval { $client->{authority_delegate_key}->sign_event_hash(event => $event,); };
    if ($EVAL_ERROR) {
      $server->{authoritative_publish_error} = 'authoritative relay signing failed';
      return 0;
    }
    if (!(ref($signed) eq 'HASH' || ref($signed) eq 'Overnet::Core::Nostr::Event')) {
      $server->{authoritative_publish_error} = 'authoritative relay signing returned an invalid event';
      return 0;
    }

    my $event_hash =
      ref($signed) eq 'HASH'
      ? $signed
      : $signed->to_hash;
    my $publish = eval {
      $server->_request(
        method => 'nostr.publish_event',
        params => {
          relay_url => $server->_authority_relay_url,
          event     => $event_hash,
        },
      );
    };
    if ($EVAL_ERROR) {
      $server->{authoritative_publish_error} = 'authoritative relay publish failed';
      return 0;
    }
    if (!(ref($publish) eq 'HASH' && $publish->{accepted})) {
      $server->{authoritative_publish_error} =
        ref($publish) eq 'HASH' && defined $publish->{message} && length($publish->{message})
        ? 'authoritative relay rejected event: ' . $publish->{message}
        : 'authoritative relay rejected event';
      return 0;
    }

    if ( defined $publish->{event_id}
      && !ref($publish->{event_id})
      && length($publish->{event_id})) {
      $server->{suppress_subscription_event_ids}{$publish->{event_id}} = 1;
    }

    $server->_update_authoritative_channel_cache_with_event(
      channel         => $channel,
      event           => $event_hash,
      suppress_render => 1,
    );
    return 1;
  }

  if (!(append_authoritative_nip29_event($server, $channel, $event))) {
    return 0;
  }

  refresh_authoritative_nip29_channel_cache($server, $channel);
  return 1;
}

sub append_authoritative_nip29_event {
  my ($server, $channel, $event) = @_;
  if (!(ref($event) eq 'HASH')) {
    return 0;
  }

  my $stream = $server->_authoritative_nip29_stream_name($channel);
  if (!(defined $stream)) {
    return 0;
  }

  $server->_request(
    method => 'events.append',
    params => {
      stream => $stream,
      event  => $event,
    },
  );
  return 1;
}

sub handle_subscription_event {
  my ($server, $params) = @_;
  if (!(ref($params) eq 'HASH')) {
    return 0;
  }

  if (($params->{item_type} || q{}) eq 'nostr.event') {
    return handle_nostr_subscription_event($server, $params);
  }
  if (
    !(
         ($params->{item_type} || q{}) eq 'event'
      || ($params->{item_type} || q{}) eq 'state'
      || ($params->{item_type} || q{}) eq 'private_message'
    )
  ) {
    return 0;
  }

  if (!(ref($params->{data}) eq 'HASH')) {
    return 0;
  }

  my $data = $params->{data};
  if (defined $data->{id}
    && delete $server->{suppress_subscription_event_ids}{$data->{id}}) {
    return 0;
  }
  if (defined $data->{id}
    && $server->{rendered_subscription_event_ids}{$data->{id}}) {
    return 0;
  }

  my $render = $server->_render_subscription_item(
    item_type => $params->{item_type},
    data      => $data,
  );
  if (!($render)) {
    return 0;
  }

  _remember_rendered_subscription_event_id($server, $data->{id});

  my $originating_client_id =
    defined $data->{id}
    ? delete $server->{subscription_event_origin_client_ids}{$data->{id}}
    : undef;
  my $sent = 0;
  for my $client_id (@{$render->{client_ids}}) {
    next
      if defined $originating_client_id
      && $client_id eq $originating_client_id;
    $server->_send_client_line($client_id, $render->{line});
    $sent++;
  }

  return $sent;
}

sub handle_nostr_subscription_event {
  my ($server, $params) = @_;
  if (!(ref($params->{data}) eq 'HASH')) {
    return 0;
  }

  my $subscription_id = $params->{subscription_id};
  if (!(defined $subscription_id && !ref($subscription_id) && length($subscription_id))) {
    return 0;
  }

  if (defined $params->{data}{id}
    && delete $server->{suppress_subscription_event_ids}{$params->{data}{id}}) {
    return 0;
  }
  if (defined $params->{data}{id}
    && $server->{rendered_subscription_event_ids}{$params->{data}{id}}) {
    return 0;
  }

  if (($subscription_id || q{}) eq ($server->{authoritative_grant_subscription_id} || q{})) {
    read_authoritative_grant_events($server, force => 1);
    return 1;
  }

  if (($subscription_id || q{}) eq ($server->{authoritative_discovery_subscription_id} || q{})) {
    return record_authoritative_discovery_event($server, $params->{data});
  }

  my $channel = $server->{authoritative_subscription_channels}{$subscription_id};
  if (!(defined $channel)) {
    return 0;
  }

  my $updated = $server->_update_authoritative_channel_cache_with_event(
    channel => $channel,
    event   => $params->{data},
  );
  if ($updated) {
    _remember_rendered_subscription_event_id($server, $params->{data}{id});
  }

  return $updated;
}

sub _remember_rendered_subscription_event_id {
  my ($server, $event_id) = @_;
  if (!(defined $event_id && !ref($event_id) && length($event_id))) {
    return 0;
  }

  $server->{rendered_subscription_event_ids} ||= {};
  return 1 if $server->{rendered_subscription_event_ids}{$event_id};

  $server->{rendered_subscription_event_ids}{$event_id} = 1;
  $server->{rendered_subscription_event_id_order} ||= [];
  push @{$server->{rendered_subscription_event_id_order}}, $event_id;

  while (@{$server->{rendered_subscription_event_id_order}} > $MAX_RENDERED_SUBSCRIPTION_EVENT_IDS) {
    my $expired = shift @{$server->{rendered_subscription_event_id_order}};
    if (defined $expired) {
      delete $server->{rendered_subscription_event_ids}{$expired};
    }

  }

  return 1;
}

sub reconcile_authoritative_pending_invites_from_refresh {
  my ($server, %args) = @_;
  my $channel    = $args{channel};
  my $old_view   = $args{old_view};
  my $old_events = $args{old_events};
  my $new_view   = $args{new_view};
  my $new_events = $args{new_events};
  if (!($server->_is_authoritative_channel($channel))) {
    return 0;
  }

  if (!(ref($new_view) eq 'HASH')) {
    return 0;
  }

  if (!(ref($old_events) eq 'ARRAY' && ref($new_events) eq 'ARRAY')) {
    return 0;
  }

  my %old_ids = map { (defined($_->{id}) && !ref($_->{id}) && length($_->{id})) ? ($_->{id} => 1) : () }
    grep { ref eq 'HASH' } @{$old_events};

  my $count = 0;
  for my $event (@{$new_events}) {
    if (!(ref($event) eq 'HASH')) {
      next;
    }

    if (!(($event->{kind} || 0) == 9009)) {
      next;
    }

    if (!(defined($event->{id}) && !ref($event->{id}) && length($event->{id}))) {
      next;
    }

    next if $old_ids{$event->{id}};
    $count += $server->_apply_authoritative_channel_cache_update(
      channel  => $channel,
      event    => $event,
      old_view => $old_view,
      new_view => $new_view,
    ) ? 1 : 0;
  }

  return $count;
}

1;

=head1 NAME

Overnet::Program::IRC::Authority::Coordinator - IRC authority relay coordinator

=head1 DESCRIPTION

Coordinates authoritative NIP-29 relay subscriptions, discovery cache refreshes,
event loading, event publishing, and runtime subscription handling for the IRC
server.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  Overnet::Program::IRC::Authority::Coordinator::refresh_authoritative_discovery_cache($server);

=head1 SUBROUTINES/METHODS

=head2 authoritative_grant_subscription_id

=head2 authoritative_discovery_subscription_id

=head2 authoritative_channel_subscription_ids

=head2 ensure_authoritative_grant_subscription

=head2 ensure_authoritative_discovery_subscription

=head2 ensure_authoritative_channel_subscription

=head2 read_nostr_subscription_snapshot

=head2 remember_authoritative_discovered_channel

=head2 forget_authoritative_discovered_channel

=head2 record_authoritative_discovery_event

=head2 refresh_authoritative_discovery_cache

=head2 query_nostr_events

=head2 read_authoritative_nip29_events_from_runtime

=head2 load_authoritative_nip29_events

=head2 refresh_authoritative_nip29_channel_cache

=head2 read_authoritative_nip29_events

=head2 read_authoritative_grant_events

=head2 publish_authoritative_nip29_event

=head2 append_authoritative_nip29_event

=head2 handle_subscription_event

=head2 handle_nostr_subscription_event

=head2 reconcile_authoritative_pending_invites_from_refresh

=head1 DIAGNOSTICS

Runtime query and publish failures are returned to the server caller or surfaced
through the runtime request boundary.

=head1 CONFIGURATION AND ENVIRONMENT

Configuration is read from the server object.

=head1 DEPENDENCIES

See the distribution metadata for runtime dependencies.

=head1 INCOMPATIBILITIES

No known incompatibilities are documented.

=head1 BUGS AND LIMITATIONS

No known bugs are documented.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the project license.

=cut
