package Overnet::Program::IRC::State;

use strictures 2;
use Moo;

our $VERSION = '0.001';

has clients => (
  is      => 'ro',
  default => sub { {} },
);
has channels => (
  is      => 'ro',
  default => sub { {} },
);
has nick_to_client_id => (
  is      => 'ro',
  default => sub { {} },
);

no Moo;

sub irc_casefold {
  my ($self, $value) = @_;
  if (!(defined $value && !ref($value))) {
    return;
  }

  my $folded = $value;
  $folded =~ tr/A-Z[]\\^/a-z{}|~/;
  return $folded;
}

sub nick_key {
  my ($self, $nick) = @_;
  if (!(defined $nick && !ref($nick) && length($nick))) {
    return;
  }

  return $self->irc_casefold($nick);
}

sub channel_key {
  my ($self, $channel) = @_;
  if (!($self->is_channel_name($channel))) {
    return;
  }

  return $self->irc_casefold($channel);
}

sub is_channel_name {
  my ($self, $value) = @_;
  return
       defined $value
    && !ref($value)
    && $value =~ /\A[#&][^\x00\x07\r\n ,:]+\z/mxs
    ? 1
    : 0;
}

sub is_nick_name {
  my ($self, $value) = @_;
  return
       defined $value
    && !ref($value)
    && $value =~ /\A[^\x00\x07\r\n ,:#&][^\x00\x07\r\n ,:]*\z/mxs
    ? 1
    : 0;
}

sub canonical_current_nick {
  my ($self, $nick) = @_;
  my $key = $self->nick_key($nick);
  if (!(defined $key)) {
    return;
  }

  my $client_id = $self->nick_to_client_id->{$key};
  if (!(defined $client_id && exists $self->clients->{$client_id})) {
    return;
  }

  return $self->clients->{$client_id}{nick};
}

sub client_for_current_nick {
  my ($self, $nick) = @_;
  my $key = $self->nick_key($nick);
  if (!(defined $key)) {
    return;
  }

  my $client_id = $self->nick_to_client_id->{$key};
  if (!(defined $client_id && exists $self->clients->{$client_id})) {
    return;
  }

  return $self->clients->{$client_id};
}

sub nick_in_use {
  my ($self, $nick, %args) = @_;
  my $key = $self->nick_key($nick);
  if (!(defined $key)) {
    return 0;
  }

  my $owner = $self->nick_to_client_id->{$key};
  if (!(defined $owner)) {
    return 0;
  }

  return 0
    if defined $args{exclude_client_id} && $owner eq $args{exclude_client_id};
  return 1;
}

sub assign_client_nick {
  my ($self, $client_id, $nick) = @_;
  my $client = $self->clients->{$client_id}
    or return 0;
  my $key = $self->nick_key($nick);
  if (!(defined $key)) {
    return 0;
  }

  if ( defined $client->{nick}
    && length($client->{nick})
    && $client->{nick} ne $nick) {
    $self->release_client_nick($client_id, nick => $client->{nick},);
  }

  $client->{nick} = $nick;
  $self->nick_to_client_id->{$key} = $client_id;
  return 1;
}

sub release_client_nick {
  my ($self, $client_id, %args) = @_;
  my $nick =
    defined $args{nick} ? $args{nick}
    : (
    exists $self->clients->{$client_id} ? $self->clients->{$client_id}{nick}
    : undef
    );
  my $key = $self->nick_key($nick);
  if (!(defined $key)) {
    return 0;
  }

  if (!(exists $self->nick_to_client_id->{$key})) {
    return 0;
  }
  if (!($self->nick_to_client_id->{$key} eq $client_id)) {
    return 0;
  }

  delete $self->nick_to_client_id->{$key};
  return 1;
}

sub canonical_channel_name {
  my ($self, $channel) = @_;
  my $key = $self->channel_key($channel);
  if (!(defined $key)) {
    return;
  }

  return $self->channels->{$key}{channel_name}
    if exists $self->channels->{$key}
    && defined $self->channels->{$key}{channel_name}
    && length($self->channels->{$key}{channel_name});
  return $channel;
}

sub client_joined_channel_name {
  my ($self, $client, $channel) = @_;
  if (!(ref($client) eq 'HASH')) {
    return;
  }

  my $key = $self->channel_key($channel);
  if (!(defined $key)) {
    return;
  }

  return $client->{joined_channels}{$key};
}

sub channel_state {
  my ($self, $channel) = @_;
  my $key = $self->channel_key($channel);
  if (!(defined $key)) {
    return;
  }

  return $self->channels->{$key} ||= {
    channel_name  => $channel,
    members       => {},
    visible_nicks => {},
    topic_text    => undef,
  };
}

sub add_visible_nick {
  my ($self, $channel, $nick) = @_;
  my $nick_key = $self->nick_key($nick);
  if (!(defined $nick_key)) {
    return 0;
  }

  my $state = $self->channel_state($channel);
  if (!($state)) {
    return 0;
  }

  $state->{visible_nicks}{$nick_key} ||= {
    count        => 0,
    display_nick => $nick,
  };
  $state->{visible_nicks}{$nick_key}{display_nick} = $nick;
  $state->{visible_nicks}{$nick_key}{count}++;
  return $state->{visible_nicks}{$nick_key}{count};
}

sub remove_visible_nick {
  my ($self, $channel, $nick) = @_;
  my $nick_key = $self->nick_key($nick);
  if (!(defined $nick_key)) {
    return 0;
  }

  my $channel_key = $self->channel_key($channel);
  if (!(defined $channel_key)) {
    return 0;
  }

  my $state = $self->channels->{$channel_key}
    or return 0;
  if (!(exists $state->{visible_nicks}{$nick_key})) {
    return 0;
  }

  $state->{visible_nicks}{$nick_key}{count}--;
  if ($state->{visible_nicks}{$nick_key}{count} <= 0) {
    delete $state->{visible_nicks}{$nick_key};
  }
  return 1;
}

sub rename_visible_nick {
  my ($self, $channel, %args) = @_;
  my $old_nick = $args{old_nick};
  my $new_nick = $args{new_nick};
  my $old_key  = $self->nick_key($old_nick);
  my $new_key  = $self->nick_key($new_nick);
  if (!(defined $old_key && defined $new_key)) {
    return 0;
  }

  my $channel_key = $self->channel_key($channel);
  if (!(defined $channel_key)) {
    return 0;
  }

  my $state = $self->channels->{$channel_key}
    or return 0;
  my $entry = delete $state->{visible_nicks}{$old_key}
    or return 0;
  my $count = $entry->{count} || 0;
  $state->{visible_nicks}{$new_key} ||= {
    count        => 0,
    display_nick => $new_nick,
  };
  $state->{visible_nicks}{$new_key}{count} += $count;
  $state->{visible_nicks}{$new_key}{display_nick} = $new_nick;
  return $count;
}

sub rename_visible_nick_everywhere {
  my ($self, %args) = @_;
  my $count = 0;

  for my $channel (sort keys %{$self->channels}) {
    $count += $self->rename_visible_nick(
      $channel,
      old_nick => $args{old_nick},
      new_nick => $args{new_nick},
    ) || 0;
  }

  return $count;
}

sub rename_client_channels {
  my ($self, $client, %args) = @_;
  if (!(ref($client) eq 'HASH')) {
    return 0;
  }

  my $count = 0;
  for my $channel (sort values %{$client->{joined_channels} || {}}) {
    $count += $self->rename_visible_nick(
      $channel,
      old_nick => $args{old_nick},
      new_nick => $args{new_nick},
    ) || 0;
  }

  return $count;
}

sub visible_nicks_for_channel {
  my ($self, $channel) = @_;
  my $channel_key = $self->channel_key($channel);
  if (!(defined $channel_key)) {
    return ();
  }

  my $state = $self->channels->{$channel_key}
    or return ();

  my @nicks =
    sort grep { defined && length }
    map       { $state->{visible_nicks}{$_}{display_nick} }
    grep      { ($state->{visible_nicks}{$_}{count} || 0) > 0 }
    keys %{$state->{visible_nicks} || {}};
  return @nicks;
}

1;

=head1 NAME

Overnet::Program::IRC::State - IRC client and channel indexes

=head1 DESCRIPTION

This internal collaborator owns RFC 1459 name normalization and the mutable
indexes that relate clients, nicknames, joined channels, and externally visible
channel members. It deliberately contains no sockets, runtime requests, relay
operations, or IRC rendering.

=head1 SYNOPSIS

  my $state = Overnet::Program::IRC::State->new;
  $state->clients->{1} = $client;
  $state->assign_client_nick(1, 'alice');

=head1 VERSION

Version 0.001.

=head1 SUBROUTINES/METHODS

=head2 new

Creates an empty state store.

=head2 clients

Returns the client table.

=head2 channels

Returns the channel table.

=head2 nick_to_client_id

Returns the case-folded nick index.

=head2 irc_casefold

Applies RFC 1459 case mapping.

=head2 nick_key

Returns a normalized nickname key.

=head2 channel_key

Returns a validated and normalized channel key.

=head2 is_channel_name

Reports whether a value is a supported IRC channel name.

=head2 is_nick_name

Reports whether a value is a supported IRC nickname.

=head2 canonical_current_nick

Returns the current display spelling for an indexed nickname.

=head2 client_for_current_nick

Returns the client owning an indexed nickname.

=head2 nick_in_use

Reports whether a nickname is currently owned.

=head2 assign_client_nick

Assigns a nickname to a known client.

=head2 release_client_nick

Releases a nickname owned by a client.

=head2 canonical_channel_name

Returns the first retained display spelling for a channel.

=head2 client_joined_channel_name

Returns a client's joined display spelling for a channel.

=head2 channel_state

Returns or creates the state for a valid channel.

=head2 add_visible_nick

Adds one visible observation of a nickname to a channel.

=head2 remove_visible_nick

Removes one visible observation of a nickname from a channel.

=head2 rename_visible_nick

Renames visible nickname observations in one channel.

=head2 rename_visible_nick_everywhere

Renames visible nickname observations in all channels.

=head2 rename_client_channels

Renames visible nickname observations in a client's joined channels.

=head2 visible_nicks_for_channel

Returns sorted visible nickname spellings for a channel.

=head1 DIAGNOSTICS

Invalid names and unknown clients are reported through false or undefined
returns, matching the server's tolerant connection behavior.

=head1 CONFIGURATION AND ENVIRONMENT

This module requires no configuration.

=head1 DEPENDENCIES

This module depends on Moo.

=head1 INCOMPATIBILITIES

No known incompatibilities.

=head1 BUGS AND LIMITATIONS

The state store is process-local and is not a persistence boundary.

=head1 AUTHOR

Overnet project contributors.

=head1 LICENSE AND COPYRIGHT

Copyright the Overnet project contributors.

=cut
