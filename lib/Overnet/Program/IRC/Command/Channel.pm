package Overnet::Program::IRC::Command::Channel;

use strictures 2;

our $VERSION = '0.001';

sub handle_overnetchannel {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};

  if ( @params < 2
    || !defined $params[0]
    || !length $params[0]
    || !defined $params[1]
    || !length $params[1]) {
    $server->_send_need_more_params($client_id, 'OVERNETCHANNEL');
    return 1;
  }

  my $subcommand = uc($params[0]);
  my %handlers   = (
    DELETE   => \&_handle_overnetchannel_delete,
    UNDELETE => \&_handle_overnetchannel_undelete,
    INVITES  => \&_handle_overnetchannel_invites,
    REQUESTS => \&_handle_overnetchannel_requests,
  );
  my $handler = $handlers{$subcommand};
  if (defined $handler) {
    return $handler->($server, $client_id, \@params);
  }

  $server->_send_unknown_command($client_id, 'OVERNETCHANNEL');
  return 1;
}

sub _handle_overnetchannel_delete {
  my ($server, $client_id, $params) = @_;
  my $channel = _authoritative_channel_from_param($server, $client_id, $params->[1]);
  return 1 if !defined $channel;
  return $server->_handle_authoritative_delete_command(client_id => $client_id, channel => $channel,);
}

sub _handle_overnetchannel_undelete {
  my ($server, $client_id, $params) = @_;
  my $channel = _authoritative_channel_from_param($server, $client_id, $params->[1]);
  return 1 if !defined $channel;
  return $server->_handle_authoritative_undelete_command(client_id => $client_id, channel => $channel,);
}

sub _handle_overnetchannel_invites {
  my ($server, $client_id, $params) = @_;
  my $channel = _joined_channel_from_param($server, $client_id, $params->[1]);
  return 1 if !defined $channel;
  return $server->_handle_authoritative_invites_command(client_id => $client_id, channel => $channel,);
}

sub _handle_overnetchannel_requests {
  my ($server, $client_id, $params) = @_;
  my $channel = _joined_channel_from_param($server, $client_id, $params->[1]);
  return 1 if !defined $channel;
  return $server->_handle_authoritative_requests_command(client_id => $client_id, channel => $channel,);
}

sub _authoritative_channel_from_param {
  my ($server, $client_id, $channel_input) = @_;
  if (!($server->_is_channel_name($channel_input))) {
    $server->_send_no_such_channel($client_id, $channel_input);
    return;
  }

  my $channel = $server->_canonical_channel_name($channel_input);
  if (!($server->_is_authoritative_channel($channel))) {
    $server->_send_no_such_channel($client_id, $channel_input);
    return;
  }

  return $channel;
}

sub _joined_channel_from_param {
  my ($server, $client_id, $channel_input) = @_;
  if (!($server->_is_channel_name($channel_input))) {
    $server->_send_no_such_channel($client_id, $channel_input);
    return;
  }

  my $client = $server->{clients}{$client_id}
    or return;
  my $channel = $server->_client_joined_channel_name($client, $channel_input);
  if (!(defined $channel)) {
    $server->_send_not_on_channel($client_id, $channel_input);
    return;
  }

  return $channel;
}

sub handle_mode {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $client = $server->{clients}{$client_id}
    or return 0;

  if (@params < 1 || !defined $params[0] || !length $params[0]) {
    $server->_send_need_more_params($client_id, 'MODE');
    return 1;
  }
  my $target = $params[0];
  if ($server->_is_nick_name($target)) {
    my $current_nick = $client->{nick};
    if ( defined $current_nick
      && defined $server->_nick_key($current_nick)
      && defined $server->_nick_key($target)
      && $server->_nick_key($current_nick) eq $server->_nick_key($target)) {
      $server->_send_user_mode_is($client_id);
      return 1;
    }
  }

  if (!$server->_is_channel_name($target)) {
    $server->_send_no_such_channel($client_id, $target);
    return 1;
  }

  my $channel = $server->_client_joined_channel_name($client, $target);
  if (!(defined $channel)) {
    $server->_send_not_on_channel($client_id, $target);
    return 1;
  }

  if ($server->_is_authoritative_channel($channel)) {
    if (@params >= 2 && defined $params[1] && length $params[1]) {
      return $server->_handle_authoritative_mode_command(
        client_id => $client_id,
        channel   => $channel,
        params    => \@params,
      );
    }
  }

  $server->_send_channel_mode_is($client_id, $channel);
  return 1;
}

sub handle_kick {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $client = $server->{clients}{$client_id}
    or return 0;

  if ( @params < 2
    || !defined $params[0]
    || !length $params[0]
    || !defined $params[1]
    || !length $params[1]) {
    $server->_send_need_more_params($client_id, 'KICK');
    return 1;
  }
  my $channel_input = $params[0];
  if (!$server->_is_channel_name($channel_input)) {
    $server->_send_no_such_channel($client_id, $channel_input);
    return 1;
  }

  my $channel = $server->_client_joined_channel_name($client, $channel_input);
  if (!(defined $channel)) {
    $server->_send_not_on_channel($client_id, $channel_input);
    return 1;
  }

  if ($server->_is_authoritative_channel($channel)) {
    return $server->_handle_authoritative_kick_command(
      client_id => $client_id,
      channel   => $channel,
      params    => \@params,
    );
  }

  $server->_send_unknown_command($client_id, 'KICK');
  return 1;
}

sub handle_invite {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $client = $server->{clients}{$client_id}
    or return 0;

  if ( @params < 2
    || !defined $params[0]
    || !length $params[0]
    || !defined $params[1]
    || !length $params[1]) {
    $server->_send_need_more_params($client_id, 'INVITE');
    return 1;
  }

  my $target_nick   = $params[0];
  my $channel_input = $params[1];
  if (!$server->_is_channel_name($channel_input)) {
    $server->_send_no_such_channel($client_id, $channel_input);
    return 1;
  }

  my $channel = $server->_client_joined_channel_name($client, $channel_input);
  if (!(defined $channel)) {
    $server->_send_not_on_channel($client_id, $channel_input);
    return 1;
  }

  if ($server->_is_authoritative_channel($channel)) {
    return $server->_handle_authoritative_invite_command(
      client_id   => $client_id,
      channel     => $channel,
      target_nick => $target_nick,
    );
  }

  $server->_send_unknown_command($client_id, 'INVITE');
  return 1;
}

sub handle_join {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $client = $server->{clients}{$client_id}
    or return 0;

  if (@params < 1 || !defined $params[0] || !length $params[0]) {
    $server->_send_need_more_params($client_id, 'JOIN');
    return 1;
  }
  my $channel_input = $params[0];
  if (!$server->_is_channel_name($channel_input)) {
    $server->_send_no_such_channel($client_id, $channel_input);
    return 1;
  }

  my $channel        = $server->_canonical_channel_name($channel_input);
  my $already_joined = $server->_client_joined_channel_name($client, $channel_input);

  if ($server->_is_authoritative_channel($channel)) {
    my $join_result = _prepare_authoritative_join(
      server         => $server,
      client_id      => $client_id,
      client         => $client,
      channel        => $channel,
      params         => \@params,
      already_joined => $already_joined,
    );
    return 1 if $join_result->{done};
    $already_joined = $join_result->{already_joined};
  }

  if (defined $already_joined) {
    return 1;
  }

  _complete_join(server => $server, client_id => $client_id, client => $client, channel => $channel,);
  return 1;
}

sub _prepare_authoritative_join {
  my (%args)    = @_;
  my $server    = $args{server};
  my $client_id = $args{client_id};
  my $client    = $args{client};
  my $channel   = $args{channel};
  my $join_key  = _join_key_from_params($args{params});
  my $admission =
    $server->_authoritative_join_admission_for_client($channel, $client,
    (defined($join_key) ? (join_key => $join_key) : ()),
    );
  my $already_joined = _reconcile_existing_authoritative_join(
    server         => $server,
    client_id      => $client_id,
    client         => $client,
    channel        => $channel,
    admission      => $admission,
    already_joined => $args{already_joined},
  );
  return {done => 1} if defined $already_joined;

  if (!($admission->{allowed})) {
    return {
      done => _handle_authoritative_join_denial(
        server    => $server,
        client_id => $client_id,
        client    => $client,
        channel   => $channel,
        join_key  => $join_key,
        admission => $admission,
      ),
    };
  }

  return {done => 1}
    if !_write_allowed_authoritative_join(
    server    => $server,
    client_id => $client_id,
    client    => $client,
    channel   => $channel,
    join_key  => $join_key,
    admission => $admission,
    );

  return {done => 0, already_joined => undef};
}

sub _join_key_from_params {
  my ($params) = @_;
  return if @{$params} < 2;
  return if !defined($params->[1]) || ref($params->[1]) || !length($params->[1]);
  return $params->[1];
}

sub _reconcile_existing_authoritative_join {
  my (%args) = @_;
  return                       if !defined $args{already_joined};
  return $args{already_joined} if $args{admission}{allowed} && $args{admission}{present};
  $args{server}->_remove_client_from_channel($args{client_id}, $args{channel}, nick => $args{client}{nick},);
  return;
}

sub _handle_authoritative_join_denial {
  my (%args)    = @_;
  my $server    = $args{server};
  my $client_id = $args{client_id};
  my $admission = $args{admission};

  if ($admission->{auth_required}) {
    $server->_send_server_notice($client_id, 'OVERNETAUTH AUTH is required for authoritative JOIN');
    return 1;
  }
  if ($admission->{deleted}) {
    $server->_send_no_such_channel($client_id, $args{channel});
    return 1;
  }
  if ($admission->{pending_request}) {
    $server->_send_server_notice($client_id, "Join request already pending for $args{channel}");
    return 1;
  }
  if ($admission->{request_join}) {
    return _submit_authoritative_join_request(%args);
  }

  $server->_send_cannot_join_channel($client_id, $args{channel}, reason => $admission->{reason},);
  return 1;
}

sub _submit_authoritative_join_request {
  my (%args)    = @_;
  my $server    = $args{server};
  my $client_id = $args{client_id};
  my $client    = $args{client};

  if (!_write_authoritative_join_input(%args, include_admission => 0)) {
    return 1;
  }

  $server->_send_server_notice($client_id, "Join request submitted for $args{channel}");
  return 1;
}

sub _write_allowed_authoritative_join {
  my (%args) = @_;
  my $admission = $args{admission};
  my $needs_write =
       $admission->{create_channel}
    || defined($admission->{invite_code})
    || !$admission->{member}
    || !$admission->{present};
  return 1 if !$needs_write;
  return _write_authoritative_join_input(%args, include_admission => 1);
}

sub _write_authoritative_join_input {
  my (%args)    = @_;
  my $server    = $args{server};
  my $client_id = $args{client_id};
  my $client    = $args{client};

  if ($server->_authority_relay_enabled && !$server->_client_has_authoritative_delegation($client)) {
    $server->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE is required for authoritative JOIN');
    return 0;
  }

  my $input = _authoritative_join_input(%args);
  if ($server->_authority_relay_enabled) {
    if (!($server->_publish_authoritative_input($client, $input))) {
      $server->_send_server_notice($client_id,
        $server->{authoritative_publish_error} || 'authoritative relay publish failed',
      );
      return 0;
    }
    return 1;
  }

  return $server->_emit_client_input($client, $input) ? 1 : 0;
}

sub _authoritative_join_input {
  my (%args)    = @_;
  my $server    = $args{server};
  my $client    = $args{client};
  my $admission = $args{admission} || {};
  my %input     = (
    command      => 'JOIN',
    target       => $args{channel},
    actor_pubkey => $server->_client_authoritative_pubkey($client),
    actor_mask   => $server->_authoritative_irc_mask_for_client($client),
  );
  if (defined $args{join_key}) {
    $input{join_key} = $args{join_key};
  }
  if ($args{include_admission}) {
    if (defined $admission->{invite_code}) {
      $input{invite_code} = $admission->{invite_code};
    }
    if ($admission->{create_channel}) {
      $input{create_channel} = 1;
      $input{group_metadata} = {name => $args{channel}};
    }
  }
  return \%input;
}

sub _complete_join {
  my (%args)    = @_;
  my $server    = $args{server};
  my $client_id = $args{client_id};
  my $client    = $args{client};
  my $channel   = $args{channel};

  $server->_add_client_to_channel($client_id, $channel);
  $server->_broadcast_channel_line($channel, sprintf(':%s JOIN %s', $client->{nick}, $channel),);
  $server->_send_join_bootstrap($client_id, $channel);
  $server->_ensure_channel_subscription($channel);
  if ( $server->_authority_relay_enabled
    && $server->_is_authoritative_channel($channel)) {
    $server->_ensure_authoritative_channel_subscription($channel);
  }

  if (!$server->_is_authoritative_channel($channel)) {
    $server->_emit_client_input(
      $client,
      {
        command => 'JOIN',
        target  => $channel,
      },
      suppress_render_event_types => {
        'chat.join' => 1,
      },
    );
  }
  return;
}

sub handle_part {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $client = $server->{clients}{$client_id}
    or return 0;

  if (@params < 1 || !defined $params[0] || !length $params[0]) {
    $server->_send_need_more_params($client_id, 'PART');
    return 1;
  }
  my $channel_input = $params[0];
  if (!$server->_is_channel_name($channel_input)) {
    $server->_send_no_such_channel($client_id, $channel_input);
    return 1;
  }

  my $channel = $server->_client_joined_channel_name($client, $channel_input);
  if (!(defined $channel)) {
    $server->_send_not_on_channel($client_id, $channel_input);
    return 1;
  }

  my $reason = @params >= 2 ? $params[1] : undef;
  if ($server->_is_authoritative_channel($channel)) {
    return $server->_handle_authoritative_part_command(
      client_id => $client_id,
      channel   => $channel,
      reason    => $reason,
    );
  }

  my $line = sprintf(':%s PART %s', $client->{nick}, $channel);
  if (defined $reason && length $reason) {
    $line .= ' :' . $reason;
  }

  $server->_broadcast_channel_line($channel, $line);
  $server->_remove_client_from_channel($client_id, $channel);
  $server->_emit_client_input(
    $client,
    {
      command => 'PART',
      target  => $channel,
      (defined $reason ? (text => $reason) : ()),
    },
    suppress_render_event_types => {
      'chat.part' => 1,
    },
  );
  return 1;
}

sub handle_privmsg_or_notice {
  my ($server, $client_id, $command, $params) = @_;
  my @params = @{$params || []};
  my $client = $server->{clients}{$client_id}
    or return 0;

  if ( @params < 2
    || !defined $params[0]
    || !length $params[0]
    || !defined $params[1]) {
    $server->_send_need_more_params($client_id, $command);
    return 1;
  }
  my $target = $params[0];

  if ($server->_is_channel_name($target)) {
    my $channel = $server->_client_joined_channel_name($client, $target);
    if (!(defined $channel)) {
      $server->_send_not_on_channel($client_id, $target);
      return 1;
    }

    if ($server->_is_authoritative_channel($channel)) {
      my $permission = $server->_authoritative_speak_permission_for_client($channel, $client);
      if (!($permission->{allowed})) {
        $server->_send_cannot_send_to_channel($client_id, $channel);
        return 1;
      }
    } elsif ($server->_channel_is_moderated_for_client($channel, $client)) {
      $server->_send_cannot_send_to_channel($client_id, $channel);
      return 1;
    }

    $server->_emit_client_input(
      $client,
      {
        command => $command,
        target  => $channel,
        text    => $params[1],
      },
    );
    return 1;
  }

  if (!$server->_is_nick_name($target)) {
    $server->_send_no_such_nick($client_id, $target);
    return 1;
  }

  my $target_nick = $server->_canonical_current_nick($target);
  if (!(defined $target_nick)) {
    $server->_send_no_such_nick($client_id, $target);
    return 1;
  }

  my ($e2ee_transport, $e2ee_error, $is_e2ee) =
    $server->_decode_e2ee_dm_body($params[1]);
  if ($is_e2ee) {
    if (!defined $e2ee_transport) {
      $server->_send_server_notice($client_id, $e2ee_error);
      return 1;
    }

    $server->_emit_opaque_private_message_transport(
      client      => $client,
      command     => $command,
      target_nick => $target_nick,
      body_text   => $params[1],
      transport   => $e2ee_transport,
    );
    return 1;
  }

  $server->_emit_client_input(
    $client,
    {
      command => $command,
      target  => $target_nick,
      text    => $params[1],
    },
  );
  return 1;
}

sub handle_topic {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $client = $server->{clients}{$client_id}
    or return 0;

  if (@params < 1 || !defined $params[0] || !length $params[0]) {
    $server->_send_need_more_params($client_id, 'TOPIC');
    return 1;
  }
  my $target = $params[0];
  if (!$server->_is_channel_name($target)) {
    $server->_send_no_such_channel($client_id, $target);
    return 1;
  }
  my $channel = $server->_client_joined_channel_name($client, $target);
  if (!(defined $channel)) {
    $server->_send_not_on_channel($client_id, $target);
    return 1;
  }

  if (@params == 1) {
    $server->_send_topic_reply($client_id, $channel);
    return 1;
  }

  if ($server->_is_authoritative_channel($channel)) {
    my $permission = $server->_authoritative_topic_permission_for_client($channel, $client);
    if (!($permission->{allowed})) {
      if (($permission->{reason} || q{}) eq 'deleted') {
        $server->_send_no_such_channel($client_id, $channel);
      } else {
        $server->_send_chan_op_privs_needed($client_id, $channel);
      }
      return 1;
    }
    return $server->_handle_authoritative_topic_command(
      client_id => $client_id,
      channel   => $channel,
      text      => $params[1],
    );
  }

  if ($server->_channel_is_topic_restricted_for_client($channel, $client)) {
    $server->_send_chan_op_privs_needed($client_id, $channel);
    return 1;
  }

  $server->_emit_client_input(
    $client,
    {
      command => 'TOPIC',
      target  => $channel,
      text    => $params[1],
    },
  );
  return 1;
}

sub handle_list {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $target = @params ? $params[0] : undef;
  $server->_send_list_reply($client_id, $target);
  return 1;
}

1;

=head1 NAME

Overnet::Program::IRC::Command::Channel - IRC channel command handlers

=head1 DESCRIPTION

Handles channel-oriented IRC commands and bridges them into Overnet channel
inputs or authoritative channel actions.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  Overnet::Program::IRC::Command::Channel::handle_join($server, $client_id, \@params);

=head1 SUBROUTINES/METHODS

=head2 handle_overnetchannel

=head2 handle_mode

=head2 handle_kick

=head2 handle_invite

=head2 handle_join

=head2 handle_part

=head2 handle_privmsg_or_notice

=head2 handle_topic

=head2 handle_list

=head1 DIAGNOSTICS

Invalid channel flows are reported as IRC numerics or server notices.

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
