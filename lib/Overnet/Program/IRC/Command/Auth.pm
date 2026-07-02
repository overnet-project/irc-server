package Overnet::Program::IRC::Command::Auth;

use strictures 2;
use English      qw(-no_match_vars);
use JSON         ();
use MIME::Base64 qw(decode_base64 encode_base64);
use Overnet::Authority::Delegation;
use Overnet::Core::Nostr;
use Overnet::Program::IRC::Renderer ();

our $VERSION = '0.001';

my %OVERNETAUTH_HANDLERS = (
  CHALLENGE => \&_handle_overnetauth_challenge,
  AUTH      => \&_handle_overnetauth_auth,
  DELEGATE  => \&_handle_overnetauth_delegate,
);

sub handle_cap {
  my ($server, $client_id, $params) = @_;
  my @params     = @{$params || []};
  my $subcommand = defined $params[0] ? uc($params[0]) : q{};
  my $client     = $server->{clients}{$client_id}
    or return 0;
  my @supported = $server->_supported_capabilities;

  if ($subcommand eq 'LS') {
    if (!$client->{registered}) {
      $client->{cap_negotiation_active} = 1;
    }

    return $server->_send_client_line($client_id,
      sprintf(':%s CAP * LS :%s', $server->{config}{server_name}, join(q{ }, @supported)),
    );
  }

  if ($subcommand eq 'REQ') {
    if (@params < 2 || !defined $params[1] || !length $params[1]) {
      $server->_send_need_more_params($client_id, 'CAP');
      return 1;
    }
    if (!$client->{registered}) {
      $client->{cap_negotiation_active} = 1;
    }

    my @requested             = grep { defined && length } split /\s+/mxs, $params[1];
    my %supported             = map  { $_ => 1 } @supported;
    my $unsupported_requested = grep { !$supported{$_} } @requested;
    if (@requested && !$unsupported_requested) {
      for (@requested) {
        $client->{capabilities}{$_} = 1;
      }

      if ( $client->{capabilities}{'server-time'}
        || $client->{capabilities}{'account-tag'}) {
        $client->{capabilities}{'message-tags'} = 1;
      }

      return $server->_send_client_line($client_id,
        sprintf(':%s CAP * ACK :%s', $server->{config}{server_name}, join(q{ }, @requested)),
      );
    }

    return $server->_send_client_line($client_id,
      sprintf(':%s CAP * NAK :%s', $server->{config}{server_name}, $params[1]),);
  }

  if ($subcommand eq 'END') {
    $client->{cap_negotiation_active} = 0;
    $server->_register_client_if_ready($client);
    return 1;
  }

  $server->_send_unknown_command($client_id, 'CAP');
  return 1;
}

sub handle_authenticate {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $client = $server->{clients}{$client_id}
    or return 0;

  if (!@params || !defined($params[0]) || !length($params[0])) {
    $server->_send_need_more_params($client_id, 'AUTHENTICATE');
    return 1;
  }

  my $argument = $params[0];
  if ( !defined($client->{sasl_mechanism})
    || !length($client->{sasl_mechanism})) {
    if (!($server->_client_has_capability($client, 'sasl'))) {
      $server->_send_sasl_fail($client_id);
      return 1;
    }

    my $mechanism = uc $argument;
    if (!($mechanism eq 'NOSTR' && $server->_authority_profile eq 'nip29')) {
      $server->_send_sasl_fail($client_id);
      return 1;
    }

    my $challenge_payload = start_sasl_nostr_exchange($server, $client);
    if (!(ref($challenge_payload) eq 'HASH')) {
      $server->_send_sasl_fail($client_id);
      return 1;
    }

    my $payload = encode_base64(JSON::encode_json($challenge_payload), q{});
    $server->_send_authenticate_payload($client_id, $payload);
    return 1;
  }

  if ($argument eq q{*}) {
    reset_sasl_state($server, $client);
    $server->_send_sasl_fail($client_id);
    return 1;
  }

  if ($argument eq q{+}) {
    return complete_sasl_exchange($server, $client_id);
  }

  $client->{sasl_buffer} .= $argument;
  return 1 if length($argument) == 400;
  return complete_sasl_exchange($server, $client_id);
}

sub handle_overnetauth {
  my ($server, $client_id, $params) = @_;
  my @params = @{$params || []};
  my $client = $server->{clients}{$client_id}
    or return 0;

  if (@params < 1 || !defined $params[0] || !length $params[0]) {
    $server->_send_need_more_params($client_id, 'OVERNETAUTH');
    return 1;
  }

  my $subcommand = uc($params[0]);
  my $handler    = $OVERNETAUTH_HANDLERS{$subcommand};
  if (defined $handler) {
    return $handler->($server, $client_id, $client, \@params);
  }

  $server->_send_unknown_command($client_id, 'OVERNETAUTH');
  return 1;
}

sub _handle_overnetauth_challenge {
  my ($server, $client_id, $client) = @_;
  my $challenge = $server->_generate_authoritative_auth_challenge($client);
  $client->{authority_challenge} = $challenge;
  $server->_send_server_notice($client_id, "OVERNETAUTH CHALLENGE $challenge");
  return 1;
}

sub _handle_overnetauth_auth {
  my ($server, $client_id, $client, $params) = @_;
  if (!_has_param($params, 1)) {
    $server->_send_need_more_params($client_id, 'OVERNETAUTH');
    return 1;
  }

  my $event_hash = _decoded_event_param($params->[1]);
  if (!(ref($event_hash) eq 'HASH')) {
    $server->_send_server_notice($client_id, 'OVERNETAUTH AUTH requires a base64-encoded event object');
    return 1;
  }

  my $validation = validate_authoritative_auth_event(
    $server,
    challenge => $client->{authority_challenge},
    event     => $event_hash,
  );
  if (!($validation->{valid})) {
    $server->_send_server_notice($client_id, _auth_failure_notice($validation->{reason}));
    return 1;
  }

  apply_authoritative_auth_validation($server, $client, $validation);
  delete $client->{authority_challenge};
  $server->_send_server_notice($client_id, 'OVERNETAUTH AUTH ' . $client->{authority_pubkey});
  return 1;
}

sub _handle_overnetauth_delegate {
  my ($server, $client_id, $client, $params) = @_;
  if (!($server->_authority_relay_enabled)) {
    $server->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE requires authority_relay');
    return 1;
  }

  if (!_client_has_authority_pubkey($client)) {
    $server->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE requires a prior AUTH');
    return 1;
  }

  if (@{$params} == 1) {
    return _send_overnetauth_delegate_offer($server, $client_id, $client);
  }

  my $delegate = _delegate_offer_state($client);
  if (!(ref($delegate) eq 'HASH')) {
    $server->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE requires a prior parameter request');
    return 1;
  }

  my $event_hash = _decoded_event_param($params->[1]);
  if (!(ref($event_hash) eq 'HASH')) {
    $server->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE requires a base64-encoded event object');
    return 1;
  }

  my $validation = accept_authoritative_delegate_event(
    $server,
    client          => $client,
    event_hash      => $event_hash,
    relay_url       => $server->_authority_relay_url,
    session_id      => $delegate->{session_id},
    expires_at      => $delegate->{expires_at},
    delegate_pubkey => $delegate->{key}->pubkey_hex,
    kind            => $server->_authority_grant_kind,
  );
  if (!($validation->{valid})) {
    $server->_send_server_notice($client_id, _delegate_failure_notice($validation->{reason}));
    return 1;
  }

  $server->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE');
  return 1;
}

sub _has_param {
  my ($params, $index) = @_;
  return 0 if !(ref($params) eq 'ARRAY');
  return 0 if @{$params} <= $index;
  return 0 if !defined $params->[$index];
  return 0 if ref($params->[$index]);
  return length($params->[$index]) ? 1 : 0;
}

sub _decoded_event_param {
  my ($encoded) = @_;
  my $decoded   = eval { decode_base64($encoded) };
  return eval { JSON::decode_json($decoded) };
}

sub _client_has_authority_pubkey {
  my ($client) = @_;
  return 0 if !(ref($client) eq 'HASH');
  return 0 if !defined $client->{authority_pubkey};
  return 0 if ref($client->{authority_pubkey});
  return length($client->{authority_pubkey}) ? 1 : 0;
}

sub _send_overnetauth_delegate_offer {
  my ($server, $client_id, $client) = @_;
  my $delegate = ensure_authoritative_delegate_offer($server, $client);
  $server->_send_server_notice(
    $client_id, join q{ },
    'OVERNETAUTH DELEGATE',
    $delegate->{delegate_pubkey},
    $delegate->{session_id},
    $delegate->{relay_url},
    $delegate->{expires_at},
  );
  return 1;
}

sub _delegate_offer_state {
  my ($client)            = @_;
  my $delegate_key        = $client->{authority_delegate_key};
  my $delegate_session_id = $client->{authority_delegate_session_id};
  my $delegate_expires_at = $client->{authority_delegate_expires_at};
  return if !(ref($delegate_key) eq 'Overnet::Core::Nostr::Key');
  return if !defined $delegate_session_id;
  return if ref($delegate_session_id);
  return if !length($delegate_session_id);
  return if !defined $delegate_expires_at;
  return {
    key        => $delegate_key,
    session_id => $delegate_session_id,
    expires_at => $delegate_expires_at,
  };
}

sub _auth_failure_notice {
  my ($reason) = @_;
  $reason ||= q{};
  return 'OVERNETAUTH AUTH requires kind 22242'
    if $reason =~ /kind\ 22242/imxs;
  return 'OVERNETAUTH AUTH challenge does not match'
    if $reason =~ /challenge/imxs;
  return 'OVERNETAUTH AUTH relay scope does not match'
    if $reason =~ /relay\ scope/imxs;
  return 'OVERNETAUTH AUTH requires a valid signed Nostr event';
}

sub _delegate_failure_notice {
  my ($reason) = @_;
  $reason ||= q{};
  my @notices = (
    [qr/wrong\ event\ kind/imxs,           'OVERNETAUTH DELEGATE uses the wrong event kind'],
    [qr/authenticated\ user/imxs,          'OVERNETAUTH DELEGATE pubkey does not match the authenticated user'],
    [qr/relay\ does\ not\ match/imxs,      'OVERNETAUTH DELEGATE relay does not match'],
    [qr/server\ scope/imxs,                'OVERNETAUTH DELEGATE server scope does not match'],
    [qr/delegate\ pubkey/imxs,             'OVERNETAUTH DELEGATE delegate pubkey does not match'],
    [qr/session\ does\ not\ match/imxs,    'OVERNETAUTH DELEGATE session does not match'],
    [qr/expiration\ does\ not\ match/imxs, 'OVERNETAUTH DELEGATE expiration does not match'],
    [qr/relay\ publish\ failed/imxs,       'OVERNETAUTH DELEGATE relay publish failed'],
  );
  for my $notice (@notices) {
    return $notice->[1] if $reason =~ $notice->[0];
  }
  return 'OVERNETAUTH DELEGATE requires a valid signed Nostr event';
}

sub start_sasl_nostr_exchange {
  my ($server, $client) = @_;
  if (!(ref($client) eq 'HASH')) {
    return;
  }

  my $challenge = $server->_generate_authoritative_auth_challenge($client);
  my %payload   = (
    challenge => $challenge,
    scope     => $server->_authoritative_auth_scope,
  );

  if ($server->_authority_relay_enabled) {
    my $delegate = ensure_authoritative_delegate_offer($server, $client);
    if (!(ref($delegate) eq 'HASH')) {
      return;
    }

    @payload{qw(relay_url grant_kind delegate_pubkey session_id expires_at)} = (
      $delegate->{relay_url},  $delegate->{grant_kind}, $delegate->{delegate_pubkey},
      $delegate->{session_id}, $delegate->{expires_at},
    );
  }

  $client->{authority_challenge}    = $challenge;
  $client->{sasl_mechanism}         = 'NOSTR';
  $client->{sasl_buffer}            = q{};
  $client->{sasl_challenge_payload} = \%payload;
  return \%payload;
}

sub complete_sasl_exchange {
  my ($server, $client_id) = @_;
  my $client = $server->{clients}{$client_id}
    or return 0;

  my $decoded = eval { decode_base64($client->{sasl_buffer} || q{}) };
  my $payload = eval { JSON::decode_json($decoded) };
  if (!(ref($payload) eq 'HASH')) {
    reset_sasl_state($server, $client);
    $server->_send_sasl_fail($client_id);
    return 1;
  }

  my $challenge_payload =
    ref($client->{sasl_challenge_payload}) eq 'HASH'
    ? $client->{sasl_challenge_payload}
    : {};
  my $delegate_offer =
    $server->_authority_relay_enabled
    ? {
    key        => $client->{authority_delegate_key},
    session_id => $challenge_payload->{session_id},
    expires_at => $challenge_payload->{expires_at},
    }
    : undef;
  my $auth_validation = validate_authoritative_auth_event(
    $server,
    challenge => $challenge_payload->{challenge},
    event     => $payload->{auth_event},
  );
  if (!($auth_validation->{valid})) {
    reset_sasl_state($server, $client);
    $server->_send_sasl_fail($client_id);
    return 1;
  }

  apply_authoritative_auth_validation($server, $client, $auth_validation);
  if ($server->_authority_relay_enabled) {
    if (ref($delegate_offer) eq 'HASH') {
      if (ref($delegate_offer->{key}) eq 'Overnet::Core::Nostr::Key') {
        $client->{authority_delegate_key} = $delegate_offer->{key};
      }

      if (defined $delegate_offer->{session_id}) {
        $client->{authority_delegate_session_id} = $delegate_offer->{session_id};
      }

      if (defined $delegate_offer->{expires_at}) {
        $client->{authority_delegate_expires_at} = $delegate_offer->{expires_at};
      }

    }
    if (!(ref($payload->{delegate_event}) eq 'HASH')) {
      clear_authoritative_binding($server, $client);
      reset_sasl_state($server, $client);
      $server->_send_sasl_fail($client_id);
      return 1;
    }
    my $delegate_result = accept_authoritative_delegate_event(
      $server,
      client          => $client,
      event_hash      => $payload->{delegate_event},
      relay_url       => $challenge_payload->{relay_url},
      session_id      => $challenge_payload->{session_id},
      expires_at      => $challenge_payload->{expires_at},
      delegate_pubkey => $challenge_payload->{delegate_pubkey},
      kind            => $challenge_payload->{grant_kind},
    );
    if (!($delegate_result->{valid})) {
      clear_authoritative_binding($server, $client);
      reset_sasl_state($server, $client);
      $server->_send_sasl_fail($client_id);
      return 1;
    }
  }

  reset_sasl_state($server, $client);
  $server->_send_sasl_success($client_id);
  $server->_register_client_if_ready($client);
  return 1;
}

sub reset_sasl_state {
  my ($server, $client) = @_;
  if (!(ref($client) eq 'HASH')) {
    return 0;
  }

  delete $client->{sasl_mechanism};
  $client->{sasl_buffer} = q{};
  delete $client->{sasl_challenge_payload};
  delete $client->{authority_challenge};
  return 1;
}

sub validate_authoritative_auth_event {
  my ($server, %args) = @_;
  my $challenge = $args{challenge};
  if (!(defined $challenge && !ref($challenge) && length($challenge))) {
    return {
      valid  => 0,
      reason => 'auth event challenge does not match',
    };
  }

  return Overnet::Authority::Delegation->verify_auth_event(
    challenge => $challenge,
    scope     => $server->_authoritative_auth_scope,
    event     => $args{event},
  );
}

sub apply_authoritative_auth_validation {
  my ($server, $client, $validation) = @_;
  if (!(ref($client) eq 'HASH')) {
    return 0;
  }

  if (!(ref($validation) eq 'HASH' && $validation->{valid})) {
    return 0;
  }

  return set_authoritative_account($server, $client, account => $validation->{pubkey},);
}

sub clear_authoritative_binding {
  my ($server, $client) = @_;
  if (!(ref($client) eq 'HASH')) {
    return 0;
  }

  return set_authoritative_account($server, $client);
}

sub set_authoritative_account {
  my ($server, $client, %args) = @_;
  if (!(ref($client) eq 'HASH')) {
    return 0;
  }

  my $old_account = _normalized_account($client->{authority_pubkey});
  my $new_account = _normalized_account($args{account});
  return 1
    if defined($old_account)
    && defined($new_account)
    && $old_account eq $new_account;
  return 1
    if !defined($old_account) && !defined($new_account);

  if (ref($server)) {
    _send_account_notify($server, $client, $new_account);
  }

  _clear_authoritative_delegate_state($server, $client);
  if (defined $new_account) {
    $client->{authority_pubkey} = $new_account;
  } else {
    delete $client->{authority_pubkey};
  }

  return 1;
}

sub _normalized_account {
  my ($account) = @_;
  if (!(defined($account) && !ref($account) && length($account))) {
    return;
  }

  return $account;
}

sub _send_account_notify {
  my ($server, $client, $new_account) = @_;
  if (!(ref($server) && ref($client) eq 'HASH')) {
    return 1;
  }

  if (!($client->{registered})) {
    return 1;
  }

  if (!(defined($client->{nick}) && !ref($client->{nick}) && length($client->{nick}))) {
    return 1;
  }

  my %recipient_ids;
  for my $recipient_id ($server->_shared_client_ids_for_client($client->{id})) {
    if (!(defined($recipient_id) && exists $server->{clients}{$recipient_id})) {
      next;
    }

    my $recipient = $server->{clients}{$recipient_id};
    if (!(ref($recipient) eq 'HASH' && $recipient->{registered})) {
      next;
    }

    if (!($server->_client_has_capability($recipient, 'account-notify'))) {
      next;
    }

    $recipient_ids{$recipient_id} = 1;
  }
  if (!(%recipient_ids)) {
    return 1;
  }

  my $line = Overnet::Program::IRC::Renderer::account_notify_line(
    nick     => $client->{nick},
    username => (
      defined($client->{username}) && !ref($client->{username}) && length($client->{username})
      ? $client->{username}
      : $client->{nick}
    ),
    host    => $server->_presentational_host_for_client($client),
    account => $new_account,
  );

  for my $recipient_id (sort keys %recipient_ids) {
    $server->_send_client_line($recipient_id, $line);
  }

  return 1;
}

sub _clear_authoritative_delegate_state {
  my ($server, $client) = @_;
  if (!(ref($client) eq 'HASH')) {
    return 0;
  }

  delete $client->{authority_delegate_key};
  delete $client->{authority_delegate_session_id};
  delete $client->{authority_delegate_expires_at};
  delete $client->{authority_delegate_event_id};
  delete $client->{authority_delegate_sequence};
  if (ref($server)) {
    delete $server->{authoritative_last_created_at}{$client->{id}};
    delete $server->{authoritative_delegate_sequences}{$client->{id}};
  }
  return 1;
}

sub ensure_authoritative_delegate_offer {
  my ($server, $client) = @_;
  if (!(ref($client) eq 'HASH')) {
    return;
  }

  if (!ref($client->{authority_delegate_key})
    || ref($client->{authority_delegate_key}) ne 'Overnet::Core::Nostr::Key') {
    $client->{authority_delegate_key} = Overnet::Core::Nostr->generate_key;
  }
  if (!defined $client->{authority_delegate_session_id}
    || ref($client->{authority_delegate_session_id})
    || !length($client->{authority_delegate_session_id})) {
    $client->{authority_delegate_session_id} = $server->_generate_authoritative_delegate_session_id($client);
  }
  $client->{authority_delegate_expires_at} = int(time()) + 3600;

  return {
    relay_url       => $server->_authority_relay_url,
    grant_kind      => $server->_authority_grant_kind,
    delegate_pubkey => $client->{authority_delegate_key}->pubkey_hex,
    session_id      => $client->{authority_delegate_session_id},
    expires_at      => $client->{authority_delegate_expires_at},
  };
}

sub accept_authoritative_delegate_event {
  my ($server, %args) = @_;
  my $client = $args{client};
  if (
    !(
         ref($client) eq 'HASH'
      && defined $client->{authority_pubkey}
      && !ref($client->{authority_pubkey})
      && $client->{authority_pubkey} =~ /\A[0-9a-f]{64}\z/mxs
    )
  ) {
    return {
      valid  => 0,
      reason => 'delegation event pubkey does not match the authenticated user',
    };
  }

  my $validation = Overnet::Authority::Delegation->verify_delegation_grant(
    authority_pubkey => $client->{authority_pubkey},
    relay_url        => $args{relay_url},
    scope            => $server->_authoritative_auth_scope,
    delegate_pubkey  => $args{delegate_pubkey},
    session_id       => $args{session_id},
    expires_at       => $args{expires_at},
    kind             => $args{kind},
    event            => $args{event_hash},
  );
  if (!($validation->{valid})) {
    return $validation;
  }

  my $publish = eval {
    $server->_request(
      method => 'nostr.publish_event',
      params => {
        relay_url => $args{relay_url},
        event     => $validation->{event},
      },
    );
  };
  if ($EVAL_ERROR || ref($publish) ne 'HASH' || !$publish->{accepted}) {
    return {
      valid  => 0,
      reason => 'delegation relay publish failed',
    };
  }

  $client->{authority_delegate_event_id}                     = $validation->{event_id};
  $client->{authority_delegate_sequence}                     = 0;
  $server->{authoritative_last_created_at}{$client->{id}}    = 0;
  $server->{authoritative_delegate_sequences}{$client->{id}} = 0;
  $server->_read_authoritative_grant_events(force => 1);
  return $validation;
}

1;

=head1 NAME

Overnet::Program::IRC::Command::Auth - IRC authentication command handlers

=head1 DESCRIPTION

Handles IRC capability negotiation, SASL NOSTR authentication, and
authoritative Overnet authentication/delegation commands.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  Overnet::Program::IRC::Command::Auth::handle_cap($server, $client_id, \@params);

=head1 SUBROUTINES/METHODS

=head2 handle_cap

=head2 handle_authenticate

=head2 handle_overnetauth

=head2 start_sasl_nostr_exchange

=head2 complete_sasl_exchange

=head2 reset_sasl_state

=head2 validate_authoritative_auth_event

=head2 apply_authoritative_auth_validation

=head2 clear_authoritative_binding

=head2 set_authoritative_account

=head2 ensure_authoritative_delegate_offer

=head2 accept_authoritative_delegate_event

=head1 DIAGNOSTICS

Invalid IRC auth flows are reported as IRC numerics or server notices.

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
