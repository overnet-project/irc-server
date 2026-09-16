package Overnet::Program::IRC::Renderer;

use strictures 2;
use English qw(-no_match_vars);

our $VERSION = '0.001';

sub rendering_failure {
  warn "IRC rendering rejected an invalid field\n";
  return;
}

sub middle_is_valid {
  my ($value) = @_;
  return
       defined($value)
    && !ref($value)
    && length($value)
    && $value !~ /[\x00-\x20\x7f]/mxs
    && $value !~ /\A:/mxs;
}

sub text_is_valid {
  my ($value) = @_;
  return defined($value) && !ref($value) && $value !~ /[\x00\r\n]/mxs;
}

sub format_line {
  my ($format, @values) = @_;
  my $trailing   = index($format, ' :');
  my $prefix_end = index($format, q{ });
  my $index      = 0;
  while ($format =~ /%([sd])/gmxs) {
    my $position   = $LAST_MATCH_START[0];
    my $conversion = $1;
    my $value      = $values[$index++];
    my $valid      = $trailing >= 0 && $position > $trailing ? text_is_valid($value) : middle_is_valid($value);
    if ($conversion eq 'd') {
      $valid &&= $value =~ /\A[0-9]+\z/mxs;
    }
    if ($position < $prefix_end) {
      $valid &&= $value !~ /[!\@:]/mxs;
    }
    return rendering_failure() if !$valid;
  }
  return rendering_failure() if $index != @values;
  my $line = sprintf($format, @values);
  return line_is_valid($line) ? $line : rendering_failure();
}

sub line_is_valid {
  my ($line) = @_;
  return 0 if !text_is_valid($line) || !length($line);

  # A final framing check also covers callers forwarding complete lines.
  my $middle  = qr/[^ :\x00-\x1f\x7f][^ \x00-\x1f\x7f]*/mxs;
  my $tags    = qr/[^ \x00-\x1f\x7f]+/mxs;
  my $prefix  = qr/(?:\@$tags\x20)?(?::$middle\x20)?/mxs;
  my $command = qr/(?:[A-Za-z]+|[0-9]{3})/mxs;
  return $line =~ /\A$prefix$command(?:\x20$middle)*(?:\x20:[^\x00\r\n]*)?\z/mxs ? 1 : 0;
}

sub append_reason {
  my ($line, $reason) = @_;
  return                     if !defined $line;
  return rendering_failure() if defined($reason) && !text_is_valid($reason);
  return $line               if !defined($reason) || !length($reason);
  return $line . ' :' . $reason;
}

sub append_parameters {
  my ($line, @parameters) = @_;
  return if !defined $line;
  for my $parameter (@parameters) {
    return rendering_failure() if !middle_is_valid($parameter);
  }
  return join q{ }, $line, @parameters;
}

sub authenticate_payload_lines {
  my (%args) = @_;
  my $remaining = defined($args{payload}) ? $args{payload} : q{};
  my @lines;

  return [] if !text_is_valid($remaining) || $remaining =~ /[^A-Za-z0-9+\/=]/mxs;

  while (length($remaining) >= 400) {
    push @lines, 'AUTHENTICATE ' . substr($remaining, 0, 400, q{});
  }

  if (length $remaining) {
    push @lines, 'AUTHENTICATE ' . $remaining;
  } else {
    push @lines, 'AUTHENTICATE +';
  }

  return \@lines;
}

sub sasl_success_line {
  my (%args) = @_;
  return format_line(':%s 903 %s :SASL authentication successful', $args{server_name}, $args{nick},);
}

sub sasl_fail_line {
  my (%args) = @_;
  return format_line(':%s 904 %s :SASL authentication failed', $args{server_name}, $args{nick},);
}

sub unknown_command_line {
  my (%args) = @_;
  return format_line(':%s 421 %s %s :Unknown command', $args{server_name}, $args{nick}, $args{command},);
}

sub registration_prelude_lines {
  my (%args) = @_;
  return [] if !defined $args{isupport_tokens};
  my $support = append_parameters(
    format_line(':%s 005 %s', $args{server_name}, $args{nick}),
    split(/\x20/mxs, $args{isupport_tokens}, -1),
  );
  return [
    format_line(':%s 001 %s :Welcome to Overnet IRC', $args{server_name}, $args{nick},),
    append_reason($support, 'are supported by this server'),
    format_line(':%s 422 %s :MOTD File is missing', $args{server_name}, $args{nick},),
  ];
}

sub nonickname_given_line {
  my (%args) = @_;
  return format_line(':%s 431 %s :No nickname given', $args{server_name}, $args{nick},);
}

sub not_registered_line {
  my (%args) = @_;
  return format_line(':%s 451 * :You have not registered', $args{server_name},);
}

sub need_more_params_line {
  my (%args) = @_;
  return format_line(':%s 461 %s %s :Not enough parameters', $args{server_name}, $args{nick}, $args{command},);
}

sub server_notice_line {
  my (%args) = @_;
  return format_line(':%s NOTICE %s :%s', $args{server_name}, $args{nick}, $args{text},);
}

sub account_notify_line {
  my (%args) = @_;
  my $account =
       defined($args{account})
    && !ref($args{account})
    && length($args{account})
    ? $args{account}
    : q{*};
  return format_line(':%s!%s@%s ACCOUNT %s', $args{nick}, $args{username}, $args{host}, $account,);
}

sub no_such_nick_line {
  my (%args) = @_;
  return format_line(':%s 401 %s %s :No such nick/channel', $args{server_name}, $args{nick}, $args{target_nick},);
}

sub no_such_channel_line {
  my (%args) = @_;
  return format_line(':%s 403 %s %s :No such channel', $args{server_name}, $args{nick}, $args{channel},);
}

sub not_on_channel_line {
  my (%args) = @_;
  return format_line(':%s 442 %s %s :You\'re not on that channel', $args{server_name}, $args{nick}, $args{channel},);
}

sub cannot_send_to_channel_line {
  my (%args) = @_;
  return format_line(':%s 404 %s %s :Cannot send to channel', $args{server_name}, $args{nick}, $args{channel},);
}

sub chan_op_privs_needed_line {
  my (%args) = @_;
  return format_line(':%s 482 %s %s :You\'re not channel operator', $args{server_name}, $args{nick}, $args{channel},);
}

sub cannot_join_channel_line {
  my (%args) = @_;
  my $numeric = 473;
  if (defined($args{reason}) && $args{reason} eq '+b') {
    $numeric = 474;
  }

  if (defined($args{reason}) && $args{reason} eq '+k') {
    $numeric = 475;
  }

  if (defined($args{reason}) && $args{reason} eq '+l') {
    $numeric = 471;
  }

  my $reason = 'Cannot join channel';
  if (defined($args{reason}) && length($args{reason})) {
    $reason .= ' (' . $args{reason} . ')';
  }

  return format_line(':%s %d %s %s :%s', $args{server_name}, $numeric, $args{nick}, $args{channel}, $reason,);
}

sub ban_list_entry_line {
  my (%args) = @_;
  return format_line(':%s 367 %s %s %s %s 0',
    $args{server_name}, $args{nick}, $args{channel}, $args{ban_mask}, $args{server_name},);
}

sub end_of_ban_list_line {
  my (%args) = @_;
  return format_line(':%s 368 %s %s :End of channel ban list', $args{server_name}, $args{nick}, $args{channel},);
}

sub exception_list_entry_line {
  my (%args) = @_;
  return format_line(
    ':%s 348 %s %s %s %s 0', $args{server_name},    $args{nick},
    $args{channel},          $args{exception_mask}, $args{server_name},
  );
}

sub end_of_exception_list_line {
  my (%args) = @_;
  return format_line(':%s 349 %s %s :End of channel exception list', $args{server_name}, $args{nick}, $args{channel},);
}

sub invite_exception_list_entry_line {
  my (%args) = @_;
  return format_line(
    ':%s 346 %s %s %s %s 0',
    $args{server_name}, $args{nick}, $args{channel}, $args{invite_exception_mask},
    $args{server_name},
  );
}

sub end_of_invite_exception_list_line {
  my (%args) = @_;
  return format_line(':%s 347 %s %s :End of channel invite exception list', $args{server_name}, $args{nick},
    $args{channel},);
}

sub inviting_line {
  my (%args) = @_;
  return format_line(':%s 341 %s %s %s', $args{server_name}, $args{nick}, $args{target_nick}, $args{channel},);
}

sub authoritative_invite_list_entry_line {
  my (%args) = @_;
  return format_line(':%s 336 %s %s %s %s',
    $args{server_name}, $args{nick}, $args{channel}, $args{target_pubkey}, $args{invite_code},);
}

sub end_of_authoritative_invite_list_line {
  my (%args) = @_;
  return format_line(':%s 337 %s %s :End of authoritative invite list', $args{server_name}, $args{nick},
    $args{channel},);
}

sub authoritative_join_request_list_entry_line {
  my (%args) = @_;
  return format_line(
    ':%s 338 %s %s %s %s',
    $args{server_name}, $args{nick}, $args{channel}, $args{requester_pubkey},
    (defined($args{actor_mask}) && length($args{actor_mask}) ? $args{actor_mask} : q{*}),
  );
}

sub end_of_authoritative_join_request_list_line {
  my (%args) = @_;
  return format_line(':%s 339 %s %s :End of authoritative join request list',
    $args{server_name}, $args{nick}, $args{channel},);
}

sub channel_mode_is_line {
  my (%args) = @_;
  return append_parameters(
    format_line(':%s 324 %s %s %s', $args{server_name}, $args{nick}, $args{channel}, $args{channel_modes}),
    @{$args{mode_args} || []},
  );
}

sub user_mode_is_line {
  my (%args) = @_;
  return format_line(':%s 221 %s +', $args{server_name}, $args{nick},);
}

sub lusers_reply_lines {
  my (%args) = @_;
  return [
    format_line(
      ':%s 251 %s :There are %d users and 0 services on 1 server',
      $args{server_name}, $args{nick}, $args{registered_users},
    ),
    format_line(':%s 252 %s 0 :operator(s) online',    $args{server_name}, $args{nick},),
    format_line(':%s 253 %s 0 :unknown connection(s)', $args{server_name}, $args{nick},),
    format_line(':%s 254 %s %d :channels formed',      $args{server_name}, $args{nick}, $args{channels},),
    format_line(
      ':%s 255 %s :I have %d clients and 1 server',
      $args{server_name}, $args{nick}, $args{connected_clients},
    ),
  ];
}

sub list_reply_lines {
  my (%args) = @_;
  my @lines = (format_line(':%s 321 %s Channel :Users Name', $args{server_name}, $args{nick},),);

  for my $entry (@{$args{entries} || []}) {
    push @lines,
      format_line(
      ':%s 322 %s %s %d :%s', $args{server_name},      $args{nick},
      $entry->{channel},      $entry->{visible_users}, $entry->{topic},
      );
  }

  push @lines, format_line(':%s 323 %s :End of /LIST', $args{server_name}, $args{nick},);

  return \@lines;
}

sub topic_is_line {
  my (%args) = @_;
  return format_line(':%s 332 %s %s :%s', $args{server_name}, $args{nick}, $args{channel}, $args{topic},);
}

sub no_topic_line {
  my (%args) = @_;
  return format_line(':%s 331 %s %s :No topic is set', $args{server_name}, $args{nick}, $args{channel},);
}

sub userhost_line {
  my (%args) = @_;
  for my $entry (@{$args{entries} || []}) {
    return rendering_failure() if !middle_is_valid($entry);
  }
  return format_line(':%s 302 %s :%s', $args{server_name}, $args{nick}, join(q{ }, @{$args{entries} || []}),);
}

sub who_list_lines {
  my (%args) = @_;
  my @lines;

  for my $entry (@{$args{entries} || []}) {
    push @lines,
      format_line(
      ':%s 352 %s %s %s %s %s %s H :0 %s', $args{server_name}, $args{nick},
      $args{channel},                      $entry->{username}, $entry->{host},
      $args{server_name},                  $entry->{nick},     $entry->{realname},
      );
  }

  push @lines, format_line(':%s 315 %s %s :End of /WHO list.', $args{server_name}, $args{nick}, $args{channel},);

  return \@lines;
}

sub whois_reply_lines {
  my (%args) = @_;
  my $entry  = $args{entry} || {};
  my @lines  = (
    format_line(
      ':%s 311 %s %s %s %s * :%s', $args{server_name}, $args{nick}, $entry->{nick},
      $entry->{username},          $entry->{host},     $entry->{realname},
    ),
  );

  if ( defined($entry->{account})
    && !ref($entry->{account})
    && length($entry->{account})) {
    push @lines,
      format_line(':%s 330 %s %s %s :is logged in as',
      $args{server_name}, $args{nick}, $entry->{nick}, $entry->{account},);
  }

  push @lines,
    format_line(
    ':%s 312 %s %s %s :%s',
    $args{server_name}, $args{nick}, $entry->{nick}, $args{server_name}, $args{server_description},
    ),
    format_line(':%s 318 %s %s :End of /WHOIS list.', $args{server_name}, $args{nick}, $entry->{nick},);

  return \@lines;
}

sub nick_in_use_line {
  my (%args) = @_;
  return format_line(':%s 433 %s %s :Nickname is already in use', $args{server_name}, $args{nick},
    $args{attempted_nick},);
}

sub names_list_lines {
  my (%args) = @_;
  for my $name (@{$args{names} || []}) {
    if (!middle_is_valid($name) || $name =~ /[!:]/mxs || substr($name, 1) =~ /@/mxs) {
      rendering_failure();
      return [];
    }
  }
  return [
    format_line(
      ':%s 353 %s = %s :%s',
      $args{server_name}, $args{nick}, $args{channel}, join(q{ }, @{$args{names} || []}),
    ),
    format_line(':%s 366 %s %s :End of /NAMES list.', $args{server_name}, $args{nick}, $args{channel},),
  ];
}

1;

=head1 NAME

Overnet::Program::IRC::Renderer - IRC protocol line renderer

=head1 DESCRIPTION

Provides small rendering helpers for IRC numerics, notices, capabilities,
channel lists, identity replies, and authority-specific replies.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $line = Overnet::Program::IRC::Renderer::server_notice_line(%args);

=head1 SUBROUTINES/METHODS

=head2 format_line

Checks each field against its position in a literal IRC format before combining
fields. Only C<%s> and C<%d> substitutions are supported. The result has no CRLF;
the socket writer adds exactly one terminator after checking the whole line.
Invalid fields produce no line and a diagnostic that contains no message text.

=head2 middle_is_valid

=head2 text_is_valid

=head2 line_is_valid

=head2 rendering_failure

=head2 append_reason

=head2 append_parameters

These helpers validate IRC fields and construct optional parameters without
allowing a value to supply IRC framing.

=head2 authenticate_payload_lines

=head2 sasl_success_line

=head2 sasl_fail_line

=head2 unknown_command_line

=head2 registration_prelude_lines

=head2 nonickname_given_line

=head2 not_registered_line

=head2 need_more_params_line

=head2 server_notice_line

=head2 account_notify_line

=head2 no_such_nick_line

=head2 no_such_channel_line

=head2 not_on_channel_line

=head2 cannot_send_to_channel_line

=head2 chan_op_privs_needed_line

=head2 cannot_join_channel_line

=head2 ban_list_entry_line

=head2 end_of_ban_list_line

=head2 exception_list_entry_line

=head2 end_of_exception_list_line

=head2 invite_exception_list_entry_line

=head2 end_of_invite_exception_list_line

=head2 inviting_line

=head2 authoritative_invite_list_entry_line

=head2 end_of_authoritative_invite_list_line

=head2 authoritative_join_request_list_entry_line

=head2 end_of_authoritative_join_request_list_line

=head2 channel_mode_is_line

=head2 user_mode_is_line

=head2 lusers_reply_lines

=head2 list_reply_lines

=head2 topic_is_line

=head2 no_topic_line

=head2 userhost_line

=head2 who_list_lines

=head2 whois_reply_lines

=head2 nick_in_use_line

=head2 names_list_lines

=head1 DIAGNOSTICS

Invalid fields produce a diagnostic without including their contents.

=head1 CONFIGURATION AND ENVIRONMENT

No environment configuration is read by this module.

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
