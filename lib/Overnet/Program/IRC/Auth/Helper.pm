package Overnet::Program::IRC::Auth::Helper;

use strictures 2;

use Carp         qw(croak);
use English      qw(-no_match_vars);
use JSON         ();
use MIME::Base64 qw(decode_base64 encode_base64);
use Overnet::Auth::Bridge::IRC;
use Overnet::Program::IRC::Renderer ();

our $VERSION = '0.001';

sub run {
  my ($class, %args) = @_;
  my $command = $args{command} || q{};

  if ($command eq 'auth') {
    return $class->_authorize_auth(%args);
  }
  if ($command eq 'delegate') {
    return $class->_authorize_delegate(%args);
  }
  if ($command eq 'bridge') {
    if (!(defined($args{line}) && !ref($args{line}) && length($args{line}))) {
      return $class->_bridge_stream(%args);
    }

    return $class->_bridge_line(%args);
  }

  croak "unsupported command: $command\n";
}

sub _authorize_auth {
  my ($class, %args) = @_;
  my $artifact = $class->_authorize_auth_artifact(%args);
  return $class->_render_irc_artifact(
    artifact    => $artifact,
    irc_command => 'OVERNETAUTH AUTH',
    quote       => $args{quote},
  );
}

sub _authorize_auth_artifact {
  my ($class, %args) = @_;
  my $challenge = $args{challenge};
  my $scope     = $args{scope};

  if (!(defined $challenge && !ref($challenge) && length($challenge))) {
    croak "--challenge is required\n";
  }

  if (!(defined $scope && !ref($scope) && length($scope))) {
    croak "--scope is required\n";
  }

  return $class->_authorize_artifact(
    %args,
    action    => 'session.authenticate',
    challenge => {
      type  => 'opaque',
      value => $challenge,
    },
    artifacts => [
      {
        type   => 'nostr.event',
        params => {
          kind => 22_242,
          tags => [[relay => $scope], [challenge => $challenge],],
        },
      },
    ],
  );
}

sub _authorize_delegate {
  my ($class, %args) = @_;
  my $artifact = $class->_authorize_delegate_artifact(%args);
  return $class->_render_irc_artifact(
    artifact    => $artifact,
    irc_command => 'OVERNETAUTH DELEGATE',
    quote       => $args{quote},
  );
}

sub _authorize_delegate_artifact {
  my ($class, %args) = @_;
  my $relay_url       = $args{relay_url};
  my $scope           = $args{scope};
  my $delegate_pubkey = $args{delegate_pubkey};
  my $session_id      = $args{session_id};
  my $expires_at      = $args{expires_at};

  if (!(defined $relay_url && !ref($relay_url) && length($relay_url))) {
    croak "--relay-url is required\n";
  }

  if (!(defined $scope && !ref($scope) && length($scope))) {
    croak "--scope is required\n";
  }

  if (!(defined $delegate_pubkey && !ref($delegate_pubkey) && length($delegate_pubkey))) {
    croak "--delegate-pubkey is required\n";
  }

  if (!(defined $session_id && !ref($session_id) && length($session_id))) {
    croak "--session-id is required\n";
  }

  if (!(defined $expires_at && !ref($expires_at) && length($expires_at))) {
    croak "--expires-at is required\n";
  }

  my @tags = (
    [relay      => $relay_url],
    [server     => $scope],
    [delegate   => $delegate_pubkey],
    [session    => $session_id],
    [expires_at => $expires_at],
  );
  if (defined($args{nick}) && !ref($args{nick}) && length($args{nick})) {
    push @tags, [nick => $args{nick}];
  }

  return $class->_authorize_artifact(
    %args,
    action    => 'session.delegate',
    artifacts => [
      {
        type   => 'nostr.event',
        params => {
          kind => defined($args{grant_kind})
          ? $args{grant_kind}
          : 14_142,
          tags => \@tags,
        },
      },
    ],
  );
}

sub _bridge_line {
  my ($class, %args) = @_;
  my $line = $args{line};

  if (!(defined $line && !ref($line) && length($line))) {
    croak "--line is required\n";
  }

  my $parsed = $class->_maybe_parse_bridge_line($line)
    or croak "unsupported OVERNETAUTH bridge line\n";
  if ($parsed->{type} eq 'auth') {
    return $class->_authorize_auth(%args, challenge => $parsed->{challenge},);
  }

  return $class->_authorize_delegate(
    %args,
    relay_url       => $parsed->{relay_url},
    delegate_pubkey => $parsed->{delegate_pubkey},
    session_id      => $parsed->{session_id},
    expires_at      => $parsed->{expires_at},
  );
}

sub consume_sasl_challenge_line {
  my ($class, %args) = @_;
  my $line = $args{line};
  if (!(defined $line && !ref($line) && length($line))) {
    croak "line is required\n";
  }

  my $chunk = $class->_maybe_parse_sasl_chunk($line);
  if (!$chunk) {
    return {
      handled => 0,
      lines   => [],
    };
  }

  my @lines = $class->_consume_sasl_chunk(%args, chunk => $chunk->{chunk},);
  return {
    handled => 1,
    lines   => \@lines,
  };
}

sub _bridge_stream {
  my ($class, %args) = @_;
  my $input  = $args{input}  || \*STDIN;
  my $output = $args{output} || \*STDOUT;
  my $count  = 0;
  my %sasl_state;

  while (my $line = <$input>) {
    my $parsed = $class->_maybe_parse_bridge_line($line);
    if ($parsed) {
      my $wire =
        $parsed->{type} eq 'auth'
        ? $class->_authorize_auth(
        %args,
        line      => undef,
        challenge => $parsed->{challenge},
        )
        : $class->_authorize_delegate(
        %args,
        line            => undef,
        relay_url       => $parsed->{relay_url},
        delegate_pubkey => $parsed->{delegate_pubkey},
        session_id      => $parsed->{session_id},
        expires_at      => $parsed->{expires_at},
        );

      print {$output} $wire
        or croak "write bridge output failed: $OS_ERROR";
      $count++;
      next;
    }

    if (my $chunk = $class->_maybe_parse_sasl_chunk($line)) {
      my @lines = $class->_consume_sasl_chunk(
        %args,
        state => \%sasl_state,
        chunk => $chunk->{chunk},
      );
      for my $wire (@lines) {
        print {$output} $wire
          or croak "write bridge output failed: $OS_ERROR";
        $count++;
      }
      next;
    }

    my @flush = $class->_flush_sasl_chunk_state(%args, state => \%sasl_state,);
    for my $wire (@flush) {
      print {$output} $wire
        or croak "write bridge output failed: $OS_ERROR";
      $count++;
    }
  }

  my @flush = $class->_flush_sasl_chunk_state(%args, state => \%sasl_state,);
  for my $wire (@flush) {
    print {$output} $wire
      or croak "write bridge output failed: $OS_ERROR";
    $count++;
  }

  return $count;
}

sub _authorize_artifact {
  my ($class, %args) = @_;
  my $client = $args{client};
  if (!($client && ref($client))) {
    croak "client is required\n";
  }

  my $scope = $args{scope};
  my $locator =
       defined($args{locator})
    && !ref($args{locator})
    && length($args{locator})
    ? $args{locator}
    : $scope;
  my $program_id =
       defined($args{program_id})
    && !ref($args{program_id})
    && length($args{program_id})
    ? $args{program_id}
    : 'irc.bridge';

  my $service          = {locators => [$locator],};
  my $service_identity = _service_identity_descriptor(%args);
  if ($service_identity) {
    $service->{service_identity} = $service_identity;
  }

  my $response = $client->sessions_authorize(
    program_id => $program_id,
    (
      defined($args{identity_id})
        && !ref($args{identity_id})
        && length($args{identity_id}) ? (identity_id => $args{identity_id})
      : ()
    ),
    service     => $service,
    scope       => $scope,
    action      => $args{action},
    interactive => $args{interactive} ? JSON::true
    : JSON::false,
    (
      ref($args{challenge}) eq 'HASH' ? (challenge => $args{challenge})
      : ()
    ),
    artifacts => $args{artifacts},
  );

  if (!(ref($response) eq 'HASH' && $response->{ok})) {
    croak _error_message($response)
      . _policy_hint(
      response    => $response,
      program_id  => $program_id,
      identity_id => $args{identity_id},
      scope       => $scope,
      locator     => $locator,
      action      => $args{action},
      );
  }

  if (
    !(
         ref($response->{result}) eq 'HASH'
      && ref($response->{result}{artifacts}) eq 'ARRAY'
      && @{$response->{result}{artifacts}}
    )
  ) {
    croak "auth agent did not return any artifacts\n";
  }

  return $response->{result}{artifacts}[0];
}

sub _maybe_parse_bridge_line {
  my ($class, $line) = @_;
  $line =~ s/\r?\n\z//mxs;

  my $hex_64 = qr/[0-9a-f]{64}/imxs;
  if ($line =~ /\bOVERNETAUTH\s+CHALLENGE\s+($hex_64)\b/imxs) {
    return {
      type      => 'auth',
      challenge => lc $1,
    };
  }

  my $delegate_line = qr/\bOVERNETAUTH\s+DELEGATE\s+($hex_64)\s+(\S+)\s+(\S+)\s+(\d+)\b/imxs;
  if ($line =~ $delegate_line) {
    return {
      type            => 'delegate',
      delegate_pubkey => lc $1,
      session_id      => $2,
      relay_url       => $3,
      expires_at      => $4,
    };
  }

  return;
}

sub _maybe_parse_sasl_chunk {
  my ($class, $line) = @_;
  $line =~ s/\r?\n\z//mxs;

  my ($chunk) = $line =~ /\A(?::\S+\s+)?AUTHENTICATE\s+(\S+)\z/imxs;
  if (!(defined $chunk)) {
    return;
  }

  return if uc($chunk) eq 'NOSTR';

  return {chunk => $chunk,};
}

sub _consume_sasl_chunk {
  my ($class, %args) = @_;
  my $state = $args{state} || {};
  my $chunk = $args{chunk};

  if (!($chunk eq q{+})) {
    $state->{buffer} .= $chunk;
  }

  return ()
    if $chunk ne q{+}
    && length($chunk) == 400;

  return $class->_flush_sasl_chunk_state(%args);
}

sub _flush_sasl_chunk_state {
  my ($class, %args) = @_;
  my $state  = $args{state} || {};
  my $buffer = delete $state->{buffer};

  if (!(defined($buffer) && length($buffer))) {
    return ();
  }

  my $decoded = eval { decode_base64($buffer) };
  if (!(defined $decoded)) {    # uncoverable branch true reason: decode_base64 skips invalid bytes instead of failing
    return ();    # uncoverable statement reason: defensive guard for a decode_base64 failure that cannot happen
  }

  my $challenge_payload = eval { JSON::decode_json($decoded) };
  if (!(ref($challenge_payload) eq 'HASH')) {
    return ();
  }

  return $class->_render_sasl_response(%args, challenge_payload => $challenge_payload,);
}

sub _render_sasl_response {
  my ($class, %args) = @_;
  my $challenge_payload = $args{challenge_payload};

  my ($challenge, $scope) = _sasl_challenge_scope($challenge_payload);
  if (!(defined $challenge)) {
    return ();
  }

  my %response = (
    auth_event => $class->_authorize_auth_artifact(
      %args,
      scope     => $scope,
      challenge => $challenge,
    )->{value},
  );

  if (_sasl_delegate_required($challenge_payload)) {
    if (exists($args{auto_delegate}) && !$args{auto_delegate}) {
      croak "SASL NOSTR delegation is disabled\n";
    }
    my $delegate = _sasl_delegate_payload($challenge_payload);
    $response{delegate_event} = $class->_authorize_delegate_artifact(
      %args,
      scope => $scope,
      %{$delegate},
    )->{value};
  }

  my $payload = encode_base64(JSON::encode_json(\%response), q{});
  my $lines   = Overnet::Program::IRC::Renderer::authenticate_payload_lines(payload => $payload,);

  return map { $args{quote} ? "/quote $_\n" : "$_\n" } @{$lines};
}

sub _sasl_challenge_scope {
  my ($payload) = @_;
  return if !(ref($payload) eq 'HASH');
  return if !_nonempty_scalar($payload->{challenge});
  return if !_nonempty_scalar($payload->{scope});
  return ($payload->{challenge}, $payload->{scope});
}

sub _sasl_delegate_required {
  my ($payload) = @_;
  return 0 if !(ref($payload) eq 'HASH');
  for my $field (_sasl_delegate_fields()) {
    return 1 if exists $payload->{$field};
  }
  return 0;
}

sub _sasl_delegate_payload {
  my ($payload) = @_;
  my @fields = _sasl_delegate_fields();
  for my $field (@fields) {
    if (!_nonempty_scalar($payload->{$field})) {
      croak "malformed SASL NOSTR challenge payload\n";
    }
  }
  return {map { ($_ => $payload->{$_}) } @fields};
}

sub _sasl_delegate_fields {
  my @fields;
  push @fields, 'relay_url';
  push @fields, 'grant_kind';
  push @fields, 'delegate_pubkey';
  push @fields, 'session_id';
  push @fields, 'expires_at';
  return @fields;
}

sub _nonempty_scalar {
  my ($value) = @_;
  return 0 if !defined $value;
  return 0 if ref($value);
  return length($value) ? 1 : 0;
}

sub _render_irc_artifact {
  my ($class, %args) = @_;
  my $wire = Overnet::Auth::Bridge::IRC->encode_artifact(
    artifact => $args{artifact},
    protocol => 'irc',
    command  => $args{irc_command},
    encoding => 'base64-json',
  );

  return $args{quote}
    ? "/quote $wire->{command} $wire->{payload}\n"
    : "$wire->{payload}\n";
}

sub _service_identity_descriptor {
  my (%args) = @_;
  my $scheme = $args{service_identity_scheme};
  my $value  = $args{service_identity_value};

  if (!(defined($scheme) || defined($value) || defined($args{service_identity_display}))) {
    return;
  }

  if (!(defined($scheme) && !ref($scheme) && length($scheme) && defined($value) && !ref($value) && length($value))) {
    croak "--service-identity-scheme and --service-identity-value are required together\n";
  }

  my %descriptor = (
    scheme => $scheme,
    value  => $value,
  );
  if ( defined($args{service_identity_display})
    && !ref($args{service_identity_display})
    && length($args{service_identity_display})) {
    $descriptor{display} = $args{service_identity_display};
  }

  return \%descriptor;
}

# The agent exposes no approval UI, so with no matching policy it fails closed
# with auth.headless_unavailable -- whose message says only that approval is
# unavailable. That is the likeliest failure a new user meets, and on its own it
# names none of the four values that must match, so there is no way to tell
# which one is wrong. All of them are known here, at the point of failure, so
# say what would authorize this exact request.
#
# Only for that one code: a refusal the user made deliberately (auth.denied)
# must not be answered with instructions for overriding it.
sub _policy_hint {
  my (%args) = @_;

  my $code =
    ref($args{response}) eq 'HASH' && ref($args{response}{error}) eq 'HASH'
    ? $args{response}{error}{code}
    : undef;
  if (!(defined $code && !ref($code) && $code eq 'auth.headless_unavailable')) {
    return q{};
  }

  my @grant = ('overnet-auth.pl policy-grant');
  if (defined $args{identity_id} && !ref($args{identity_id}) && length $args{identity_id}) {
    push @grant, "--identity-id $args{identity_id}";
  }
  for my $field (['program_id', '--program-id'], ['scope', '--scope'], ['action', '--action'],) {
    my ($key, $flag) = @{$field};
    my $value = $args{$key};
    next if !(defined $value && !ref($value) && length $value);
    push @grant, "$flag $value";
  }
  if (defined $args{locator} && !ref($args{locator}) && length $args{locator}) {
    push @grant, "--service-locator $args{locator}";
  }

  return
      "no policy authorizes this request, and this agent cannot ask you to approve one.\n"
    . "grant it with:\n  "
    . join(q{ }, @grant) . "\n";
}

sub _error_message {
  my ($response) = @_;
  if (!(ref($response) eq 'HASH')) {
    return "auth agent request failed\n";
  }

  if (!(ref($response->{error}) eq 'HASH')) {
    return "auth agent request failed\n";
  }

  my $code    = $response->{error}{code};
  my $message = $response->{error}{message};
  $code =
    defined($code) && !ref($code) && length($code) ? $code : 'unknown_error';
  $message =
       defined($message)
    && !ref($message)
    && length($message) ? $message : 'unknown auth-agent failure';
  return "$code: $message\n";
}

1;

=head1 NAME

Overnet::Program::IRC::Auth::Helper - IRC auth helper command runner

=head1 DESCRIPTION

Runs helper flows for producing IRC authentication artifacts, delegation
artifacts, and bridge output for SASL NOSTR authentication.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  Overnet::Program::IRC::Auth::Helper->run(command => 'auth', %args);

=head1 SUBROUTINES/METHODS

=head2 run

=head2 consume_sasl_challenge_line

Consumes one IRC C<AUTHENTICATE> line from a SASL NOSTR challenge stream and
returns whether the line was handled plus any response lines that should be sent
back to the IRC server.

=head1 DIAGNOSTICS

Invalid helper arguments are reported through exceptions.

=head1 CONFIGURATION AND ENVIRONMENT

Configuration is supplied through method arguments.

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
