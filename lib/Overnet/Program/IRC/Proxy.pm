package Overnet::Program::IRC::Proxy;

use strictures 2;
use Moo;
use Overnet::Program::IRC::Auth::Helper;

our $VERSION = '0.001';

has client => (
  is       => 'ro',
  reader   => '_client',
  required => 1,
);
has identity_id => (
  is     => 'ro',
  reader => '_identity_id',
);
has program_id => (
  is      => 'ro',
  reader  => '_program_id',
  default => sub {'irc.proxy'},
);
has locator => (
  is     => 'ro',
  reader => '_locator',
);
has service_identity_scheme => (
  is     => 'ro',
  reader => '_service_identity_scheme',
);
has service_identity_value => (
  is     => 'ro',
  reader => '_service_identity_value',
);
has service_identity_display => (
  is     => 'ro',
  reader => '_service_identity_display',
);
has interactive => (
  is      => 'ro',
  reader  => '_interactive',
  default => sub {1},
);
has auto_delegate => (
  is      => 'ro',
  reader  => '_auto_delegate',
  default => sub {1},
);
has proxy_server_name => (
  is      => 'ro',
  reader  => '_proxy_server_name',
  default => sub {'overnet-irc-proxy'},
);
has started => (
  is      => 'rw',
  reader  => '_started',
  writer  => '_set_started',
  default => sub {0},
);
has authenticated => (
  is      => 'rw',
  reader  => 'authenticated',
  writer  => '_set_authenticated',
  default => sub {0},
);
has buffered_client_lines => (
  is      => 'rw',
  reader  => '_buffered_client_lines',
  writer  => '_set_buffered_client_lines',
  default => sub { [] },
);
has sasl_state => (
  is      => 'rw',
  reader  => '_sasl_state',
  writer  => '_set_sasl_state',
  default => sub { {} },
);

no Moo;

sub start {
  my ($self) = @_;
  if ($self->{started}) {
    return _result();
  }

  $self->{started} = 1;
  return _result(to_server => ["CAP LS 302\r\n", "CAP REQ :sasl\r\n",],);
}

sub client_line {
  my ($self, $raw_line) = @_;
  my $line = _wire_line($raw_line);
  return _result() if !defined $line;

  if ($self->{authenticated}) {
    return _result(to_server => [$line],);
  }

  if (my $cap_response = $self->_client_cap_response($line)) {
    return _result(to_client => [$cap_response],);
  }

  my $command = _command($line);
  if (_preauth_forward_command($command)) {
    return _result(to_server => [$line],);
  }

  if ($command eq 'CAP' || $command eq 'AUTHENTICATE') {
    return _result();
  }

  push @{$self->{buffered_client_lines}}, $line;
  return _result();
}

sub server_line {
  my ($self, $raw_line) = @_;
  my $line = _wire_line($raw_line);
  return _result() if !defined $line;

  if ($self->{authenticated}) {
    return _result(to_client => [$line],);
  }

  if (_server_cap_ack_sasl($line)) {
    return _result(to_server => ["AUTHENTICATE NOSTR\r\n"],);
  }

  if (_server_cap_nak_sasl($line)) {
    return _result(to_client => ["ERROR :Overnet IRC server does not accept SASL\r\n"],);
  }

  my $sasl = Overnet::Program::IRC::Auth::Helper->consume_sasl_challenge_line(
    $self->_auth_helper_args,
    state => $self->{sasl_state},
    line  => $line,
    quote => 0,
  );
  if ($sasl->{handled}) {
    return _result(to_server => [_crlf_lines(@{$sasl->{lines}})],);
  }

  if (_server_sasl_success($line)) {
    $self->{authenticated} = 1;
    my @buffered = splice @{$self->{buffered_client_lines}};
    return _result(to_server => ["CAP END\r\n", @buffered],);
  }

  if (_server_sasl_failure($line)) {
    return _result(to_client => [$line],);
  }

  if (_server_cap_line($line)) {
    return _result();
  }

  if (my $pong = _proxy_pong_for_server_ping($line)) {
    return _result(to_server => [$pong],);
  }

  return _result(to_client => [$line],);
}

sub _auth_helper_args {
  my ($self) = @_;
  return (
    client                   => $self->{client},
    identity_id              => $self->{identity_id},
    program_id               => $self->{program_id},
    locator                  => $self->{locator},
    service_identity_scheme  => $self->{service_identity_scheme},
    service_identity_value   => $self->{service_identity_value},
    service_identity_display => $self->{service_identity_display},
    interactive              => $self->{interactive},
    auto_delegate            => $self->{auto_delegate},
  );
}

sub _client_cap_response {
  my ($self, $line) = @_;
  my $body = _line_body($line);

  if ($body =~ /\ACAP\s+LS(?:\s+\S+)?\z/imxs) {
    return sprintf(":%s CAP * LS :\r\n", $self->{proxy_server_name});
  }

  if ($body =~ /\ACAP\s+REQ\s+:(.+)\z/imxs) {
    return sprintf(":%s CAP * NAK :%s\r\n", $self->{proxy_server_name}, $1);
  }

  return;
}

sub _preauth_forward_command {
  my ($command) = @_;
  return 1 if $command eq 'PASS';
  return 1 if $command eq 'NICK';
  return 1 if $command eq 'USER';
  return 1 if $command eq 'QUIT';
  return 0;
}

sub _command {
  my ($line) = @_;
  my $body = _line_body($line);
  $body =~ s/\A:\S+\s+//mxs;
  my ($command) = $body =~ /\A(\S+)/mxs;
  return defined($command) ? uc($command) : q{};
}

sub _server_cap_ack_sasl {
  my ($line) = @_;
  my $body = _line_body($line);
  return $body =~ /\A(?::\S+\s+)?CAP\s+\S+\s+ACK\s+:.*\bsasl\b/imxs ? 1 : 0;
}

sub _server_cap_nak_sasl {
  my ($line) = @_;
  my $body = _line_body($line);
  return $body =~ /\A(?::\S+\s+)?CAP\s+\S+\s+NAK\s+:.*\bsasl\b/imxs ? 1 : 0;
}

sub _server_cap_line {
  my ($line) = @_;
  return _command($line) eq 'CAP' ? 1 : 0;
}

sub _server_sasl_success {
  my ($line) = @_;
  my $body = _line_body($line);
  return $body =~ /\A:\S+\s+903\s+/mxs ? 1 : 0;
}

sub _server_sasl_failure {
  my ($line) = @_;
  my $body = _line_body($line);
  return $body =~ /\A:\S+\s+90[4567]\s+/mxs ? 1 : 0;
}

sub _proxy_pong_for_server_ping {
  my ($line)    = @_;
  my $body      = _line_body($line);
  my ($payload) = $body =~ /\APING(\s+.+)\z/imxs;
  return if !defined $payload;
  return "PONG$payload\r\n";
}

sub _crlf_lines {
  my (@lines) = @_;
  return map { _wire_line($_) } grep {defined} @lines;
}

sub _wire_line {
  my ($line) = @_;
  return if !defined $line;
  $line =~ s/\r?\n\z//mxs;
  return if !length $line;
  return "$line\r\n";
}

sub _line_body {
  my ($line) = @_;
  $line =~ s/\r?\n\z//mxs;
  return $line;
}

sub _result {
  my (%args) = @_;
  return {
    to_server => $args{to_server} || [],
    to_client => $args{to_client} || [],
  };
}

1;

=head1 NAME

Overnet::Program::IRC::Proxy - Line-oriented IRC proxy session

=head1 DESCRIPTION

Tracks a single local IRC client session while a proxy performs upstream SASL
NOSTR authentication with the Overnet auth agent.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $proxy = Overnet::Program::IRC::Proxy->new(client => $auth_client);
  my $start = $proxy->start;

=head1 SUBROUTINES/METHODS

=head2 start

Starts hidden upstream capability negotiation.

=head2 client_line

Processes one local client IRC line and returns lines to write to the upstream
server or local client.

=head2 server_line

Processes one upstream server IRC line and returns lines to write to the
upstream server or local client.

=head2 authenticated

Returns true after hidden upstream SASL authentication succeeds.

=head1 DIAGNOSTICS

Auth-agent failures are reported through exceptions.

=head1 CONFIGURATION AND ENVIRONMENT

Configuration is supplied through constructor arguments.

=head1 DEPENDENCIES

See the distribution metadata for runtime dependencies.

=head1 INCOMPATIBILITIES

No known incompatibilities are documented.

=head1 BUGS AND LIMITATIONS

The proxy session owns upstream SASL negotiation and deliberately hides it from
the local IRC client.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the project license.

=cut
