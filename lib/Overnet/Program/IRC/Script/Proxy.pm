package Overnet::Program::IRC::Script::Proxy;

use strictures 2;
use Carp         qw(croak);
use English      qw(-no_match_vars);
use Getopt::Long qw(GetOptionsFromArray);
use IO::Handle   ();
use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL qw(SSL_VERIFY_NONE SSL_VERIFY_PEER);
use Overnet::Auth::Client;
use Overnet::Program::IRC::Proxy;
use Overnet::Program::IRC::Script::Util qw(checked_print_stderr checked_print_stdout validate_port);

our $VERSION = '0.001';

sub run {
  my ($class, @argv) = @_;

  my %options = (
    listen_host            => '127.0.0.1',
    listen_port            => 16_668,
    listen_backlog         => 5,
    server_host            => '127.0.0.1',
    server_port            => 16_667,
    server_tls             => 0,
    server_tls_min_version => 'TLSv1.2',
    interactive            => 1,
    auto_delegate          => 1,
    program_id             => 'irc.proxy',
    proxy_server_name      => 'overnet-irc-proxy',
  );
  my $help = 0;

  my $parsed = GetOptionsFromArray(
    \@argv,
    'listen-host=s'              => \$options{listen_host},
    'listen-port=i'              => \$options{listen_port},
    'listen-backlog=i'           => \$options{listen_backlog},
    'server-host=s'              => \$options{server_host},
    'server-port=i'              => \$options{server_port},
    'server-tls!'                => \$options{server_tls},
    'server-tls-no-verify!'      => \$options{server_tls_no_verify},
    'server-tls-ca-file=s'       => \$options{server_tls_ca_file},
    'server-tls-name=s'          => \$options{server_tls_name},
    'server-tls-min-version=s'   => \$options{server_tls_min_version},
    'auth-sock=s'                => \$options{auth_sock},
    'identity-id=s'              => \$options{identity_id},
    'program-id=s'               => \$options{program_id},
    'locator=s'                  => \$options{locator},
    'service-identity-scheme=s'  => \$options{service_identity_scheme},
    'service-identity-value=s'   => \$options{service_identity_value},
    'service-identity-display=s' => \$options{service_identity_display},
    'interactive!'               => \$options{interactive},
    'auto-delegate!'             => \$options{auto_delegate},
    'proxy-server-name=s'        => \$options{proxy_server_name},
    'help'                       => \$help,
  );
  if (!$parsed) {
    checked_print_stderr(_usage());
    return 1;
  }

  if ($help) {
    checked_print_stdout(_usage());
    return 0;
  }

  _validate_options(\%options);
  my $client = Overnet::Auth::Client->new(
    (
      defined($options{auth_sock})
      ? (endpoint => $options{auth_sock})
      : ()
    ),
  );

  _serve(\%options, $client);
  return 0;
}

sub _validate_options {
  my ($options) = @_;
  $options->{listen_port} = validate_port($options->{listen_port}, 'listen-port');
  $options->{server_port} = validate_port($options->{server_port}, 'server-port');
  if (!(defined $options->{listen_host} && length($options->{listen_host}))) {
    croak "--listen-host is required\n";
  }
  if (!(defined $options->{server_host} && length($options->{server_host}))) {
    croak "--server-host is required\n";
  }
  if (!(defined $options->{listen_backlog} && $options->{listen_backlog} =~ /\A[1-9]\d*\z/mxs)) {
    croak "--listen-backlog must be a positive integer\n";
  }
  return 1;
}

sub _serve {
  my ($options, $auth_client) = @_;
  my $listener = _open_listener($options);
  checked_print_stdout(
    sprintf(
      "Listening on %s:%s and proxying %s:%s\n",
      $options->{listen_host},
      $listener->sockport,
      $options->{server_host},
      $options->{server_port},
    )
  );

  while (1) {
    my $client_socket = $listener->accept
      or croak "Failed to accept IRC proxy client connection: $OS_ERROR\n";
    my $ok = eval {
      _serve_connection($options, $auth_client, $client_socket);
      1;
    };
    if (!$ok) {
      my $error = $EVAL_ERROR || "unknown IRC proxy connection failure\n";
      chomp $error;
      checked_print_stderr("connection failed: $error\n");
    }
  }
  return 1;
}

sub _open_listener {
  my ($options) = @_;
  my $listener = IO::Socket::INET->new(
    LocalAddr => $options->{listen_host},
    LocalPort => $options->{listen_port},
    Listen    => $options->{listen_backlog},
    Proto     => 'tcp',
    ReuseAddr => 1,
  ) or croak "Failed to listen on $options->{listen_host}:$options->{listen_port}: $OS_ERROR\n";

  binmode($listener, ':raw')
    or croak "binmode failed for IRC proxy listener: $OS_ERROR\n";
  $listener->autoflush(1);
  return $listener;
}

sub _serve_connection {
  my ($options, $auth_client, $client_socket) = @_;
  my $server_socket = _open_server_socket($options);
  _prepare_socket($client_socket, 'IRC proxy client socket');
  _prepare_socket($server_socket, 'IRC upstream server socket');

  my $session = Overnet::Program::IRC::Proxy->new(
    client                   => $auth_client,
    identity_id              => $options->{identity_id},
    program_id               => $options->{program_id},
    locator                  => $options->{locator},
    service_identity_scheme  => $options->{service_identity_scheme},
    service_identity_value   => $options->{service_identity_value},
    service_identity_display => $options->{service_identity_display},
    interactive              => $options->{interactive},
    auto_delegate            => $options->{auto_delegate},
    proxy_server_name        => $options->{proxy_server_name},
  );

  my %buffers = (
    client => q{},
    server => q{},
  );
  my $selector = IO::Select->new($client_socket, $server_socket);
  _write_lines($server_socket, @{$session->start->{to_server}});

  my $ok = eval {
    while (1) {
      my @ready = $selector->can_read(0.1);
      next if !@ready;

      for my $handle (@ready) {
        if (_same_handle($handle, $client_socket)) {
          return 1 if !_read_ready_lines(
            $handle,
            \$buffers{client},
            sub {
              my ($line) = @_;
              my $result = $session->client_line($line);
              _write_result($client_socket, $server_socket, $result);
            }
          );
          next;
        }

        return 1 if !_read_ready_lines(
          $handle,
          \$buffers{server},
          sub {
            my ($line) = @_;
            my $result = $session->server_line($line);
            _write_result($client_socket, $server_socket, $result);
          }
        );
      }
    }
  };
  my $error = $EVAL_ERROR;
  if (!$ok && defined($error) && length($error)) {
    chomp $error;
    _try_report_client_error($client_socket, $error);
  }

  _close_socket($server_socket, 'IRC upstream server socket');
  _close_socket($client_socket, 'IRC proxy client socket');
  croak $error if !$ok && defined($error) && length($error);
  return 1;
}

sub _open_server_socket {
  my ($options) = @_;
  my %base_args = (
    PeerHost => $options->{server_host},
    PeerPort => $options->{server_port},
    Timeout  => 5,
  );

  if (!$options->{server_tls}) {
    my $socket = IO::Socket::INET->new(%base_args, Proto => 'tcp');
    if (!$socket) {
      croak "Can't connect to $options->{server_host}:$options->{server_port}: $OS_ERROR\n";
    }
    return $socket;
  }

  my $socket = IO::Socket::SSL->new(%base_args, _server_tls_args($options));
  if (!$socket) {
    my $error = IO::Socket::SSL::errstr();
    croak "Can't connect TLS to $options->{server_host}:$options->{server_port}: $error\n";
  }
  return $socket;
}

sub _server_tls_args {
  my ($options) = @_;
  my @args = (
    SSL_verify_mode => $options->{server_tls_no_verify}
    ? SSL_VERIFY_NONE()
    : SSL_VERIFY_PEER(),
    SSL_hostname => _server_tls_hostname($options),
  );

  if (defined $options->{server_tls_ca_file} && length($options->{server_tls_ca_file})) {
    push @args, SSL_ca_file => $options->{server_tls_ca_file};
  }

  if (defined $options->{server_tls_min_version}) {
    push @args, SSL_version => _ssl_version_for_min_version($options->{server_tls_min_version});
  }

  return @args;
}

sub _server_tls_hostname {
  my ($options) = @_;
  if (defined $options->{server_tls_name} && length($options->{server_tls_name})) {
    return $options->{server_tls_name};
  }
  return $options->{server_host};
}

sub _ssl_version_for_min_version {
  my ($min_version) = @_;
  if ($min_version eq 'TLSv1.2') {
    return 'SSLv23:!SSLv3:!SSLv2:!TLSv1:!TLSv1_1';
  }
  if ($min_version eq 'TLSv1.3') {
    return 'TLSv1_3';
  }

  croak "Unsupported --server-tls-min-version: $min_version\n";
}

sub _prepare_socket {
  my ($socket, $description) = @_;
  binmode($socket, ':raw')
    or croak "binmode failed for $description: $OS_ERROR\n";
  $socket->autoflush(1);
  return 1;
}

sub _read_ready_lines {
  my ($handle, $buffer_ref, $callback) = @_;
  my $bytes = sysread($handle, my $chunk, 4_096);
  if (!(defined $bytes && $bytes > 0)) {
    return 0;
  }

  ${$buffer_ref} .= $chunk;
  while (${$buffer_ref} =~ s/\A([^\n]*\n)//mxs) {
    $callback->($1);
  }
  return 1;
}

sub _write_result {
  my ($client_socket, $server_socket, $result) = @_;
  _write_lines($server_socket, @{$result->{to_server} || []});
  _write_lines($client_socket, @{$result->{to_client} || []});
  return 1;
}

sub _write_lines {
  my ($handle, @lines) = @_;
  for my $line (@lines) {
    my $offset = 0;
    while ($offset < length $line) {
      my $written = syswrite($handle, $line, length($line) - $offset, $offset);
      if (!defined $written) {
        next if $OS_ERROR{EINTR};
        croak "Failed to write IRC proxy line: $OS_ERROR\n";
      }
      if ($written == 0) {
        croak "Failed to write IRC proxy line: wrote zero bytes\n";
      }
      $offset += $written;
    }
  }
  return 1;
}

sub _same_handle {
  my ($left_handle, $right_handle) = @_;
  return 0 if !defined fileno($left_handle);
  return 0 if !defined fileno($right_handle);
  return fileno($left_handle) == fileno($right_handle) ? 1 : 0;
}

sub _try_report_client_error {
  my ($client_socket, $error) = @_;
  my $reported = eval {
    _write_lines($client_socket, "ERROR :Overnet IRC proxy authentication failed: $error\r\n");
    1;
  };
  return $reported ? 1 : 0;
}

sub _close_socket {
  my ($socket, $description) = @_;
  return 1 if !defined $socket;
  close $socket
    or croak "close failed for $description: $OS_ERROR\n";
  return 1;
}

sub _usage {
  return <<'USAGE';
Usage:
  overnet-irc-server proxy [options]

Proxy options:
  --listen-host HOST          Local listen host (default: 127.0.0.1)
  --listen-port PORT          Local listen port (default: 16668)
  --server-host HOST          Upstream IRC server host (default: 127.0.0.1)
  --server-port PORT          Upstream IRC server port (default: 16667)
  --server-tls                Connect to the upstream server with TLS
  --server-tls-no-verify      Skip upstream TLS certificate verification
  --server-tls-ca-file PATH   Trust this CA bundle/file for upstream TLS
  --server-tls-name NAME      Expected upstream TLS server name
  --server-tls-min-version V  Upstream TLS minimum version (default: TLSv1.2)
  --proxy-server-name NAME    Server name used for local CAP replies

Auth-agent options:
  --auth-sock PATH
  --identity-id ID
  --program-id PROGRAM_ID     Auth-agent program id (default: irc.proxy)
  --locator LOCATOR
  --service-identity-scheme SCHEME
  --service-identity-value VALUE
  --service-identity-display DISPLAY
  --interactive / --no-interactive
  --auto-delegate / --no-auto-delegate

The proxy handles upstream SASL NOSTR authentication and optional relay
delegation behind the scenes. Point a normal IRC client at the local listen
address; the client does not need to run SASL NOSTR itself.
USAGE
}

1;

=head1 NAME

Overnet::Program::IRC::Script::Proxy - Local IRC proxy script runner

=head1 DESCRIPTION

Runs C<overnet-irc-server proxy>, a local line-oriented IRC proxy that performs
upstream SASL NOSTR authentication with the Overnet auth agent.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  Overnet::Program::IRC::Script::Proxy->run(@ARGV);

=head1 SUBROUTINES/METHODS

=head2 run

=head1 DIAGNOSTICS

Invalid command-line arguments, connection failures, and auth-agent failures
are reported through exceptions or stderr.

=head1 CONFIGURATION AND ENVIRONMENT

Configuration is supplied through command-line arguments.

=head1 DEPENDENCIES

See the distribution metadata for runtime dependencies.

=head1 INCOMPATIBILITIES

No known incompatibilities are documented.

=head1 BUGS AND LIMITATIONS

This script accepts local IRC clients and handles one connected client per
process loop iteration.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the project license.

=cut
