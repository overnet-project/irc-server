package Overnet::Program::IRC::Script::ChatClient;

use strictures 2;
use Moo;
use Carp         qw(croak);
use English      qw(-no_match_vars);
use Getopt::Long qw(GetOptionsFromArray);
use IO::Handle   ();
use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL qw(SSL_VERIFY_NONE SSL_VERIFY_PEER);
use Overnet::Program::IRC::Script::Util
  qw(checked_close checked_print checked_print_stderr checked_print_stdout validate_port);

our $VERSION = '0.001';

has options => (
  is      => 'ro',
  reader  => '_options',
  default => sub { {} },
);
has input => (
  is      => 'ro',
  reader  => '_input',
  default => sub { \*STDIN },
);
has output => (
  is      => 'ro',
  reader  => '_output',
  default => sub { \*STDOUT },
);
has error => (
  is      => 'ro',
  reader  => '_error',
  default => sub { \*STDERR },
);
has socket_buffer => (
  is      => 'rw',
  reader  => '_socket_buffer',
  writer  => '_set_socket_buffer',
  default => sub {q{}},
);
has done => (
  is      => 'rw',
  reader  => '_done',
  writer  => '_set_done',
  default => sub {0},
);
has registered => (
  is      => 'rw',
  reader  => '_registered',
  writer  => '_set_registered',
  default => sub {0},
);
has auto_join_sent => (
  is      => 'rw',
  reader  => '_auto_join_sent',
  writer  => '_set_auto_join_sent',
  default => sub {0},
);
has current_target => (
  is     => 'rw',
  reader => '_current_target',
  writer => '_set_current_target',
);
has socket => (
  is     => 'rw',
  reader => '_socket',
  writer => '_set_socket',
);
has selector => (
  is     => 'rw',
  reader => '_selector',
  writer => '_set_selector',
);

no Moo;

sub run {
  my ($class, @argv) = @_;

  my %options = (
    host            => '127.0.0.1',
    port            => 16_667,
    channel         => '#overnet',
    realname        => 'Overnet IRC Demo User',
    auto_join       => 1,
    tls             => 0,
    tls_min_version => 'TLSv1.2',
  );
  my $help = 0;

  my $parsed = GetOptionsFromArray(
    \@argv,
    'host=s'            => \$options{host},
    'port=i'            => \$options{port},
    'nick=s'            => \$options{nick},
    'username=s'        => \$options{username},
    'realname=s'        => \$options{realname},
    'channel=s'         => \$options{channel},
    'auto-join!'        => \$options{auto_join},
    'tls!'              => \$options{tls},
    'tls-no-verify!'    => \$options{tls_no_verify},
    'tls-ca-file=s'     => \$options{tls_ca_file},
    'tls-server-name=s' => \$options{tls_server_name},
    'tls-min-version=s' => \$options{tls_min_version},
    'help'              => \$help,
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
  if (!defined $options{username} || !length($options{username})) {
    $options{username} = $options{nick};
  }
  my $client = $class->new(
    options        => \%options,
    current_target => $options{channel},
  );
  $client->_connect;
  $client->_run;
  return 0;
}

sub _validate_options {
  my ($options) = @_;

  if (!(defined $options->{nick} && length($options->{nick}))) {
    croak "--nick is required\n";
  }

  $options->{port} = validate_port($options->{port}, '--port');
  return 1;
}

sub _connect {
  my ($self)  = @_;
  my $socket  = $self->_open_socket;
  my $input   = $self->{input};
  my $output  = $self->{output};
  my $options = $self->{options};

  binmode($socket, ':raw')
    or croak "binmode failed for IRC socket: $OS_ERROR\n";
  binmode($input, ':raw')
    or croak "binmode failed for input: $OS_ERROR\n";
  binmode($output, ':raw')
    or croak "binmode failed for output: $OS_ERROR\n";
  $socket->autoflush(1);
  $output->autoflush(1);

  $self->{socket}   = $socket;
  $self->{selector} = IO::Select->new($socket, $input);

  my $tls_suffix = $options->{tls} ? ' over TLS' : q{};
  checked_print($output, "Connected to $options->{host}:$options->{port}$tls_suffix as $options->{nick}\n");
  if ($options->{auto_join}) {
    checked_print($output, "Plain text sends to $self->{current_target}\n");
  }
  checked_print($output, "Type /help for commands.\n");

  $self->_send_line('CAP END');
  $self->_send_line('NICK ' . $options->{nick});
  $self->_send_line(sprintf('USER %s 0 * :%s', $options->{username}, $options->{realname}));
  return 1;
}

sub _open_socket {
  my ($self)    = @_;
  my $options   = $self->{options};
  my %base_args = (
    PeerHost => $options->{host},
    PeerPort => $options->{port},
    Timeout  => 3,
  );

  if (!$options->{tls}) {
    my $plain_socket = IO::Socket::INET->new(%base_args, Proto => 'tcp');
    if (!$plain_socket) {
      croak "Can't connect to $options->{host}:$options->{port}: $OS_ERROR\n";
    }
    return $plain_socket;
  }

  my $tls_socket = IO::Socket::SSL->new(%base_args, $self->_tls_socket_args);
  if (!$tls_socket) {
    my $error = IO::Socket::SSL::errstr();
    croak "Can't connect TLS to $options->{host}:$options->{port}: $error\n";
  }
  return $tls_socket;
}

sub _tls_socket_args {
  my ($self) = @_;
  my $options = $self->{options};

  my @args = (
    SSL_verify_mode => $options->{tls_no_verify}
    ? SSL_VERIFY_NONE()
    : SSL_VERIFY_PEER(),
    SSL_hostname => _tls_hostname($options),
  );

  if (defined $options->{tls_ca_file} && length($options->{tls_ca_file})) {
    push @args, (SSL_ca_file => $options->{tls_ca_file});
  }

  if (defined $options->{tls_min_version}) {
    push @args, (SSL_version => _ssl_version_for_min_version($options->{tls_min_version}));
  }

  return @args;
}

sub _tls_hostname {
  my ($options) = @_;
  if (defined $options->{tls_server_name}
    && length($options->{tls_server_name})) {
    return $options->{tls_server_name};
  }
  return $options->{host};
}

sub _run {
  my ($self) = @_;

  while (!$self->{done}) {
    my @ready = $self->{selector}->can_read(0.1);
    if (!@ready) {
      next;
    }

    for my $handle (@ready) {
      if ($self->_is_socket_handle($handle)) {
        $self->_read_socket;
      } else {
        $self->_read_input;
      }

      if ($self->{done}) {
        last;
      }
    }
  }

  checked_close($self->{socket}, 'IRC client socket');
  return 1;
}

sub _is_socket_handle {
  my ($self, $handle) = @_;
  if (!defined fileno($handle)) {
    return 0;
  }
  if (!defined fileno($self->{socket})) {
    return 0;
  }
  return fileno($handle) == fileno($self->{socket}) ? 1 : 0;
}

sub _read_socket {
  my ($self) = @_;

  my $bytes = sysread($self->{socket}, my $chunk, 4_096);
  if (!(defined $bytes && $bytes > 0)) {
    croak "Server disconnected\n";
  }

  $self->{socket_buffer} .= $chunk;
  while ($self->{socket_buffer} =~ s/\A([^\n]*\n)//mxs) {
    my $line = $1;
    $line =~ s/\r?\n\z//mxs;
    if (length($line)) {
      $self->_handle_server_line($line);
    }
    if ($self->{done}) {
      last;
    }
  }
  return 1;
}

sub _read_input {
  my ($self) = @_;

  my $input = readline($self->{input});
  if (!defined $input) {
    $self->_send_line('QUIT :stdin closed');
    $self->{done} = 1;
    return 1;
  }

  $input =~ s/\r?\n\z//mxs;
  if (!length($input)) {
    return 1;
  }

  my $handled = eval {
    $self->_handle_user_input($input);
    1;
  };
  if (!$handled) {
    my $error = $EVAL_ERROR || "unknown client input error\n";
    chomp $error;
    checked_print($self->{error}, "error: $error\n");
  }
  return 1;
}

sub _handle_server_line {
  my ($self, $line) = @_;

  if ($line =~ /\APING\ :(.*)\z/imxs) {
    $self->_send_line('PONG :' . $1);
    return 1;
  }

  if ($line =~ /\A:\S+\s+001\s+/mxs) {
    $self->{registered} = 1;
    $self->_send_auto_join;
  }

  checked_print($self->{output}, _format_server_line($line), "\n");
  return 1;
}

sub _send_auto_join {
  my ($self)   = @_;
  my $options  = $self->{options};
  my $can_join = $options->{auto_join} && !$self->{auto_join_sent};
  my $has_target =
    defined $options->{channel} && length($options->{channel});

  if ($can_join && $has_target) {
    $self->_send_line('JOIN ' . $options->{channel});
    $self->{auto_join_sent} = 1;
  }
  return 1;
}

sub _handle_user_input {
  my ($self, $input) = @_;

  if ($input eq '/help') {
    checked_print($self->{output}, _help_text());
    return 1;
  }

  if ($self->_handle_target_command($input)) {
    return 1;
  }
  if ($self->_handle_channel_command($input)) {
    return 1;
  }
  if ($self->_handle_session_command($input)) {
    return 1;
  }

  if (!(defined $self->{current_target} && length($self->{current_target}))) {
    croak "No current target. Use /join, /msg, or /target first.\n";
  }

  $self->_send_line(sprintf('PRIVMSG %s :%s', $self->{current_target}, $input));
  return 1;
}

sub _handle_target_command {
  my ($self, $input) = @_;

  if ($input =~ m{\A/join\s+(\S+)\z}mxs) {
    $self->{current_target} = $1;
    $self->_send_line('JOIN ' . $1);
    return 1;
  }

  if ($input =~ m{\A/target\s+(\S+)\z}mxs) {
    $self->{current_target} = $1;
    checked_print($self->{output}, "Current target set to $1\n");
    return 1;
  }

  if ($input =~ m{\A/msg\s+(\S+)\s+(.+)\z}mxs) {
    $self->_send_line(sprintf('PRIVMSG %s :%s', $1, $2));
    return 1;
  }

  if ($input =~ m{\A/notice\s+(\S+)\s+(.+)\z}mxs) {
    $self->_send_line(sprintf('NOTICE %s :%s', $1, $2));
    return 1;
  }

  if ($input =~ m{\A/topic\s+(\S+)\s+(.+)\z}mxs) {
    $self->_send_line(sprintf('TOPIC %s :%s', $1, $2));
    return 1;
  }

  return 0;
}

sub _handle_channel_command {
  my ($self, $input) = @_;

  if ($input =~ m{\A/names(?:\s+(\S+))?\z}mxs) {
    my $target = defined $1 ? $1 : $self->{current_target};
    if (!(defined $target && length($target))) {
      croak "No current target for /names\n";
    }
    $self->_send_line('NAMES ' . $target);
    return 1;
  }

  if ($input =~ m{\A/part(?:\s+(\S+))?(?:\s+(.+))?\z}mxs) {
    my $target = defined $1 ? $1 : $self->{current_target};
    if (!(defined $target && length($target))) {
      croak "No current target for /part\n";
    }
    my $line = 'PART ' . $target;
    if (defined $2 && length($2)) {
      $line .= ' :' . $2;
    }
    $self->_send_line($line);
    return 1;
  }

  return 0;
}

sub _handle_session_command {
  my ($self, $input) = @_;

  if ($input =~ m{\A/nick\s+(\S+)\z}mxs) {
    $self->_send_line('NICK ' . $1);
    return 1;
  }

  if ($input =~ m{\A/raw\s+(.+)\z}mxs) {
    $self->_send_line($1);
    return 1;
  }

  if ($input =~ m{\A/quit(?:\s+(.+))?\z}mxs) {
    my $reason = defined $1 ? $1 : 'client quit';
    $self->_send_line('QUIT :' . $reason);
    $self->{done} = 1;
    return 1;
  }

  return 0;
}

sub _format_server_line {
  my ($line) = @_;

  if ($line =~ /\A:([^ ]+)\s+PRIVMSG\s+(\S+)\s+:(.*)\z/mxs) {
    return sprintf('<%s -> %s> %s', $1, $2, $3);
  }

  if ($line =~ /\A:([^ ]+)\s+NOTICE\s+(\S+)\s+:(.*)\z/mxs) {
    return sprintf('-%s -> %s- %s', $1, $2, $3);
  }

  if ($line =~ /\A:([^ ]+)\s+JOIN\s+(\S+)\z/mxs) {
    return sprintf('* %s joined %s', $1, $2);
  }

  if ($line =~ /\A:([^ ]+)\s+PART\s+(\S+)(?:\s+:(.*))?\z/mxs) {
    return defined $3 && length($3)
      ? sprintf('* %s left %s (%s)', $1, $2, $3)
      : sprintf('* %s left %s', $1, $2);
  }

  if ($line =~ /\A:([^ ]+)\s+QUIT(?:\s+:(.*))?\z/mxs) {
    return defined $2 && length($2)
      ? sprintf('* %s quit (%s)', $1, $2)
      : sprintf('* %s quit', $1);
  }

  if ($line =~ /\A:([^ ]+)\s+TOPIC\s+(\S+)\s+:(.*)\z/mxs) {
    return sprintf('* %s changed the topic on %s to: %s', $1, $2, $3);
  }

  if ($line =~ /\A:\S+\s+353\s+\S+\s+=\s+(\S+)\s+:(.*)\z/mxs) {
    return sprintf('* names for %s: %s', $1, $2);
  }

  return $line;
}

sub _send_line {
  my ($self, $line) = @_;

  my $payload = $line . "\r\n";
  my $offset  = 0;
  while ($offset < length $payload) {
    my $written = syswrite($self->{socket}, $payload, length($payload) - $offset, $offset);
    if (!defined $written) {
      next if $OS_ERROR{EINTR};
      croak "Failed to write IRC line: $OS_ERROR\n";
    }
    if ($written == 0) {
      croak "Failed to write IRC line: wrote zero bytes\n";
    }
    $offset += $written;
  }

  return 1;
}

sub _help_text {
  return <<'HELP';
Commands:
  /help                     Show this help
  /join #channel            Join a channel and make it the current target
  /target <target>          Set the current target for plain text
  /msg <target> <text>      Send a direct message or channel message
  /notice <target> <text>   Send a notice
  /topic <channel> <text>   Set the topic on a joined channel
  /names [channel]          Ask the server for the current names list
  /part [channel] [reason]  Leave a channel
  /nick <newnick>           Change your nick
  /raw <line>               Send a raw IRC line
  /quit [reason]            Quit the client

Plain text sends a PRIVMSG to the current target.
HELP
}

sub _usage {
  return <<'USAGE';
Usage:
  perl irc-server/bin/overnet-irc-server chat-client --nick NICK [options]

Options:
  --host HOST        IRC server host (default: 127.0.0.1)
  --port PORT        IRC server port (default: 16667)
  --nick NICK        Nickname to register with
  --username NAME    IRC USER field (default: same as nick)
  --realname NAME    IRC realname field (default: Overnet IRC Demo User)
  --channel NAME     Auto-join this channel after 001 (default: #overnet)
  --auto-join        Auto-join the initial channel (default)
  --no-auto-join     Do not auto-join on connect
  --tls              Connect to the IRC server over TLS
  --tls-no-verify    Skip TLS certificate verification for local self-signed demos
  --tls-ca-file PATH Trust this CA bundle/file for TLS verification
  --tls-server-name NAME
                     Expected server name for TLS hostname verification
  --tls-min-version NAME
                     TLS minimum version (default: TLSv1.2)
  --help             Show this message
USAGE
}

sub _ssl_version_for_min_version {
  my ($min_version) = @_;

  if ($min_version eq 'TLSv1.2') {
    return 'SSLv23:!SSLv3:!SSLv2:!TLSv1:!TLSv1_1';
  }
  if ($min_version eq 'TLSv1.3') {
    return 'TLSv1_3';
  }

  croak "Unsupported --tls-min-version: $min_version\n";
}

1;

=head1 NAME

Overnet::Program::IRC::Script::ChatClient - IRC demo chat client script runner

=head1 DESCRIPTION

Runs the C<overnet-irc-server chat-client> command-line demo client.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  Overnet::Program::IRC::Script::ChatClient->run(@ARGV);

=head1 SUBROUTINES/METHODS

=head2 run

=head1 DIAGNOSTICS

Invalid arguments, connection failures, and IO failures are reported through exceptions.

=head1 CONFIGURATION AND ENVIRONMENT

Configuration is supplied through command-line arguments.

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
