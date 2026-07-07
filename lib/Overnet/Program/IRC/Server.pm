package Overnet::Program::IRC::Server;

use strictures 2;
use Moo;
use Carp        qw(croak);
use Digest::SHA qw(sha256_hex hmac_sha256_hex);
use Encode      qw(encode);
use English     qw(-no_match_vars);
use IO::Handle;
use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL ();
use JSON            ();
use MIME::Base64    qw(decode_base64 encode_base64);
use Overnet::Authority::HostedChannel;
use Overnet::Core::Nostr;
use Overnet::Program::IRC::Authority::Coordinator;
use Overnet::Program::IRC::Command::Auth;
use Overnet::Program::IRC::Command::Channel;
use Overnet::Program::IRC::Renderer;
use Time::HiRes qw(time);
use Overnet::Program::Protocol;
use Overnet::Program::TLSConfig;

our $VERSION = '0.001';
my $E2EE_DM_BODY_PREFIX     = '+overnet-e2ee-v1 ';
my %SERVER_CONSTRUCTOR_ARGS = map { $_ => 1 } qw(protocol program_id program_version supported_protocol_versions);

has protocol => (
  is      => 'ro',
  reader  => '_protocol',
  default => sub { Overnet::Program::Protocol->new },
);
has program_id => (
  is      => 'ro',
  reader  => '_program_id',
  default => sub {'overnet.program.irc_server'},
);
has program_version => (
  is      => 'ro',
  reader  => '_program_version',
  default => sub {$VERSION},
);
has supported_protocol_versions => (
  is      => 'ro',
  reader  => '_supported_protocol_versions',
  default => sub { ['0.1'] },
);
has next_request_id => (
  is      => 'rw',
  reader  => '_next_request_id',
  writer  => '_set_next_request_id',
  default => sub {1},
);
has pending_messages => (
  is      => 'rw',
  reader  => '_pending_messages',
  writer  => '_set_pending_messages',
  default => sub { [] },
);
has next_client_id => (
  is      => 'rw',
  reader  => '_next_client_id',
  writer  => '_set_next_client_id',
  default => sub {1},
);
has clients => (
  is      => 'rw',
  reader  => '_clients',
  writer  => '_set_clients',
  default => sub { {} },
);
has channels => (
  is      => 'rw',
  reader  => '_channels',
  writer  => '_set_channels',
  default => sub { {} },
);
has nick_to_client_id => (
  is      => 'rw',
  reader  => '_nick_to_client_id',
  writer  => '_set_nick_to_client_id',
  default => sub { {} },
);
has suppress_subscription_event_ids => (
  is      => 'rw',
  reader  => '_suppress_subscription_event_ids',
  writer  => '_set_suppress_subscription_event_ids',
  default => sub { {} },
);
has subscription_event_origin_client_ids => (
  is      => 'rw',
  reader  => '_subscription_event_origin_client_ids',
  writer  => '_set_subscription_event_origin_client_ids',
  default => sub { {} },
);
has rendered_subscription_event_ids => (
  is      => 'rw',
  reader  => '_rendered_subscription_event_ids',
  writer  => '_set_rendered_subscription_event_ids',
  default => sub { {} },
);
has rendered_subscription_event_id_order => (
  is      => 'rw',
  reader  => '_rendered_subscription_event_id_order',
  writer  => '_set_rendered_subscription_event_id_order',
  default => sub { [] },
);
has authoritative_last_created_at => (
  is      => 'rw',
  reader  => '_authoritative_last_created_at',
  writer  => '_set_authoritative_last_created_at',
  default => sub { {} },
);
has authoritative_delegate_sequences => (
  is      => 'rw',
  reader  => '_authoritative_delegate_sequences',
  writer  => '_set_authoritative_delegate_sequences',
  default => sub { {} },
);
has authoritative_subscription_channels => (
  is      => 'rw',
  reader  => '_authoritative_subscription_channels',
  writer  => '_set_authoritative_subscription_channels',
  default => sub { {} },
);
has authoritative_discovered_channels => (
  is      => 'rw',
  reader  => '_authoritative_discovered_channels',
  writer  => '_set_authoritative_discovered_channels',
  default => sub { {} },
);
has authoritative_grant_subscription_id => (
  is     => 'rw',
  reader => '_stored_authoritative_grant_subscription_id',
  writer => '_set_authoritative_grant_subscription_id',
);
has authoritative_discovery_subscription_id => (
  is     => 'rw',
  reader => '_stored_authoritative_discovery_subscription_id',
  writer => '_set_authoritative_discovery_subscription_id',
);
has inputs_processed => (
  is      => 'rw',
  reader  => '_inputs_processed',
  writer  => '_set_inputs_processed',
  default => sub {0},
);
has events_emitted => (
  is      => 'rw',
  reader  => '_events_emitted',
  writer  => '_set_events_emitted',
  default => sub {0},
);
has state_emitted => (
  is      => 'rw',
  reader  => '_state_emitted',
  writer  => '_set_state_emitted',
  default => sub {0},
);
has private_messages_emitted => (
  is      => 'rw',
  reader  => '_private_messages_emitted',
  writer  => '_set_private_messages_emitted',
  default => sub {0},
);
has capabilities_emitted => (
  is      => 'rw',
  reader  => '_capabilities_emitted',
  writer  => '_set_capabilities_emitted',
  default => sub {0},
);

no Moo;

sub BUILDARGS {
  my ($class, @args) = @_;
  my %args = _constructor_args_hash(@args);

  my %constructor_args = _server_constructor_args(%args);
  if ($class ne __PACKAGE__) {
    _copy_subclass_constructor_args(\%args, \%constructor_args);
  }

  return \%constructor_args;
}

sub _constructor_args_hash {
  my (@args) = @_;
  return %{$args[0]} if @args == 1 && ref($args[0]) eq 'HASH';
  return @args       if @args % 2 == 0;
  die "constructor arguments must be a hash or hash reference\n";
}

sub _server_constructor_args {
  my (%args) = @_;

  my $protocol                    = _constructor_protocol(%args);
  my $program_id                  = _constructor_program_id(%args);
  my $program_version             = _constructor_program_version(%args);
  my $supported_protocol_versions = _constructor_supported_protocol_versions(%args);

  return (
    protocol                    => $protocol,
    program_id                  => $program_id,
    program_version             => $program_version,
    supported_protocol_versions => $supported_protocol_versions,
  );
}

sub _constructor_protocol {
  my (%args) = @_;

  my $protocol = $args{protocol} || Overnet::Program::Protocol->new;

  if (!(ref($protocol) && $protocol->isa('Overnet::Program::Protocol'))) {
    croak "protocol must be an Overnet::Program::Protocol instance\n";
  }

  return $protocol;
}

sub _constructor_program_id {
  my (%args) = @_;

  my $program_id = $args{program_id} || 'overnet.program.irc_server';

  if (!(defined $program_id && !ref($program_id) && length($program_id))) {
    croak "program_id is required\n";
  }

  return $program_id;
}

sub _constructor_program_version {
  my (%args) = @_;

  my $program_version = exists $args{program_version} ? $args{program_version} : $VERSION;

  croak "program_version must be a non-empty string\n"
    if defined $program_version && (ref($program_version) || !length($program_version));

  return $program_version;
}

sub _constructor_supported_protocol_versions {
  my (%args) = @_;

  my $supported_protocol_versions = $args{supported_protocol_versions} || ['0.1'];

  if (!_supported_protocol_versions_are_valid($supported_protocol_versions)) {
    croak "supported_protocol_versions must be a non-empty array of strings\n";
  }

  return [@{$supported_protocol_versions}];
}

sub _supported_protocol_versions_are_valid {
  my ($supported_protocol_versions) = @_;

  return 0 if ref($supported_protocol_versions) ne 'ARRAY';
  return 0 if !@{$supported_protocol_versions};

  for my $version (@{$supported_protocol_versions}) {
    return 0 if !defined($version) || ref($version) || !length($version);
  }

  return 1;
}

sub _copy_subclass_constructor_args {
  my ($source_args, $constructor_args) = @_;

  for my $name (keys %{$source_args}) {
    next if $SERVER_CONSTRUCTOR_ARGS{$name};
    $constructor_args->{$name} = $source_args->{$name};
  }

  return 1;
}

sub _is_shutdown_sentinel_error {
  my ($error) = @_;
  if (!(defined $error && !ref($error))) {
    return 0;
  }

  return $error =~ /\A__shutdown__(?:\s+at\b.*)?\z/smx ? 1 : 0;
}

sub run {
  my ($self) = @_;

  binmode(STDIN,  ':raw');
  binmode(STDOUT, ':raw');
  binmode(STDERR, ':raw');
  STDOUT->autoflush(1);
  STDERR->autoflush(1);
  local $SIG{PIPE} = 'IGNORE';

  $self->_send_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => $self->{program_id},
      supported_protocol_versions => $self->{supported_protocol_versions},
      (
        defined $self->{program_version}
        ? (program_version => $self->{program_version})
        : ()
      ),
    )
  );

  while (!$self->{initialized} && !$self->{shutdown_complete}) {
    my $message = $self->_next_runtime_message;

    if ( ($message->{type} || q{}) eq 'request'
      && ($message->{method} || q{}) eq 'runtime.init') {
      $self->_handle_runtime_init($message);
      next;
    }

    if ( ($message->{type} || q{}) eq 'request'
      && ($message->{method} || q{}) eq 'runtime.shutdown') {
      $self->_handle_runtime_shutdown($message);
      next;
    }

    if ( ($message->{type} || q{}) eq 'notification'
      && ($message->{method} || q{}) eq 'runtime.fatal') {
      croak "runtime fatal: " . ($message->{params}{code} || 'unknown') . "\n";
    }

    croak "Unexpected message before runtime.init\n";
  }

  return 1 if $self->{shutdown_complete};

  my $ok = eval {
    $self->_run_server_loop;
    1;
  };
  my $error = $EVAL_ERROR;
  croak $error if !$ok && !_is_shutdown_sentinel_error($error);
  return 1;
}

sub _handle_runtime_init {
  my ($self, $message) = @_;
  my $params = $message->{params} || {};

  my $loaded = eval {
    $self->_load_runtime_init($params);
    $self->_open_listen_socket;
    1;
  };
  if (!$loaded) {
    my $error = $EVAL_ERROR || "Invalid runtime.init configuration\n";
    chomp $error;
    $self->_send_message(
      Overnet::Program::Protocol::build_response_error(
        id      => $message->{id},
        code    => 'program.operation_failed',
        message => $error,
      )
    );
    $self->_close_all_clients;
    $self->_close_listen_socket;
    return;
  }

  $self->_send_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $message->{id},
    )
  );

  $self->_send_message(Overnet::Program::Protocol::build_program_ready());

  my $opened = eval {
    $self->_open_adapter_session;
    $self->_ensure_authoritative_discovery_subscription;
    $self->_refresh_authoritative_discovery_cache;
    1;
  };
  if (!$opened) {
    my $error = $EVAL_ERROR || "Failed to open IRC adapter session\n";
    chomp $error;
    return if _is_shutdown_sentinel_error($error);
    $self->_health(
      status  => 'failed',
      message => $error,
    );
    croak "$error\n";
  }

  $self->_log(
    level   => 'info',
    message => 'runtime.init accepted',
    context => {
      instance_id => $self->{instance_id},
      adapter_id  => $self->{config}{adapter_id},
      network     => $self->{config}{network},
      listen_host => $self->{config}{listen_host},
      listen_port => $self->{config}{listen_port},
      server_name => $self->{config}{server_name},
    },
  );
  $self->_health(
    status  => 'ready',
    message => 'IRC server listening',
    details => {
      network           => $self->{config}{network},
      listen_host       => $self->{config}{listen_host},
      listen_port       => $self->{config}{listen_port},
      server_name       => $self->{config}{server_name},
      clients_connected => 0,
      joined_channels   => [],
      inputs_processed  => 0,
      events_emitted    => 0,
      state_emitted     => 0,
    },
  );
  $self->{initialized} = 1;
  return;
}

sub _handle_runtime_shutdown {
  my ($self, $message) = @_;
  $self->_send_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $message->{id},
    )
  );
  $self->{shutdown_complete} = 1;
  return;
}

sub _load_runtime_init {
  my ($self, $params) = @_;

  _validate_runtime_instance_id($params);
  my $config      = _normalized_runtime_config($params->{config});
  my $signing_key = Overnet::Core::Nostr->load_key(privkey => $config->{signing_key_file});

  $self->{instance_id}     = $params->{instance_id};
  $self->{config}          = $config;
  $self->{signing_key}     = $signing_key;
  $self->{tls_server_args} = _tls_server_args_for_config($config);

  return 1;
}

sub _validate_runtime_instance_id {
  my ($params) = @_;
  if (!_nonempty_scalar($params->{instance_id})) {
    croak "runtime.init params.instance_id is required\n";
  }
  return 1;
}

sub _normalized_runtime_config {
  my ($raw_config) = @_;
  if (!(ref($raw_config) eq 'HASH')) {
    croak "runtime.init params.config must be an object\n";
  }

  my $config = {
    adapter_id       => $raw_config->{adapter_id},
    network          => $raw_config->{network},
    listen_host      => _config_value($raw_config, 'listen_host',    '127.0.0.1'),
    listen_port      => _config_value($raw_config, 'listen_port',    6667),
    listen_backlog   => _config_value($raw_config, 'listen_backlog', 10),
    server_name      => _config_value($raw_config, 'server_name',    'overnet.irc.local'),
    signing_key_file => $raw_config->{signing_key_file},
    cloak_secret     => $raw_config->{cloak_secret},
    adapter_config   => _normalized_runtime_adapter_config($raw_config),
  };
  _validate_normalized_runtime_config($config);

  my $authority_relay = _normalized_runtime_authority_relay($raw_config);
  if (defined $authority_relay) {
    $config->{authority_relay} = $authority_relay;
  }

  my $tls = _normalized_runtime_tls($raw_config);
  if (defined $tls) {
    $config->{tls} = $tls;
  }

  return $config;
}

sub _config_value {
  my ($config, $key, $default) = @_;
  if (exists $config->{$key}) {
    return $config->{$key};
  }
  return $default;
}

sub _normalized_runtime_adapter_config {
  my ($raw_config) = @_;
  my $adapter_config = _config_value($raw_config, 'adapter_config', {});
  if (!(ref($adapter_config) eq 'HASH')) {
    croak "config.adapter_config must be an object\n";
  }
  return {%{$adapter_config}};
}

sub _validate_normalized_runtime_config {
  my ($config) = @_;
  croak "config.adapter_id is required\n"
    if !_nonempty_scalar($config->{adapter_id});
  croak "config.network is required\n"
    if !_nonempty_scalar($config->{network});
  croak "config.listen_host is required\n"
    if !_nonempty_scalar($config->{listen_host});
  croak "config.server_name is required\n"
    if !_nonempty_scalar($config->{server_name});
  croak "config.signing_key_file is required\n"
    if !_nonempty_scalar($config->{signing_key_file});
  croak "config.listen_port must be an integer between 0 and 65_535\n"
    if !_port_integer($config->{listen_port});
  croak "config.listen_backlog must be a positive integer\n"
    if !_positive_integer($config->{listen_backlog});
  $config->{listen_port}    = 0 + $config->{listen_port};
  $config->{listen_backlog} = 0 + $config->{listen_backlog};
  return 1;
}

sub _normalized_runtime_authority_relay {
  my ($raw_config) = @_;
  if (!(exists $raw_config->{authority_relay})) {
    return;
  }

  my $authority_relay = $raw_config->{authority_relay};
  if (!(defined $authority_relay)) {
    return;
  }

  _validate_runtime_authority_relay($authority_relay);
  return {
    url              => $authority_relay->{url},
    poll_interval_ms => _numeric_config_value($authority_relay, 'poll_interval_ms', 250),
    query_timeout_ms => _numeric_config_value($authority_relay, 'query_timeout_ms', 1_000),
  };
}

sub _validate_runtime_authority_relay {
  my ($authority_relay) = @_;
  if (!(ref($authority_relay) eq 'HASH')) {
    croak "config.authority_relay must be an object\n";
  }
  if (!_nonempty_scalar($authority_relay->{url})) {
    croak "config.authority_relay.url is required\n";
  }
  _validate_optional_positive_integer($authority_relay, 'poll_interval_ms', 'config.authority_relay.poll_interval_ms');
  _validate_optional_positive_integer($authority_relay, 'query_timeout_ms', 'config.authority_relay.query_timeout_ms');
  return 1;
}

sub _validate_optional_positive_integer {
  my ($config, $key, $label) = @_;
  if (!(exists $config->{$key})) {
    return 1;
  }
  if (!_positive_integer($config->{$key})) {
    croak "$label must be a positive integer\n";
  }
  return 1;
}

sub _numeric_config_value {
  my ($config, $key, $default) = @_;
  return 0 + _config_value($config, $key, $default);
}

sub _normalized_runtime_tls {
  my ($raw_config) = @_;
  if (!(exists $raw_config->{tls})) {
    return;
  }
  return Overnet::Program::TLSConfig->normalize(
    tls           => $raw_config->{tls},
    implicit_mode => 'server',
  );
}

sub _tls_server_args_for_config {
  my ($config) = @_;
  if (!(defined $config->{tls})) {
    return;
  }
  return Overnet::Program::TLSConfig->server_start_args($config->{tls});
}

sub _nonempty_scalar {
  my ($value) = @_;
  return 0 if !defined $value;
  return 0 if ref($value);
  return length($value) ? 1 : 0;
}

sub _positive_integer {
  my ($value) = @_;
  return 0 if !defined $value;
  return 0 if ref($value);
  return $value =~ /\A[1-9]\d*\z/mxs ? 1 : 0;
}

sub _port_integer {
  my ($value) = @_;
  return 0 if !defined $value;
  return 0 if ref($value);
  return 0 if $value !~ /\A(?:0|[1-9]\d{0,4})\z/mxs;
  return $value <= 65_535 ? 1 : 0;
}

sub _open_listen_socket {
  my ($self) = @_;

  my $listener = IO::Socket::INET->new(
    LocalAddr => $self->{config}{listen_host},
    LocalPort => $self->{config}{listen_port},
    Listen    => $self->{config}{listen_backlog},
    Proto     => 'tcp',
    ReuseAddr => 1,
  ) or croak "Failed to listen on $self->{config}{listen_host}:$self->{config}{listen_port}: $OS_ERROR\n";

  binmode($listener, ':raw');
  $listener->autoflush(1);

  $self->{listener_socket} = $listener;
  $self->{config}{listen_port} = $listener->sockport;
  return 1;
}

sub _open_adapter_session {
  my ($self) = @_;

  my $open = $self->_request(
    method => 'adapters.open_session',
    params => {
      adapter_id => $self->{config}{adapter_id},
      config     => $self->{config}{adapter_config},
    },
  );
  $self->{adapter_session_id} = $open->{adapter_session_id};
  return $self->{adapter_session_id};
}

sub _run_server_loop {
  my ($self) = @_;

  my $ok = eval {
    while (!$self->{shutdown_complete}) {
      my $drained = $self->_drain_pending_runtime_messages(max_messages => 8);
      last if $self->{shutdown_complete};

      my @handles = (\*STDIN);
      if (defined $self->{listener_socket}) {
        push @handles, $self->{listener_socket};
      }
      push @handles, map { $self->{clients}{$_}{socket} }
        sort keys %{$self->{clients}};

      my $selector = IO::Select->new(@handles);
      my @ready    = $selector->can_read(0.1);
      if (!@ready) {
        $self->_maybe_poll_authoritative_relay;
        last if $self->{shutdown_complete};
        next;
      }

      for my $handle (@ready) {
        if ($self->_is_listener_socket($handle)) {
          $self->_accept_client;
          next;
        }

        if ($self->_is_runtime_stdin($handle)) {
          $self->_read_runtime_chunk;
          $self->_drain_pending_runtime_messages(max_messages => 8);
          last if $self->{shutdown_complete};
          next;
        }

        my $client_id = $self->_client_id_for_handle($handle);
        if (!(defined $client_id)) {
          next;
        }

        $self->_pump_client_socket($client_id);
        last if $self->{shutdown_complete};
      }
    }
    1;
  };
  my $error = $EVAL_ERROR;

  $self->_close_all_clients;
  $self->_close_listen_socket;
  croak $error if !$ok && !_is_shutdown_sentinel_error($error);
  return 1;
}

sub _accept_client {
  my ($self) = @_;
  if (!(defined $self->{listener_socket})) {
    return 1;
  }

  my $socket = $self->{listener_socket}->accept
    or croak "Failed to accept IRC client connection: $OS_ERROR\n";

  binmode($socket, ':raw');
  $socket->autoflush(1);

  if (defined $self->{tls_server_args}) {
    my $upgraded = eval {
      IO::Socket::SSL->start_SSL($socket, %{$self->{tls_server_args}},)
        or croak(IO::Socket::SSL::errstr() || "unknown TLS handshake failure");
    };
    if (!$upgraded) {
      my $error = $EVAL_ERROR || "unknown TLS handshake failure";
      chomp $error;
      $self->_log(
        level   => 'warn',
        message => 'TLS handshake failed for IRC client connection',
        context => {
          error => $error,
        },
      );
      $self->_close_socket($socket);
      return 1;
    }
    $socket = $upgraded;
  }

  my $client_id = 'client-' . $self->{next_client_id}++;
  $self->{clients}{$client_id} = {
    id                     => $client_id,
    socket                 => $socket,
    read_buffer            => q{},
    registered             => 0,
    cap_negotiation_active => 0,
    capabilities           => {},
    nick                   => undef,
    username               => undef,
    realname               => undef,
    dm_key                 => undef,
    e2ee_pubkey            => undef,
    authority_pubkey       => undef,
    authority_challenge    => undef,
    sasl_mechanism         => undef,
    sasl_buffer            => q{},
    sasl_challenge_payload => undef,
    joined_channels        => {},
    peerhost               => eval { $socket->peerhost } || q{},
    peerport               => eval { $socket->peerport } || 0,
  };

  return 1;
}

sub _pump_client_socket {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 1;

  my $bytes = sysread($client->{socket}, my $chunk, 4096);
  if (!defined $bytes) {
    if (!($OS_ERROR{EINTR})) {
      croak "Failed to read IRC client socket: $OS_ERROR\n";
    }

    return 1;
  }

  if ($bytes == 0) {
    $self->_disconnect_client(
      $client_id,
      emit_quit => 0,
      reason    => 'client disconnected',
    );
    return 1;
  }

  my $probe_buffer = $client->{read_buffer} . $chunk;
  if (!defined $self->{tls_server_args}
    && $self->_looks_like_tls_client_hello($probe_buffer)) {
    $self->_log(
      level   => 'warn',
      message => 'TLS client hello received on plain IRC listener',
      context => {
        client_id => $client_id,
        peerhost  => $client->{peerhost},
        peerport  => $client->{peerport},
      },
    );
    $self->_disconnect_client(
      $client_id,
      emit_quit => 0,
      reason    => 'tls client hello on plain listener',
    );
    return 1;
  }

  $client->{read_buffer} = $probe_buffer;
  while ($client->{read_buffer} =~ s/\A([^\n]*\n)//mxs) {
    my $line = $1;
    $line =~ s/\r?\n\z//mxs;
    if (!(length $line)) {
      next;
    }

    $self->_handle_client_line($client_id, $line);
    if (!(exists $self->{clients}{$client_id})) {
      last;
    }

    last if $self->{shutdown_complete};
  }

  return 1;
}

sub _looks_like_tls_client_hello {
  my ($self, $buffer) = @_;
  if (!(defined $buffer)) {
    return 0;
  }

  if (!(length($buffer) >= 3)) {
    return 0;
  }

  my ($content_type, $major, $minor) =
    unpack('C3', substr($buffer, 0, 3));
  if (!($content_type == 0x16)) {
    return 0;
  }

  if (!($major == 0x03)) {
    return 0;
  }

  if (!($minor >= 0x00 && $minor <= 0x04)) {
    return 0;
  }

  return 1;
}

sub _handle_client_line {
  my ($self, $client_id, $line) = @_;
  my $client = $self->{clients}{$client_id}
    or return 1;
  my $message = $self->_parse_irc_message($line);
  if (!($message)) {
    return 1;
  }

  my $command = $message->{command};
  my @params  = @{$message->{params} || []};

  my $connection_result = $self->_handle_connection_command($client_id, $client, $command, \@params);
  if (defined $connection_result) {
    return $connection_result;
  }

  if (!$client->{registered}) {
    return $self->_handle_unregistered_command($client_id, $command);
  }

  return $self->_handle_registered_command($client_id, $client, $command, \@params);
}

my %CONNECTION_COMMAND_HANDLERS = (
  CAP => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Auth::handle_cap($self, $client_id, $params,);
  },
  NICK => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return $self->_handle_nick_command($client_id, $client, $params);
  },
  USER => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return $self->_handle_user_command($client_id, $client, $params);
  },
  PING => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return $self->_handle_ping_command($client_id, $params);
  },
  AUTHENTICATE => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Auth::handle_authenticate($self, $client_id, $params,);
  },
  QUIT => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return $self->_handle_quit_command($client_id, $params);
  },
);

sub _handle_connection_command {
  my ($self, $client_id, $client, $command, $params) = @_;

  my $handler = $CONNECTION_COMMAND_HANDLERS{$command};
  if (!(defined $handler)) {
    return;
  }
  return $handler->($self, $client_id, $client, $command, $params);
}

sub _handle_nick_command {
  my ($self, $client_id, $client, $params) = @_;
  if (!@{$params} || !defined $params->[0] || !length $params->[0]) {
    $self->_send_nonickname_given($client_id);
    return 1;
  }
  my $requested_nick = $params->[0];

  if ($client->{registered}) {
    return $self->_handle_registered_nick_command($client_id, $client, $requested_nick);
  }

  return $self->_handle_unregistered_nick_command($client_id, $client, $requested_nick);
}

sub _handle_registered_nick_command {
  my ($self, $client_id, $client, $new_nick) = @_;
  my $old_nick = $client->{nick};
  if (defined $old_nick && $old_nick eq $new_nick) {
    return 1;
  }

  if ($self->_nick_in_use($new_nick, exclude_client_id => $client_id)) {
    $self->_send_nick_in_use($client_id, $new_nick);
    return 1;
  }

  my @shared_client_ids = $self->_shared_client_ids_for_client($client_id);
  $self->_send_line_to_client_ids(\@shared_client_ids, sprintf(':%s NICK :%s', $old_nick, $new_nick),);
  $self->_rename_client_channels(
    $client,
    old_nick => $old_nick,
    new_nick => $new_nick,
  );
  $self->_assign_client_nick($client_id, $new_nick);
  $self->_ensure_client_dm_subscription($client_id);
  $self->_emit_nick_change_input($client, $old_nick, $new_nick);
  return 1;
}

sub _emit_nick_change_input {
  my ($self, $client, $old_nick, $new_nick) = @_;
  if (!(defined $old_nick && length $old_nick)) {
    return 1;
  }

  $self->_emit_client_input(
    $client,
    {
      command  => 'NICK',
      nick     => $old_nick,
      new_nick => $new_nick,
    },
    suppress_render_event_types => {
      'irc.nick' => 1,
    },
  );
  return 1;
}

sub _handle_unregistered_nick_command {
  my ($self, $client_id, $client, $requested_nick) = @_;
  if ($self->_nick_matches_current_client_nick($client, $requested_nick)) {
    $self->_assign_client_nick($client_id, $requested_nick);
    $self->_register_client_if_ready($client);
    return 1;
  }

  if ($self->_nick_in_use($requested_nick, exclude_client_id => $client_id)) {
    $self->_send_nick_in_use($client_id, $requested_nick);
    return 1;
  }

  $self->_assign_client_nick($client_id, $requested_nick);
  $self->_register_client_if_ready($client);
  return 1;
}

sub _nick_matches_current_client_nick {
  my ($self, $client, $requested_nick) = @_;
  return 0 if !defined $client->{nick};
  my $current_key   = $self->_nick_key($client->{nick});
  my $requested_key = $self->_nick_key($requested_nick);
  return 0 if !defined $current_key;
  return 0 if !defined $requested_key;
  return $current_key eq $requested_key ? 1 : 0;
}

sub _handle_user_command {
  my ($self, $client_id, $client, $params) = @_;
  if ($client->{registered}) {
    return 1;
  }

  if (@{$params} < 4) {
    $self->_send_need_more_params($client_id, 'USER');
    return 1;
  }

  $client->{username} = $params->[0];
  $client->{realname} = $params->[3];
  $self->_register_client_if_ready($client);
  return 1;
}

sub _handle_ping_command {
  my ($self, $client_id, $params) = @_;
  my $token = defined $params->[0] ? $params->[0] : q{};
  $self->_send_client_line($client_id, 'PONG :' . $token);
  return 1;
}

sub _handle_quit_command {
  my ($self, $client_id, $params) = @_;
  my $reason = @{$params} >= 1 ? $params->[0] : undef;
  $self->_disconnect_client(
    $client_id,
    emit_quit => 1,
    reason    => $reason,
  );
  return 1;
}

sub _handle_unregistered_command {
  my ($self, $client_id, $command) = @_;
  if ($self->_command_requires_registration($command)) {
    $self->_send_not_registered($client_id);
    return 1;
  }

  $self->_send_unknown_command($client_id, $command);
  return 1;
}

my %REGISTERED_COMMAND_HANDLERS = (
  OVERNETKEY => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return $self->_handle_overnetkey_command($client_id, $client, $params);
  },
  OVERNETAUTH => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Auth::handle_overnetauth($self, $client_id, $params,);
  },
  OVERNETCHANNEL => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_overnetchannel($self, $client_id, $params,);
  },
  USERHOST => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return $self->_handle_userhost_command($client_id, $params);
  },
  WHO => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return $self->_handle_who_command($client_id, $client, $params);
  },
  WHOIS => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return $self->_handle_whois_command($client_id, $params);
  },
  MODE => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_mode($self, $client_id, $params,);
  },
  KICK => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_kick($self, $client_id, $params,);
  },
  INVITE => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_invite($self, $client_id, $params,);
  },
  JOIN => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_join($self, $client_id, $params,);
  },
  NAMES => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return $self->_handle_names_command($client_id, $params);
  },
  PART => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_part($self, $client_id, $params,);
  },
  PRIVMSG => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_privmsg_or_notice($self, $client_id, $command, $params,);
  },
  NOTICE => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_privmsg_or_notice($self, $client_id, $command, $params,);
  },
  TOPIC => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_topic($self, $client_id, $params,);
  },
  LUSERS => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    $self->_send_lusers_reply($client_id);
    return 1;
  },
  LIST => sub {
    my ($self, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_list($self, $client_id, $params,);
  },
);

sub _handle_registered_command {
  my ($self, $client_id, $client, $command, $params) = @_;

  my $handler = $REGISTERED_COMMAND_HANDLERS{$command};
  if (defined $handler) {
    return $handler->($self, $client_id, $client, $command, $params);
  }

  $self->_send_unknown_command($client_id, $command);
  return 1;
}

sub _handle_overnetkey_command {
  my ($self, $client_id, $client, $params) = @_;
  if (!$self->_client_has_capability($client, 'overnet-e2ee')) {
    $self->_send_server_notice($client_id, 'OVERNETKEY requires CAP overnet-e2ee');
    return 1;
  }

  if ( @{$params} < 2
    || !_nonempty_scalar($params->[0])
    || !_nonempty_scalar($params->[1])) {
    $self->_send_need_more_params($client_id, 'OVERNETKEY');
    return 1;
  }

  my $subcommand = uc($params->[0]);
  if ($subcommand eq 'SET') {
    return $self->_handle_overnetkey_set_command($client_id, $client, $params->[1]);
  }
  if ($subcommand eq 'GET') {
    return $self->_handle_overnetkey_get_command($client_id, $params->[1]);
  }

  $self->_send_unknown_command($client_id, 'OVERNETKEY');
  return 1;
}

sub _handle_overnetkey_set_command {
  my ($self, $client_id, $client, $pubkey_input) = @_;
  my $pubkey = lc $pubkey_input;
  if ($pubkey !~ /\A[0-9a-f]{64}\z/mxs) {
    $self->_send_server_notice($client_id, 'OVERNETKEY SET requires a 64-character lowercase hex pubkey');
    return 1;
  }

  $client->{e2ee_pubkey} = $pubkey;
  $self->_send_server_notice($client_id, "OVERNETKEY SET $pubkey");
  return 1;
}

sub _handle_overnetkey_get_command {
  my ($self, $client_id, $target_nick_input) = @_;
  my $target_nick = $self->_canonical_current_nick($target_nick_input);
  if (!defined $target_nick) {
    $self->_send_no_such_nick($client_id, $target_nick_input);
    return 1;
  }

  my $target_client = $self->_client_for_current_nick($target_nick);
  my $pubkey =
    ref($target_client) eq 'HASH'
    ? ($target_client->{e2ee_pubkey} || q{*})
    : q{*};
  $self->_send_server_notice($client_id, "OVERNETKEY GET $target_nick $pubkey");
  return 1;
}

sub _handle_userhost_command {
  my ($self, $client_id, $params) = @_;
  if (!@{$params}) {
    $self->_send_need_more_params($client_id, 'USERHOST');
    return 1;
  }

  my @entries;
  my %seen;
  for my $nick (@{$params}) {
    my $nick_key = $self->_nick_key($nick);
    if (!(defined $nick_key)) {
      next;
    }

    next if $seen{$nick_key}++;

    my $entry = $self->_userhost_entry_for_nick($nick);
    if (defined $entry) {
      push @entries, $entry;
    }

  }

  $self->_send_userhost_reply($client_id, \@entries);
  return 1;
}

sub _handle_who_command {
  my ($self, $client_id, $client, $params) = @_;
  if (@{$params} < 1 || !_nonempty_scalar($params->[0])) {
    $self->_send_need_more_params($client_id, 'WHO');
    return 1;
  }

  my $target = $params->[0];
  if (!$self->_is_channel_name($target)) {
    $self->_send_no_such_channel($client_id, $target);
    return 1;
  }

  my $channel = $self->_client_joined_channel_name($client, $target);
  if (!(defined $channel)) {
    $self->_send_not_on_channel($client_id, $target);
    return 1;
  }

  $self->_send_who_list($client_id, $channel);
  return 1;
}

sub _handle_whois_command {
  my ($self, $client_id, $params) = @_;
  if (@{$params} < 1 || !_nonempty_scalar($params->[0])) {
    $self->_send_need_more_params($client_id, 'WHOIS');
    return 1;
  }

  my $target_nick = $params->[0];
  my $entry       = $self->_whois_entry_for_nick($target_nick);
  if (!($entry)) {
    $self->_send_no_such_nick($client_id, $target_nick);
    return 1;
  }

  $self->_send_whois_reply($client_id, $entry);
  return 1;
}

sub _handle_names_command {
  my ($self, $client_id, $params) = @_;
  if (@{$params} < 1 || !_nonempty_scalar($params->[0])) {
    $self->_send_need_more_params($client_id, 'NAMES');
    return 1;
  }

  my $channel_input = $params->[0];
  if (!$self->_is_channel_name($channel_input)) {
    $self->_send_no_such_channel($client_id, $channel_input);
    return 1;
  }

  my $channel = $self->_canonical_channel_name($channel_input);
  $self->_send_names_list($client_id, $channel, force => 1);
  return 1;
}

sub _register_client_if_ready {
  my ($self, $client) = @_;
  return 0 if $client->{registered};
  if (!(defined $client->{nick} && length($client->{nick}))) {
    return 0;
  }

  if (!(defined $client->{username} && length($client->{username}))) {
    return 0;
  }

  return 0 if $client->{cap_negotiation_active};
  return 0
    if defined $client->{sasl_mechanism}
    && length($client->{sasl_mechanism});

  $client->{registered} = 1;
  $client->{dm_key} ||= Overnet::Core::Nostr->generate_key;
  $self->_send_registration_prelude($client->{id});
  $self->_ensure_client_dm_subscription($client->{id});
  return 1;
}

sub _send_authenticate_payload {
  my ($self, $client_id, $payload) = @_;
  return $self->_send_rendered_lines(
    $client_id,
    Overnet::Program::IRC::Renderer::authenticate_payload_lines(
      payload => $payload,
    ),
  );
}

sub _send_sasl_success {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::sasl_success_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
    ),
  );
}

sub _send_sasl_fail {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::sasl_fail_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
    ),
  );
}

sub _command_requires_registration {
  my ($self, $command) = @_;
  return
    scalar grep { $_ eq ($command || q{}) }
    qw(JOIN PART PRIVMSG NOTICE TOPIC NAMES MODE KICK INVITE USERHOST WHO WHOIS LUSERS LIST OVERNETKEY OVERNETAUTH OVERNETCHANNEL);
}

sub _send_rendered_lines {
  my ($self, $client_id, $lines) = @_;
  if (!(ref($lines) eq 'ARRAY')) {
    return 0;
  }

  my $sent = 0;
  for my $line (@{$lines}) {
    if (!(defined $line && !ref($line))) {
      next;
    }

    $self->_send_client_line($client_id, $line);
    $sent = 1;
  }

  return $sent ? 1 : 0;
}

sub _send_unknown_command {
  my ($self, $client_id, $command) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::unknown_command_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      command     => $command,
    ),
  );
}

sub _send_registration_prelude {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_rendered_lines(
    $client_id,
    Overnet::Program::IRC::Renderer::registration_prelude_lines(
      server_name     => $self->{config}{server_name},
      nick            => $client->{nick},
      isupport_tokens => $self->_isupport_tokens,
    ),
  );
}

sub _send_nonickname_given {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::nonickname_given_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
    ),
  );
}

sub _send_not_registered {
  my ($self, $client_id) = @_;
  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::not_registered_line(
      server_name => $self->{config}{server_name},
    ),
  );
}

sub _send_need_more_params {
  my ($self, $client_id, $command) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::need_more_params_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      command     => $command,
    ),
  );
}

sub _send_server_notice {
  my ($self, $client_id, $text) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  if (!(defined $client->{nick} && length($client->{nick}))) {
    return 0;
  }

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::server_notice_line(
      server_name => $self->{config}{server_name},
      nick        => $client->{nick},
      text        => $text,
    ),
  );
}

sub _send_no_such_nick {
  my ($self, $client_id, $nick) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::no_such_nick_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      target_nick => $nick,
    ),
  );
}

sub _send_no_such_channel {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::no_such_channel_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $channel,
    ),
  );
}

sub _send_not_on_channel {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::not_on_channel_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $channel,
    ),
  );
}

sub _send_cannot_send_to_channel {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::cannot_send_to_channel_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $channel,
    ),
  );
}

sub _send_chan_op_privs_needed {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::chan_op_privs_needed_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $channel,
    ),
  );
}

sub _send_cannot_join_channel {
  my ($self, $client_id, $channel, %args) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::cannot_join_channel_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $channel,
      reason      => $args{reason},
    ),
  );
}

sub _send_ban_list_entry {
  my ($self, $client_id, $channel, $ban_mask) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::ban_list_entry_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $channel,
      ban_mask    => $ban_mask,
    ),
  );
}

sub _send_end_of_ban_list {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::end_of_ban_list_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $channel,
    ),
  );
}

sub _send_exception_list_entry {
  my ($self, $client_id, $channel, $exception_mask) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::exception_list_entry_line(
      server_name    => $self->{config}{server_name},
      nick           => $self->_client_numeric_target($client),
      channel        => $channel,
      exception_mask => $exception_mask,
    ),
  );
}

sub _send_end_of_exception_list {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::end_of_exception_list_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $channel,
    ),
  );
}

sub _send_invite_exception_list_entry {
  my ($self, $client_id, $channel, $invite_exception_mask) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::invite_exception_list_entry_line(
      server_name           => $self->{config}{server_name},
      nick                  => $self->_client_numeric_target($client),
      channel               => $channel,
      invite_exception_mask => $invite_exception_mask,
    ),
  );
}

sub _send_end_of_invite_exception_list {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::end_of_invite_exception_list_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $channel,
    ),
  );
}

sub _send_inviting {
  my ($self, $client_id, $target_nick, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::inviting_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      target_nick => $target_nick,
      channel     => $channel,
    ),
  );
}

sub _send_channel_mode_is {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $display_channel = $self->_canonical_channel_name($channel);
  if (!(defined $display_channel)) {
    return 0;
  }

  my $channel_modes = '+n';
  my @mode_args;

  if (
    my $authoritative = $self->_derive_authoritative_channel_state(
      $display_channel, force => 1
    )
  ) {
    if ( defined $authoritative->{channel_modes}
      && !ref($authoritative->{channel_modes})
      && length($authoritative->{channel_modes})) {
      $channel_modes = $authoritative->{channel_modes};
    }
    if ( defined($authoritative->{channel_key})
      && !ref($authoritative->{channel_key})
      && length($authoritative->{channel_key})) {
      push @mode_args, $authoritative->{channel_key};
    }
    if (defined($authoritative->{user_limit})
      && !ref($authoritative->{user_limit})) {
      push @mode_args, $authoritative->{user_limit};
    }
  }

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::channel_mode_is_line(
      server_name   => $self->{config}{server_name},
      nick          => $self->_client_numeric_target($client),
      channel       => $display_channel,
      channel_modes => $channel_modes,
      mode_args     => \@mode_args,
    ),
  );
}

sub _send_user_mode_is {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::user_mode_is_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
    ),
  );
}

sub _send_lusers_reply {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $target           = $self->_client_numeric_target($client);
  my $registered_users = scalar grep { $self->{clients}{$_}{registered} }
    keys %{$self->{clients}};
  my $connected_clients = scalar keys %{$self->{clients}};
  my $channels          = scalar keys %{$self->{channels}};

  return $self->_send_rendered_lines(
    $client_id,
    Overnet::Program::IRC::Renderer::lusers_reply_lines(
      server_name       => $self->{config}{server_name},
      nick              => $target,
      registered_users  => $registered_users,
      connected_clients => $connected_clients,
      channels          => $channels,
    ),
  );
}

sub _send_list_reply {
  my ($self, $client_id, $target) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $nick = $self->_client_numeric_target($client);

  return $self->_send_rendered_lines(
    $client_id,
    Overnet::Program::IRC::Renderer::list_reply_lines(
      server_name => $self->{config}{server_name},
      nick        => $nick,
      entries     => [$self->_list_entries($client, $target)],
    ),
  );
}

sub _send_authoritative_invite_list_reply {
  my ($self, $client_id, $channel, $pending_invites) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $nick  = $self->_client_numeric_target($client);
  my @lines = map {
    Overnet::Program::IRC::Renderer::authoritative_invite_list_entry_line(
      server_name   => $self->{config}{server_name},
      nick          => $nick,
      channel       => $channel,
      target_pubkey => $_->{target_pubkey},
      invite_code   => $_->{code},
    )
  } grep {
         ref eq 'HASH'
      && defined($_->{target_pubkey})
      && !ref($_->{target_pubkey})
      && length($_->{target_pubkey})
      && defined($_->{code})
      && !ref($_->{code})
      && length($_->{code})
  } @{$pending_invites || []};

  push @lines,
    Overnet::Program::IRC::Renderer::end_of_authoritative_invite_list_line(
    server_name => $self->{config}{server_name},
    nick        => $nick,
    channel     => $channel,
    );

  return $self->_send_rendered_lines($client_id, \@lines);
}

sub _send_authoritative_join_request_list_reply {
  my ($self, $client_id, $channel, $pending_join_requests) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $nick  = $self->_client_numeric_target($client);
  my @lines = map {
    Overnet::Program::IRC::Renderer::authoritative_join_request_list_entry_line(
      server_name      => $self->{config}{server_name},
      nick             => $nick,
      channel          => $channel,
      requester_pubkey => $_->{pubkey},
      actor_mask       => $_->{actor_mask},
    )
  } grep { ref eq 'HASH' && defined($_->{pubkey}) && !ref($_->{pubkey}) && length($_->{pubkey}) }
    @{$pending_join_requests || []};

  push @lines,
    Overnet::Program::IRC::Renderer::end_of_authoritative_join_request_list_line(
    server_name => $self->{config}{server_name},
    nick        => $nick,
    channel     => $channel,
    );

  return $self->_send_rendered_lines($client_id, \@lines);
}

sub _send_topic_reply {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $display_channel = $self->_canonical_channel_name($channel);
  if (!(defined $display_channel)) {
    return 0;
  }

  my $channel_key = $self->_channel_key($display_channel);
  if (!(defined $channel_key)) {
    return 0;
  }

  my $target = $self->_client_numeric_target($client);

  if ($self->_is_authoritative_channel($display_channel)) {
    my $cached_view = $self->_cached_authoritative_channel_view($display_channel);
    my $view =
      $self->_authority_relay_enabled
      ? eval { $self->_derive_authoritative_channel_view($display_channel, force => 1); }
      : $self->_derive_authoritative_channel_view($display_channel);
    if (!(ref($view) eq 'HASH')) {
      $view = $cached_view;
    }

    if (!$self->_authority_relay_enabled && ref($view) ne 'HASH') {
      $view = $self->_derive_authoritative_channel_view($display_channel, force => 1);
    }

    $self->_sync_authoritative_topic_state_from_view($display_channel, $view);
    if (ref($view) eq 'HASH' && exists $view->{topic}) {
      return $self->_send_client_line(
        $client_id,
        Overnet::Program::IRC::Renderer::topic_is_line(
          server_name => $self->{config}{server_name},
          nick        => $target,
          channel     => $display_channel,
          topic       => $view->{topic},
        ),
      );
    }

    return $self->_send_client_line(
      $client_id,
      Overnet::Program::IRC::Renderer::no_topic_line(
        server_name => $self->{config}{server_name},
        nick        => $target,
        channel     => $display_channel,
      ),
    );
  }

  my $state = $self->{channels}{$channel_key}
    || $self->_channel_state($display_channel);

  if (defined $state->{topic_text} && !ref($state->{topic_text})) {
    return $self->_send_client_line(
      $client_id,
      Overnet::Program::IRC::Renderer::topic_is_line(
        server_name => $self->{config}{server_name},
        nick        => $target,
        channel     => $display_channel,
        topic       => $state->{topic_text},
      ),
    );
  }

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::no_topic_line(
      server_name => $self->{config}{server_name},
      nick        => $target,
      channel     => $display_channel,
    ),
  );
}

sub _send_userhost_reply {
  my ($self, $client_id, $entries) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  return $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::userhost_line(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      entries     => $entries,
    ),
  );
}

sub _send_who_list {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $display_channel = $self->_canonical_channel_name($channel);
  if (!(defined $display_channel)) {
    return 0;
  }

  return $self->_send_rendered_lines(
    $client_id,
    Overnet::Program::IRC::Renderer::who_list_lines(
      server_name => $self->{config}{server_name},
      nick        => $self->_client_numeric_target($client),
      channel     => $display_channel,
      entries     => [$self->_who_entries_for_channel($display_channel)],
    ),
  );
}

sub _send_whois_reply {
  my ($self, $client_id, $entry) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  if (!(ref($entry) eq 'HASH')) {
    return 0;
  }

  my $target       = $self->_client_numeric_target($client);
  my $display_nick = $entry->{nick};
  my $username     = $entry->{username};
  my $host         = $entry->{host};
  my $realname     = $entry->{realname};

  return $self->_send_rendered_lines(
    $client_id,
    Overnet::Program::IRC::Renderer::whois_reply_lines(
      server_name        => $self->{config}{server_name},
      nick               => $target,
      server_description => $self->_server_description,
      entry              => {
        nick     => $display_nick,
        username => $username,
        host     => $host,
        realname => $realname,
        (
          defined($entry->{account})
            && !ref($entry->{account})
            && length($entry->{account})
          ? (account => $entry->{account})
          : ()
        ),
      },
    ),
  );
}

sub _client_numeric_target {
  my ($self, $client) = @_;
  if (!(ref($client) eq 'HASH' && defined $client->{nick} && !ref($client->{nick}) && length($client->{nick}))) {
    return q{*};
  }

  return $client->{nick};
}

sub _irc_casefold {
  my ($self, $value) = @_;
  if (!(defined $value && !ref($value))) {
    return;
  }

  my $folded = $value;
  $folded =~ tr/A-Z[]\\^/a-z{}|~/s;
  return $folded;
}

sub _nick_key {
  my ($self, $nick) = @_;
  if (!(defined $nick && !ref($nick) && length($nick))) {
    return;
  }

  return $self->_irc_casefold($nick);
}

sub _default_presentational_host {
  my ($self) = @_;
  return 'overnet.invalid';
}

sub _isupport_tokens {
  my ($self) = @_;
  return join q{ }, 'CASEMAPPING=rfc1459', 'CHANTYPES=#&', 'NETWORK=' . $self->{config}{network};
}

sub _supported_capabilities {
  my ($self) = @_;
  my @capabilities;
  push @capabilities, 'message-tags';
  push @capabilities, 'server-time';
  push @capabilities, 'overnet-e2ee';
  if ($self->_authority_profile eq 'nip29') {
    push @capabilities, 'account-tag';
    push @capabilities, 'account-notify';
    push @capabilities, 'sasl';
  }
  return @capabilities;
}

sub _server_description {
  my ($self) = @_;
  return 'Overnet IRC';
}

sub _presentational_host_for_client {
  my ($self, $client) = @_;
  if (!(ref($client) eq 'HASH')) {
    return $self->_default_presentational_host;
  }

  # An already-resolved presentational host (for example an operator-assigned
  # vhost) is presented verbatim. A raw transport address is never presented as
  # is; it is always replaced by a cloak.
  my $vhost = $client->{presentational_host};
  if (defined $vhost && !ref($vhost) && length($vhost)) {
    return $vhost;
  }

  my $peerhost = $client->{peerhost};
  if (defined $peerhost && !ref($peerhost) && length($peerhost)) {
    return $self->_cloak_host_for_address($peerhost);
  }
  return $self->_default_presentational_host;
}

sub _cloak_domain {
  my ($self) = @_;
  return 'users.overnet';
}

# Present a stable per-connection cloak of the client's transport address rather
# than the raw IP, so a user's network address is never exposed through WHO,
# WHOIS, USERHOST, or authoritative masks. The cloak is a keyed hash of the
# address, so it is stable for a given address but not reversible or enumerable
# without the server cloak secret.
sub _cloak_host_for_address {
  my ($self, $address) = @_;
  my $token = substr hmac_sha256_hex($address, $self->_cloak_secret), 0, 16;
  return $token . q{.} . $self->_cloak_domain;
}

sub _cloak_secret {
  my ($self) = @_;
  if (defined $self->{_cloak_secret}) {
    return $self->{_cloak_secret};
  }

  my $configured = ref($self->{config}) eq 'HASH' ? $self->{config}{cloak_secret} : undef;
  if (defined $configured && !ref($configured) && length($configured)) {
    $self->{_cloak_secret} = $configured;
  } else {

    # No stable secret was configured, so derive a per-process secret. Cloaks
    # stay stable for this process but differ across restarts; configure
    # cloak_secret for cloaks that are stable across restarts.
    $self->{_cloak_secret} = sha256_hex(join q{:}, 'overnet-irc-cloak', $PROCESS_ID, time(), rand());
  }
  return $self->{_cloak_secret};
}

sub _canonical_current_nick {
  my ($self, $nick) = @_;
  my $key = $self->_nick_key($nick);
  if (!(defined $key)) {
    return;
  }

  my $client_id = $self->{nick_to_client_id}{$key};
  if (!(defined $client_id && exists $self->{clients}{$client_id})) {
    return;
  }

  return $self->{clients}{$client_id}{nick};
}

sub _client_for_current_nick {
  my ($self, $nick) = @_;
  my $key = $self->_nick_key($nick);
  if (!(defined $key)) {
    return;
  }

  my $client_id = $self->{nick_to_client_id}{$key};
  if (!(defined $client_id && exists $self->{clients}{$client_id})) {
    return;
  }

  return $self->{clients}{$client_id};
}

sub _client_has_capability {
  my ($self, $client, $capability) = @_;
  if (!(ref($client) eq 'HASH')) {
    return 0;
  }

  if (!(defined $capability && !ref($capability) && length($capability))) {
    return 0;
  }

  return $client->{capabilities}{$capability} ? 1 : 0;
}

sub _client_account_name {
  my ($self, $client) = @_;
  if (!(ref($client) eq 'HASH')) {
    return;
  }

  if (
    !(defined($client->{authority_pubkey}) && !ref($client->{authority_pubkey}) && length($client->{authority_pubkey})))
  {
    return;
  }

  return $client->{authority_pubkey};
}

sub _authority_profile {
  my ($self) = @_;
  return $self->{config}{adapter_config}{authority_profile} || q{};
}

sub _authority_grant_kind {
  return 14_142;
}

sub _authority_relay_config {
  my ($self) = @_;
  return $self->{config}{authority_relay};
}

sub _authority_relay_url {
  my ($self) = @_;
  my $config = $self->_authority_relay_config;
  if (!(ref($config) eq 'HASH')) {
    return;
  }

  return $config->{url};
}

sub _authority_relay_poll_interval_ms {
  my ($self) = @_;
  my $config = $self->_authority_relay_config;
  if (!(ref($config) eq 'HASH')) {
    return;
  }

  return $config->{poll_interval_ms};
}

sub _authority_relay_query_timeout_ms {
  my ($self) = @_;
  my $config = $self->_authority_relay_config;
  my $timeout_ms =
    ref($config) eq 'HASH'
    ? $config->{query_timeout_ms}
    : undef;
  if (!(defined $timeout_ms && !ref($timeout_ms) && $timeout_ms =~ /\A[1-9]\d*\z/mxs)) {
    $timeout_ms = 1_000;
  }

  return $timeout_ms;
}

sub _authority_relay_enabled {
  my ($self) = @_;
  my $url = $self->_authority_relay_url;
  return defined $url && !ref($url) && length($url) ? 1 : 0;
}

sub _authoritative_auth_scope {
  my ($self) = @_;
  return sprintf('irc://%s/%s', $self->{config}{server_name}, $self->{config}{network},);
}

sub _generate_authoritative_auth_challenge {
  my ($self, $client) = @_;
  return sha256_hex(
    join q{:}, time(), $PROCESS_ID, rand(),
    (ref($client) eq 'HASH' ? ($client->{id}       || q{}) : q{}),
    (ref($client) eq 'HASH' ? ($client->{peerhost} || q{}) : q{}),
    (ref($client) eq 'HASH' ? ($client->{peerport} || 0)   : 0),
  );
}

sub _generate_authoritative_invite_code {
  my ($self, %args) = @_;
  return sha256_hex(
    join q{:}, time(), $PROCESS_ID, rand(),
    ($args{channel}       || q{}),
    ($args{actor_pubkey}  || q{}),
    ($args{target_pubkey} || q{}),
  );
}

sub _generate_authoritative_delegate_session_id {
  my ($self, $client) = @_;
  return sha256_hex(join q{:}, time(), $PROCESS_ID, rand(), (ref($client) eq 'HASH' ? ($client->{id} || q{}) : q{}),
    $self->{instance_id},);
}

sub _is_authoritative_channel {
  my ($self, $channel) = @_;
  if (!($self->_authority_profile eq 'nip29')) {
    return 0;
  }

  if (!($self->_is_channel_name($channel))) {
    return 0;
  }

  my $config = $self->{config}{adapter_config} || {};
  if (!(defined $config->{group_host} && !ref($config->{group_host}) && length($config->{group_host}))) {
    return 0;
  }

  return 1;
}

sub _authoritative_group_binding {
  my ($self, $channel) = @_;
  if (!($self->_is_authoritative_channel($channel))) {
    return;
  }

  my $canonical = $self->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    return;
  }

  my ($group_host, $group_id) = Overnet::Authority::HostedChannel::resolve_nip29_group_binding(
    network        => $self->{config}{network},
    session_config => $self->{config}{adapter_config},
    target         => $canonical,
  );
  if (!(defined $group_host && defined $group_id)) {
    return;
  }

  return ($group_host, $group_id);
}

sub _authoritative_nip29_stream_name {
  my ($self,       $channel)  = @_;
  my ($group_host, $group_id) = $self->_authoritative_group_binding($channel);
  if (!(defined $group_host && defined $group_id)) {
    return;
  }

  return join q{:}, q{irc.authority.nip29}, $self->{config}{network}, $group_host, $group_id;
}

sub _authoritative_channels {
  my ($self) = @_;
  my %channels;
  my $channel_groups = $self->{config}{adapter_config}{channel_groups};
  if (ref($channel_groups) eq 'HASH') {
    for my $channel (sort keys %{$channel_groups}) {
      my $channel_key = $self->_channel_key($channel);
      if (!(defined $channel_key)) {
        next;
      }

      $channels{$channel_key} ||= $channel;
    }
  }
  for my $channel (sort keys %{$self->{authoritative_discovered_channels} || {}}) {
    my $channel_key = $self->_channel_key($channel);
    if (!(defined $channel_key)) {
      next;
    }

    $channels{$channel_key} ||= $channel;
  }
  for my $channel_key (keys %{$self->{channels} || {}}) {
    my $channel_name = $self->{channels}{$channel_key}{channel_name};
    if (!($self->_is_authoritative_channel($channel_name))) {
      next;
    }

    $channels{$channel_key} ||= $channel_name;
  }
  my @channel_names = sort values %channels;
  return @channel_names;
}

sub _authoritative_grant_subscription_id {
  my ($self) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::authoritative_grant_subscription_id($self);
}

sub _authoritative_discovery_subscription_id {
  my ($self) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::authoritative_discovery_subscription_id($self);
}

sub _authoritative_channel_subscription_ids {
  my ($self, $channel) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::authoritative_channel_subscription_ids($self, $channel);
}

sub _ensure_authoritative_grant_subscription {
  my ($self) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::ensure_authoritative_grant_subscription($self);
}

sub _ensure_authoritative_discovery_subscription {
  my ($self) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::ensure_authoritative_discovery_subscription($self);
}

sub _ensure_authoritative_channel_subscription {
  my ($self, $channel) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::ensure_authoritative_channel_subscription($self, $channel);
}

sub _read_nostr_subscription_snapshot {
  my ($self, $subscription_id, %args) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::read_nostr_subscription_snapshot($self, $subscription_id,
    %args);
}

sub _remember_authoritative_discovered_channel {
  my ($self, %args) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::remember_authoritative_discovered_channel($self, %args);
}

sub _forget_authoritative_discovered_channel {
  my ($self, $channel) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::forget_authoritative_discovered_channel($self, $channel);
}

sub _record_authoritative_discovery_event {
  my ($self, $event) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::record_authoritative_discovery_event($self, $event);
}

sub _refresh_authoritative_discovery_cache {
  my ($self, %args) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::refresh_authoritative_discovery_cache($self, %args);
}

sub _query_nostr_events {
  my ($self, %args) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::query_nostr_events($self, %args);
}

sub _read_authoritative_nip29_events_from_runtime {
  my ($self, $channel) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::read_authoritative_nip29_events_from_runtime($self, $channel);
}

sub _load_authoritative_nip29_events {
  my ($self, $channel, %args) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::load_authoritative_nip29_events($self, $channel, %args);
}

sub _refresh_authoritative_nip29_channel_cache {
  my ($self, $channel, %args) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::refresh_authoritative_nip29_channel_cache($self, $channel,
    %args);
}

sub _read_authoritative_nip29_events {
  my ($self, $channel, %args) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::read_authoritative_nip29_events($self, $channel, %args);
}

sub _authoritative_channel_is_known {
  my ($self, $channel) = @_;
  if (!($self->_is_authoritative_channel($channel))) {
    return 0;
  }

  my $canonical = $self->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    return 0;
  }

  return 1 if exists $self->{authoritative_discovered_channels}{$canonical};

  my $cache = $self->{authoritative_channel_cache}{$canonical};
  if (!(ref($cache) eq 'HASH')) {
    return 0;
  }

  return 1 if ref($cache->{events}) eq 'ARRAY' && @{$cache->{events}};
  return 0;
}

sub _derive_authoritative_view_from_events {
  my ($self, $operation, $channel, $authoritative_events, %args) = @_;
  if (!(defined $operation && !ref($operation) && length($operation))) {
    return;
  }

  if (!($self->_is_authoritative_channel($channel))) {
    return;
  }

  if (!(ref($authoritative_events) eq 'ARRAY')) {
    return;
  }

  my $result = eval {
    $self->_request(
      method => 'adapters.derive',
      params => {
        adapter_session_id => $self->{adapter_session_id},
        operation          => $operation,
        input              => {
          network              => $self->{config}{network},
          target               => $self->_canonical_channel_name($channel),
          authoritative_events => $authoritative_events,
          (
            defined $args{actor_pubkey} ? (actor_pubkey => $args{actor_pubkey})
            : ()
          ),
          (
            defined $args{actor_mask} ? (actor_mask => $args{actor_mask})
            : ()
          ),
          (
            ref($args{extra_input}) eq 'HASH' ? %{$args{extra_input}}
            : ()
          ),
        },
      },
    );
  };
  return if $EVAL_ERROR;
  if (!(ref($result->{view}) eq 'ARRAY' && @{$result->{view}})) {
    return;
  }

  return $result->{view}[0];
}

sub _derive_authoritative_channel_view_from_events {
  my ($self, $channel, $authoritative_events, %args) = @_;
  return $self->_derive_authoritative_view_from_events('authoritative_channel_view', $channel,
    $authoritative_events, %args,);
}

sub _derive_authoritative_join_admission_from_events {
  my ($self, $channel, $authoritative_events, %args) = @_;
  if (!($self->_is_authoritative_channel($channel))) {
    return;
  }

  if (!(ref($authoritative_events) eq 'ARRAY')) {
    return;
  }

  my $result = eval {
    $self->_request(
      method => 'adapters.derive',
      params => {
        adapter_session_id => $self->{adapter_session_id},
        operation          => 'authoritative_join_admission',
        input              => {
          network              => $self->{config}{network},
          target               => $self->_canonical_channel_name($channel),
          authoritative_events => $authoritative_events,
          (
            defined $args{actor_pubkey} ? (actor_pubkey => $args{actor_pubkey})
            : ()
          ),
          (
            defined $args{actor_mask} ? (actor_mask => $args{actor_mask})
            : ()
          ),
          (
            ref($args{extra_input}) eq 'HASH' ? %{$args{extra_input}}
            : ()
          ),
        },
      },
    );
  };
  return if $EVAL_ERROR;
  if (!(ref($result->{admission}) eq 'ARRAY' && @{$result->{admission}})) {
    return;
  }

  return $result->{admission}[0];
}

sub _derive_authoritative_permission_from_events {
  my ($self, $operation, $channel, $authoritative_events, %args) = @_;
  if (!(defined $operation && !ref($operation) && length($operation))) {
    return;
  }

  if (!($self->_is_authoritative_channel($channel))) {
    return;
  }

  if (!(ref($authoritative_events) eq 'ARRAY')) {
    return;
  }

  my $result = eval {
    $self->_request(
      method => 'adapters.derive',
      params => {
        adapter_session_id => $self->{adapter_session_id},
        operation          => $operation,
        input              => {
          network              => $self->{config}{network},
          target               => $self->_canonical_channel_name($channel),
          authoritative_events => $authoritative_events,
          (
            defined $args{actor_pubkey} ? (actor_pubkey => $args{actor_pubkey})
            : ()
          ),
          (
            defined $args{actor_mask} ? (actor_mask => $args{actor_mask})
            : ()
          ),
          (
            ref($args{extra_input}) eq 'HASH' ? %{$args{extra_input}}
            : ()
          ),
        },
      },
    );
  };
  return if $EVAL_ERROR;
  if (!(ref($result->{permission}) eq 'ARRAY' && @{$result->{permission}})) {
    return;
  }

  return $result->{permission}[0];
}

sub _derive_authoritative_view {
  my ($self, $operation, $channel, %args) = @_;
  if (!(defined $operation && !ref($operation) && length($operation))) {
    return;
  }

  if (!($self->_is_authoritative_channel($channel))) {
    return;
  }

  my $canonical = $self->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    return;
  }

  my $cache   = $self->{authoritative_channel_cache}{$canonical};
  my $refresh = $args{force} || !$cache || ref($cache->{events}) ne 'ARRAY';
  if ($refresh) {
    $self->_refresh_authoritative_nip29_channel_cache($canonical,
      ($args{force} && $self->_authority_relay_enabled ? (refresh => 1) : ()),
    );
    $cache = $self->{authoritative_channel_cache}{$canonical};
  }

  if (!($cache && ref($cache->{events}) eq 'ARRAY')) {
    return;
  }

  return $self->_derive_authoritative_view_from_events($operation, $canonical, $cache->{events}, %args,);
}

sub _authoritative_channel_state_from_view {
  my ($self, $view) = @_;
  if (!(ref($view) eq 'HASH')) {
    return;
  }

  return {
    operation         => 'authoritative_channel_state',
    authority_profile => $view->{authority_profile},
    object_type       => $view->{object_type},
    object_id         => $view->{object_id},
    group_host        => $view->{group_host},
    group_id          => $view->{group_id},
    group_ref         => $view->{group_ref},
    channel_modes     => $view->{channel_modes},
    (
      ref($view->{ban_masks}) eq 'ARRAY' ? (ban_masks => [@{$view->{ban_masks}}])
      : ()
    ),
    (
      ref($view->{exception_masks}) eq 'ARRAY' ? (exception_masks => [@{$view->{exception_masks}}])
      : ()
    ),
    (
      ref($view->{invite_exception_masks}) eq 'ARRAY' ? (invite_exception_masks => [@{$view->{invite_exception_masks}}])
      : ()
    ),
    (
      defined($view->{channel_key}) ? (channel_key => $view->{channel_key})
      : ()
    ),
    (
      defined($view->{user_limit}) ? (user_limit => $view->{user_limit})
      : ()
    ),
    (exists $view->{topic} ? (topic => $view->{topic}) : ()),
    (
      exists $view->{topic_actor_pubkey} ? (topic_actor_pubkey => $view->{topic_actor_pubkey})
      : ()
    ),
    ($view->{private}    ? (private    => 1) : ()),
    ($view->{restricted} ? (restricted => 1) : ()),
    ($view->{hidden}     ? (hidden     => 1) : ()),
    ($view->{tombstoned} ? (tombstoned => 1) : ()),
    supported_roles => [@{$view->{supported_roles} || []}],
    members         => [
      map {
        +{
          pubkey                => $_->{pubkey},
          roles                 => [@{$_->{roles} || []}],
          presentational_prefix => $_->{presentational_prefix},
        }
      } @{$view->{members} || []}
    ],
    (
      ref($view->{retained_members}) eq 'ARRAY'
      ? (
        retained_members => [
          map {
            +{
              pubkey                => $_->{pubkey},
              roles                 => [@{$_->{roles} || []}],
              presentational_prefix => $_->{presentational_prefix},
            }
          } @{$view->{retained_members}}
        ],
        )
      : ()
    ),
  };
}

sub _derive_authoritative_channel_view {
  my ($self, $channel, %args) = @_;
  if (!($self->_is_authoritative_channel($channel))) {
    return;
  }

  my $canonical = $self->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    return;
  }

  my $cache   = $self->{authoritative_channel_cache}{$canonical};
  my $refresh = $args{force} || !$cache || !exists($cache->{view});
  if ($refresh) {
    my $old_view =
        $cache && ref($cache->{view}) eq 'HASH'
      ? $cache->{view}
      : undef;
    my $old_events =
      $cache && ref($cache->{events}) eq 'ARRAY'
      ? [@{$cache->{events}}]
      : [];
    $self->_refresh_authoritative_nip29_channel_cache($canonical,
      ($args{force} && $self->_authority_relay_enabled ? (refresh => 1) : ()),
    );
    $cache = $self->{authoritative_channel_cache}{$canonical};
    if ( $args{reconcile_pending_invites}
      && $self->_authority_relay_enabled) {
      $self->_reconcile_authoritative_pending_invites_from_refresh(
        channel    => $canonical,
        old_view   => $old_view,
        old_events => $old_events,
        new_view   => $cache->{view},
        new_events => $cache->{events},
      );
    }
  }

  if (!($cache && ref($cache->{events}) eq 'ARRAY')) {
    return;
  }

  return $self->_derive_authoritative_channel_view_from_events($canonical, $cache->{events}, %args,)
    if defined $args{actor_pubkey};

  return $cache->{view};
}

sub _cached_authoritative_channel_view {
  my ($self, $channel) = @_;
  my $canonical = $self->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    return;
  }

  my $cache = $self->{authoritative_channel_cache}{$canonical};
  if (!(ref($cache) eq 'HASH' && ref($cache->{view}) eq 'HASH')) {
    return;
  }

  return $cache->{view};
}

sub _derive_authoritative_ban_list_view {
  my ($self, $channel, %args) = @_;
  return $self->_derive_authoritative_view('authoritative_ban_list_view', $channel, %args,);
}

sub _derive_authoritative_list_entry_view {
  my ($self, $channel, %args) = @_;
  return $self->_derive_authoritative_view('authoritative_list_entry_view', $channel, %args,);
}

sub _derive_authoritative_join_admission {
  my ($self, $channel, %args) = @_;
  if (!($self->_is_authoritative_channel($channel))) {
    return;
  }

  my $canonical = $self->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    return;
  }

  my $cache   = $self->{authoritative_channel_cache}{$canonical};
  my $refresh = $args{force} || !$cache || ref($cache->{events}) ne 'ARRAY';
  if ($refresh) {
    my $old_view =
        $cache && ref($cache->{view}) eq 'HASH'
      ? $cache->{view}
      : undef;
    my $old_events =
      $cache && ref($cache->{events}) eq 'ARRAY'
      ? [@{$cache->{events}}]
      : [];
    $self->_refresh_authoritative_nip29_channel_cache($canonical,
      ($args{force} && $self->_authority_relay_enabled ? (refresh => 1) : ()),
    );
    $cache = $self->{authoritative_channel_cache}{$canonical};
    if ( $args{reconcile_pending_invites}
      && $self->_authority_relay_enabled) {
      $self->_reconcile_authoritative_pending_invites_from_refresh(
        channel    => $canonical,
        old_view   => $old_view,
        old_events => $old_events,
        new_view   => $cache->{view},
        new_events => $cache->{events},
      );
    }
  }

  if (!($cache && ref($cache->{events}) eq 'ARRAY')) {
    return;
  }

  return $self->_derive_authoritative_join_admission_from_events($canonical, $cache->{events}, %args,);
}

sub _derive_authoritative_speak_permission {
  my ($self, $channel, %args) = @_;
  if (!($self->_is_authoritative_channel($channel))) {
    return;
  }

  my $canonical = $self->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    return;
  }

  my $cache   = $self->{authoritative_channel_cache}{$canonical};
  my $refresh = $args{force} || !$cache || ref($cache->{events}) ne 'ARRAY';
  if ($refresh) {
    $self->_refresh_authoritative_nip29_channel_cache($canonical,
      ($args{force} && $self->_authority_relay_enabled ? (refresh => 1) : ()),
    );
    $cache = $self->{authoritative_channel_cache}{$canonical};
  }

  if (!($cache && ref($cache->{events}) eq 'ARRAY')) {
    return;
  }

  return $self->_derive_authoritative_permission_from_events('authoritative_speak_permission',
    $canonical, $cache->{events}, %args,);
}

sub _derive_authoritative_topic_permission {
  my ($self, $channel, %args) = @_;
  if (!($self->_is_authoritative_channel($channel))) {
    return;
  }

  my $canonical = $self->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    return;
  }

  my $cache   = $self->{authoritative_channel_cache}{$canonical};
  my $refresh = $args{force} || !$cache || ref($cache->{events}) ne 'ARRAY';
  if ($refresh) {
    $self->_refresh_authoritative_nip29_channel_cache($canonical,
      ($args{force} && $self->_authority_relay_enabled ? (refresh => 1) : ()),
    );
    $cache = $self->{authoritative_channel_cache}{$canonical};
  }

  if (!($cache && ref($cache->{events}) eq 'ARRAY')) {
    return;
  }

  return $self->_derive_authoritative_permission_from_events('authoritative_topic_permission',
    $canonical, $cache->{events}, %args,);
}

sub _derive_authoritative_mode_write_permission {
  my ($self, $channel, %args) = @_;
  if (!($self->_is_authoritative_channel($channel))) {
    return;
  }

  my $canonical = $self->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    return;
  }

  my $cache   = $self->{authoritative_channel_cache}{$canonical};
  my $refresh = $args{force} || !$cache || ref($cache->{events}) ne 'ARRAY';
  if ($refresh) {
    $self->_refresh_authoritative_nip29_channel_cache($canonical,
      ($args{force} && $self->_authority_relay_enabled ? (refresh => 1) : ()),
    );
    $cache = $self->{authoritative_channel_cache}{$canonical};
  }

  if (!($cache && ref($cache->{events}) eq 'ARRAY')) {
    return;
  }

  return $self->_derive_authoritative_permission_from_events(
    'authoritative_mode_write_permission',
    $canonical,
    $cache->{events},
    actor_pubkey => $args{actor_pubkey},
    extra_input  => {
      mode      => $args{mode},
      mode_args => ref($args{mode_args}) eq 'ARRAY'
      ? $args{mode_args}
      : [],
    },
  );
}

sub _derive_authoritative_channel_action_permission {
  my ($self, $channel, %args) = @_;
  if (!($self->_is_authoritative_channel($channel))) {
    return;
  }

  my $canonical = $self->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    return;
  }

  my $cache   = $self->{authoritative_channel_cache}{$canonical};
  my $refresh = $args{force} || !$cache || ref($cache->{events}) ne 'ARRAY';
  if ($refresh) {
    $self->_refresh_authoritative_nip29_channel_cache($canonical,
      ($args{force} && $self->_authority_relay_enabled ? (refresh => 1) : ()),
    );
    $cache = $self->{authoritative_channel_cache}{$canonical};
  }

  if (!($cache && ref($cache->{events}) eq 'ARRAY')) {
    return;
  }

  return $self->_derive_authoritative_permission_from_events(
    'authoritative_channel_action_permission',
    $canonical,
    $cache->{events},
    actor_pubkey => $args{actor_pubkey},
    extra_input  => {
      action => $args{action},
      (
        defined $args{target_pubkey}
        ? (target_pubkey => $args{target_pubkey})
        : ()
      ),
    },
  );
}

sub _authoritative_join_admission_is_populated {
  my ($self, $admission) = @_;
  if (!(ref($admission) eq 'HASH')) {
    return 0;
  }

  return 1 if exists $admission->{allowed};
  return 1 if exists $admission->{member};
  return 1 if exists $admission->{present};
  return 1 if exists $admission->{invite_code};
  return 1 if exists $admission->{deleted};
  return 1 if exists $admission->{create_channel};
  return 1 if exists $admission->{auth_required};
  return 1 if exists $admission->{request_join};
  return 1 if exists $admission->{pending_request};
  return 1 if exists $admission->{reason};
  return 0;
}

sub _authoritative_permission_is_populated {
  my ($self, $permission) = @_;
  if (!(ref($permission) eq 'HASH')) {
    return 0;
  }

  return 1 if exists $permission->{allowed};
  return 1 if exists $permission->{reason};
  return 1 if exists $permission->{roles};
  return 1 if exists $permission->{presentational_prefix};
  return 0;
}

sub _derive_authoritative_channel_state {
  my ($self, $channel, %args) = @_;
  my $view = $self->_derive_authoritative_channel_view($channel, %args);
  return $self->_authoritative_channel_state_from_view($view);
}

sub _sort_authoritative_events {
  my ($self, $events) = @_;
  my @decorated;
  my $index = 0;
  for my $event (@{$events || []}) {
    push @decorated, [$index++, $event];
  }
  return [
    map  { $_->[1] }
    sort { ((($a->[1]{created_at}) || 0) <=> (($b->[1]{created_at}) || 0)) || ($a->[0] <=> $b->[0]) } @decorated
  ];
}

sub _read_authoritative_grant_events {
  my ($self, %args) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::read_authoritative_grant_events($self, %args);
}

sub _client_authoritative_pubkey {
  my ($self, $client) = @_;
  if (!(ref($client) eq 'HASH')) {
    return;
  }

  if (
    !(defined $client->{authority_pubkey} && !ref($client->{authority_pubkey}) && length($client->{authority_pubkey})))
  {
    return;
  }

  return $client->{authority_pubkey};
}

sub _effective_authoritative_actor_pubkey_from_event {
  my ($self, $event) = @_;
  if (!(ref($event) eq 'HASH')) {
    return;
  }

  my %tags = $self->_first_tag_values($event->{tags});
  return $tags{overnet_actor}
    if defined $tags{overnet_actor}
    && !ref($tags{overnet_actor})
    && $tags{overnet_actor} =~ /\A[0-9a-f]{64}\z/mxs;
  return $event->{pubkey}
    if defined $event->{pubkey}
    && !ref($event->{pubkey})
    && $event->{pubkey} =~ /\A[0-9a-f]{64}\z/mxs;
  return;
}

sub _authoritative_grant_nick_map {
  my ($self) = @_;
  my $cache  = $self->{authoritative_grant_cache} ||= {};
  return $cache->{nick_by_pubkey}
    if ref($cache->{nick_by_pubkey}) eq 'HASH';

  my %nick_by_pubkey;
  for my $event (@{$self->_read_authoritative_grant_events}) {
    my $entry = $self->_authoritative_grant_nick_entry_from_event($event);
    if (!(ref($entry) eq 'HASH')) {
      next;
    }

    my $current = $nick_by_pubkey{$entry->{pubkey}};
    if ($current
      && (($current->{created_at} || 0) > $entry->{created_at})) {
      next;
    }

    $nick_by_pubkey{$entry->{pubkey}} = {
      nick       => $entry->{nick},
      created_at => $entry->{created_at},
    };
  }

  $cache->{nick_by_pubkey} = \%nick_by_pubkey;
  return $cache->{nick_by_pubkey};
}

sub _authoritative_grant_nick_entry_from_event {
  my ($self, $event) = @_;
  if (!(ref($event) eq 'HASH')) {
    return;
  }
  if (!(($event->{kind} || 0) == $self->_authority_grant_kind)) {
    return;
  }
  if (!_hex_pubkey($event->{pubkey})) {
    return;
  }

  my %tags = $self->_first_tag_values($event->{tags});
  if (!(defined $tags{relay} && $tags{relay} eq $self->_authority_relay_url)) {
    return;
  }
  if (_authoritative_grant_is_expired($tags{expires_at})) {
    return;
  }
  if (!_nonempty_scalar($tags{nick})) {
    return;
  }

  return {
    pubkey     => $event->{pubkey},
    nick       => $tags{nick},
    created_at => $event->{created_at} || 0,
  };
}

sub _authoritative_grant_is_expired {
  my ($expires_at) = @_;
  if (!(defined $expires_at && $expires_at =~ /\A\d+\z/mxs)) {
    return 0;
  }
  return $expires_at < time() ? 1 : 0;
}

sub _hex_pubkey {
  my ($value) = @_;
  return 0 if !defined $value;
  return 0 if ref($value);
  return $value =~ /\A[0-9a-f]{64}\z/mxs ? 1 : 0;
}

sub _authoritative_nick_for_pubkey {
  my ($self, $pubkey) = @_;
  if (!(defined $pubkey && !ref($pubkey) && $pubkey =~ /\A[0-9a-f]{64}\z/mxs)) {
    return;
  }

  for my $client_id (sort keys %{$self->{clients}}) {
    my $client = $self->{clients}{$client_id};
    if (!(ref($client) eq 'HASH' && $client->{registered})) {
      next;
    }

    if (!(defined $client->{nick} && !ref($client->{nick}) && length($client->{nick}))) {
      next;
    }

    my $client_pubkey = $self->_client_authoritative_pubkey($client);
    if (!(defined $client_pubkey && $client_pubkey eq $pubkey)) {
      next;
    }

    return $client->{nick};
  }

  my $nick_map = $self->_authoritative_grant_nick_map;
  if (!(ref($nick_map) eq 'HASH')) {
    return;
  }

  return $nick_map->{$pubkey}{nick}
    if ref($nick_map->{$pubkey}) eq 'HASH';
  return;
}

sub _authoritative_member_for_pubkey {
  my ($self, $state, $pubkey, %args) = @_;
  if (!(ref($state) eq 'HASH')) {
    return;
  }

  if (!(defined $pubkey && !ref($pubkey) && length($pubkey))) {
    return;
  }

  my $field =
       defined $args{field}
    && !ref($args{field})
    && length($args{field})
    ? $args{field}
    : 'members';

  for my $member (@{$state->{$field} || []}) {
    if (!(ref($member) eq 'HASH')) {
      next;
    }

    if (!(defined $member->{pubkey})) {
      next;
    }

    return $member if $member->{pubkey} eq $pubkey;
  }

  return;
}

sub _authoritative_roles_for_client {
  my ($self, $channel, $client) = @_;
  my $pubkey = $self->_client_authoritative_pubkey($client);
  if (!(defined $pubkey)) {
    return ();
  }

  my $state = $self->_authoritative_channel_state_for_enforcement($channel);
  if (!(ref($state) eq 'HASH')) {
    return ();
  }

  my $member = $self->_authoritative_member_for_pubkey($state, $pubkey);
  if (!(ref($member) eq 'HASH')) {
    return ();
  }

  return @{$member->{roles} || []};
}

sub _authoritative_retained_roles_for_client {
  my ($self, $channel, $client) = @_;
  my $pubkey = $self->_client_authoritative_pubkey($client);
  if (!(defined $pubkey)) {
    return ();
  }

  my $state = $self->_authoritative_channel_state_for_enforcement($channel);
  if (!(ref($state) eq 'HASH')) {
    return ();
  }

  my $member = $self->_authoritative_member_for_pubkey($state, $pubkey, field => 'retained_members',);
  if (!(ref($member) eq 'HASH')) {
    return ();
  }

  return @{$member->{roles} || []};
}

sub _client_is_authoritative_operator {
  my ($self, $channel, $client) = @_;
  return scalar grep { $_ eq 'irc.operator' } $self->_authoritative_roles_for_client($channel, $client);
}

sub _client_is_retained_authoritative_operator {
  my ($self, $channel, $client) = @_;
  return scalar grep { $_ eq 'irc.operator' } $self->_authoritative_retained_roles_for_client($channel, $client);
}

sub _client_has_authoritative_voice {
  my ($self, $channel, $client) = @_;
  return scalar grep { $_ eq 'irc.voice' } $self->_authoritative_roles_for_client($channel, $client);
}

sub _channel_mode_enabled {
  my ($self, $state, $mode_letter) = @_;
  if (!(ref($state) eq 'HASH')) {
    return 0;
  }

  if (!(defined $mode_letter && !ref($mode_letter) && length($mode_letter) == 1)) {
    return 0;
  }

  my $channel_modes = $state->{channel_modes} || q{};
  return $channel_modes =~ /\Q$mode_letter\E/mxs ? 1 : 0;
}

sub _authoritative_channel_state_for_enforcement {
  my ($self, $channel) = @_;
  my $state = $self->_derive_authoritative_channel_state($channel);
  return $state if ref($state) eq 'HASH';
  return $self->_derive_authoritative_channel_state($channel, force => 1);
}

sub _channel_is_moderated_for_client {
  my ($self, $channel, $client) = @_;
  my $state = $self->_authoritative_channel_state_for_enforcement($channel);
  if (!(ref($state) eq 'HASH')) {
    return 0;
  }

  if (!($self->_channel_mode_enabled($state, 'm'))) {
    return 0;
  }

  return 0 if $self->_client_is_authoritative_operator($channel, $client);
  return 0 if $self->_client_has_authoritative_voice($channel, $client);
  return 1;
}

sub _channel_is_topic_restricted_for_client {
  my ($self, $channel, $client) = @_;
  my $state = $self->_authoritative_channel_state_for_enforcement($channel);
  if (!(ref($state) eq 'HASH')) {
    return 0;
  }

  if (!($self->_channel_mode_enabled($state, 't'))) {
    return 0;
  }

  return 0 if $self->_client_is_authoritative_operator($channel, $client);
  return 1;
}

sub _authoritative_group_metadata_from_state {
  my ($self, $state) = @_;
  return {
    closed           => $self->_channel_mode_enabled($state, 'i') ? 1 : 0,
    moderated        => $self->_channel_mode_enabled($state, 'm') ? 1 : 0,
    topic_restricted => $self->_channel_mode_enabled($state, 't') ? 1 : 0,
    ban_masks        => ref($state->{ban_masks}) eq 'ARRAY'       ? [@{$state->{ban_masks}}]
    : [],
    (
      ref($state->{exception_masks}) eq 'ARRAY'
        && @{$state->{exception_masks}} ? (exception_masks => [@{$state->{exception_masks}}])
      : ()
    ),
    (
      ref($state->{invite_exception_masks}) eq 'ARRAY'
        && @{$state->{invite_exception_masks}} ? (invite_exception_masks => [@{$state->{invite_exception_masks}}])
      : ()
    ),
    (
      defined($state->{channel_key}) ? (channel_key => $state->{channel_key})
      : ()
    ),
    (
      defined($state->{user_limit}) ? (user_limit => $state->{user_limit})
      : ()
    ),
    ($state->{private}    ? (private    => 1) : ()),
    ($state->{restricted} ? (restricted => 1) : ()),
    ($state->{hidden}     ? (hidden     => 1) : ()),
    tombstoned => $state->{tombstoned} ? 1 : 0,
    (exists($state->{topic}) ? (topic => $state->{topic}) : ()),
  };
}

sub _authoritative_irc_mask_for_client {
  my ($self, $client) = @_;
  if (!(ref($client) eq 'HASH')) {
    return;
  }

  if (!(defined $client->{nick} && !ref($client->{nick}) && length($client->{nick}))) {
    return;
  }

  my $username =
       defined $client->{username}
    && !ref($client->{username})
    && length($client->{username})
    ? $client->{username}
    : $client->{nick};
  my $host = $self->_presentational_host_for_client($client);

  return Overnet::Authority::HostedChannel::irc_user_mask(
    nick => $client->{nick},
    user => $username,
    host => $host,
  );
}

sub _authoritative_topic_line_from_view {
  my ($self, $channel, $view) = @_;
  if (!(ref($view) eq 'HASH')) {
    return;
  }

  if (!(exists $view->{topic})) {
    return;
  }

  my $display_channel = $self->_canonical_channel_name($channel);
  if (!(defined $display_channel)) {
    return;
  }

  my $prefix = $self->{config}{server_name};
  if ( defined $view->{topic_actor_pubkey}
    && !ref($view->{topic_actor_pubkey})
    && $view->{topic_actor_pubkey} =~ /\A[0-9a-f]{64}\z/mxs) {
    $prefix = $self->_authoritative_nick_for_pubkey($view->{topic_actor_pubkey})
      || $prefix;
  }

  return sprintf(':%s TOPIC %s :%s', $prefix, $display_channel, $view->{topic});
}

sub _sync_authoritative_topic_state_from_view {
  my ($self, $channel, $view) = @_;
  my $display_channel = $self->_canonical_channel_name($channel);
  if (!(defined $display_channel)) {
    return 0;
  }

  my $channel_key = $self->_channel_key($display_channel);
  if (!(defined $channel_key)) {
    return 0;
  }

  if (ref($view) eq 'HASH' && $view->{tombstoned}) {
    if (exists $self->{channels}{$channel_key}) {
      $self->{channels}{$channel_key}{topic_text} = undef;
      $self->{channels}{$channel_key}{topic_line} = undef;
    }
    return 1;
  }

  my $state = $self->_channel_state($display_channel);
  if (ref($view) eq 'HASH' && exists $view->{topic}) {
    $state->{topic_text} = $view->{topic};
    $state->{topic_line} = $self->_authoritative_topic_line_from_view($display_channel, $view);
  } else {
    $state->{topic_text} = undef;
    $state->{topic_line} = undef;
  }

  return 1;
}

sub _apply_authoritative_channel_tombstone {
  my ($self, $channel, %args) = @_;
  my $display_channel = $self->_canonical_channel_name($channel);
  if (!(defined $display_channel)) {
    return 0;
  }

  my $reason =
       defined($args{reason})
    && !ref($args{reason})
    && length($args{reason})
    ? $args{reason}
    : 'channel deleted';
  my $channel_key = $self->_channel_key($display_channel);
  if (!(defined $channel_key)) {
    return 0;
  }

  $self->_forget_authoritative_discovered_channel($display_channel);

  my $state = $self->{channels}{$channel_key};
  if (!(ref($state) eq 'HASH')) {
    $self->_close_channel_subscription($display_channel);
    return 1;
  }

  my @client_ids = grep { exists $self->{clients}{$_} }
    sort keys %{$state->{members} || {}};
  for my $client_id (@client_ids) {
    my $client = $self->{clients}{$client_id};
    if (!(ref($client) eq 'HASH')) {
      next;
    }

    my $nick =
         defined $client->{nick}
      && !ref($client->{nick})
      && length($client->{nick})
      ? $client->{nick}
      : $self->{config}{server_name};
    my $line = sprintf(':%s PART %s', $nick, $display_channel);
    $line .= ' :' . $reason;
    $self->_broadcast_channel_line($display_channel, $line);
    $self->_remove_client_from_channel($client_id, $display_channel, nick => $nick,);
  }

  if (exists $self->{channels}{$channel_key}) {
    $self->_close_channel_subscription($display_channel);
    delete $self->{channels}{$channel_key};
  }

  return 1;
}

sub _authoritative_join_admission_for_client {
  my ($self, $channel, $client, %args) = @_;
  my $pubkey     = $self->_client_authoritative_pubkey($client);
  my $actor_mask = $self->_authoritative_irc_mask_for_client($client);
  my $join_key   = $args{join_key};

  my $events          = $self->_read_authoritative_join_events($channel);
  my $empty_admission = $self->_empty_authoritative_join_admission($channel, $pubkey, $events);
  if (defined $empty_admission) {
    return $empty_admission;
  }

  my $admission = $self->_derive_join_admission_for_actor(
    channel    => $channel,
    pubkey     => $pubkey,
    actor_mask => $actor_mask,
    join_key   => $join_key,
  );
  if (!$self->_authoritative_join_admission_is_populated($admission)) {
    $admission = $self->_derive_join_admission_for_actor(
      channel    => $channel,
      pubkey     => $pubkey,
      actor_mask => $actor_mask,
      join_key   => $join_key,
      force      => 1,
    );
  }

  $admission = $self->_refresh_relay_invite_join_admission(
    admission  => $admission,
    channel    => $channel,
    pubkey     => $pubkey,
    actor_mask => $actor_mask,
    join_key   => $join_key,
  );
  if (!$self->_authoritative_join_admission_is_populated($admission)) {
    $admission = $self->_fallback_authoritative_join_admission(
      channel    => $channel,
      pubkey     => $pubkey,
      actor_mask => $actor_mask,
    );
  }

  return _normalized_authoritative_join_admission($admission, $pubkey);
}

sub _read_authoritative_join_events {
  my ($self, $channel) = @_;
  my $canonical = $self->_canonical_channel_name($channel);
  my $cache =
    defined $canonical
    ? $self->{authoritative_channel_cache}{$canonical}
    : undef;
  my $events =
      $self->_authority_relay_enabled && !(ref($cache) eq 'HASH' && ref($cache->{events}) eq 'ARRAY')
    ? $self->_read_authoritative_nip29_events($channel, force => 1)
    : $self->_read_authoritative_nip29_events($channel);
  if ( ref($events) eq 'ARRAY'
    && !@{$events}
    && $self->_authority_relay_enabled
    && ref($cache) eq 'HASH') {
    return $self->_read_authoritative_nip29_events($channel, force => 1);
  }
  return $events;
}

sub _empty_authoritative_join_admission {
  my ($self, $channel, $pubkey, $events) = @_;
  if (!(ref($events) eq 'ARRAY' && !@{$events})) {
    return;
  }

  if ($self->_authoritative_channel_is_known($channel)) {
    return {
      allowed        => 0,
      create_channel => 0,
      auth_required  => 0,
      reason         => 'authoritative state unavailable',
    };
  }

  return {
    allowed        => $pubkey ? 1 : 0,
    create_channel => $pubkey ? 1 : 0,
    auth_required  => $pubkey ? 0 : 1,
    reason         => q{},
  };
}

sub _derive_join_admission_for_actor {
  my ($self, %args) = @_;
  if (!(defined $args{pubkey})) {
    return $self->_derive_authoritative_join_admission($args{channel}, ($args{force} ? (force => 1) : ()),);
  }

  return $self->_derive_authoritative_join_admission(
    $args{channel},
    _join_admission_actor_args(%args),
    ($args{force} ? (force => 1) : ()),
  );
}

sub _join_admission_actor_args {
  my (%args) = @_;
  return (
    actor_pubkey => $args{pubkey},
    actor_mask   => $args{actor_mask},
    (
      defined($args{join_key})
      ? (extra_input => {join_key => $args{join_key}})
      : ()
    ),
    reconcile_pending_invites => 1,
  );
}

sub _refresh_relay_invite_join_admission {
  my ($self, %args) = @_;
  my $admission = $args{admission};
  if (!$self->_needs_relay_invite_join_refresh($admission, $args{pubkey})) {
    return $admission;
  }

  my $refreshed_admission = $self->_derive_join_admission_for_actor(%args, force => 1);
  if ($self->_authoritative_join_admission_is_populated($refreshed_admission)) {
    return $refreshed_admission;
  }
  return $admission;
}

sub _needs_relay_invite_join_refresh {
  my ($self, $admission, $pubkey) = @_;
  return 0 if !$self->_authority_relay_enabled;
  return 0 if !defined $pubkey;
  return 0 if !(ref($admission) eq 'HASH');
  return 0 if $admission->{allowed};
  return 0 if (($admission->{reason} || q{}) ne '+i');
  return 0 if defined $admission->{invite_code};
  return 1;
}

sub _normalized_authoritative_join_admission {
  my ($admission, $pubkey) = @_;
  if (ref($admission) ne 'HASH') {
    return {
      allowed       => 0,
      auth_required => $pubkey ? 0 : 1,
      reason        => q{},
    };
  }

  return {
    allowed => $admission->{allowed} ? 1 : 0,
    (
      defined $admission->{member}
      ? (member => $admission->{member} ? 1 : 0)
      : ()
    ),
    (
      defined $admission->{present}
      ? (present => $admission->{present} ? 1 : 0)
      : ()
    ),
    (
      defined $admission->{invite_code}
      ? (invite_code => $admission->{invite_code})
      : ()
    ),
    (
      defined $admission->{deleted}
      ? (deleted => $admission->{deleted} ? 1 : 0)
      : ()
    ),
    (
      defined $admission->{create_channel}
      ? (create_channel => $admission->{create_channel} ? 1 : 0)
      : ()
    ),
    (
      defined $admission->{auth_required}
      ? (auth_required => $admission->{auth_required} ? 1 : 0)
      : ()
    ),
    (
      defined $admission->{request_join}
      ? (request_join => $admission->{request_join} ? 1 : 0)
      : ()
    ),
    (
      defined $admission->{pending_request}
      ? (pending_request => $admission->{pending_request} ? 1 : 0)
      : ()
    ),
    reason => defined $admission->{reason} ? $admission->{reason} : q{},
  };
}

sub _fallback_authoritative_join_admission {
  my ($self, %args) = @_;
  my $channel    = $args{channel};
  my $pubkey     = $args{pubkey};
  my $actor_mask = $args{actor_mask};

  if (defined $pubkey) {
    my $view = $self->_derive_authoritative_channel_view(
      $channel,
      actor_pubkey              => $pubkey,
      actor_mask                => $actor_mask,
      reconcile_pending_invites => 1,
    );
    if (ref($view) ne 'HASH') {
      $view = $self->_derive_authoritative_channel_view(
        $channel,
        force                     => 1,
        actor_pubkey              => $pubkey,
        actor_mask                => $actor_mask,
        reconcile_pending_invites => 1,
      );
    }
    return $self->_join_admission_from_authoritative_view($view, $pubkey);
  }

  my $view = $self->_derive_authoritative_channel_view($channel);
  if (ref($view) ne 'HASH') {
    $view = $self->_derive_authoritative_channel_view($channel, force => 1);
  }
  return $self->_join_admission_from_authoritative_view($view, undef);
}

sub _join_admission_from_authoritative_view {
  my ($self, $view, $pubkey) = @_;

  if (ref($view) eq 'HASH' && ref($view->{admission}) eq 'HASH') {
    return _join_admission_from_view_admission($view, $pubkey);
  }

  if (ref($view) eq 'HASH' && $view->{tombstoned}) {
    return {
      allowed => 0,
      deleted => 1,
      reason  => 'deleted',
    };
  }

  if (ref($view) eq 'HASH') {
    return $self->_join_admission_from_view_state($view);
  }

  return;
}

sub _join_admission_from_view_admission {
  my ($view, $pubkey) = @_;
  my $admission = $view->{admission};
  my $present =
    scalar grep { ref eq 'HASH' && defined($_->{pubkey}) && $_->{pubkey} eq $pubkey } @{$view->{present_members} || []};
  return {
    allowed => $admission->{allowed} ? 1 : 0,
    (
      defined $admission->{member}
      ? (member => $admission->{member} ? 1 : 0)
      : ()
    ),
    (
      defined $admission->{invite_code}
      ? (invite_code => $admission->{invite_code})
      : ()
    ),
    (
      defined $admission->{deleted}
      ? (deleted => $admission->{deleted} ? 1 : 0)
      : ()
    ),
    (
      defined $admission->{request_join}
      ? (request_join => $admission->{request_join} ? 1 : 0)
      : ()
    ),
    (
      defined $admission->{pending_request}
      ? (pending_request => $admission->{pending_request} ? 1 : 0)
      : ()
    ),
    present => $present                     ? 1                    : 0,
    reason  => defined $admission->{reason} ? $admission->{reason} : q{},
  };
}

sub _join_admission_from_view_state {
  my ($self, $view) = @_;
  my $state       = $self->_authoritative_channel_state_from_view($view);
  my $invite_only = $self->_channel_mode_enabled($state, 'i') ? 1 : 0;
  return {
    allowed => $invite_only ? 0 : 1,
    present => 0,
    reason  => $invite_only ? '+i' : q{},
  };
}

sub _authoritative_speak_permission_for_client {
  my ($self, $channel, $client) = @_;
  my $pubkey = $self->_client_authoritative_pubkey($client);
  if (!defined $pubkey) {
    return {
      allowed => $self->_channel_is_moderated_for_client($channel, $client) ? 0
      : 1,
      reason => $self->_channel_is_moderated_for_client($channel, $client) ? '+m'
      : q{},
    };
  }

  my $permission = $self->_derive_authoritative_speak_permission($channel, actor_pubkey => $pubkey,);
  if (!$self->_authoritative_permission_is_populated($permission)) {
    $permission = $self->_derive_authoritative_speak_permission(
      $channel,
      force        => 1,
      actor_pubkey => $pubkey,
    );
  }

  if ($self->_authoritative_permission_is_populated($permission)
    && (($permission->{reason} || q{}) ne 'authoritative state unavailable')) {
    return {
      allowed => $permission->{allowed} ? 1 : 0,
      reason  => defined $permission->{reason}
      ? $permission->{reason}
      : q{},
    };
  }

  return {
    allowed => $self->_channel_is_moderated_for_client($channel, $client) ? 0
    : 1,
    reason => $self->_channel_is_moderated_for_client($channel, $client) ? '+m'
    : q{},
  };
}

sub _authoritative_topic_permission_for_client {
  my ($self, $channel, $client) = @_;
  my $pubkey = $self->_client_authoritative_pubkey($client);
  if (!defined $pubkey) {
    return {
      allowed => $self->_channel_is_topic_restricted_for_client($channel, $client) ? 0    : 1,
      reason  => $self->_channel_is_topic_restricted_for_client($channel, $client) ? '+t' : q{},
    };
  }

  my $permission = $self->_derive_authoritative_topic_permission($channel, actor_pubkey => $pubkey,);
  if (!$self->_authoritative_permission_is_populated($permission)) {
    $permission = $self->_derive_authoritative_topic_permission(
      $channel,
      force        => 1,
      actor_pubkey => $pubkey,
    );
  }

  if ($self->_authoritative_permission_is_populated($permission)
    && (($permission->{reason} || q{}) ne 'authoritative state unavailable')) {
    return {
      allowed => $permission->{allowed} ? 1 : 0,
      reason  => defined $permission->{reason}
      ? $permission->{reason}
      : q{},
    };
  }

  return {
    allowed => $self->_channel_is_topic_restricted_for_client($channel, $client) ? 0
    : 1,
    reason => $self->_channel_is_topic_restricted_for_client($channel, $client) ? '+t'
    : q{},
  };
}

sub _authoritative_mode_write_permission_for_client {
  my ($self, $channel, $client, %args) = @_;
  my $pubkey    = $self->_client_authoritative_pubkey($client);
  my $mode      = $args{mode};
  my $mode_args = ref($args{mode_args}) eq 'ARRAY' ? $args{mode_args} : [];

  my $derived = $self->_derived_authoritative_mode_write_permission($channel, $pubkey, $mode, $mode_args);
  if (defined $derived) {
    return $derived;
  }

  my $state      = $self->_authoritative_channel_state_for_enforcement($channel);
  my $permission = $self->_fallback_authoritative_mode_write_permission($channel, $client, $pubkey, $state);
  if (!($permission->{allowed})) {
    return $permission;
  }

  $self->_add_authoritative_mode_permission_details($permission, $state, $mode, $mode_args);
  return $permission;
}

sub _derived_authoritative_mode_write_permission {
  my ($self, $channel, $pubkey, $mode, $mode_args) = @_;
  if (!(defined $pubkey)) {
    return;
  }

  my $permission = $self->_derive_authoritative_mode_write_permission(
    $channel,
    actor_pubkey => $pubkey,
    mode         => $mode,
    mode_args    => $mode_args,
  );
  if (!$self->_authoritative_permission_is_populated($permission)) {
    $permission = $self->_derive_authoritative_mode_write_permission(
      $channel,
      force        => 1,
      actor_pubkey => $pubkey,
      mode         => $mode,
      mode_args    => $mode_args,
    );
  }

  if (!_usable_authoritative_permission($self, $permission)) {
    return;
  }
  return _normalized_authoritative_mode_permission($permission);
}

sub _fallback_authoritative_mode_write_permission {
  my ($self, $channel, $client, $pubkey, $state) = @_;
  if (ref($state) ne 'HASH') {
    return {
      allowed => 0,
      reason  => 'state_unavailable',
    };
  }
  if ($state->{tombstoned}) {
    return {
      allowed => 0,
      reason  => 'deleted',
    };
  }
  if (!(defined($pubkey) && $self->_client_is_authoritative_operator($channel, $client))) {
    return {
      allowed => 0,
      reason  => 'not_operator',
    };
  }
  return {
    allowed => 1,
    reason  => q{},
  };
}

sub _normalized_authoritative_mode_permission {
  my ($permission) = @_;
  return {
    allowed => $permission->{allowed}         ? 1 : 0,
    reason  => defined($permission->{reason}) ? $permission->{reason}
    : q{},
    (
      defined $permission->{target_pubkey} ? (target_pubkey => $permission->{target_pubkey})
      : ()
    ),
    (
      ref($permission->{current_roles}) eq 'ARRAY' ? (current_roles => [@{$permission->{current_roles}}])
      : ()
    ),
    (
      defined $permission->{normalized_ban_mask} ? (normalized_ban_mask => $permission->{normalized_ban_mask})
      : ()
    ),
    (
      defined $permission->{normalized_exception_mask}
      ? (normalized_exception_mask => $permission->{normalized_exception_mask})
      : ()
    ),
    (
      defined $permission->{normalized_invite_exception_mask}
      ? (normalized_invite_exception_mask => $permission->{normalized_invite_exception_mask})
      : ()
    ),
    (
      defined $permission->{channel_key} ? (channel_key => $permission->{channel_key})
      : ()
    ),
    (
      defined $permission->{user_limit} ? (user_limit => $permission->{user_limit})
      : ()
    ),
    (
      ref($permission->{group_metadata}) eq 'HASH' ? (group_metadata => {%{$permission->{group_metadata}}})
      : ()
    ),
  };
}

sub _usable_authoritative_permission {
  my ($self, $permission) = @_;
  return 0 if !$self->_authoritative_permission_is_populated($permission);
  return 0
    if (($permission->{reason} || q{}) eq 'authoritative state unavailable');
  return 1;
}

sub _add_authoritative_mode_permission_details {
  my ($self, $permission, $state, $mode, $mode_args) = @_;
  my $argument = $mode_args->[0];
  return $self->_add_authoritative_role_mode_permission($permission, $state, $mode, $argument)
    if $mode =~ /\A[+-][ov]\z/mxs && defined($argument);
  return $self->_add_authoritative_mask_mode_permission($permission, $state, $mode, $argument)
    if $mode =~ /\A[+-][beI]\z/mxs && defined($argument);
  return $self->_add_authoritative_key_limit_mode_permission($permission, $state, $mode, $argument)
    if $mode =~ /\A(?:[+]k|[+]l)\z/mxs && defined($argument);
  return $self->_add_authoritative_metadata_mode_permission($permission, $state)
    if $mode eq '-k' || $mode eq '-l' || $mode =~ /\A[+-][imt]\z/mxs;
  return 1;
}

sub _add_authoritative_role_mode_permission {
  my ($self, $permission, $state, $mode, $target_pubkey) = @_;
  my $member = $self->_authoritative_member_for_pubkey($state, $target_pubkey) || {};
  $permission->{target_pubkey} = $target_pubkey;
  $permission->{current_roles} = [@{$member->{roles} || []}];
  return 1;
}

sub _add_authoritative_mask_mode_permission {
  my ($self, $permission, $state, $mode, $mask) = @_;
  my %field_by_mode;
  $field_by_mode{b} = 'normalized_ban_mask';
  $field_by_mode{e} = 'normalized_exception_mask';
  $field_by_mode{I} = 'normalized_invite_exception_mask';
  my ($mode_letter) = $mode =~ /\A[+-]([beI])\z/mxs;
  if (defined $mode_letter) {
    $permission->{$field_by_mode{$mode_letter}} = $mask;
    $permission->{group_metadata} = $self->_authoritative_group_metadata_from_state($state);
  }
  return 1;
}

sub _add_authoritative_key_limit_mode_permission {
  my ($self, $permission, $state, $mode, $argument) = @_;
  if ($mode eq '+k') {
    $permission->{channel_key} = $argument;
  }
  if ($mode eq '+l') {
    $permission->{user_limit} = 0 + $argument;
  }
  return $self->_add_authoritative_metadata_mode_permission($permission, $state);
}

sub _add_authoritative_metadata_mode_permission {
  my ($self, $permission, $state) = @_;
  $permission->{group_metadata} = $self->_authoritative_group_metadata_from_state($state);
  return 1;
}

sub _authoritative_channel_action_permission_for_client {
  my ($self, $channel, $client, %args) = @_;
  my $pubkey = $self->_client_authoritative_pubkey($client);
  my $action = $args{action};

  my $derived = $self->_derived_authoritative_channel_action_permission($channel, $pubkey, $action, %args);
  if (defined $derived) {
    return $derived;
  }

  my $state = $self->_authoritative_channel_state_for_enforcement($channel);
  if (ref($state) ne 'HASH') {
    return {
      allowed => 0,
      reason  => 'state_unavailable',
    };
  }

  if (($action || q{}) eq 'undelete') {
    return $self->_fallback_authoritative_undelete_permission($channel, $client, $pubkey, $state);
  }

  return $self->_fallback_authoritative_channel_action_permission($channel, $client, $pubkey, $state, %args);
}

sub _derived_authoritative_channel_action_permission {
  my ($self, $channel, $pubkey, $action, %args) = @_;
  if (!(defined $pubkey)) {
    return;
  }

  my @target_args =
    defined $args{target_pubkey}
    ? (target_pubkey => $args{target_pubkey})
    : ();
  my $permission = $self->_derive_authoritative_channel_action_permission(
    $channel,
    actor_pubkey => $pubkey,
    action       => $action,
    @target_args,
  );
  if (!$self->_authoritative_permission_is_populated($permission)) {
    $permission = $self->_derive_authoritative_channel_action_permission(
      $channel,
      force        => 1,
      actor_pubkey => $pubkey,
      action       => $action,
      @target_args,
    );
  }

  if (!_usable_authoritative_permission($self, $permission)) {
    return;
  }
  return _normalized_authoritative_channel_action_permission($permission);
}

sub _normalized_authoritative_channel_action_permission {
  my ($permission) = @_;
  return {
    allowed => $permission->{allowed}         ? 1 : 0,
    reason  => defined($permission->{reason}) ? $permission->{reason}
    : q{},
    (
      defined $permission->{target_pubkey} ? (target_pubkey => $permission->{target_pubkey})
      : ()
    ),
    (
      ref($permission->{group_metadata}) eq 'HASH' ? (group_metadata => {%{$permission->{group_metadata}}})
      : ()
    ),
  };
}

sub _fallback_authoritative_undelete_permission {
  my ($self, $channel, $client, $pubkey, $state) = @_;
  if (!$state->{tombstoned}) {
    return {
      allowed => 0,
      reason  => 'not_deleted',
    };
  }
  if (!(defined($pubkey) && $self->_client_is_retained_authoritative_operator($channel, $client))) {
    return {
      allowed => 0,
      reason  => 'not_operator',
    };
  }
  return {
    allowed        => 1,
    reason         => q{},
    group_metadata => $self->_authoritative_group_metadata_from_state($state),
  };
}

sub _fallback_authoritative_channel_action_permission {
  my ($self, $channel, $client, $pubkey, $state, %args) = @_;
  if ($state->{tombstoned}) {
    return {
      allowed => 0,
      reason  => 'deleted',
    };
  }
  if (!(defined($pubkey) && $self->_client_is_authoritative_operator($channel, $client))) {
    return {
      allowed => 0,
      reason  => 'not_operator',
    };
  }
  return {
    allowed => 1,
    reason  => q{},
    (
      defined $args{target_pubkey} ? (target_pubkey => $args{target_pubkey})
      : ()
    ),
    (
        ($args{action} || q{}) eq 'delete' ? (group_metadata => $self->_authoritative_group_metadata_from_state($state))
      : ()
    ),
  };
}

sub _authoritative_name_entries_for_channel {
  my ($self, $client, $channel, %args) = @_;
  if (!(ref($client) eq 'HASH')) {
    return ();
  }

  my $view =
    ref($args{view}) eq 'HASH'
    ? $args{view}
    : $self->_derive_authoritative_channel_view($channel, ($args{force} ? (force => 1) : ()),);
  if (!(ref($view) eq 'HASH')) {
    return ();
  }

  my $channel_key = $self->_channel_key($channel);
  if (!(defined $channel_key)) {
    return ();
  }

  my $channel_state = $self->{channels}{$channel_key}
    or return ();

  my @entries;
  my %seen;
  my $state   = $self->_authoritative_channel_state_from_view($view);
  my %present = _present_authoritative_members_by_pubkey($view);
  $self->_add_local_authoritative_name_entries(\@entries, \%seen, $channel_state, $state);
  $self->_add_present_authoritative_name_entries(\@entries, \%seen, $state, \%present);
  $self->_add_visible_name_entries(\@entries, \%seen, $channel);
  $self->_add_self_name_entry_if_empty(\@entries, $client, $channel);

  return map { $_->{display} }
    sort { $a->{nick} cmp $b->{nick} } @entries;
}

sub _present_authoritative_members_by_pubkey {
  my ($view) = @_;
  return map { ($_->{pubkey} => $_) }
    grep { ref eq 'HASH' && defined($_->{pubkey}) } @{$view->{present_members} || []};
}

sub _add_local_authoritative_name_entries {
  my ($self, $entries, $seen, $channel_state, $state) = @_;
  for my $client_id (sort keys %{$channel_state->{members} || {}}) {
    if (!(exists $self->{clients}{$client_id})) {
      next;
    }

    my $member_client = $self->{clients}{$client_id};
    if (!($member_client->{registered})) {
      next;
    }

    if (!(defined $member_client->{nick} && !ref($member_client->{nick}) && length($member_client->{nick}))) {
      next;
    }

    my $pubkey = $self->_client_authoritative_pubkey($member_client);
    my $member =
      defined $pubkey
      ? $self->_authoritative_member_for_pubkey($state, $pubkey)
      : undef;
    my $prefix =
      ref($member) eq 'HASH'
      ? ($member->{presentational_prefix} || q{})
      : q{};

    push @{$entries},
      {
      nick    => $member_client->{nick},
      display => $prefix . $member_client->{nick},
      };
    $seen->{$member_client->{nick}} = 1;
  }
  return 1;
}

sub _add_present_authoritative_name_entries {
  my ($self, $entries, $seen, $state, $present) = @_;
  for my $member (@{$state->{members} || []}) {
    if (!(ref($member) eq 'HASH')) {
      next;
    }

    if (!(defined $member->{pubkey})) {
      next;
    }

    if (!($present->{$member->{pubkey}})) {
      next;
    }

    my $nick = $self->_authoritative_nick_for_pubkey($member->{pubkey});
    if (!(defined $nick && length($nick))) {
      next;
    }

    next if $seen->{$nick}++;

    push @{$entries},
      {
      nick    => $nick,
      display => ($member->{presentational_prefix} || q{}) . $nick,
      };
  }
  return 1;
}

sub _add_visible_name_entries {
  my ($self, $entries, $seen, $channel) = @_;
  for my $nick ($self->_visible_nicks_for_channel($channel)) {
    next if $seen->{$nick}++;
    push @{$entries},
      {
      nick    => $nick,
      display => $nick,
      };
  }
  return 1;
}

sub _add_self_name_entry_if_empty {
  my ($self, $entries, $client, $channel) = @_;
  if (@{$entries}) {
    return 1;
  }
  if (!(defined $self->_client_joined_channel_name($client, $channel))) {
    return 1;
  }

  push @{$entries},
    {
    nick    => $client->{nick},
    display => $client->{nick},
    };
  return 1;
}

sub _handle_authoritative_part_command {
  my ($self, %args) = @_;
  my $client_id = $args{client_id};
  my $channel   = $args{channel};
  my $reason    = $args{reason};
  my $client    = $self->{clients}{$client_id}
    or return 0;

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  if (!(defined $actor_pubkey)) {
    $self->_send_server_notice($client_id, 'OVERNETAUTH AUTH is required for authoritative PART');
    return 1;
  }

  if ($self->_authority_relay_enabled
    && !$self->_client_has_authoritative_delegation($client)) {
    $self->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE is required for authoritative PART');
    return 1;
  }

  my %input = (
    command      => 'PART',
    target       => $channel,
    actor_pubkey => $actor_pubkey,
    (defined $reason ? (text => $reason) : ()),
  );
  if ($self->_authority_relay_enabled) {
    if (!($self->_publish_authoritative_input($client, \%input))) {
      $self->_send_server_notice($client_id,
        $self->{authoritative_publish_error} || 'authoritative relay publish failed',
      );
      return 1;
    }
  } else {
    if (!($self->_emit_client_input($client, \%input))) {
      return 1;
    }

  }

  my $line = sprintf(':%s PART %s', $client->{nick}, $channel);
  if (defined $reason && length $reason) {
    $line .= ' :' . $reason;
  }

  $self->_broadcast_channel_line($channel, $line);
  $self->_remove_client_from_channel($client_id, $channel, nick => $client->{nick},);
  return 1;
}

sub _handle_authoritative_topic_command {
  my ($self, %args) = @_;
  my $client_id = $args{client_id};
  my $channel   = $args{channel};
  my $text      = $args{text};
  my $client    = $self->{clients}{$client_id}
    or return 0;

  my $state = $self->_authoritative_channel_state_for_enforcement($channel);
  if (!(ref($state) eq 'HASH')) {
    return $self->_send_chan_op_privs_needed($client_id, $channel);
  }

  if (!($self->_client_is_authoritative_operator($channel, $client))) {
    return $self->_send_chan_op_privs_needed($client_id, $channel);
  }

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  if (!(defined $actor_pubkey)) {
    return $self->_send_chan_op_privs_needed($client_id, $channel);
  }

  if ($self->_authority_relay_enabled
    && !$self->_client_has_authoritative_delegation($client)) {
    $self->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE is required for authoritative TOPIC');
    return 1;
  }

  my %input = (
    command        => 'TOPIC',
    target         => $channel,
    actor_pubkey   => $actor_pubkey,
    text           => $text,
    group_metadata => $self->_authoritative_group_metadata_from_state($state),
  );
  if ($self->_authority_relay_enabled) {
    if (!($self->_publish_authoritative_input($client, \%input))) {
      $self->_send_server_notice($client_id,
        $self->{authoritative_publish_error} || 'authoritative relay publish failed',
      );
      return 1;
    }
  } else {
    if (!($self->_emit_client_input($client, \%input))) {
      return 1;
    }

    $self->_refresh_authoritative_nip29_channel_cache($channel);
  }

  if (!$self->_authority_relay_enabled) {
    my $line = sprintf(':%s TOPIC %s :%s', $client->{nick}, $channel, $text);
    $self->_broadcast_channel_line($channel, $line);
    $self->_channel_state($channel)->{topic_text} = $text;
    $self->_channel_state($channel)->{topic_line} = $line;
  }
  return 1;
}

sub _handle_authoritative_delete_command {
  my ($self, %args) = @_;
  my $client_id = $args{client_id};
  my $channel   = $args{channel};
  my $client    = $self->{clients}{$client_id}
    or return 0;

  my $permission = $self->_authoritative_channel_action_permission_for_client($channel, $client, action => 'delete',);
  return $self->_send_no_such_channel($client_id, $channel)
    if (($permission->{reason} || q{}) eq 'deleted');
  if (!($permission->{allowed})) {
    return $self->_send_chan_op_privs_needed($client_id, $channel);
  }

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  my $group_metadata =
    ref($permission->{group_metadata}) eq 'HASH'
    ? $permission->{group_metadata}
    : undef;

  if ($self->_authority_relay_enabled
    && !$self->_client_has_authoritative_delegation($client)) {
    $self->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE is required for authoritative channel deletion');
    return 1;
  }

  my %input = (
    command        => 'DELETE',
    target         => $channel,
    actor_pubkey   => $actor_pubkey,
    group_metadata => $group_metadata,
  );
  if ($self->_authority_relay_enabled) {
    if (!($self->_publish_authoritative_input($client, \%input))) {
      $self->_send_server_notice($client_id,
        $self->{authoritative_publish_error} || 'authoritative relay publish failed',
      );
      return 1;
    }
  } else {
    if (!($self->_emit_client_input($client, \%input))) {
      return 1;
    }

    $self->_refresh_authoritative_nip29_channel_cache($channel);
  }

  $self->_send_server_notice($client_id, "OVERNETCHANNEL DELETE $channel");
  return 1;
}

sub _handle_authoritative_undelete_command {
  my ($self, %args) = @_;
  my $client_id = $args{client_id};
  my $channel   = $args{channel};
  my $client    = $self->{clients}{$client_id}
    or return 0;

  my $permission = $self->_authoritative_channel_action_permission_for_client($channel, $client, action => 'undelete',);
  return $self->_send_no_such_channel($client_id, $channel)
    if (($permission->{reason} || q{}) eq 'not_deleted');
  if (!($permission->{allowed})) {
    return $self->_send_chan_op_privs_needed($client_id, $channel);
  }

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  my $group_metadata =
    ref($permission->{group_metadata}) eq 'HASH'
    ? $permission->{group_metadata}
    : undef;

  if ($self->_authority_relay_enabled
    && !$self->_client_has_authoritative_delegation($client)) {
    $self->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE is required for authoritative channel undeletion');
    return 1;
  }

  my %input = (
    command        => 'UNDELETE',
    target         => $channel,
    actor_pubkey   => $actor_pubkey,
    group_metadata => $group_metadata,
  );
  if ($self->_authority_relay_enabled) {
    if (!($self->_publish_authoritative_input($client, \%input))) {
      $self->_send_server_notice($client_id,
        $self->{authoritative_publish_error} || 'authoritative relay publish failed',
      );
      return 1;
    }
  } else {
    if (!($self->_emit_client_input($client, \%input))) {
      return 1;
    }

    $self->_refresh_authoritative_nip29_channel_cache($channel);
  }

  $self->_send_server_notice($client_id, "OVERNETCHANNEL UNDELETE $channel");
  return 1;
}

sub _handle_authoritative_mode_command {
  my ($self, %args) = @_;
  my $client_id = $args{client_id};
  my $channel   = $args{channel};
  my @params    = @{$args{params} || []};
  my $client    = $self->{clients}{$client_id}
    or return 0;

  my $mode = $params[1];
  if (!(defined $mode && !ref($mode) && length($mode))) {
    return $self->_send_need_more_params($client_id, 'MODE');
  }

  my $state = $self->_authoritative_channel_state_for_enforcement($channel);
  if (!(ref($state) eq 'HASH')) {
    return $self->_send_chan_op_privs_needed($client_id, $channel);
  }

  my $list_result = $self->_handle_authoritative_mode_list_query($client_id, $channel, $mode, \@params, $state);
  if (defined $list_result) {
    return $list_result;
  }

  my $details = $self->_authoritative_mode_command_details($client_id, $client, $channel, $mode, \@params);
  if (!(ref($details) eq 'HASH')) {
    return 1;
  }

  my $permission = $self->_authoritative_mode_write_permission_for_client(
    $channel,
    $client,
    mode      => $mode,
    mode_args => $details->{mode_args},
  );
  my $permission_result = $self->_handle_authoritative_mode_permission_result($client_id, $channel, $permission);
  if (defined $permission_result) {
    return $permission_result;
  }

  if ($self->_authority_relay_enabled
    && !$self->_client_has_authoritative_delegation($client)) {
    $self->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE is required for authoritative MODE');
    return 1;
  }

  my $input = $self->_authoritative_mode_input($channel, $client, $mode, $permission);
  if (!($self->_write_authoritative_mode_input($client_id, $client, $input))) {
    return 1;
  }

  $self->_broadcast_channel_line($channel, $details->{mode_line});
  return 1;
}

sub _handle_authoritative_mode_list_query {
  my ($self, $client_id, $channel, $mode, $params, $state) = @_;
  if (_mode_has_argument($params)) {
    return;
  }

  if ($mode eq '+b') {
    return $self->_send_authoritative_ban_mode_list($client_id, $channel, $state);
  }
  if ($mode eq '+e') {
    return $self->_send_authoritative_exception_mode_list($client_id, $channel);
  }
  if ($mode eq '+I') {
    return $self->_send_authoritative_invite_exception_mode_list($client_id, $channel);
  }
  return;
}

sub _mode_has_argument {
  my ($params) = @_;
  return 0 if !(ref($params) eq 'ARRAY');
  return 0 if !defined $params->[2];
  return 0 if ref($params->[2]);
  return length($params->[2]) ? 1 : 0;
}

sub _send_authoritative_ban_mode_list {
  my ($self, $client_id, $channel, $state) = @_;
  my $ban_list_view = $self->_authoritative_ban_list_view_for_mode($channel);
  my $ban_masks =
    ref($ban_list_view) eq 'HASH' && ref($ban_list_view->{ban_masks}) eq 'ARRAY'
    ? $ban_list_view->{ban_masks}
    : $state->{ban_masks}
    || [];
  for my $ban_mask (@{$ban_masks}) {
    $self->_send_ban_list_entry($client_id, $channel, $ban_mask);
  }
  $self->_send_end_of_ban_list($client_id, $channel);
  return 1;
}

sub _authoritative_ban_list_view_for_mode {
  my ($self, $channel) = @_;
  my $ban_list_view =
    $self->_authority_relay_enabled
    ? eval { $self->_derive_authoritative_ban_list_view($channel, force => 1); }
    : $self->_derive_authoritative_ban_list_view($channel);
  if (!$self->_authority_relay_enabled && ref($ban_list_view) ne 'HASH') {
    return $self->_derive_authoritative_ban_list_view($channel, force => 1,);
  }
  return $ban_list_view;
}

sub _send_authoritative_exception_mode_list {
  my ($self, $client_id, $channel) = @_;
  my $view = $self->_authoritative_channel_view_for_mode_list($channel);
  for my $exception_mask (@{_view_array($view, 'exception_masks')}) {
    $self->_send_exception_list_entry($client_id, $channel, $exception_mask);
  }
  $self->_send_end_of_exception_list($client_id, $channel);
  return 1;
}

sub _send_authoritative_invite_exception_mode_list {
  my ($self, $client_id, $channel) = @_;
  my $view = $self->_authoritative_channel_view_for_mode_list($channel);
  for my $invite_exception_mask (@{_view_array($view, 'invite_exception_masks')}) {
    $self->_send_invite_exception_list_entry($client_id, $channel, $invite_exception_mask);
  }
  $self->_send_end_of_invite_exception_list($client_id, $channel);
  return 1;
}

sub _authoritative_channel_view_for_mode_list {
  my ($self, $channel) = @_;
  my $view =
    $self->_authority_relay_enabled
    ? eval { $self->_derive_authoritative_channel_view($channel, force => 1) }
    : $self->_derive_authoritative_channel_view($channel);
  if (!(ref($view) eq 'HASH')) {
    $view = $self->_cached_authoritative_channel_view($channel);
  }
  if (!$self->_authority_relay_enabled && ref($view) ne 'HASH') {
    return $self->_derive_authoritative_channel_view($channel, force => 1);
  }
  return $view;
}

sub _view_array {
  my ($view, $field) = @_;
  if (ref($view) eq 'HASH' && ref($view->{$field}) eq 'ARRAY') {
    return $view->{$field};
  }
  return [];
}

sub _authoritative_mode_command_details {
  my ($self, $client_id, $client, $channel, $mode, $params) = @_;
  if ($mode =~ /\A[+-][ov]\z/mxs) {
    return $self->_authoritative_role_mode_command_details($client_id, $client, $channel, $mode, $params);
  }
  if ($mode =~ /\A[+-][beIklimt]\z/mxs) {
    return $self->_authoritative_scalar_mode_command_details($client_id, $client, $channel, $mode, $params);
  }

  $self->_send_unknown_command($client_id, 'MODE');
  return;
}

sub _authoritative_role_mode_command_details {
  my ($self, $client_id, $client, $channel, $mode, $params) = @_;
  if (!_mode_has_argument($params)) {
    $self->_send_need_more_params($client_id, 'MODE');
    return;
  }

  my $target_nick_input = $params->[2];
  my $target_nick       = $self->_canonical_current_nick($target_nick_input);
  if (!(defined $target_nick)) {
    $self->_send_no_such_nick($client_id, $target_nick_input);
    return;
  }

  my $target_client = $self->_client_for_current_nick($target_nick);
  if (!(ref($target_client) eq 'HASH')) {
    $self->_send_no_such_nick($client_id, $target_nick_input);
    return;
  }

  my $target_pubkey = $self->_client_authoritative_pubkey($target_client);
  if (!(defined $target_pubkey)) {
    $self->_send_no_such_nick($client_id, $target_nick_input);
    return;
  }

  return _authoritative_mode_details($client, $channel, $mode, [$target_pubkey], $target_nick);
}

sub _authoritative_scalar_mode_command_details {
  my ($self, $client_id, $client, $channel, $mode, $params) = @_;
  if (_authoritative_mode_requires_text_arg($mode)) {
    return $self->_authoritative_text_arg_mode_details($client_id, $client, $channel, $mode, $params);
  }
  if ($mode eq '+l') {
    return $self->_authoritative_limit_mode_details($client_id, $client, $channel, $mode, $params);
  }
  return _authoritative_mode_details($client, $channel, $mode, [], undef);
}

sub _authoritative_mode_requires_text_arg {
  my ($mode) = @_;
  return 1 if $mode =~ /\A[+-][beI]\z/mxs;
  return 1 if $mode eq '+k';
  return 0;
}

sub _authoritative_text_arg_mode_details {
  my ($self, $client_id, $client, $channel, $mode, $params) = @_;
  if (!_mode_has_argument($params)) {
    $self->_send_need_more_params($client_id, 'MODE');
    return;
  }
  return _authoritative_mode_details($client, $channel, $mode, [$params->[2]], $params->[2]);
}

sub _authoritative_limit_mode_details {
  my ($self, $client_id, $client, $channel, $mode, $params) = @_;
  if (!_mode_has_argument($params) || $params->[2] !~ /\A[1-9][0-9]*\z/mxs) {
    $self->_send_need_more_params($client_id, 'MODE');
    return;
  }
  return _authoritative_mode_details($client, $channel, $mode, [$params->[2]], $params->[2]);
}

sub _authoritative_mode_details {
  my ($client, $channel, $mode, $mode_args, $display_arg) = @_;
  my $mode_line = sprintf(':%s MODE %s %s', $client->{nick}, $channel, $mode);
  if (defined $display_arg) {
    $mode_line .= q{ } . $display_arg;
  }
  return {
    mode_args => $mode_args,
    mode_line => $mode_line,
  };
}

sub _handle_authoritative_mode_permission_result {
  my ($self, $client_id, $channel, $permission) = @_;
  if (($permission->{reason} || q{}) eq 'deleted') {
    return $self->_send_no_such_channel($client_id, $channel);
  }
  if (!($permission->{allowed})) {
    return $self->_send_chan_op_privs_needed($client_id, $channel);
  }
  return;
}

sub _authoritative_mode_input {
  my ($self, $channel, $client, $mode, $permission) = @_;
  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  my %input        = (
    command      => 'MODE',
    target       => $channel,
    mode         => $mode,
    actor_pubkey => $actor_pubkey,
  );
  _copy_defined_field($permission, \%input, 'target_pubkey', 'target_pubkey');
  _copy_array_field($permission, \%input, 'current_roles', 'current_roles');
  _copy_hash_field($permission, \%input, 'group_metadata', 'group_metadata');
  _copy_defined_field($permission, \%input, 'normalized_ban_mask',              'ban_mask');
  _copy_defined_field($permission, \%input, 'normalized_exception_mask',        'exception_mask');
  _copy_defined_field($permission, \%input, 'normalized_invite_exception_mask', 'invite_exception_mask');
  _copy_defined_field($permission, \%input, 'channel_key',                      'channel_key');
  _copy_defined_field($permission, \%input, 'user_limit',                       'user_limit');
  return \%input;
}

sub _copy_defined_field {
  my ($source, $target, $source_key, $target_key) = @_;
  if (defined $source->{$source_key}) {
    $target->{$target_key} = $source->{$source_key};
  }
  return 1;
}

sub _copy_array_field {
  my ($source, $target, $source_key, $target_key) = @_;
  if (ref($source->{$source_key}) eq 'ARRAY') {
    $target->{$target_key} = [@{$source->{$source_key}}];
  }
  return 1;
}

sub _copy_hash_field {
  my ($source, $target, $source_key, $target_key) = @_;
  if (ref($source->{$source_key}) eq 'HASH') {
    $target->{$target_key} = $source->{$source_key};
  }
  return 1;
}

sub _write_authoritative_mode_input {
  my ($self, $client_id, $client, $input) = @_;
  if ($self->_authority_relay_enabled) {
    if (!($self->_publish_authoritative_input($client, $input))) {
      $self->_send_server_notice($client_id,
        $self->{authoritative_publish_error} || 'authoritative relay publish failed',
      );
      return 0;
    }
    return 1;
  }

  if (!($self->_emit_client_input($client, $input))) {
    return 0;
  }
  return 1;
}

sub _handle_authoritative_kick_command {
  my ($self, %args) = @_;
  my $client_id = $args{client_id};
  my $channel   = $args{channel};
  my @params    = @{$args{params} || []};
  my $client    = $self->{clients}{$client_id}
    or return 0;

  my $target_nick = $self->_canonical_current_nick($params[1]);
  if (!(defined $target_nick)) {
    return $self->_send_no_such_nick($client_id, $params[1]);
  }

  my $target_client = $self->_client_for_current_nick($target_nick);
  if (!(ref($target_client) eq 'HASH')) {
    return $self->_send_no_such_nick($client_id, $params[1]);
  }

  my $target_pubkey = $self->_client_authoritative_pubkey($target_client);
  if (!(defined $target_pubkey)) {
    return $self->_send_no_such_nick($client_id, $params[1]);
  }

  my $permission = $self->_authoritative_channel_action_permission_for_client(
    $channel,
    $client,
    action        => 'kick',
    target_pubkey => $target_pubkey,
  );
  return $self->_send_no_such_channel($client_id, $channel)
    if (($permission->{reason} || q{}) eq 'deleted');
  if (!($permission->{allowed})) {
    return $self->_send_chan_op_privs_needed($client_id, $channel);
  }

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  my $reason       = @params >= 3 ? $params[2] : undef;
  if ($self->_authority_relay_enabled
    && !$self->_client_has_authoritative_delegation($client)) {
    $self->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE is required for authoritative KICK');
    return 1;
  }

  my %input = (
    command       => 'KICK',
    target        => $channel,
    actor_pubkey  => $actor_pubkey,
    target_pubkey => $permission->{target_pubkey},
    (defined $reason ? (text => $reason) : ()),
  );
  if ($self->_authority_relay_enabled) {
    if (!($self->_publish_authoritative_input($client, \%input))) {
      $self->_send_server_notice($client_id,
        $self->{authoritative_publish_error} || 'authoritative relay publish failed',
      );
      return 1;
    }
  } else {
    if (!($self->_emit_client_input($client, \%input))) {
      return 1;
    }

  }

  my $line = sprintf(':%s KICK %s %s', $client->{nick}, $channel, $target_nick);
  if (defined $reason && length $reason) {
    $line .= ' :' . $reason;
  }

  $self->_broadcast_channel_line($channel, $line);
  $self->_remove_client_from_channel($target_client->{id}, $channel, nick => $target_client->{nick},);
  return 1;
}

sub _handle_authoritative_invite_command {
  my ($self, %args) = @_;
  my $client_id         = $args{client_id};
  my $channel           = $args{channel};
  my $target_nick_input = $args{target_nick};
  my $client            = $self->{clients}{$client_id}
    or return 0;

  my $target_nick = $self->_canonical_current_nick($target_nick_input);
  if (!(defined $target_nick)) {
    return $self->_send_no_such_nick($client_id, $target_nick_input);
  }

  my $target_client = $self->_client_for_current_nick($target_nick);
  if (!(ref($target_client) eq 'HASH')) {
    return $self->_send_no_such_nick($client_id, $target_nick_input);
  }

  my $target_pubkey = $self->_client_authoritative_pubkey($target_client);
  if (!(defined $target_pubkey)) {
    return $self->_send_no_such_nick($client_id, $target_nick_input);
  }

  my $permission = $self->_authoritative_channel_action_permission_for_client(
    $channel,
    $client,
    action        => 'invite',
    target_pubkey => $target_pubkey,
  );
  return $self->_send_no_such_channel($client_id, $channel)
    if (($permission->{reason} || q{}) eq 'deleted');
  if (!($permission->{allowed})) {
    return $self->_send_chan_op_privs_needed($client_id, $channel);
  }

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  my $invite_code  = $self->_generate_authoritative_invite_code(
    channel       => $channel,
    actor_pubkey  => $actor_pubkey,
    target_pubkey => $target_pubkey,
  );

  if ($self->_authority_relay_enabled
    && !$self->_client_has_authoritative_delegation($client)) {
    $self->_send_server_notice($client_id, 'OVERNETAUTH DELEGATE is required for authoritative INVITE');
    return 1;
  }

  my %input = (
    command       => 'INVITE',
    target        => $channel,
    actor_pubkey  => $actor_pubkey,
    target_nick   => $target_nick,
    target_pubkey => $permission->{target_pubkey},
    invite_code   => $invite_code,
  );
  if ($self->_authority_relay_enabled) {
    if (!($self->_publish_authoritative_input($client, \%input))) {
      $self->_send_server_notice($client_id,
        $self->{authoritative_publish_error} || 'authoritative relay publish failed',
      );
      return 1;
    }
  } else {
    if (!($self->_emit_client_input($client, \%input))) {
      return 1;
    }

  }

  $self->_send_inviting($client_id, $target_nick, $channel);
  $target_client->{authority_seen_invites}{$channel}{$invite_code} = 1;
  $self->_send_client_line($target_client->{id},
    sprintf(':%s INVITE %s :%s', $client->{nick}, $target_nick, $channel),);
  return 1;
}

sub _handle_authoritative_invites_command {
  my ($self, %args) = @_;
  my $client_id = $args{client_id};
  my $channel   = $args{channel};
  my $client    = $self->{clients}{$client_id}
    or return 0;

  my $permission =
    $self->_authoritative_channel_action_permission_for_client($channel, $client, action => 'list_invites',);
  return $self->_send_no_such_channel($client_id, $channel)
    if (($permission->{reason} || q{}) eq 'deleted');
  if (!($permission->{allowed})) {
    return $self->_send_chan_op_privs_needed($client_id, $channel);
  }

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  my $view         = $self->_derive_authoritative_channel_view(
    $channel,
    force => 1,
    (defined($actor_pubkey) ? (actor_pubkey => $actor_pubkey) : ()),
  );

  return $self->_send_authoritative_invite_list_reply($client_id, $channel,
    ref($view) eq 'HASH' ? ($view->{pending_invites} || []) : [],
  );
}

sub _handle_authoritative_requests_command {
  my ($self, %args) = @_;
  my $client_id = $args{client_id};
  my $channel   = $args{channel};
  my $client    = $self->{clients}{$client_id}
    or return 0;

  my $permission =
    $self->_authoritative_channel_action_permission_for_client($channel, $client, action => 'list_requests',);
  return $self->_send_no_such_channel($client_id, $channel)
    if (($permission->{reason} || q{}) eq 'deleted');
  if (!($permission->{allowed})) {
    return $self->_send_chan_op_privs_needed($client_id, $channel);
  }

  my $actor_pubkey = $self->_client_authoritative_pubkey($client);
  my $view         = $self->_derive_authoritative_channel_view(
    $channel,
    force => 1,
    (defined($actor_pubkey) ? (actor_pubkey => $actor_pubkey) : ()),
  );

  return $self->_send_authoritative_join_request_list_reply($client_id, $channel,
    ref($view) eq 'HASH' ? ($view->{pending_join_requests} || []) : [],
  );
}

sub _nick_in_use {
  my ($self, $nick, %args) = @_;
  my $key = $self->_nick_key($nick);
  if (!(defined $key)) {
    return 0;
  }

  my $owner = $self->{nick_to_client_id}{$key};
  if (!(defined $owner)) {
    return 0;
  }

  return 0
    if defined $args{exclude_client_id} && $owner eq $args{exclude_client_id};
  return 1;
}

sub _assign_client_nick {
  my ($self, $client_id, $nick) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $key = $self->_nick_key($nick);
  if (!(defined $key)) {
    return 0;
  }

  if ( defined $client->{nick}
    && length($client->{nick})
    && $client->{nick} ne $nick) {
    $self->_release_client_nick($client_id, nick => $client->{nick},);
  }

  $client->{nick} = $nick;
  $self->{nick_to_client_id}{$key} = $client_id;
  return 1;
}

sub _release_client_nick {
  my ($self, $client_id, %args) = @_;
  my $nick =
    defined $args{nick} ? $args{nick}
    : (
    exists $self->{clients}{$client_id} ? $self->{clients}{$client_id}{nick}
    : undef
    );
  my $key = $self->_nick_key($nick);
  if (!(defined $key)) {
    return 0;
  }

  if (!(exists $self->{nick_to_client_id}{$key})) {
    return 0;
  }

  if (!($self->{nick_to_client_id}{$key} eq $client_id)) {
    return 0;
  }

  delete $self->{nick_to_client_id}{$key};
  return 1;
}

sub _send_nick_in_use {
  my ($self, $client_id, $attempted_nick) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  my $target =
      $client->{registered} && defined $client->{nick} && length($client->{nick})
    ? $client->{nick}
    : q{*};
  $self->_send_client_line(
    $client_id,
    Overnet::Program::IRC::Renderer::nick_in_use_line(
      server_name    => $self->{config}{server_name},
      nick           => $target,
      attempted_nick => $attempted_nick,
    ),
  );
  return 1;
}

sub _emit_client_input {
  my ($self, $client, $input, %opts) = @_;
  my %payload = (
    %{$input},
    network    => $self->{config}{network},
    nick       => $input->{nick} || $client->{nick},
    created_at => $self->_next_authoritative_created_at($client),
  );
  if ( $self->_authority_relay_enabled
    && $self->_is_authoritative_channel($payload{target})
    && $self->_client_has_authoritative_delegation($client)) {
    $payload{signing_pubkey}     = $client->{authority_delegate_key}->pubkey_hex;
    $payload{authority_event_id} = $client->{authority_delegate_event_id};
    $payload{authority_sequence} = $self->_next_authoritative_delegate_sequence($client);
  }

  my $mapped = $self->_request(
    method => 'adapters.map_input',
    params => {
      adapter_session_id => $self->{adapter_session_id},
      input              => \%payload,
    },
  );
  $self->{inputs_processed}++;

  my $authoritative_result = $self->_handle_authoritative_mapped_result(
    client => $client,
    target => $payload{target},
    mapped => $mapped,
  );
  if ($authoritative_result) {
    return 1;
  }
  return 0 if defined $authoritative_result && $authoritative_result < 0;

  $self->_emit_mapped_result(
    $mapped,
    originating_client_id       => $client->{id},
    suppress_render_event_types => $opts{suppress_render_event_types},
  );

  return 1;
}

sub _publish_authoritative_input {
  my ($self, $client, $input) = @_;
  if (!(ref($client) eq 'HASH')) {
    return 0;
  }

  if (!(ref($input) eq 'HASH')) {
    return 0;
  }

  delete $self->{authoritative_publish_error};

  my %payload = (
    %{$input},
    network    => $self->{config}{network},
    nick       => $input->{nick} || $client->{nick},
    created_at => $self->_next_authoritative_created_at($client),
  );
  if ( $self->_authority_relay_enabled
    && $self->_is_authoritative_channel($payload{target})
    && $self->_client_has_authoritative_delegation($client)) {
    $payload{signing_pubkey}     = $client->{authority_delegate_key}->pubkey_hex;
    $payload{authority_event_id} = $client->{authority_delegate_event_id};
    $payload{authority_sequence} = $self->_next_authoritative_delegate_sequence($client);
  }

  my $mapped = $self->_request(
    method => 'adapters.map_input',
    params => {
      adapter_session_id => $self->{adapter_session_id},
      input              => \%payload,
    },
  );
  $self->{inputs_processed}++;
  if (!(ref($mapped) eq 'HASH')) {
    $self->{authoritative_publish_error} = 'authoritative relay mapping failed';
    return 0;
  }

  my @events;
  if (ref($mapped->{event}) eq 'HASH') {
    push @events, $mapped->{event};
  }
  if (ref($mapped->{events}) eq 'ARRAY') {
    push @events, grep { ref eq 'HASH' } @{$mapped->{events}};
  }
  if (!(@events)) {
    $self->{authoritative_publish_error} = 'authoritative relay mapping produced no event drafts';
    return 0;
  }

  for my $event (@events) {
    if (
      !(
        $self->_publish_authoritative_nip29_event(
          channel => $payload{target},
          client  => $client,
          event   => $event,
        )
      )
    ) {
      return 0;
    }

  }

  return 1;
}

sub _client_has_authoritative_delegation {
  my ($self, $client) = @_;
  if (!(ref($client) eq 'HASH')) {
    return 0;
  }

  if (!($self->_authority_relay_enabled)) {
    return 0;
  }

  if (!(ref($client->{authority_delegate_key}) eq 'Overnet::Core::Nostr::Key')) {
    return 0;
  }

  if (
    !(
         defined $client->{authority_delegate_event_id}
      && !ref($client->{authority_delegate_event_id})
      && $client->{authority_delegate_event_id} =~ /\A[0-9a-f]{64}\z/mxs
    )
  ) {
    return 0;
  }

  return 0
    if defined $client->{authority_delegate_expires_at}
    && $client->{authority_delegate_expires_at} < time();
  return 1;
}

sub _next_authoritative_delegate_sequence {
  my ($self, $client) = @_;
  if (!(ref($client) eq 'HASH')) {
    return;
  }

  my $sequence_key =
       defined($client->{id})
    && !ref($client->{id})
    && length($client->{id})
    ? $client->{id}
    : undef;
  my $next =
    defined($sequence_key)
    && exists($self->{authoritative_delegate_sequences}{$sequence_key})
    ? $self->{authoritative_delegate_sequences}{$sequence_key}
    : exists($client->{authority_delegate_sequence}) ? $client->{authority_delegate_sequence}
    :                                                  0;
  $next++;
  $client->{authority_delegate_sequence} = $next;
  if (defined $sequence_key) {
    $self->{authoritative_delegate_sequences}{$sequence_key} = $next;
  }
  return $next;
}

sub _next_authoritative_created_at {
  my ($self, $client) = @_;
  my $now = int(time());
  if (!(ref($client) eq 'HASH')) {
    return $now;
  }

  my $key =
       defined($client->{id})
    && !ref($client->{id})
    && length($client->{id})
    ? $client->{id}
    : undef;
  if (!(defined $key)) {
    return $now;
  }

  my $previous_created_at = $self->{authoritative_last_created_at}{$key} || 0;
  my $next                = $now > $previous_created_at ? $now : $previous_created_at + 1;
  $self->{authoritative_last_created_at}{$key} = $next;
  return $next;
}

sub _publish_authoritative_nip29_event {
  my ($self, %args) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::publish_authoritative_nip29_event($self, %args);
}

sub _append_authoritative_nip29_event {
  my ($self, $channel, $event) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::append_authoritative_nip29_event($self, $channel, $event);
}

sub _is_authoritative_nip29_event {
  my ($self, %args) = @_;
  my $channel = $args{channel};
  my $event   = $args{event};
  if (!($self->_is_authoritative_channel($channel))) {
    return 0;
  }

  if (!(ref($event) eq 'HASH')) {
    return 0;
  }

  my $kind = $event->{kind};
  if (!(defined $kind && !ref($kind))) {
    return 0;
  }

  if (
    !(
         $kind == 9000
      || $kind == 9001
      || $kind == 9_002
      || $kind == 9009
      || $kind == 9021
      || $kind == 9022
      || $kind == 39_000
      || $kind == 39_001
      || $kind == 39_002
      || $kind == 39_003
    )
  ) {
    return 0;
  }

  my (undef, $group_id) = $self->_authoritative_group_binding($channel);
  if (!(defined $group_id)) {
    return 0;
  }

  my %tags = $self->_first_tag_values($event->{tags});
  if (!(defined $tags{h} && $tags{h} eq $group_id)) {
    return 0;
  }

  return 1;
}

sub _handle_authoritative_mapped_result {
  my ($self, %args) = @_;
  my $client  = $args{client};
  my $channel = $args{target};
  my $mapped  = $args{mapped};
  if (!($self->_is_authoritative_channel($channel))) {
    return 0;
  }

  if (!(ref($mapped) eq 'HASH')) {
    return 0;
  }

  my @events;
  if (ref($mapped->{event}) eq 'HASH') {
    push @events, $mapped->{event};
  }
  if (ref($mapped->{events}) eq 'ARRAY') {
    push @events, grep { ref eq 'HASH' } @{$mapped->{events}};
  }
  if (!(@events)) {
    return 0;
  }

  return 0 if exists $mapped->{state} || exists $mapped->{capabilities};
  if (!(@events == grep { $self->_is_authoritative_nip29_event(channel => $channel, event => $_,) } @events)) {
    return 0;
  }

  for my $event (@events) {
    if (
      !(
        $self->_publish_authoritative_nip29_event(
          channel => $channel,
          client  => $client,
          event   => $event,
        )
      )
    ) {
      return -1;
    }

  }

  return 1;
}

sub _maybe_poll_authoritative_relay {
  my ($self) = @_;
  return 1;
}

sub _has_authoritative_relay_poll_interest {
  my ($self) = @_;
  return 0;
}

sub _apply_authoritative_channel_cache_update {
  my ($self, %args) = @_;
  my $channel         = $args{channel};
  my $event           = $args{event};
  my $old_view        = $args{old_view};
  my $new_view        = $args{new_view};
  my $old_state       = $args{old_state};
  my $new_state       = $args{new_state};
  my $suppress_render = $args{suppress_render} ? 1 : 0;

  if (!($self->_is_authoritative_channel($channel))) {
    return 0;
  }

  if (!(ref($event) eq 'HASH')) {
    return 0;
  }

  my $diff = _authoritative_cache_update_diff(
    old_view => $old_view,
    new_view => $new_view,
  );
  if ($self->_apply_authoritative_tombstone_update($channel, $diff)) {
    return 1;
  }

  $self->_broadcast_authoritative_mode_updates($channel, $event, $old_state, $new_state, $suppress_render);

  if (($event->{kind} || 0) == 9009) {
    return $self->_apply_authoritative_pending_invite_update($channel, $event, $diff);
  }

  $self->_apply_authoritative_topic_update($channel, $new_view, $diff);

  my $channel_key = $self->_channel_key($channel);
  if (!(defined $channel_key)) {
    return 1;
  }

  my $channel_state = $self->{channels}{$channel_key}
    or return 1;

  $self->_broadcast_authoritative_join_updates($channel, $event, $channel_state, $diff);
  $self->_broadcast_authoritative_leave_updates($channel, $event, $channel_key, $channel_state, $diff);

  return 1;
}

sub _authoritative_cache_update_diff {
  my (%args)   = @_;
  my $old_view = $args{old_view};
  my $new_view = $args{new_view};
  return {
    old_pending    => {_pending_invites_by_code($old_view)},
    new_pending    => {_pending_invites_by_code($new_view)},
    old_present    => {_present_authoritative_members_by_pubkey($old_view)},
    new_present    => {_present_authoritative_members_by_pubkey($new_view)},
    old_topic      => _authoritative_topic_snapshot($old_view),
    new_topic      => _authoritative_topic_snapshot($new_view),
    old_tombstoned => _view_tombstoned($old_view),
    new_tombstoned => _view_tombstoned($new_view),
  };
}

sub _pending_invites_by_code {
  my ($view) = @_;
  return map { ($_->{code} => $_) }
    grep { ref eq 'HASH' && defined($_->{code}) } @{ref($view) eq 'HASH' ? ($view->{pending_invites} || []) : []};
}

sub _authoritative_topic_snapshot {
  my ($view) = @_;
  my $has_topic = ref($view) eq 'HASH' && exists $view->{topic} ? 1 : 0;
  return {
    has_topic => $has_topic,
    topic     => $has_topic ? $view->{topic} : undef,
    actor     => ref($view) eq 'HASH' && exists $view->{topic_actor_pubkey}
    ? $view->{topic_actor_pubkey}
    : undef,
  };
}

sub _view_tombstoned {
  my ($view) = @_;
  return ref($view) eq 'HASH' && $view->{tombstoned} ? 1 : 0;
}

sub _apply_authoritative_tombstone_update {
  my ($self, $channel, $diff) = @_;
  if (!($diff->{new_tombstoned})) {
    return 0;
  }
  if (!($diff->{old_tombstoned})) {
    $self->_apply_authoritative_channel_tombstone($channel, reason => 'channel deleted',);
  }
  return 1;
}

sub _broadcast_authoritative_mode_updates {
  my ($self, $channel, $event, $old_state, $new_state, $suppress_render) = @_;
  if ($suppress_render || !(($event->{kind} || 0) == 9_002)) {
    return 1;
  }

  my $actor_nick = $self->_authoritative_event_actor_nick($event);
  $self->_broadcast_authoritative_mode_flag_updates($channel, $actor_nick, $old_state, $new_state);
  $self->_broadcast_authoritative_ban_mask_updates($channel, $actor_nick, $old_state, $new_state);
  return 1;
}

sub _authoritative_event_actor_nick {
  my ($self, $event) = @_;
  return $self->_authoritative_nick_for_pubkey($self->_effective_authoritative_actor_pubkey_from_event($event))
    || $self->{config}{server_name};
}

sub _broadcast_authoritative_mode_flag_updates {
  my ($self, $channel, $actor_nick, $old_state, $new_state) = @_;
  my %old_mode_flags = _authoritative_mode_flags($old_state);
  my %new_mode_flags = _authoritative_mode_flags($new_state);
  my @mode_letters;
  push @mode_letters, 'i';
  push @mode_letters, 'm';
  push @mode_letters, 't';
  for my $mode_letter (@mode_letters) {
    if (_same_authoritative_mode_flag($mode_letter, \%old_mode_flags, \%new_mode_flags)) {
      next;
    }

    $self->_broadcast_channel_line($channel,
      sprintf(':%s MODE %s %s%s', $actor_nick, $channel, $new_mode_flags{$mode_letter} ? q{+} : q{-}, $mode_letter,),
    );
  }
  return 1;
}

sub _authoritative_mode_flags {
  my ($state) = @_;
  return map { ($_ => 1) } grep {/[imt]/mxs} split //mxs, (($state->{channel_modes} || q{}) =~ s/^\+//rmxs);
}

sub _same_authoritative_mode_flag {
  my ($mode_letter, $old_flags, $new_flags) = @_;
  return 1 if $old_flags->{$mode_letter} && $new_flags->{$mode_letter};
  return 1 if !($old_flags->{$mode_letter} || $new_flags->{$mode_letter});
  return 0;
}

sub _broadcast_authoritative_ban_mask_updates {
  my ($self, $channel, $actor_nick, $old_state, $new_state) = @_;
  my %old_ban_masks =
    map { ($_ => 1) } @{_state_array($old_state, 'ban_masks')};
  my %new_ban_masks =
    map { ($_ => 1) } @{_state_array($new_state, 'ban_masks')};
  for my $ban_mask (sort keys %new_ban_masks) {
    if ($old_ban_masks{$ban_mask}) {
      next;
    }
    $self->_broadcast_channel_line($channel, sprintf(':%s MODE %s +b %s', $actor_nick, $channel, $ban_mask),);
  }
  for my $ban_mask (sort keys %old_ban_masks) {
    if ($new_ban_masks{$ban_mask}) {
      next;
    }
    $self->_broadcast_channel_line($channel, sprintf(':%s MODE %s -b %s', $actor_nick, $channel, $ban_mask),);
  }
  return 1;
}

sub _state_array {
  my ($state, $field) = @_;
  if (ref($state) eq 'HASH' && ref($state->{$field}) eq 'ARRAY') {
    return $state->{$field};
  }
  return [];
}

sub _apply_authoritative_pending_invite_update {
  my ($self, $channel, $event, $diff) = @_;
  my %tags = $self->_first_tag_values($event->{tags});
  if (!(defined $tags{code} && length($tags{code}))) {
    return 1;
  }
  if (exists $diff->{old_pending}{$tags{code}}) {
    return 1;
  }
  if (!(exists $diff->{new_pending}{$tags{code}})) {
    return 1;
  }

  my $actor_nick = $self->_authoritative_event_actor_nick($event);
  for my $client_id (sort keys %{$self->{clients}}) {
    $self->_send_authoritative_pending_invite_to_client($client_id, $channel, $actor_nick, \%tags);
  }
  return 1;
}

sub _send_authoritative_pending_invite_to_client {
  my ($self, $client_id, $channel, $actor_nick, $tags) = @_;
  my $client = $self->{clients}{$client_id};
  if (!(ref($client) eq 'HASH' && $client->{registered})) {
    return 1;
  }
  if (!_nonempty_scalar($client->{nick})) {
    return 1;
  }
  my $pubkey = $self->_client_authoritative_pubkey($client);
  if (!(defined $pubkey)) {
    return 1;
  }
  if (!(defined $tags->{p} && $tags->{p} eq $pubkey)) {
    return 1;
  }
  if ($client->{authority_seen_invites}{$channel}{$tags->{code}}++) {
    return 1;
  }

  $self->_send_client_line($client_id, sprintf(':%s INVITE %s :%s', $actor_nick, $client->{nick}, $channel),);
  return 1;
}

sub _apply_authoritative_topic_update {
  my ($self, $channel, $new_view, $diff) = @_;
  if (!_authoritative_topic_changed($diff->{old_topic}, $diff->{new_topic})) {
    return 1;
  }

  $self->_sync_authoritative_topic_state_from_view($channel, $new_view);
  if ($diff->{new_topic}{has_topic}) {
    my $line = $self->_authoritative_topic_line_from_view($channel, $new_view);
    if (defined $line && length $line) {
      $self->_broadcast_channel_line($channel, $line);
    }
  }
  return 1;
}

sub _authoritative_topic_changed {
  my ($old_topic, $new_topic) = @_;
  return 1 if $old_topic->{has_topic} != $new_topic->{has_topic};
  return 1
    if (($old_topic->{topic} // q{}) ne ($new_topic->{topic} // q{}));
  return 1
    if (($old_topic->{actor} // q{}) ne ($new_topic->{actor} // q{}));
  return 0;
}

sub _broadcast_authoritative_join_updates {
  my ($self, $channel, $event, $channel_state, $diff) = @_;
  if (!(($event->{kind} || 0) == 9021)) {
    return 1;
  }

  my $actor_pubkey = $self->_effective_authoritative_actor_pubkey_from_event($event) || q{};
  for my $pubkey (_added_authoritative_pubkeys($diff)) {
    if (!($actor_pubkey eq $pubkey)) {
      next;
    }
    if ($self->_has_local_authoritative_client($channel_state, $pubkey)) {
      next;
    }

    my $actor_nick = $self->_authoritative_nick_for_pubkey($pubkey)
      || $self->{config}{server_name};
    $self->_broadcast_channel_line($channel, sprintf(':%s JOIN %s', $actor_nick, $channel),);
  }
  return 1;
}

sub _added_authoritative_pubkeys {
  my ($diff) = @_;
  my @pubkeys =
    sort grep { !$diff->{old_present}{$_} && $diff->{new_present}{$_} }
    keys %{$diff->{new_present}};
  return @pubkeys;
}

sub _removed_authoritative_pubkeys {
  my ($diff) = @_;
  my @pubkeys =
    sort grep { $diff->{old_present}{$_} && !$diff->{new_present}{$_} }
    keys %{$diff->{old_present}};
  return @pubkeys;
}

sub _has_local_authoritative_client {
  my ($self, $channel_state, $pubkey) = @_;
  my @client_ids = $self->_local_authoritative_client_ids($channel_state, $pubkey);
  return @client_ids ? 1 : 0;
}

sub _local_authoritative_client_ids {
  my ($self, $channel_state, $pubkey) = @_;
  return grep {
    my $client = $self->{clients}{$_};
    ref($client) eq 'HASH'
      && (($self->_client_authoritative_pubkey($client) || q{}) eq $pubkey)
  } sort keys %{$channel_state->{members} || {}};
}

sub _broadcast_authoritative_leave_updates {
  my ($self, $channel, $event, $channel_key, $channel_state, $diff) = @_;
  for my $pubkey (_removed_authoritative_pubkeys($diff)) {
    my @affected_client_ids = $self->_local_authoritative_client_ids($channel_state, $pubkey);
    if (($event->{kind} || 0) == 9001) {
      $self->_broadcast_authoritative_kick_update($channel, $event, $pubkey, \@affected_client_ids);
      next;
    }
    if (($event->{kind} || 0) == 9022) {
      $self->_broadcast_authoritative_part_update($channel, $event, $pubkey, \@affected_client_ids);
      $channel_state = $self->{channels}{$channel_key};
      if (!(ref($channel_state) eq 'HASH')) {
        return 1;
      }
    }
  }
  return 1;
}

sub _broadcast_authoritative_kick_update {
  my ($self, $channel, $event, $pubkey, $affected_client_ids) = @_;
  my %tags = $self->_first_tag_values($event->{tags});
  if (!(defined($tags{p}) && $tags{p} eq $pubkey)) {
    return 1;
  }

  my $target_nick = $self->_authoritative_target_nick($pubkey, $affected_client_ids);
  if (!(defined $target_nick && length $target_nick)) {
    return 1;
  }

  my $line = sprintf(':%s KICK %s %s', $self->_authoritative_event_actor_nick($event), $channel, $target_nick);
  $line = _line_with_reason($line, $event->{content});
  $self->_broadcast_channel_line($channel, $line);
  $self->_remove_authoritative_affected_clients($channel, $affected_client_ids);
  return 1;
}

sub _broadcast_authoritative_part_update {
  my ($self, $channel, $event, $pubkey, $affected_client_ids) = @_;
  if (!(($self->_effective_authoritative_actor_pubkey_from_event($event) || q{}) eq $pubkey)) {
    return 1;
  }

  my $actor_nick =
    @{$affected_client_ids}
    ? $self->{clients}{$affected_client_ids->[0]}{nick}
    : (  $self->_authoritative_nick_for_pubkey($pubkey)
      || $self->{config}{server_name});
  my $line = sprintf(':%s PART %s', $actor_nick, $channel);
  $line = _line_with_reason($line, $event->{content});
  $self->_broadcast_channel_line($channel, $line);
  $self->_remove_authoritative_affected_clients($channel, $affected_client_ids);
  return 1;
}

sub _authoritative_target_nick {
  my ($self, $pubkey, $affected_client_ids) = @_;
  if (@{$affected_client_ids}) {
    return $self->{clients}{$affected_client_ids->[0]}{nick};
  }
  return $self->_authoritative_nick_for_pubkey($pubkey);
}

sub _line_with_reason {
  my ($line, $reason) = @_;
  if (defined $reason && !ref($reason) && length($reason)) {
    $line .= ' :' . $reason;
  }
  return $line;
}

sub _remove_authoritative_affected_clients {
  my ($self, $channel, $affected_client_ids) = @_;
  for my $client_id (@{$affected_client_ids}) {
    if (!(exists $self->{clients}{$client_id})) {
      next;
    }
    $self->_remove_client_from_channel($client_id, $channel, nick => $self->{clients}{$client_id}{nick},);
  }
  return 1;
}

sub _update_authoritative_channel_cache_with_event {
  my ($self, %args) = @_;
  my $channel         = $args{channel};
  my $event           = $args{event};
  my $suppress_render = $args{suppress_render} ? 1 : 0;
  if (!($self->_is_authoritative_channel($channel))) {
    return 0;
  }

  if (!(ref($event) eq 'HASH')) {
    return 0;
  }

  my $canonical = $self->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    return 0;
  }

  my $cache     = $self->{authoritative_channel_cache}{$canonical} || {};
  my $old_view  = $cache->{view};
  my $old_state = $cache->{state};
  my $event_id =
       defined($event->{id})
    && !ref($event->{id})
    && length($event->{id})
    ? $event->{id}
    : undef;
  my $new_cache;

  if (ref($cache->{events}) eq 'ARRAY') {
    my @events = @{$cache->{events}};
    my $already_cached =
      defined($event_id)
      ? grep { ref eq 'HASH' && defined($_->{id}) && $_->{id} eq $event_id } @events
      : 0;
    if (!$already_cached) {
      push @events, $event;
    }
    my $sorted_events = $self->_sort_authoritative_events(\@events);
    my $new_view      = $self->_derive_authoritative_channel_view_from_events($canonical, $sorted_events);
    $new_cache = $self->{authoritative_channel_cache}{$canonical} = {
      %{$cache},
      events       => $sorted_events,
      view         => $new_view,
      state        => $self->_authoritative_channel_state_from_view($new_view),
      refreshed_at => time(),
    };
    return 1 if $already_cached;
  } else {
    my $sorted_events = $self->_sort_authoritative_events([$event]);
    my $new_view      = $self->_derive_authoritative_channel_view_from_events($canonical, $sorted_events);
    $new_cache = $self->{authoritative_channel_cache}{$canonical} = {
      %{$cache},
      events       => $sorted_events,
      view         => $new_view,
      state        => $self->_authoritative_channel_state_from_view($new_view),
      refreshed_at => time(),
    };
  }

  $self->_sync_authoritative_topic_state_from_view($canonical, $new_cache->{view});
  $self->_apply_authoritative_channel_cache_update(
    channel         => $canonical,
    event           => $event,
    old_view        => $old_view,
    new_view        => $new_cache->{view},
    old_state       => $old_state,
    new_state       => $new_cache->{state},
    suppress_render => $suppress_render,
  );

  return 1;
}

sub _reconcile_authoritative_pending_invites_from_refresh {
  my ($self, %args) = @_;
  my $channel    = $args{channel};
  my $old_view   = $args{old_view};
  my $old_events = $args{old_events};
  my $new_view   = $args{new_view};
  my $new_events = $args{new_events};
  if (!($self->_is_authoritative_channel($channel))) {
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

    $count += $self->_apply_authoritative_channel_cache_update(
      channel   => $channel,
      event     => $event,
      old_view  => $old_view,
      new_view  => $new_view,
      old_state => $self->_authoritative_channel_state_from_view($old_view),
      new_state => $self->_authoritative_channel_state_from_view($new_view),
    ) || 0;
  }

  return $count;
}

sub _userhost_entry_for_nick {
  my ($self, $nick) = @_;
  my $nick_key = $self->_nick_key($nick);
  if (!(defined $nick_key)) {
    return;
  }

  my $client_id = $self->{nick_to_client_id}{$nick_key};
  if (!(defined $client_id && exists $self->{clients}{$client_id})) {
    return;
  }

  my $client = $self->{clients}{$client_id};

  my $display_nick = $client->{nick};
  my $username =
       defined $client->{username}
    && !ref($client->{username})
    && length($client->{username})
    ? $client->{username}
    : $display_nick;
  my $host = $self->_presentational_host_for_client($client);

  return sprintf('%s=+%s@%s', $display_nick, $username, $host);
}

sub _whois_entry_for_nick {
  my ($self, $nick) = @_;
  my $nick_key = $self->_nick_key($nick);
  if (!(defined $nick_key)) {
    return;
  }

  my $client_id = $self->{nick_to_client_id}{$nick_key};
  if (!(defined $client_id && exists $self->{clients}{$client_id})) {
    return;
  }

  my $client = $self->{clients}{$client_id};

  return {
    nick     => $client->{nick},
    username => (
      defined $client->{username} && !ref($client->{username}) && length($client->{username}) ? $client->{username}
      : $client->{nick}
    ),
    host     => $self->_presentational_host_for_client($client),
    realname => (
      defined $client->{realname} && !ref($client->{realname}) && length($client->{realname}) ? $client->{realname}
      : $client->{nick}
    ),
    (
      defined($client->{authority_pubkey}) ? (account => $client->{authority_pubkey})
      : ()
    ),
  };
}

sub _who_entries_for_channel {
  my ($self, $channel) = @_;
  my @entries;

  for my $display_nick ($self->_visible_nicks_for_channel($channel)) {
    my $nick_key = $self->_nick_key($display_nick);
    if (!(defined $nick_key)) {
      next;
    }

    my $client_id = $self->{nick_to_client_id}{$nick_key};
    if (defined $client_id && exists $self->{clients}{$client_id}) {
      my $client = $self->{clients}{$client_id};
      push @entries,
        {
        nick     => $client->{nick},
        username => (
          defined $client->{username} && !ref($client->{username}) && length($client->{username}) ? $client->{username}
          : $client->{nick}
        ),
        host     => $self->_presentational_host_for_client($client),
        realname => (
          defined $client->{realname} && !ref($client->{realname}) && length($client->{realname}) ? $client->{realname}
          : $client->{nick}
        ),
        };
      next;
    }

    push @entries,
      {
      nick     => $display_nick,
      username => 'overnet',
      host     => $self->_default_presentational_host,
      realname => $display_nick,
      };
  }

  return @entries;
}

sub _list_entries {
  my ($self, $client, $target) = @_;
  $self->_refresh_list_authoritative_discovery;
  my @channels = $self->_list_channels($target);

  my @entries;
  for my $channel (@channels) {
    my $entry = $self->_list_entry_for_channel($client, $channel);
    if (!(ref($entry) eq 'HASH')) {
      next;
    }
    push @entries, $entry;
  }

  return @entries;
}

sub _refresh_list_authoritative_discovery {
  my ($self) = @_;
  if ( $self->_authority_relay_enabled
    && $self->_authority_profile eq 'nip29') {
    $self->_refresh_authoritative_discovery_cache(refresh => 1);
  }
  return 1;
}

sub _list_channels {
  my ($self, $target) = @_;
  my %channels;
  for my $channel ($self->_local_list_channels, $self->_authoritative_channels) {
    $channels{$channel} = 1;
  }
  my @channels = sort keys %channels;
  if ( defined $target
    && length($target)
    && $self->_is_channel_name($target)) {
    return $self->_filter_list_channels_by_target(\@channels, $target);
  }
  return @channels;
}

sub _local_list_channels {
  my ($self) = @_;
  my @channels;
  for my $channel_key (keys %{$self->{channels} || {}}) {
    my $state = $self->{channels}{$channel_key};
    if (!(ref($state) eq 'HASH')) {
      next;
    }
    if (!_nonempty_scalar($state->{channel_name})) {
      next;
    }
    push @channels, $state->{channel_name};
  }
  return @channels;
}

sub _filter_list_channels_by_target {
  my ($self, $channels, $target) = @_;
  my $target_key = $self->_channel_key($target);
  return grep { defined $self->_channel_key($_) && $self->_channel_key($_) eq $target_key } @{$channels};
}

sub _list_entry_for_channel {
  my ($self, $client, $channel) = @_;
  my $channel_key = $self->_channel_key($channel);
  if (!(defined $channel_key)) {
    return;
  }

  my $state = $self->{channels}{$channel_key};
  if ($self->_is_authoritative_channel($channel)) {
    return $self->_authoritative_list_entry_for_channel($client, $channel, $state);
  }
  return $self->_local_list_entry_for_channel($state);
}

sub _authoritative_list_entry_for_channel {
  my ($self, $client, $channel, $state) = @_;
  my ($list_view, $view) = $self->_authoritative_list_views($client, $channel);
  if (!(ref($view) eq 'HASH' || ref($state) eq 'HASH')) {
    return;
  }
  if (_authoritative_list_view_hidden($list_view)) {
    return;
  }
  if (ref($view) eq 'HASH' && $view->{tombstoned}) {
    return;
  }
  return {
    channel       => $self->_authoritative_list_display_channel($channel, $list_view, $state),
    visible_users => $self->_authoritative_list_visible_users($channel, $list_view, $view, $state),
    topic         => $self->_authoritative_list_topic($list_view, $view, $state),
  };
}

sub _authoritative_list_views {
  my ($self, $client, $channel) = @_;
  my $actor_pubkey =
    ref($client) eq 'HASH'
    ? $self->_client_authoritative_pubkey($client)
    : undef;
  my $list_view = $self->_derive_authoritative_list_entry_view(
    $channel,
    force => 1,
    (defined($actor_pubkey) ? (actor_pubkey => $actor_pubkey) : ()),
  );
  my $view = $self->_derive_authoritative_channel_view($channel, force => 1,);
  return ($list_view, $view);
}

sub _authoritative_list_view_hidden {
  my ($list_view) = @_;
  return 0 if !(ref($list_view) eq 'HASH');
  return 0 if !(exists $list_view->{visible_in_list});
  return $list_view->{visible_in_list} ? 0 : 1;
}

sub _authoritative_list_visible_users {
  my ($self, $channel, $list_view, $view, $state) = @_;
  if ( ref($list_view) eq 'HASH'
    && defined($list_view->{visible_users})
    && !ref($list_view->{visible_users})) {
    return $list_view->{visible_users};
  }
  if (ref($view) eq 'HASH' && ref($view->{present_members}) eq 'ARRAY') {
    return scalar(@{$view->{present_members}});
  }
  if (ref($state) eq 'HASH') {
    return $self->_visible_users_for_channel_state($channel, $state);
  }
  return 0;
}

sub _authoritative_list_display_channel {
  my ($self, $channel, $list_view, $state) = @_;
  if (ref($list_view) eq 'HASH'
    && _nonempty_scalar($list_view->{channel})) {
    return $list_view->{channel};
  }
  if (ref($state) eq 'HASH' && _nonempty_scalar($state->{channel_name})) {
    return $state->{channel_name};
  }
  if (exists($self->{authoritative_discovered_channels}{$channel})) {
    return $self->{authoritative_discovered_channels}{$channel}{channel_name};
  }
  return $channel;
}

sub _authoritative_list_topic {
  my ($self, $list_view, $view, $state) = @_;
  if (ref($list_view) eq 'HASH' && exists($list_view->{topic})) {
    return $list_view->{topic};
  }
  if (ref($view) eq 'HASH' && exists($view->{topic})) {
    return $view->{topic};
  }
  if ( ref($state) eq 'HASH'
    && defined($state->{topic_text})
    && !ref($state->{topic_text})) {
    return $state->{topic_text};
  }
  return q{};
}

sub _local_list_entry_for_channel {
  my ($self, $state) = @_;
  if (!(ref($state) eq 'HASH')) {
    return;
  }
  return {
    channel       => $state->{channel_name},
    visible_users => $self->_visible_users_for_channel_state($state->{channel_name}, $state),
    topic         => defined $state->{topic_text} && !ref($state->{topic_text}) ? $state->{topic_text} : q{},
  };
}

sub _visible_users_for_channel_state {
  my ($self, $channel, $state) = @_;
  my %presented_nicks =
    map { $_ => 1 } $self->_visible_nicks_for_channel($channel);
  for my $client_id (keys %{$state->{members} || {}}) {
    my $member_client = $self->{clients}{$client_id};
    if (!_list_member_client_is_visible($member_client)) {
      next;
    }
    $presented_nicks{$member_client->{nick}} = 1;
  }
  return scalar(keys %presented_nicks);
}

sub _list_member_client_is_visible {
  my ($client) = @_;
  return 0 if !(ref($client) eq 'HASH');
  return 0 if !($client->{registered});
  return 0 if !_nonempty_scalar($client->{nick});
  return 1;
}

sub _ensure_channel_subscription {
  my ($self, $channel) = @_;
  my $state = $self->_channel_state($channel);
  return $state->{subscription_id}
    if defined $state->{subscription_id};

  my $subscription_id = 'channel:' . $self->_channel_object_id($channel);
  $self->_request(
    method => 'subscriptions.open',
    params => {
      subscription_id => $subscription_id,
      query           => {
        overnet_ot  => 'chat.channel',
        overnet_oid => $self->_channel_object_id($channel),
      },
    },
  );
  $state->{subscription_id} = $subscription_id;

  return $subscription_id;
}

sub _ensure_client_dm_subscription {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return;
  if (!($client->{registered})) {
    return;
  }

  if (!(defined $client->{nick} && length($client->{nick}))) {
    return;
  }

  my $object_id = $self->_dm_object_id($client->{nick});
  if ( defined $client->{dm_subscription_id}
    && defined $client->{dm_object_id}
    && $client->{dm_object_id} eq $object_id) {
    return $client->{dm_subscription_id};
  }

  if (defined $client->{dm_subscription_id}) {
    $self->_close_client_dm_subscription($client_id);
  }

  my $subscription_id = 'dm:' . $client_id;
  $self->_request(
    method => 'subscriptions.open',
    params => {
      subscription_id => $subscription_id,
      query           => {
        overnet_ot  => 'chat.dm',
        overnet_oid => $object_id,
      },
    },
  );
  $client->{dm_subscription_id} = $subscription_id;
  $client->{dm_object_id}       = $object_id;

  return $subscription_id;
}

sub _close_client_dm_subscription {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return 1;
  if (!(defined $client->{dm_subscription_id})) {
    return 1;
  }

  my $subscription_id = delete $client->{dm_subscription_id};
  delete $client->{dm_object_id};
  $self->_request(
    method => 'subscriptions.close',
    params => {
      subscription_id => $subscription_id,
    },
  );

  return 1;
}

sub _close_channel_subscription {
  my ($self, $channel) = @_;
  my $channel_key = $self->_channel_key($channel);
  if (!(defined $channel_key)) {
    return 1;
  }

  my $state = $self->{channels}{$channel_key}
    or return 1;
  if (!(defined $state->{subscription_id})) {
    return 1;
  }

  my $subscription_id = delete $state->{subscription_id};
  $self->_request(
    method => 'subscriptions.close',
    params => {
      subscription_id => $subscription_id,
    },
  );

  return 1;
}

sub _add_client_to_channel {
  my ($self, $client_id, $channel) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  my $channel_key = $self->_channel_key($channel);
  if (!(defined $channel_key)) {
    return 0;
  }

  my $state = $self->_channel_state($channel);
  $client->{joined_channels}{$channel_key} = $state->{channel_name};
  $state->{members}{$client_id}            = 1;
  $self->_add_visible_nick($state->{channel_name}, $client->{nick});
  return 1;
}

sub _remove_client_from_channel {
  my ($self, $client_id, $channel, %opts) = @_;
  my $client      = $self->{clients}{$client_id};
  my $channel_key = $self->_channel_key($channel);
  if (!(defined $channel_key)) {
    return 0;
  }

  my $state = $self->{channels}{$channel_key}
    or return 0;
  my $nick =
    defined $opts{nick}
    ? $opts{nick}
    : ($client ? $client->{nick} : undef);

  if ($client) {
    delete $client->{joined_channels}{$channel_key};
  }
  delete $state->{members}{$client_id};
  $self->_remove_visible_nick($state->{channel_name}, $nick);

  if (!keys %{$state->{members}}) {
    $self->_close_channel_subscription($state->{channel_name});
    delete $self->{channels}{$channel_key};
  }

  return 1;
}

sub _disconnect_client {
  my ($self, $client_id, %args) = @_;
  my $client = $self->{clients}{$client_id}
    or return 1;
  my $current_nick = $client->{nick};

  my @channels = sort values %{$client->{joined_channels} || {}};
  if ($args{emit_quit}) {
    my $line = sprintf(':%s QUIT', $client->{nick});
    if (defined $args{reason} && length $args{reason}) {
      $line .= ' :' . $args{reason};
    }
    $self->_send_line_to_client_ids(
      [
        $self->_shared_client_ids_for_channels(
          \@channels, exclude_client_id => $client_id
        )
      ],
      $line,
    );

    for my $channel (@channels) {
      $self->_remove_client_from_channel($client_id, $channel, nick => $client->{nick},);
    }

    for my $channel (@channels) {
      $self->_emit_client_input(
        $client,
        {
          command => 'QUIT',
          target  => $channel,
          (defined $args{reason} ? (text => $args{reason}) : ()),
        },
        suppress_render_event_types => {
          'chat.quit' => 1,
        },
      );
    }
  } else {
    for my $channel (@channels) {
      $self->_remove_client_from_channel($client_id, $channel, nick => $client->{nick},);
    }
  }

  $self->_close_client_dm_subscription($client_id);
  $self->_release_client_nick($client_id, nick => $current_nick,);

  $self->_close_socket($client->{socket});
  delete $self->{authoritative_last_created_at}{$client_id};
  delete $self->{authoritative_delegate_sequences}{$client_id};
  delete $self->{clients}{$client_id};

  return 1;
}

sub _handle_subscription_event {
  my ($self, $params) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::handle_subscription_event($self, $params);
}

sub _handle_nostr_subscription_event {
  my ($self, $params) = @_;
  return Overnet::Program::IRC::Authority::Coordinator::handle_nostr_subscription_event($self, $params);
}

sub _render_subscription_item {
  my ($self, %args) = @_;
  my $item_type = $args{item_type};
  my $data      = $args{data};
  if (!(ref($data) eq 'HASH')) {
    return;
  }

  if ($item_type eq 'private_message') {
    return $self->_render_private_subscription_item($data);
  }

  my $context = $self->_subscription_event_context($data);
  if (!(ref($context) eq 'HASH')) {
    return;
  }

  if ($context->{object_type} eq 'chat.channel') {
    return $self->_render_channel_subscription_item($item_type, $context);
  }

  if ($context->{object_type} eq 'chat.dm' && $item_type eq 'event') {
    return $self->_render_private_message_item(
      event_type => $context->{event_type},
      object_id  => $context->{object_id},
      provenance => $context->{provenance},
      body       => $context->{body},
    );
  }

  if ( $context->{object_type} eq 'irc.network'
    && $item_type eq 'event'
    && $context->{event_type} eq 'irc.nick') {
    return $self->_render_network_nick_subscription_item($context);
  }

  return;
}

sub _render_private_subscription_item {
  my ($self, $data) = @_;
  my $rumor = $data->{decrypted_rumor};
  if (ref($rumor) eq 'HASH') {
    my $content = $rumor->{content};
    if (!(ref($content) eq 'HASH')) {
      return;
    }
    return $self->_render_private_message_item(
      event_type => $data->{private_type},
      object_id  => $data->{object_id},
      provenance => $content->{provenance},
      body       => $content->{body},
    );
  }

  return $self->_render_opaque_private_message_item(
    event_type      => $data->{private_type},
    object_id       => $data->{object_id},
    sender_identity => $data->{sender_identity},
    transport       => $data->{transport},
  );
}

sub _subscription_event_context {
  my ($self, $data) = @_;
  my $event = Overnet::Core::Nostr->event_from_wire($data);
  if (!($event)) {
    return;
  }

  my %tags    = $self->_first_tag_values($event->tags);
  my $content = eval { JSON::decode_json($event->content) };
  if (!(ref($content) eq 'HASH')) {
    return;
  }

  return {
    object_type => $tags{overnet_ot}      || q{},
    object_id   => $tags{overnet_oid}     || q{},
    event_type  => $tags{overnet_et}      || q{},
    provenance  => $content->{provenance} || {},
    body        => $content->{body}       || {},
  };
}

sub _render_channel_subscription_item {
  my ($self, $item_type, $context) = @_;
  my $channel = $self->_channel_name_from_object_id($context->{object_id});
  if (!(defined $channel)) {
    return;
  }

  my $nick = $context->{provenance}{external_identity};
  if (!_nonempty_scalar($nick)) {
    return;
  }

  my $line = $self->_channel_subscription_line($item_type, $context->{event_type}, $channel, $nick, $context->{body});
  if (!(defined $line)) {
    return;
  }

  my @client_ids = $self->_channel_subscription_client_ids($channel);
  if (!(@client_ids)) {
    return;
  }

  return {
    channel    => $channel,
    line       => $line,
    client_ids => \@client_ids,
  };
}

sub _channel_subscription_line {
  my ($self, $item_type, $event_type, $channel, $nick, $body) = @_;
  my %builders;
  $builders{'event:chat.message'} = sub {
    return _channel_text_line('PRIVMSG', $nick, $channel, $body->{text});
  };
  $builders{'event:chat.notice'} = sub {
    return _channel_text_line('NOTICE', $nick, $channel, $body->{text});
  };
  $builders{'state:chat.topic'} = sub {
    return $self->_channel_topic_subscription_line($nick, $channel, $body->{topic});
  };
  $builders{'event:chat.join'} = sub {
    $self->_add_visible_nick($channel, $nick);
    return sprintf(':%s JOIN %s', $nick, $channel);
  };
  $builders{'event:chat.part'} = sub {
    $self->_remove_visible_nick($channel, $nick);
    return _line_with_reason(sprintf(':%s PART %s', $nick, $channel), $body->{reason});
  };
  $builders{'event:chat.quit'} = sub {
    $self->_remove_visible_nick($channel, $nick);
    return _line_with_reason(sprintf(':%s QUIT', $nick), $body->{reason});
  };

  my $builder = $builders{"$item_type:$event_type"};
  if (!(defined $builder)) {
    return;
  }
  return $builder->();
}

sub _channel_text_line {
  my ($command, $nick, $channel, $text) = @_;
  if (!(defined $text && !ref($text))) {
    return;
  }
  return sprintf(':%s %s %s :%s', $nick, $command, $channel, $text);
}

sub _channel_topic_subscription_line {
  my ($self, $nick, $channel, $topic) = @_;
  if (!(defined $topic && !ref($topic))) {
    return;
  }
  my $line = sprintf(':%s TOPIC %s :%s', $nick, $channel, $topic);
  $self->_channel_state($channel)->{topic_line} = $line;
  $self->_channel_state($channel)->{topic_text} = $topic;
  return $line;
}

sub _channel_subscription_client_ids {
  my ($self, $channel) = @_;
  return grep {
         exists $self->{clients}{$_}
      && $self->{clients}{$_}{registered}
      && defined $self->_client_joined_channel_name($self->{clients}{$_}, $channel)
  } sort keys %{$self->{clients}};
}

sub _render_network_nick_subscription_item {
  my ($self, $context) = @_;
  my $network_object_id = q{irc:} . $self->{config}{network};
  if (!(($context->{object_id} || q{}) eq $network_object_id)) {
    return;
  }

  my $body = $context->{body};
  if ( !_nonempty_scalar($body->{old_nick})
    || !_nonempty_scalar($body->{new_nick})) {
    return;
  }

  my @client_ids = $self->_shared_client_ids_for_nick($body->{old_nick});
  $self->_rename_visible_nick_everywhere(
    old_nick => $body->{old_nick},
    new_nick => $body->{new_nick},
  );
  if (!(@client_ids)) {
    return;
  }

  return {
    line       => sprintf(':%s NICK :%s', $body->{old_nick}, $body->{new_nick}),
    client_ids => \@client_ids,
  };
}

sub _render_private_message_item {
  my ($self, %args) = @_;
  my $event_type  = $args{event_type} || q{};
  my $target_nick = $self->_dm_nick_from_object_id($args{object_id});
  if (!(defined $target_nick)) {
    return;
  }

  my $provenance = $args{provenance};
  if (!(ref($provenance) eq 'HASH')) {
    return;
  }

  my $nick = $provenance->{external_identity};
  if (!(defined $nick && !ref($nick) && length($nick))) {
    return;
  }

  my $body = $args{body};
  if (!(ref($body) eq 'HASH')) {
    return;
  }

  if (!(defined $body->{text} && !ref($body->{text}))) {
    return;
  }

  my $display_target_nick = $self->_canonical_current_nick($target_nick) || $target_nick;
  my $line;
  if ($event_type eq 'chat.dm_message') {
    $line = sprintf(':%s PRIVMSG %s :%s', $nick, $display_target_nick, $body->{text});
  } elsif ($event_type eq 'chat.dm_notice') {
    $line = sprintf(':%s NOTICE %s :%s', $nick, $display_target_nick, $body->{text});
  } else {
    return;
  }

  my $target_key = $self->_nick_key($target_nick);
  if (!(defined $target_key)) {
    return;
  }

  my @client_ids = grep {
         exists $self->{clients}{$_}
      && $self->{clients}{$_}{registered}
      && defined $self->_nick_key($self->{clients}{$_}{nick})
      && $self->_nick_key($self->{clients}{$_}{nick}) eq $target_key
  } sort keys %{$self->{clients}};
  if (!(@client_ids)) {
    return;
  }

  return {
    line       => $line,
    client_ids => \@client_ids,
  };
}

sub _render_opaque_private_message_item {
  my ($self, %args) = @_;
  my $event_type  = $args{event_type} || q{};
  my $target_nick = $self->_dm_nick_from_object_id($args{object_id});
  if (!(defined $target_nick)) {
    return;
  }

  my $sender_identity = $args{sender_identity};
  if (!(defined $sender_identity && !ref($sender_identity) && length($sender_identity))) {
    return;
  }

  my $transport = $args{transport};
  if (!(ref($transport) eq 'HASH')) {
    return;
  }

  my $display_target_nick = $self->_canonical_current_nick($target_nick) || $target_nick;
  my $body                = $self->_encode_e2ee_dm_body($transport);
  my $line;
  if ($event_type eq 'chat.dm_message') {
    $line = sprintf(':%s PRIVMSG %s :%s', $sender_identity, $display_target_nick, $body);
  } elsif ($event_type eq 'chat.dm_notice') {
    $line = sprintf(':%s NOTICE %s :%s', $sender_identity, $display_target_nick, $body);
  } else {
    return;
  }

  my $target_key = $self->_nick_key($target_nick);
  if (!(defined $target_key)) {
    return;
  }

  my @client_ids = grep {
    my $client = $self->{clients}{$_};
    exists $self->{clients}{$_}
      && $client->{registered}
      && defined $self->_nick_key($client->{nick})
      && $self->_nick_key($client->{nick}) eq $target_key
      && $self->_client_has_capability($client, 'overnet-e2ee')
      && defined $client->{e2ee_pubkey}
  } sort keys %{$self->{clients}};
  if (!(@client_ids)) {
    return;
  }

  return {
    line       => $line,
    client_ids => \@client_ids,
  };
}

sub _decode_e2ee_dm_body {
  my ($self, $body) = @_;
  if (!(defined $body && !ref($body))) {
    return (undef, undef, 0);
  }

  if (!(index($body, $E2EE_DM_BODY_PREFIX) == 0)) {
    return (undef, undef, 0);
  }

  my $encoded = substr($body, length($E2EE_DM_BODY_PREFIX));
  if (!(defined $encoded && length($encoded))) {
    return (undef, 'Malformed overnet-e2ee body: missing transport payload', 1);
  }

  my $decoded = eval { decode_base64($encoded) };
  if ($EVAL_ERROR || !defined $decoded || !length($decoded)) {
    return (undef, 'Malformed overnet-e2ee body: base64 decode failed', 1);
  }

  my $transport = eval { JSON::decode_json($decoded) };
  if ($EVAL_ERROR || ref($transport) ne 'HASH') {
    return (undef, 'Malformed overnet-e2ee body: transport JSON is invalid', 1);
  }

  return ($transport, undef, 1);
}

sub _encode_e2ee_dm_body {
  my ($self, $transport) = @_;
  if (!(ref($transport) eq 'HASH')) {
    croak "transport must be an object\n";
  }

  return $E2EE_DM_BODY_PREFIX . encode_base64(JSON::encode_json($transport), q{});
}

sub _emit_mapped_result {
  my ($self, $result, %opts) = @_;
  my $suppress              = $opts{suppress_render_event_types} || {};
  my $originating_client_id = $opts{originating_client_id};
  $self->_emit_mapped_events($result, $suppress, $originating_client_id);
  $self->_emit_mapped_state($result);
  $self->_emit_mapped_capabilities($result);
  return 1;
}

sub _emit_mapped_events {
  my ($self, $result, $suppress, $originating_client_id) = @_;
  for my $event (@{$result->{events} || []}) {
    $self->_emit_mapped_event($event, $suppress, $originating_client_id);
  }
  return 1;
}

sub _emit_mapped_event {
  my ($self, $event, $suppress, $originating_client_id) = @_;
  if ($self->_is_private_message_candidate($event)) {
    $self->_emit_private_message_candidate($event, originating_client_id => $originating_client_id,);
    return 1;
  }

  my $signed = $self->_sign_candidate_event($event);
  my %tags   = $self->_first_tag_values($signed->{tags});
  $self->_maybe_suppress_subscription_event($signed, \%tags, $suppress);
  $self->_maybe_track_originating_channel_event($signed, \%tags, $originating_client_id);
  $self->_request(
    method => 'overnet.emit_event',
    params => {event => $signed},
  );
  $self->{events_emitted}++;
  return 1;
}

sub _is_private_message_candidate {
  my ($self, $event) = @_;
  my %candidate_tags = $self->_first_tag_values($event->{tags});
  return 0 if !(($candidate_tags{overnet_ot} || q{}) eq 'chat.dm');
  return 1 if ($candidate_tags{overnet_et} || q{}) eq 'chat.dm_message';
  return 1 if ($candidate_tags{overnet_et} || q{}) eq 'chat.dm_notice';
  return 0;
}

sub _maybe_suppress_subscription_event {
  my ($self, $signed, $tags, $suppress) = @_;
  if ($suppress->{$tags->{overnet_et} || q{}}) {
    $self->{suppress_subscription_event_ids}{$signed->{id}} = 1;
  }
  return 1;
}

sub _maybe_track_originating_channel_event {
  my ($self, $signed, $tags, $originating_client_id) = @_;
  if (!_originating_channel_event_should_be_tracked($tags, $originating_client_id)) {
    return 1;
  }
  $self->{subscription_event_origin_client_ids}{$signed->{id}} =
    $originating_client_id;
  return 1;
}

sub _originating_channel_event_should_be_tracked {
  my ($tags, $originating_client_id) = @_;
  return 0 if !defined $originating_client_id;
  return 0 if !(($tags->{overnet_ot} || q{}) eq 'chat.channel');
  return 1 if ($tags->{overnet_et} || q{}) eq 'chat.message';
  return 1 if ($tags->{overnet_et} || q{}) eq 'chat.notice';
  return 0;
}

sub _emit_mapped_state {
  my ($self, $result) = @_;
  for my $state (@{$result->{state} || []}) {
    my $signed = $self->_sign_candidate_event($state);
    $self->_request(
      method => 'overnet.emit_state',
      params => {state => $signed},
    );
    $self->{state_emitted}++;
  }
  return 1;
}

sub _emit_mapped_capabilities {
  my ($self, $result) = @_;
  if (!(@{$result->{capabilities} || []})) {
    return 1;
  }

  $self->_request(
    method => 'overnet.emit_capabilities',
    params => {capabilities => $result->{capabilities}},
  );
  $self->{capabilities_emitted} += scalar @{$result->{capabilities}};
  return 1;
}

sub _emit_private_message_candidate {
  my ($self, $candidate, %opts) = @_;
  if (!(ref($candidate) eq 'HASH')) {
    croak "private-message candidate event must be an object\n";
  }

  my $sender = $self->_private_message_candidate_sender($opts{originating_client_id});
  my $meta   = $self->_private_message_candidate_meta($candidate);
  my ($content, $body) = _private_message_candidate_content($candidate);
  my $recipient = $self->_private_message_candidate_recipient($meta->{object_id});
  my $payload   = _private_message_candidate_payload($meta, $content, $body);
  my $transport = Overnet::Core::Nostr->wrap_private_message(
    sender_key        => $sender->{dm_key},
    payload           => $payload,
    recipient_pubkeys => [$recipient->{dm_key}->pubkey_hex],
    skip_sender       => 1,
  );

  return $self->_emit_wrapped_private_message_candidate($sender, $recipient, $meta, $body, $transport);
}

sub _private_message_candidate_sender {
  my ($self, $originating_client_id) = @_;
  if (!_nonempty_scalar($originating_client_id)) {
    croak "originating_client_id is required for encrypted private messages\n";
  }

  my $sender = $self->{clients}{$originating_client_id}
    or croak "Unknown originating_client_id for encrypted private message\n";
  if (!($sender->{registered})) {
    croak "Encrypted private-message sender must be registered\n";
  }

  $sender->{dm_key} ||= Overnet::Core::Nostr->generate_key;
  return $sender;
}

sub _private_message_candidate_meta {
  my ($self, $candidate) = @_;
  my %tags         = $self->_first_tag_values($candidate->{tags});
  my $private_type = $tags{overnet_et}  || q{};
  my $object_type  = $tags{overnet_ot}  || q{};
  my $object_id    = $tags{overnet_oid} || q{};
  if (!($object_type eq 'chat.dm')) {
    croak "Encrypted private-message candidate must target chat.dm\n";
  }
  if (!($private_type eq 'chat.dm_message' || $private_type eq 'chat.dm_notice')) {
    croak "Encrypted private-message candidate must be chat.dm_message or chat.dm_notice\n";
  }
  return {
    overnet_v    => $tags{overnet_v} || '0.1.0',
    private_type => $private_type,
    object_type  => $object_type,
    object_id    => $object_id,
  };
}

sub _private_message_candidate_content {
  my ($candidate) = @_;
  my $content = eval { JSON::decode_json($candidate->{content}) };
  if (!(ref($content) eq 'HASH')) {
    croak "Encrypted private-message candidate content must decode to an object\n";
  }

  my $body = $content->{body};
  if (!(ref($body) eq 'HASH')) {
    croak "Encrypted private-message candidate body must be an object\n";
  }
  if (!(defined $body->{text} && !ref($body->{text}))) {
    croak "Encrypted private-message candidate body.text must be a string\n";
  }
  return ($content, $body);
}

sub _private_message_candidate_recipient {
  my ($self, $object_id) = @_;
  my $target_nick = $self->_dm_nick_from_object_id($object_id);
  if (!(defined $target_nick)) {
    croak "Encrypted private-message candidate object_id must target an IRC nick\n";
  }

  my $target_key = $self->_nick_key($target_nick);
  if (!(defined $target_key)) {
    croak "Encrypted private-message target nick is invalid\n";
  }

  my $target_client_id = $self->{nick_to_client_id}{$target_key};
  if (!(defined $target_client_id && exists $self->{clients}{$target_client_id})) {
    croak "Encrypted private-message target nick is not connected\n";
  }

  my $recipient = $self->{clients}{$target_client_id};
  if (!($recipient->{registered})) {
    croak "Encrypted private-message recipient must be registered\n";
  }

  $recipient->{dm_key} ||= Overnet::Core::Nostr->generate_key;
  return $recipient;
}

sub _private_message_candidate_payload {
  my ($meta, $content, $body) = @_;
  return {
    overnet_v    => $meta->{overnet_v},
    private_type => $meta->{private_type},
    object_type  => $meta->{object_type},
    object_id    => $meta->{object_id},
    provenance   => $content->{provenance},
    body         => $body,
  };
}

sub _emit_wrapped_private_message_candidate {
  my ($self, $sender, $recipient, $meta, $body, $transport) = @_;
  my $irc_command = $meta->{private_type} eq 'chat.dm_notice' ? 'NOTICE' : 'PRIVMSG';
  my $result      = $self->_request(
    method => 'overnet.emit_private_message',
    params => {
      message => {
        source => {
          protocol => 'irc',
          network  => $self->{config}{network},
          line     => sprintf(':%s %s %s :%s', $sender->{nick}, $irc_command, $recipient->{nick}, $body->{text}),
        },
        transport => {
          %{$transport->{transport}->to_hash}, decrypted_rumor => $transport->{decrypted_rumor}->to_hash,
        },
      },
    },
  );
  $self->{private_messages_emitted}++;

  return $result;
}

sub _emit_opaque_private_message_transport {
  my ($self, %args) = @_;
  my ($client, $command, $target_nick, $body_text, $transport) = _opaque_private_message_args(%args);

  if (!($self->_opaque_private_message_sender_ready($client))) {
    return 0;
  }

  my $recipient = $self->_opaque_private_message_recipient($client, $target_nick);
  if (!(ref($recipient) eq 'HASH')) {
    return 0;
  }

  my $wrap = $self->_opaque_private_message_wrap($client, $recipient, $transport);
  if (!($wrap)) {
    return 0;
  }

  return $self->_emit_valid_opaque_private_message($client, $recipient, $command, $body_text, $wrap);
}

sub _opaque_private_message_args {
  my (%args)      = @_;
  my $client      = $args{client};
  my $command     = $args{command} || q{};
  my $target_nick = $args{target_nick};
  my $body_text   = $args{body_text};
  my $transport   = $args{transport};

  if (!(ref($client) eq 'HASH')) {
    croak "client is required for opaque private-message transport\n";
  }

  if (!($command eq 'PRIVMSG' || $command eq 'NOTICE')) {
    croak "command must be PRIVMSG or NOTICE for opaque private-message transport\n";
  }

  if (!(defined $target_nick && !ref($target_nick) && length($target_nick))) {
    croak "target_nick is required for opaque private-message transport\n";
  }

  if (!(ref($transport) eq 'HASH')) {
    croak "transport must be an object\n";
  }

  if (!(defined $body_text && !ref($body_text) && length($body_text))) {
    croak "body_text is required for opaque private-message transport\n";
  }

  return ($client, $command, $target_nick, $body_text, $transport);
}

sub _opaque_private_message_sender_ready {
  my ($self, $client) = @_;
  if (!($self->_client_has_capability($client, 'overnet-e2ee') && defined $client->{e2ee_pubkey})) {
    $self->_send_server_notice($client->{id}, 'E2EE direct messages require CAP overnet-e2ee and OVERNETKEY SET');
    return 0;
  }
  return 1;
}

sub _opaque_private_message_recipient {
  my ($self, $client, $target_nick) = @_;
  my $recipient = $self->_client_for_current_nick($target_nick);
  if (
    !(
         ref($recipient) eq 'HASH'
      && $self->_client_has_capability($recipient, 'overnet-e2ee')
      && defined $recipient->{e2ee_pubkey}
    )
  ) {
    $self->_send_server_notice($client->{id}, 'Target nick is not E2EE-capable');
    return 0;
  }
  return $recipient;
}

sub _opaque_private_message_wrap {
  my ($self, $client, $recipient, $transport) = @_;
  my $wrap = Overnet::Core::Nostr->event_from_wire($transport);
  if (!$wrap || !eval { $wrap->validate; 1 }) {
    $self->_send_server_notice($client->{id}, 'Malformed overnet-e2ee transport');
    return 0;
  }

  if ($wrap->kind != 1059) {
    $self->_send_server_notice($client->{id}, 'Opaque private-message transport must use kind 1059');
    return 0;
  }

  my @recipient_tags = grep { ref eq 'ARRAY' && @{$_} >= 2 && $_->[0] eq 'p' } @{$wrap->tags || []};
  if (@recipient_tags != 1
    || ($recipient_tags[0][1] || q{}) ne $recipient->{e2ee_pubkey}) {
    $self->_send_server_notice($client->{id},
      'Opaque private-message transport recipient does not match the target nick');
    return 0;
  }
  return $wrap;
}

sub _emit_valid_opaque_private_message {
  my ($self, $client, $recipient, $command, $body_text, $wrap) = @_;
  my $private_type = $command eq 'NOTICE' ? 'chat.dm_notice' : 'chat.dm_message';
  my $result       = $self->_request(
    method => 'overnet.emit_private_message',
    params => {
      message => {
        source => {
          protocol => 'irc',
          network  => $self->{config}{network},
          line     => sprintf(':%s %s %s :%s', $client->{nick}, $command, $recipient->{nick}, $body_text),
        },
        private_type    => $private_type,
        object_type     => 'chat.dm',
        object_id       => $self->_dm_object_id($recipient->{nick}),
        sender_identity => $client->{nick},
        transport       => $wrap->to_hash,
      },
    },
  );
  $self->{private_messages_emitted}++;

  return $result;
}

sub _sign_candidate_event {
  my ($self, $candidate) = @_;

  if (!(ref($candidate) eq 'HASH')) {
    croak "candidate event must be an object\n";
  }

  if (!(defined $candidate->{kind} && !ref($candidate->{kind}))) {
    croak "candidate event kind is required\n";
  }

  if (!(defined $candidate->{created_at} && !ref($candidate->{created_at}))) {
    croak "candidate event created_at is required\n";
  }

  if (!(ref($candidate->{tags}) eq 'ARRAY')) {
    croak "candidate event tags must be an array\n";
  }

  if (!(defined $candidate->{content} && !ref($candidate->{content}))) {
    croak "candidate event content is required\n";
  }

  return $self->{signing_key}->create_event_hash(
    kind       => $candidate->{kind},
    created_at => $candidate->{created_at},
    tags       => $candidate->{tags},
    content    => $candidate->{content},
  );
}

sub _request {
  my ($self, %args) = @_;
  my $method = $args{method};
  my $params = $args{params} || {};
  my @deferred_messages;

  _validate_runtime_request_args($method, $params);
  my $id = $self->_send_runtime_request($method, $params);
  while (1) {
    my $message = $self->_next_request_wait_message;
    my $result  = $self->_process_request_wait_message(
      id                => $id,
      method            => $method,
      message           => $message,
      deferred_messages => \@deferred_messages,
    );
    if ($result->{deferred}) {
      next;
    }
    return $result->{result};
  }
  return;
}

sub _validate_runtime_request_args {
  my ($method, $params) = @_;
  if (!(defined $method && !ref($method) && length($method))) {
    croak "method is required\n";
  }
  if (!(ref($params) eq 'HASH')) {
    croak "params must be an object\n";
  }
  return 1;
}

sub _send_runtime_request {
  my ($self, $method, $params) = @_;
  my $id = 'program-' . $self->{next_request_id}++;
  $self->_send_message(
    Overnet::Program::Protocol::build_request(
      id     => $id,
      method => $method,
      params => $params,
    )
  );
  return $id;
}

sub _next_request_wait_message {
  my ($self) = @_;
  if (@{$self->{pending_messages}}) {
    return shift @{$self->{pending_messages}};
  }
  return $self->_next_runtime_message;
}

sub _process_request_wait_message {
  my ($self, %args) = @_;
  my $message           = $args{message};
  my $method            = $args{method};
  my $deferred_messages = $args{deferred_messages};

  if (($message->{type} || q{}) eq 'response') {
    $self->_restore_deferred_messages($deferred_messages);
    return {result => _runtime_request_response_result($message, $args{id}, $method),};
  }
  if ( ($message->{type} || q{}) eq 'request'
    && ($message->{method} || q{}) eq 'runtime.shutdown') {
    $self->_restore_deferred_messages($deferred_messages);
    $self->_handle_runtime_shutdown($message);
    croak '__shutdown__';
  }
  if ( ($message->{type} || q{}) eq 'notification'
    && ($message->{method} || q{}) eq 'runtime.fatal') {
    $self->_restore_deferred_messages($deferred_messages);
    croak "runtime fatal: " . ($message->{params}{code} || 'unknown');
  }
  if ( ($message->{type} || q{}) eq 'notification'
    && ($message->{method} || q{}) eq 'runtime.subscription_event') {
    push @{$deferred_messages}, $message;
    return {deferred => 1,};
  }

  $self->_restore_deferred_messages($deferred_messages);
  croak "Unexpected message while awaiting response for $method\n";
}

sub _restore_deferred_messages {
  my ($self, $deferred_messages) = @_;
  if (!(@{$deferred_messages})) {
    return 1;
  }

  unshift @{$self->{pending_messages}}, @{$deferred_messages};
  @{$deferred_messages} = ();
  return 1;
}

sub _runtime_request_response_result {
  my ($message, $id, $method) = @_;
  if (!(($message->{id} || q{}) eq $id)) {
    croak "Unexpected response id while awaiting $method\n";
  }
  if ($message->{ok}) {
    return $message->{result} || {};
  }

  croak "$method failed: "
    . ($message->{error}{code}    || 'unknown') . ': '
    . ($message->{error}{message} || 'unknown error');
}

sub _read_runtime_chunk {
  my ($self) = @_;
  my $bytes = sysread(STDIN, my $chunk, 4096);
  if (!(defined $bytes)) {
    croak "unexpected EOF on runtime stdin\n";
  }

  croak '__shutdown__'
    if $bytes == 0 && $self->{shutdown_complete};
  croak "unexpected EOF on runtime stdin\n"
    if $bytes == 0;

  push @{$self->{pending_messages}}, @{$self->{protocol}->feed($chunk)};
  return $bytes;
}

sub _drain_pending_runtime_messages {
  my ($self, %args) = @_;
  my $max_messages = $args{max_messages};
  my $count        = 0;

  while (@{$self->{pending_messages}}) {
    last if defined $max_messages && $count >= $max_messages;
    my $message = shift @{$self->{pending_messages}};
    $count++;

    if ( ($message->{type} || q{}) eq 'request'
      && ($message->{method} || q{}) eq 'runtime.shutdown') {
      $self->_handle_runtime_shutdown($message);
      next;
    }

    if ( ($message->{type} || q{}) eq 'notification'
      && ($message->{method} || q{}) eq 'runtime.fatal') {
      croak "runtime fatal: " . ($message->{params}{code} || 'unknown') . "\n";
    }

    if ( ($message->{type} || q{}) eq 'notification'
      && ($message->{method} || q{}) eq 'runtime.subscription_event') {
      $self->_handle_subscription_event($message->{params} || {});
      next;
    }

    croak "Unexpected runtime message in IRC server loop\n";
  }

  return $count;
}

sub _next_runtime_message {
  my ($self) = @_;

  while (!@{$self->{pending_messages}}) {
    $self->_read_runtime_chunk;
  }

  return shift @{$self->{pending_messages}};
}

sub _parse_irc_message {
  my ($self, $line) = @_;
  my %message = (
    raw_line => $line,
    params   => [],
  );

  if ($line =~ s/\A\@(\S+)\s+//mxs) {
    $message{tags} = $self->_parse_irc_tags($1);
  }

  if ($line =~ s/\A:([^ ]+)\s+//mxs) {
    my $prefix = $1;
    $message{prefix} = $prefix;
    if ($prefix =~ /\A([^!@]+)!([^@]+)\@(.+)\z/mxs) {
      @message{qw(prefix_nick prefix_user prefix_host)} = ($1, $2, $3);
    } else {
      $message{prefix_nick} = $prefix;
    }
  }

  my ($command, $rest) = split(/\ /mxs, $line, 2);
  if (!(defined $command && length $command)) {
    return;
  }

  $message{command} = uc($command);
  if (!(defined $rest)) {
    $rest = q{};
  }

  while (length $rest) {
    $rest =~ s/\A\ +//mxs;
    if (!(length $rest)) {
      last;
    }

    if ($rest =~ s/\A:(.*)\z//mxs) {
      push @{$message{params}}, $1;
      last;
    }

    if ($rest =~ s/\A([^ ]+)//mxs) {
      push @{$message{params}}, $1;
      next;
    }

    last;
  }

  return \%message;
}

sub _parse_irc_tags {
  my ($self, $raw) = @_;
  my %tags;
  for my $entry (split /;/mxs, $raw) {
    my ($name, $value) = split /=/mxs, $entry, 2;
    if (!(defined $name && length $name)) {
      next;
    }

    $tags{$name} = defined $value ? $value : q{};
  }
  return \%tags;
}

sub _first_tag_values {
  my ($self, $tags) = @_;
  my %values;

  for my $tag (@{$tags || []}) {
    if (!(ref($tag) eq 'ARRAY' && @{$tag} >= 2)) {
      next;
    }

    next if exists $values{$tag->[0]};
    $values{$tag->[0]} = $tag->[1];
  }

  return %values;
}

sub _channel_object_id {
  my ($self, $channel) = @_;
  my $canonical = $self->_canonical_channel_name($channel);
  if (!(defined $canonical)) {
    return;
  }

  return q{irc:} . $self->{config}{network} . q{:} . $canonical;
}

sub _dm_object_id {
  my ($self, $nick) = @_;
  return q{irc:} . $self->{config}{network} . ':dm:' . $nick;
}

sub _channel_key {
  my ($self, $channel) = @_;
  if (!($self->_is_channel_name($channel))) {
    return;
  }

  return $self->_irc_casefold($channel);
}

sub _canonical_channel_name {
  my ($self, $channel) = @_;
  my $key = $self->_channel_key($channel);
  if (!(defined $key)) {
    return;
  }

  return $self->{channels}{$key}{channel_name}
    if exists $self->{channels}{$key}
    && defined $self->{channels}{$key}{channel_name}
    && length($self->{channels}{$key}{channel_name});
  return $channel;
}

sub _client_joined_channel_name {
  my ($self, $client, $channel) = @_;
  if (!(ref($client) eq 'HASH')) {
    return;
  }

  my $key = $self->_channel_key($channel);
  if (!(defined $key)) {
    return;
  }

  return $client->{joined_channels}{$key};
}

sub _channel_state {
  my ($self, $channel) = @_;
  my $key = $self->_channel_key($channel);
  if (!(defined $key)) {
    return;
  }

  return $self->{channels}{$key} ||= {
    channel_name  => $channel,
    members       => {},
    visible_nicks => {},
    topic_text    => undef,
  };
}

sub _add_visible_nick {
  my ($self, $channel, $nick) = @_;
  my $nick_key = $self->_nick_key($nick);
  if (!(defined $nick_key)) {
    return 0;
  }

  my $state = $self->_channel_state($channel);
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

sub _remove_visible_nick {
  my ($self, $channel, $nick) = @_;
  my $nick_key = $self->_nick_key($nick);
  if (!(defined $nick_key)) {
    return 0;
  }

  my $channel_key = $self->_channel_key($channel);
  if (!(defined $channel_key)) {
    return 0;
  }

  my $state = $self->{channels}{$channel_key}
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

sub _rename_visible_nick {
  my ($self, $channel, %args) = @_;
  my $old_nick = $args{old_nick};
  my $new_nick = $args{new_nick};
  my $old_key  = $self->_nick_key($old_nick);
  my $new_key  = $self->_nick_key($new_nick);
  if (!(defined $old_key)) {
    return 0;
  }

  if (!(defined $new_key)) {
    return 0;
  }

  my $channel_key = $self->_channel_key($channel);
  if (!(defined $channel_key)) {
    return 0;
  }

  my $state = $self->{channels}{$channel_key}
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

sub _rename_visible_nick_everywhere {
  my ($self, %args) = @_;
  my $count = 0;

  for my $channel (sort keys %{$self->{channels}}) {
    $count += $self->_rename_visible_nick(
      $channel,
      old_nick => $args{old_nick},
      new_nick => $args{new_nick},
    ) || 0;
  }

  return $count;
}

sub _rename_client_channels {
  my ($self, $client, %args) = @_;
  if (!(ref($client) eq 'HASH')) {
    return 0;
  }

  my $count = 0;
  for my $channel (sort values %{$client->{joined_channels} || {}}) {
    $count += $self->_rename_visible_nick(
      $channel,
      old_nick => $args{old_nick},
      new_nick => $args{new_nick},
    ) || 0;
  }

  return $count;
}

sub _visible_nicks_for_channel {
  my ($self, $channel) = @_;
  my $channel_key = $self->_channel_key($channel);
  if (!(defined $channel_key)) {
    return ();
  }

  my $state = $self->{channels}{$channel_key}
    or return ();

  my @nicks =
    sort grep { defined && length }
    map       { $state->{visible_nicks}{$_}{display_nick} }
    grep      { ($state->{visible_nicks}{$_}{count} || 0) > 0 }
    keys %{$state->{visible_nicks} || {}};
  return @nicks;
}

sub _send_names_list {
  my ($self, $client_id, $channel, %opts) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;
  my $display_channel = $self->_canonical_channel_name($channel);
  if (!(defined $display_channel)) {
    return 0;
  }

  my @nicks;
  if ($self->_is_authoritative_channel($display_channel)) {
    if ($opts{force} && ref($opts{view}) ne 'HASH') {
      $self->_refresh_authoritative_nip29_channel_cache($display_channel,
        ($opts{force} && $self->_authority_relay_enabled ? (refresh => 1) : ()),
      );
    }
    @nicks = $self->_authoritative_name_entries_for_channel(
      $client,
      $display_channel,
      force => $opts{force} ? 1 : 0,
      (ref($opts{view}) eq 'HASH' ? (view => $opts{view}) : ()),
    );
  }

  if (!@nicks) {
    @nicks = $self->_visible_nicks_for_channel($display_channel);
    my $client_present = scalar grep { defined $_ && defined $client->{nick} && $_ eq $client->{nick} } @nicks;
    if (!$client_present
      && defined $self->_client_joined_channel_name($client, $display_channel)) {
      push @nicks, $client->{nick};
      @nicks = sort @nicks;
    }
  }

  return $self->_send_rendered_lines(
    $client_id,
    Overnet::Program::IRC::Renderer::names_list_lines(
      server_name => $self->{config}{server_name},
      nick        => $client->{nick},
      channel     => $display_channel,
      names       => \@nicks,
    ),
  );
}

sub _send_join_bootstrap {
  my ($self, $client_id, $channel) = @_;
  if ($self->_is_authoritative_channel($channel)) {
    my $canonical = $self->_canonical_channel_name($channel);
    my $cache =
      defined $canonical
      ? $self->{authoritative_channel_cache}{$canonical}
      : undef;
    my $view =
      ref($cache) eq 'HASH' && ref($cache->{view}) eq 'HASH'
      ? $cache->{view}
      : $self->_derive_authoritative_channel_view($channel);
    if (!(ref($view) eq 'HASH')) {
      $view = $self->_derive_authoritative_channel_view($channel, force => 1);
    }

    $self->_sync_authoritative_topic_state_from_view($channel, $view);
    my $line = $self->_authoritative_topic_line_from_view($channel, $view);
    if (defined $line && length $line) {
      $self->_send_client_line($client_id, $line);
    }

    return $self->_send_names_list($client_id, $channel, (ref($view) eq 'HASH' ? (view => $view) : ()),);
  }

  my $channel_key = $self->_channel_key($channel);
  if (!(defined $channel_key)) {
    return 0;
  }

  my $state = $self->{channels}{$channel_key}
    or return 0;

  if (defined $state->{topic_line} && length $state->{topic_line}) {
    $self->_send_client_line($client_id, $state->{topic_line});
  }

  return $self->_send_names_list($client_id, $state->{channel_name});
}

sub _channel_name_from_object_id {
  my ($self, $object_id) = @_;
  if (!(defined $object_id && !ref($object_id))) {
    return;
  }

  my $prefix = q{irc:} . $self->{config}{network} . q{:};
  if (!(index($object_id, $prefix) == 0)) {
    return;
  }

  my $channel = substr($object_id, length($prefix));
  if (!($self->_is_channel_name($channel))) {
    return;
  }

  return $self->_canonical_channel_name($channel);
}

sub _dm_nick_from_object_id {
  my ($self, $object_id) = @_;
  if (!(defined $object_id && !ref($object_id))) {
    return;
  }

  my $prefix = q{irc:} . $self->{config}{network} . ':dm:';
  if (!(index($object_id, $prefix) == 0)) {
    return;
  }

  my $nick = substr($object_id, length($prefix));
  if (!($self->_is_nick_name($nick))) {
    return;
  }

  return $nick;
}

sub _is_channel_name {
  my ($self, $value) = @_;
  return
       defined $value
    && !ref($value)
    && $value =~ /\A[#&][^\x00\x07\r\n ,:]+\z/mxs
    ? 1
    : 0;
}

sub _is_nick_name {
  my ($self, $value) = @_;
  return
       defined $value
    && !ref($value)
    && $value =~ /\A[^\x00\x07\r\n ,:#&][^\x00\x07\r\n ,:]*\z/mxs
    ? 1
    : 0;
}

sub _broadcast_channel_line {
  my ($self, $channel, $line) = @_;
  my $channel_key = $self->_channel_key($channel);
  if (!(defined $channel_key)) {
    return 0;
  }

  my $state = $self->{channels}{$channel_key}
    or return 0;

  return $self->_send_line_to_client_ids(
    [
      grep { exists $self->{clients}{$_} }
      sort keys %{$state->{members}}
    ],
    $line,
  );
}

sub _shared_client_ids_for_channels {
  my ($self, $channels, %args) = @_;
  my %client_ids;

  for my $channel (@{$channels || []}) {
    my $channel_key = $self->_channel_key($channel);
    if (!(defined $channel_key)) {
      next;
    }

    my $state = $self->{channels}{$channel_key}
      or next;
    for my $client_id (keys %{$state->{members} || {}}) {
      next
        if defined $args{exclude_client_id}
        && $client_id eq $args{exclude_client_id};
      if (!(exists $self->{clients}{$client_id})) {
        next;
      }

      if (!($self->{clients}{$client_id}{registered})) {
        next;
      }

      $client_ids{$client_id} = 1;
    }
  }

  my @client_ids = sort keys %client_ids;
  return @client_ids;
}

sub _shared_client_ids_for_client {
  my ($self, $client_id) = @_;
  my $client = $self->{clients}{$client_id}
    or return ();
  my @channels = sort values %{$client->{joined_channels} || {}};
  if (!(@channels)) {
    return ($client_id);
  }

  return $self->_shared_client_ids_for_channels(\@channels);
}

sub _shared_client_ids_for_nick {
  my ($self, $nick) = @_;
  my $nick_key = $self->_nick_key($nick);
  if (!(defined $nick_key)) {
    return ();
  }

  my @channels = grep {
    exists $self->{channels}{$_}{visible_nicks}{$nick_key}
      && ($self->{channels}{$_}{visible_nicks}{$nick_key}{count} || 0) > 0
  } sort keys %{$self->{channels}};
  return $self->_shared_client_ids_for_channels(\@channels);
}

sub _send_line_to_client_ids {
  my ($self, $client_ids, $line) = @_;
  my $count = 0;

  for my $client_id (@{$client_ids || []}) {
    if (!(exists $self->{clients}{$client_id})) {
      next;
    }

    $self->_send_client_line($client_id, $line);
    $count++;
  }

  return $count;
}

sub _send_client_line {
  my ($self, $client_id, $line) = @_;
  my $client = $self->{clients}{$client_id}
    or return 0;

  $line = $self->_decorate_outbound_line_for_client($client, $line);
  my $payload = encode('UTF-8', $line . "\r\n", Encode::FB_CROAK);
  my $offset  = 0;
  while ($offset < length $payload) {
    my $written = syswrite($client->{socket}, $payload, length($payload) - $offset, $offset);
    if (!defined $written) {
      if ( $OS_ERROR{EPIPE}
        || $OS_ERROR{ECONNRESET}
        || $OS_ERROR{ENOTCONN}) {
        $self->_disconnect_client($client_id);
        return 0;
      }
      croak "failed to write IRC line: $OS_ERROR\n";
    }
    if ($written == 0) {
      $self->_disconnect_client($client_id);
      return 0;
    }
    $offset += $written;
  }

  return 1;
}

sub _decorate_outbound_line_for_client {
  my ($self, $client, $line) = @_;
  if (!(defined $line && !ref($line) && length($line))) {
    return $line;
  }

  if (!(ref($client) eq 'HASH')) {
    return $line;
  }

  return $line if $line =~ /\A:\S+\s+CAP\s/mxs;
  return $line if $line =~ /\AAUTHENTICATE\s/mxs;

  my @existing_tags;
  if ($line =~ s/\A\@([^ ]+)\s+//mxs) {
    @existing_tags = grep { defined && length } split /;/mxs, $1;
  }

  my @tags;
  if ($self->_client_has_capability($client, 'server-time')) {
    push @tags, [time => $self->_ircv3_server_time_tag];
  }

  if ( $self->_client_has_capability($client, 'message-tags')
    && $self->_client_has_capability($client, 'account-tag')) {
    my $account = $self->_outbound_account_tag_for_line($line);
    if (defined($account) && !ref($account) && length($account)) {
      push @tags, [account => $account];
    }

  }

  if (
    !(
      @tags && ($self->_client_has_capability($client, 'message-tags')
        || $self->_client_has_capability($client, 'server-time'))
    )
  ) {
    return $line;
  }

  my %seen;
  for my $tag (@existing_tags) {
    my ($name) = split /=/mxs, $tag, 2;
    $seen{$name} = 1;
  }
  my @merged = map { $_->[0] . q{=} . $_->[1] }
    grep { !$seen{$_->[0]}++ } @tags;
  push @merged, @existing_tags;

  if (!(@merged)) {
    return $line;
  }

  return q{@} . join(q{;}, @merged) . q{ } . $line;
}

sub _outbound_account_tag_for_line {
  my ($self, $line) = @_;
  if (!(defined $line && !ref($line) && length($line))) {
    return;
  }

  my ($prefix) = $line =~ /\A:([^ ]+)\s/mxs;
  if (!(defined $prefix)) {
    return;
  }

  my ($nick) = split /[!@]/mxs, $prefix, 2;
  if (!(defined $nick && !ref($nick) && length($nick))) {
    return;
  }

  my $sender = $self->_client_for_current_nick($nick);
  if (!(ref($sender) eq 'HASH')) {
    return;
  }

  return $self->_client_account_name($sender);
}

sub _ircv3_server_time_tag {
  my ($self, $epoch) = @_;
  if (!(defined $epoch)) {
    $epoch = time();
  }

  my ($sec, $min, $hour, $mday, $mon, $year) = gmtime($epoch);
  return sprintf('%04d-%02d-%02dT%02d:%02d:%02d.000Z', $year + 1900, $mon + 1, $mday, $hour, $min, $sec,);
}

sub _close_all_clients {
  my ($self) = @_;
  for my $client_id (keys %{$self->{clients}}) {
    my $client = delete $self->{clients}{$client_id};
    $self->_release_client_nick($client_id, nick => ($client ? $client->{nick} : undef),);
    if (defined $client) {
      $self->_close_socket($client->{socket});
    }
  }
  $self->{channels}                         = {};
  $self->{nick_to_client_id}                = {};
  $self->{authoritative_last_created_at}    = {};
  $self->{authoritative_delegate_sequences} = {};
  return 1;
}

sub _close_listen_socket {
  my ($self) = @_;
  if (!(defined $self->{listener_socket})) {
    return 1;
  }

  my $socket = delete $self->{listener_socket};
  return $self->_close_socket($socket);
}

sub _close_socket {
  my ($self, $socket) = @_;
  if (!(defined $socket)) {
    return 1;
  }

  return close $socket ? 1 : 0;
}

sub _is_listener_socket {
  my ($self, $handle) = @_;
  return
       defined $self->{listener_socket}
    && defined $handle
    && defined fileno($self->{listener_socket})
    && defined fileno($handle)
    && fileno($self->{listener_socket}) == fileno($handle)
    ? 1
    : 0;
}

sub _is_runtime_stdin {
  my ($self, $handle) = @_;
  return
       defined $handle
    && defined fileno($handle)
    && defined fileno(STDIN)
    && fileno($handle) == fileno(STDIN)
    ? 1
    : 0;
}

sub _client_id_for_handle {
  my ($self, $handle) = @_;
  if (!(defined $handle && defined fileno($handle))) {
    return;
  }

  for my $client_id (keys %{$self->{clients}}) {
    my $socket = $self->{clients}{$client_id}{socket};
    if (!(defined $socket && defined fileno($socket))) {
      next;
    }

    return $client_id if fileno($socket) == fileno($handle);
  }

  return;
}

sub _log {
  my ($self, %args) = @_;
  $self->_send_message(
    Overnet::Program::Protocol::build_notification(
      method => 'program.log',
      params => {
        level   => $args{level}   || 'info',
        message => $args{message} || q{},
        (defined $args{context} ? (context => $args{context}) : ()),
      },
    )
  );
  return;
}

sub _health {
  my ($self, %args) = @_;
  $self->_send_message(
    Overnet::Program::Protocol::build_notification(
      method => 'program.health',
      params => {
        status => $args{status},
        (defined $args{message} ? (message => $args{message}) : ()),
        (defined $args{details} ? (details => $args{details}) : ()),
      },
    )
  );
  return;
}

sub _send_message {
  my ($self, $message) = @_;
  my $frame  = $self->{protocol}->encode_message($message);
  my $offset = 0;
  while ($offset < length $frame) {
    my $written = syswrite(STDOUT, $frame, length($frame) - $offset, $offset);
    if (!(defined $written)) {
      next if $OS_ERROR{EINTR};
      croak "failed to write runtime protocol frame: $OS_ERROR\n";
    }
    if ($written == 0) {
      croak "failed to write runtime protocol frame: wrote zero bytes\n";
    }

    $offset += $written;
  }

  return 1;
}

1;

=head1 NAME

Overnet::Program::IRC::Server - Supervised listening IRC server for Overnet

=head1 DESCRIPTION

Accepts IRC client connections, maps inbound IRC commands through the runtime
adapter service, signs candidate Overnet events with Net::Nostr, emits them
through the runtime validation boundary, and fans subscribed Overnet channel
items back out as IRC lines.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  my $server = Overnet::Program::IRC::Server->new;
  $server->run;

=head1 SUBROUTINES/METHODS

=head2 new

Constructs an IRC server program instance.

=head2 run

Runs the supervised IRC server program.

=head1 DIAGNOSTICS

Failures are reported through exceptions, runtime health messages, or IRC
numeric replies depending on where the failure occurs.

=head1 CONFIGURATION AND ENVIRONMENT

Runtime configuration is supplied by the Overnet program runtime.

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
