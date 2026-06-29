package Overnet::Program::IRC::Script::Service;

use strictures 2;
use Carp    qw(croak);
use English qw(-no_match_vars);
use File::Spec;
use FindBin;
use Getopt::Long qw(GetOptionsFromArray);
use Overnet::Program::Host;
use Overnet::Program::Runtime;
use Overnet::Program::IRC::Script::Util qw(
  append_log
  checked_print_stderr
  checked_print_stdout
  default_state_dir
  ensure_signing_key
  ensure_tls_material
  executable_name
  validate_port
  wait_for_ready_details
  write_health_file
  write_new_notifications
);

our $VERSION = '0.001';

sub run {
  my ($class, @argv) = @_;

  my %options = (
    adapter_id      => 'irc.service',
    network         => 'overnet',
    listen_host     => '127.0.0.1',
    listen_port     => 16_667,
    server_name     => 'irc.overnet.local',
    tls             => 0,
    tls_min_version => 'TLSv1.2',
  );
  my @channel_group_args;
  my $health_file;
  my $log_file;
  my $help = 0;

  my $parsed = GetOptionsFromArray(
    \@argv,
    'adapter-id=s'                       => \$options{adapter_id},
    'network=s'                          => \$options{network},
    'listen-host=s'                      => \$options{listen_host},
    'listen-port=i'                      => \$options{listen_port},
    'server-name=s'                      => \$options{server_name},
    'signing-key-file=s'                 => \$options{signing_key_file},
    'group-host=s'                       => \$options{group_host},
    'channel-group=s'                    => \@channel_group_args,
    'authority-relay-url=s'              => \$options{authority_relay_url},
    'authority-relay-query-timeout-ms=i' => \$options{authority_relay_query_timeout_ms},
    'authority-relay-poll-interval-ms=i' => \$options{authority_relay_poll_interval_ms},
    'tls!'                               => \$options{tls},
    'tls-cert-chain-file=s'              => \$options{tls_cert_chain_file},
    'tls-private-key-file=s'             => \$options{tls_private_key_file},
    'tls-ca-file=s'                      => \$options{tls_ca_file},
    'tls-min-version=s'                  => \$options{tls_min_version},
    'tls-verify-peer!'                   => \$options{tls_verify_peer},
    'health-file=s'                      => \$health_file,
    'log-file=s'                         => \$log_file,
    'help'                               => \$help,
  );
  if (!$parsed) {
    checked_print_stderr(_usage());
    return 1;
  }

  if ($help) {
    checked_print_stdout(_usage());
    return 0;
  }

  $options{listen_port} = validate_port($options{listen_port}, 'listen-port');
  my $signing_key_file = _signing_key_file(\%options);
  ensure_signing_key($signing_key_file);

  my $tls_config      = _tls_config(\%options);
  my $adapter_config  = _adapter_config(\%options, \@channel_group_args);
  my $authority_relay = _authority_relay(\%options, $adapter_config);
  my $host            = _create_host(\%options, $signing_key_file, $adapter_config, $authority_relay, $tls_config);

  append_log($log_file, "starting IRC service\n");
  _run_host($host, $health_file, $log_file);
  return 0;
}

sub _signing_key_file {
  my ($options) = @_;
  if (defined $options->{signing_key_file} && length($options->{signing_key_file})) {
    return $options->{signing_key_file};
  }
  return File::Spec->catfile(default_state_dir(), 'service-signing-key.pem');
}

sub _tls_config {
  my ($options) = @_;
  if (!$options->{tls}) {
    return;
  }

  my $tls_cert_chain_file = _option_or_default(
    $options->{tls_cert_chain_file},
    File::Spec->catfile(default_state_dir(), 'service-tls-cert.pem'),
  );
  my $tls_private_key_file = _option_or_default(
    $options->{tls_private_key_file},
    File::Spec->catfile(default_state_dir(), 'service-tls-key.pem'),
  );

  ensure_tls_material(
    cert_chain_file  => $tls_cert_chain_file,
    private_key_file => $tls_private_key_file,
    listen_host      => $options->{listen_host},
  );

  my $config = {
    enabled          => 1,
    mode             => 'server',
    cert_chain_file  => $tls_cert_chain_file,
    private_key_file => $tls_private_key_file,
    min_version      => $options->{tls_min_version},
  };
  if (defined $options->{tls_verify_peer}) {
    $config->{verify_peer} = $options->{tls_verify_peer} ? 1 : 0;
  }
  if (defined $options->{tls_ca_file} && length($options->{tls_ca_file})) {
    $config->{ca_file} = $options->{tls_ca_file};
  }
  return $config;
}

sub _option_or_default {
  my ($value, $default) = @_;
  if (defined $value && length($value)) {
    return $value;
  }
  return $default;
}

sub _adapter_config {
  my ($options, $channel_group_args) = @_;

  my $adapter_config = {network => $options->{network},};
  if (defined $options->{group_host} && length($options->{group_host})) {
    $adapter_config->{group_host} = $options->{group_host};
  }
  if (@{$channel_group_args}) {
    $adapter_config->{channel_groups} = _parse_channel_groups($channel_group_args);
  }
  return $adapter_config;
}

sub _parse_channel_groups {
  my ($channel_group_args) = @_;
  my %channel_groups;

  for my $arg (@{$channel_group_args}) {
    my ($channel, $group_id) = $arg =~ /\A([^=]+)=(.+)\z/mxs;
    if (!defined $channel) {
      croak "--channel-group must be CHANNEL=GROUP_ID\n";
    }
    $channel_groups{$channel} = $group_id;
  }

  return \%channel_groups;
}

sub _authority_relay {
  my ($options, $adapter_config) = @_;

  if (!(defined $options->{authority_relay_url} && length($options->{authority_relay_url}))) {
    return;
  }

  my $authority_relay = {url => $options->{authority_relay_url},};
  $adapter_config->{authority_profile} = 'nip29';

  if (defined $options->{authority_relay_query_timeout_ms}) {
    $authority_relay->{query_timeout_ms} = 0 + $options->{authority_relay_query_timeout_ms};
  }
  if (defined $options->{authority_relay_poll_interval_ms}) {
    $authority_relay->{poll_interval_ms} = 0 + $options->{authority_relay_poll_interval_ms};
  }
  return $authority_relay;
}

sub _create_host {
  my ($options, $signing_key_file, $adapter_config, $authority_relay, $tls_config) = @_;

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => $options->{adapter_id},
      network          => $options->{network},
      listen_host      => $options->{listen_host},
      listen_port      => 0 + $options->{listen_port},
      server_name      => $options->{server_name},
      signing_key_file => $signing_key_file,
      adapter_config   => $adapter_config,
      (defined $authority_relay ? (authority_relay => $authority_relay) : ()),
      (defined $tls_config      ? (tls             => $tls_config)      : ()),
    },
  );
  _register_adapter($runtime, $options->{adapter_id});

  return Overnet::Program::Host->new(
    command             => _server_command(),
    runtime             => $runtime,
    program_id          => 'overnet.program.irc_server',
    permissions         => _permissions(),
    services            => _services(),
    startup_timeout_ms  => 2_000,
    shutdown_timeout_ms => 2_000,
  );
}

sub _register_adapter {
  my ($runtime, $adapter_id) = @_;

  my $adapter_lib = File::Spec->catdir($FindBin::Bin, File::Spec->updir, File::Spec->updir, 'adapter-irc-perl', 'lib');
  my $registered  = $runtime->register_adapter_definition(
    adapter_id => $adapter_id,
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$adapter_lib],
      constructor_args => {},
    },
  );
  if (!$registered) {
    croak "Failed to register IRC adapter definition\n";
  }

  return 1;
}

sub _server_command {
  my $program_path = File::Spec->catfile($FindBin::Bin, 'overnet-irc-server.pl');
  my $dollar       = chr 36;
  my $at           = chr 64;
  my $double_quote = chr 34;
  my $child_wrapper =
      $dollar
    . q{SIG{INT} = 'IGNORE'; exec }
    . $dollar . q{^X, }
    . $at
    . q{ARGV or die }
    . $double_quote
    . q{exec failed: }
    . $dollar . q{!}
    . $double_quote . q{;};
  return [executable_name(), '-e', $child_wrapper, $program_path];
}

sub _permissions {
  return [
    'adapters.use',       'subscriptions.read', 'events.append',
    'events.read',        'nostr.read',         'nostr.write',
    'overnet.emit_event', 'overnet.emit_state', 'overnet.emit_private_message',
    'overnet.emit_capabilities',
  ];
}

sub _services {
  return {
    'adapters.open_session'            => {},
    'adapters.map_input'               => {},
    'adapters.derive'                  => {},
    'adapters.close_session'           => {},
    'events.append'                    => {},
    'events.read'                      => {},
    'nostr.publish_event'              => {},
    'nostr.query_events'               => {},
    'nostr.open_subscription'          => {},
    'nostr.read_subscription_snapshot' => {},
    'nostr.close_subscription'         => {},
    'subscriptions.open'               => {},
    'subscriptions.close'              => {},
    'overnet.emit_event'               => {},
    'overnet.emit_state'               => {},
    'overnet.emit_private_message'     => {},
    'overnet.emit_capabilities'        => {},
  };
}

sub _run_host {
  my ($host, $health_file, $log_file) = @_;

  my $state = {
    shutdown_requested  => 0,
    notification_cursor => [0],
  };

  local $SIG{INT}  = sub { $state->{shutdown_requested} = 1; };
  local $SIG{TERM} = sub { $state->{shutdown_requested} = 1; };

  $host->start;
  my $ready_details = wait_for_ready_details($host)
    or croak "Program did not publish ready health details\n";
  _write_ready($health_file, $log_file, $ready_details);
  write_new_notifications($host, $state->{notification_cursor}, $log_file);
  _pump_until_shutdown($host, $health_file, $log_file, $ready_details, $state);
  _shutdown_host($host, $health_file, $log_file, $ready_details, $state->{notification_cursor});
  return 1;
}

sub _write_ready {
  my ($health_file, $log_file, $ready_details) = @_;

  write_health_file(
    $health_file,
    {
      status  => 'ready',
      details => $ready_details,
    }
  );
  append_log(
    $log_file,
    sprintf(
      "ready listen=%s:%s server=%s network=%s\n",
      $ready_details->{listen_host} || q{},
      $ready_details->{listen_port} || q{},
      $ready_details->{server_name} || q{},
      $ready_details->{network}     || q{},
    )
  );
  return 1;
}

sub _pump_until_shutdown {
  my ($host, $health_file, $log_file, $ready_details, $state) = @_;

  while (!$state->{shutdown_requested}) {
    $host->pump(timeout_ms => 100);
    write_new_notifications($host, $state->{notification_cursor}, $log_file);
    _check_host_running($host, $health_file);
  }

  write_health_file(
    $health_file,
    {
      status  => 'stopping',
      details => $ready_details,
    }
  );
  append_log($log_file, "shutting down IRC service\n");
  return 1;
}

sub _check_host_running {
  my ($host, $health_file) = @_;
  if (!$host->has_exited) {
    return 1;
  }

  my $exit_code = defined $host->exit_code ? $host->exit_code : 'signal';
  my $stderr    = $host->stderr_output;
  write_health_file(
    $health_file,
    {
      status  => 'failed',
      details => {
        exit_code => $exit_code,
      },
    }
  );
  croak "IRC server exited unexpectedly ($exit_code)\n$stderr";
}

sub _shutdown_host {
  my ($host, $health_file, $log_file, $ready_details, $notification_cursor) = @_;

  my $shutdown = eval {
    $host->request_shutdown(reason => 'service shutdown');
    1;
  };
  if (!$shutdown) {
    my $error = $EVAL_ERROR || "unknown shutdown error\n";
    chomp $error;
    croak "Failed to shut down cleanly: $error\n";
  }

  write_new_notifications($host, $notification_cursor, $log_file);
  write_health_file(
    $health_file,
    {
      status  => 'stopped',
      details => $ready_details,
    }
  );
  append_log($log_file, "stopped IRC service\n");
  return 1;
}

sub _usage {
  return <<'USAGE';
Usage: overnet-irc-service.pl [options]

  --adapter-id ID
  --network NAME
  --listen-host HOST
  --listen-port PORT
  --server-name NAME
  --signing-key-file PATH
  --group-host HOST
  --channel-group CHANNEL=GROUP_ID
  --authority-relay-url URL
  --authority-relay-query-timeout-ms N
  --authority-relay-poll-interval-ms N
  --tls
  --tls-cert-chain-file PATH
  --tls-private-key-file PATH
  --tls-ca-file PATH
  --tls-min-version VERSION
  --tls-verify-peer
  --health-file PATH
  --log-file PATH
  --help
USAGE
}

1;

=head1 NAME

Overnet::Program::IRC::Script::Service - IRC service script runner

=head1 DESCRIPTION

Runs the C<overnet-irc-service.pl> command-line service wrapper.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  Overnet::Program::IRC::Script::Service->run(@ARGV);

=head1 SUBROUTINES/METHODS

=head2 run

=head1 DIAGNOSTICS

Invalid arguments, host failures, and failed IO operations are reported through exceptions.

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
