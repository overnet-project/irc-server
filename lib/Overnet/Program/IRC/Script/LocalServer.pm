package Overnet::Program::IRC::Script::LocalServer;

use strictures 2;
use Carp    qw(croak);
use Cwd     qw(abs_path);
use English qw(-no_match_vars);
use File::Spec;
use FindBin;
use Getopt::Long qw(GetOptionsFromArray);
use Overnet::Program::Host;
use Overnet::Program::Runtime;
use Overnet::Program::IRC::Script::Util qw(
  checked_print_stdout
  default_state_dir
  ensure_signing_key
  ensure_tls_material
  executable_name
  hexchat_connect_host
  print_new_notifications
  shell_quote
  validate_port
  wait_for_ready_details
);

our $VERSION = '0.001';

sub run {
  my ($class, @argv) = @_;

  my %options = (
    adapter_id      => 'irc.local',
    network         => 'local',
    listen_host     => '127.0.0.1',
    listen_port     => 16_667,
    server_name     => 'overnet.irc.local',
    tls             => 0,
    tls_min_version => 'TLSv1.2',
  );
  my $help = 0;

  my $parsed = GetOptionsFromArray(
    \@argv,
    'adapter-id=s'           => \$options{adapter_id},
    'network=s'              => \$options{network},
    'listen-host=s'          => \$options{listen_host},
    'listen-port=i'          => \$options{listen_port},
    'server-name=s'          => \$options{server_name},
    'signing-key-file=s'     => \$options{signing_key_file},
    'tls!'                   => \$options{tls},
    'tls-cert-chain-file=s'  => \$options{tls_cert_chain_file},
    'tls-private-key-file=s' => \$options{tls_private_key_file},
    'tls-ca-file=s'          => \$options{tls_ca_file},
    'tls-min-version=s'      => \$options{tls_min_version},
    'tls-verify-peer!'       => \$options{tls_verify_peer},
    'help'                   => \$help,
  );
  if (!$parsed) {
    checked_print_stdout(_usage());
    return 1;
  }

  if ($help) {
    checked_print_stdout(_usage());
    return 0;
  }

  $options{listen_port} = validate_port($options{listen_port}, 'listen-port');
  my $signing_key_file = _signing_key_file(\%options);
  ensure_signing_key($signing_key_file);

  my $tls_config = _tls_config(\%options);
  my $host       = _create_host(\%options, $signing_key_file, $tls_config);
  _run_host($host, \%options, $signing_key_file, $tls_config);
  return 0;
}

sub _signing_key_file {
  my ($options) = @_;
  if (defined $options->{signing_key_file} && length($options->{signing_key_file})) {
    return $options->{signing_key_file};
  }
  return File::Spec->catfile(default_state_dir(), 'local-demo-signing-key.pem');
}

sub _tls_config {
  my ($options) = @_;
  if (!$options->{tls}) {
    return;
  }

  my $tls_cert_chain_file = _option_or_default(
    $options->{tls_cert_chain_file},
    File::Spec->catfile(default_state_dir(), 'local-demo-tls-cert.pem'),
  );
  my $tls_private_key_file = _option_or_default(
    $options->{tls_private_key_file},
    File::Spec->catfile(default_state_dir(), 'local-demo-tls-key.pem'),
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

sub _create_host {
  my ($options, $signing_key_file, $tls_config) = @_;

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => $options->{adapter_id},
      network          => $options->{network},
      listen_host      => $options->{listen_host},
      listen_port      => 0 + $options->{listen_port},
      server_name      => $options->{server_name},
      signing_key_file => $signing_key_file,
      adapter_config   => {},
      (defined $tls_config ? (tls => $tls_config) : ()),
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
    'adapters.use',       'subscriptions.read',           'overnet.emit_event',
    'overnet.emit_state', 'overnet.emit_private_message', 'overnet.emit_capabilities',
  ];
}

sub _services {
  return {
    'adapters.open_session'        => {},
    'adapters.map_input'           => {},
    'adapters.close_session'       => {},
    'subscriptions.open'           => {},
    'subscriptions.close'          => {},
    'overnet.emit_event'           => {},
    'overnet.emit_state'           => {},
    'overnet.emit_private_message' => {},
    'overnet.emit_capabilities'    => {},
  };
}

sub _run_host {
  my ($host, $options, $signing_key_file, $tls_config) = @_;

  my $state = {
    shutdown_requested  => 0,
    notification_cursor => [0],
  };

  local $SIG{INT}  = sub { $state->{shutdown_requested} = 1; };
  local $SIG{TERM} = sub { $state->{shutdown_requested} = 1; };

  $host->start;
  my $ready_details = wait_for_ready_details($host)
    or croak "Program did not publish ready health details\n";
  print_new_notifications($host, $state->{notification_cursor});
  _print_ready_message($ready_details, $signing_key_file, $tls_config);
  _pump_until_shutdown($host, $state);
  _shutdown_host($host, $state->{notification_cursor});
  return 1;
}

sub _print_ready_message {
  my ($ready_details, $signing_key_file, $tls_config) = @_;

  my $client_script = abs_path(File::Spec->catfile($FindBin::Bin, 'overnet-irc-chat-client.pl'));
  if (!$client_script) {
    $client_script = File::Spec->catfile($FindBin::Bin, 'overnet-irc-chat-client.pl');
  }

  checked_print_stdout(
    "Overnet IRC local demo server is ready.\n",
    "Listening on $ready_details->{listen_host}:$ready_details->{listen_port}\n",
    "Network: $ready_details->{network}\n",
    "Server name: $ready_details->{server_name}\n",
    "Signing key: $signing_key_file\n",
  );
  _print_tls_details($tls_config);
  _print_client_instructions($ready_details, $client_script, $tls_config);
  checked_print_stdout("Press Ctrl-C here to shut the server down.\n");
  return 1;
}

sub _print_tls_details {
  my ($tls_config) = @_;
  if (!defined $tls_config) {
    return 1;
  }

  checked_print_stdout(
    "TLS: enabled\n",
    "TLS cert: $tls_config->{cert_chain_file}\n",
    "TLS key: $tls_config->{private_key_file}\n",
    "TLS min version: $tls_config->{min_version}\n",
  );
  return 1;
}

sub _print_client_instructions {
  my ($ready_details, $client_script, $tls_config) = @_;

  my $perl       = executable_name();
  my $tls_suffix = defined $tls_config ? ' --tls --tls-no-verify' : q{};
  checked_print_stdout(
    "\n",
    "Open two more terminals and run:\n",
    "  $perl $client_script --nick alice --port $ready_details->{listen_port}$tls_suffix\n",
    "  $perl $client_script --nick bob --port $ready_details->{listen_port}$tls_suffix\n",
    "\n",
    "The client auto-joins #overnet. Plain text sends to the current target.\n",
  );
  _print_hexchat_instructions($ready_details, $tls_config);
  return 1;
}

sub _print_hexchat_instructions {
  my ($ready_details, $tls_config) = @_;
  if (!defined $tls_config) {
    return 1;
  }

  my $hexchat_host = hexchat_connect_host($ready_details->{listen_host});
  my $hexchat_uri  = sprintf('ircs://%s:%d/#overnet', $hexchat_host, $ready_details->{listen_port});
  checked_print_stdout(
    "HexChat can connect without -insecure.\n",
    "For the local generated cert, run:\n",
    '  SSL_CERT_FILE=' . shell_quote($tls_config->{cert_chain_file}) . ' hexchat ' . shell_quote($hexchat_uri) . "\n",
    "If you supply your own CA-trusted cert/key, normal HexChat TLS works without SSL_CERT_FILE.\n",
  );
  return 1;
}

sub _pump_until_shutdown {
  my ($host, $state) = @_;

  while (!$state->{shutdown_requested}) {
    $host->pump(timeout_ms => 100);
    print_new_notifications($host, $state->{notification_cursor});

    if ($host->has_exited) {
      my $exit_code = defined $host->exit_code ? $host->exit_code : 'signal';
      my $stderr    = $host->stderr_output;
      croak "IRC server exited unexpectedly ($exit_code)\n$stderr";
    }
  }
  return 1;
}

sub _shutdown_host {
  my ($host, $notification_cursor_ref) = @_;

  checked_print_stdout("\nShutting down local demo server...\n");
  print_new_notifications($host, $notification_cursor_ref);

  my $shutdown = eval {
    $host->request_shutdown(reason => 'local demo shutdown');
    1;
  };
  if (!$shutdown) {
    my $error = $EVAL_ERROR || "unknown shutdown error\n";
    chomp $error;
    croak "Failed to shut down cleanly: $error\n";
  }

  print_new_notifications($host, $notification_cursor_ref);
  checked_print_stdout("Server stopped.\n");
  return 1;
}

sub _usage {
  return <<'USAGE';
Usage:
  perl irc-server/bin/overnet-irc-local-server.pl [options]

Options:
  --adapter-id ID         Adapter id to register and use (default: irc.local)
  --network NAME          IRC network name for adapted object ids (default: local)
  --listen-host HOST      Listen host for the local IRC server (default: 127.0.0.1)
  --listen-port PORT      Listen port for the local IRC server (default: 16667)
  --server-name NAME      IRC server name shown to clients (default: overnet.irc.local)
  --signing-key-file PATH Reuse this signing key instead of auto-creating one
  --tls                   Enable TLS on the local IRC listener
  --tls-cert-chain-file PATH
                          TLS certificate chain file (auto-generated for local demo if omitted)
  --tls-private-key-file PATH
                          TLS private key file (auto-generated for local demo if omitted)
  --tls-ca-file PATH      Optional CA file to require verified client certificates
  --tls-min-version NAME  TLS minimum version (default: TLSv1.2)
  --tls-verify-peer       Require peer certificate verification
  --help                  Show this message
USAGE
}

1;

=head1 NAME

Overnet::Program::IRC::Script::LocalServer - local IRC demo server script runner

=head1 DESCRIPTION

Runs the C<overnet-irc-local-server.pl> command-line local demo server.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  Overnet::Program::IRC::Script::LocalServer->run(@ARGV);

=head1 SUBROUTINES/METHODS

=head2 run

=head1 DIAGNOSTICS

Invalid arguments and program host failures are reported through exceptions.

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
