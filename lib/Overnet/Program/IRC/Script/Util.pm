package Overnet::Program::IRC::Script::Util;

use strictures 2;
use Carp           qw(croak);
use English        qw(-no_match_vars);
use Exporter       qw(import);
use File::Basename qw(dirname);
use File::Path     qw(make_path);
use File::Spec;
use IO::Socket::SSL::Utils qw(CERT_create PEM_cert2file PEM_key2file);
use JSON                   ();
use Overnet::Core::Nostr;

our $VERSION   = '0.001';
our @EXPORT_OK = qw(
  append_log
  checked_close
  checked_print
  checked_print_stderr
  checked_print_stdout
  default_state_dir
  ensure_signing_key
  ensure_tls_material
  executable_name
  hexchat_connect_host
  shell_quote
  validate_port
  wait_for_ready_details
  write_health_file
  write_new_notifications
  print_new_notifications
);

sub executable_name {
  return $EXECUTABLE_NAME;
}

sub checked_print {
  my ($handle, @messages) = @_;

  print {$handle} @messages
    or croak "print failed: $OS_ERROR\n";
  return 1;
}

sub checked_print_stdout {
  my (@messages) = @_;
  return checked_print(\*STDOUT, @messages);
}

sub checked_print_stderr {
  my (@messages) = @_;
  return checked_print(\*STDERR, @messages);
}

sub checked_close {
  my ($handle, $description) = @_;

  close $handle
    or croak "close failed for $description: $OS_ERROR\n";
  return 1;
}

sub validate_port {
  my ($port, $label) = @_;
  if (!defined $label || ref($label) || !length($label)) {
    $label = 'port';
  }

  if (!(defined $port && !ref($port) && $port =~ /\A(?:0|[1-9]\d{0,4})\z/mxs && $port <= 65_535)) {
    croak "$label must be between 0 and 65535\n";
  }

  return 0 + $port;
}

sub default_state_dir {
  my $xdg = $ENV{XDG_STATE_HOME};
  if (defined $xdg && !ref($xdg) && length($xdg)) {
    return File::Spec->catdir($xdg, 'irc-server');
  }

  my $home = $ENV{HOME};
  if (defined $home && !ref($home) && length($home)) {
    return File::Spec->catdir($home, '.local', 'state', 'irc-server');
  }

  return File::Spec->catdir(File::Spec->tmpdir, 'irc-server');
}

sub ensure_signing_key {
  my ($path) = @_;
  if (-f $path) {
    return 1;
  }

  my $directory = dirname($path);
  if (!-d $directory) {
    make_path($directory);
  }

  my $key = Overnet::Core::Nostr->generate_key;
  $key->save_privkey($path);
  chmod 0600, $path
    or croak "chmod failed for signing key $path: $OS_ERROR\n";
  return 1;
}

sub ensure_tls_material {
  my (%args)           = @_;
  my $cert_chain_file  = $args{cert_chain_file};
  my $private_key_file = $args{private_key_file};
  my $listen_host      = $args{listen_host};

  if (-f $cert_chain_file && -f $private_key_file) {
    return 1;
  }

  my $cert_directory = dirname($cert_chain_file);
  if (!-d $cert_directory) {
    make_path($cert_directory);
  }

  my $key_directory = dirname($private_key_file);
  if (!-d $key_directory) {
    make_path($key_directory);
  }

  my @subject_alt_names = ([DNS => 'localhost'], [IP => '127.0.0.1'],);
  if ( defined $listen_host
    && length($listen_host)
    && $listen_host ne 'localhost'
    && $listen_host ne '127.0.0.1') {
    if ($listen_host =~ /\A\d{1,3}(?:\.\d{1,3}){3}\z/mxs) {
      push @subject_alt_names, [IP => $listen_host];
    } else {
      push @subject_alt_names, [DNS => $listen_host];
    }
  }

  my $common_name = 'localhost';
  if (defined $listen_host && length($listen_host)) {
    $common_name = $listen_host;
  }

  my ($cert, $key) = CERT_create(
    subject => {
      commonName => $common_name,
    },
    subjectAltNames => \@subject_alt_names,
  );
  PEM_cert2file($cert, $cert_chain_file);
  PEM_key2file($key, $private_key_file);
  chmod 0600, $private_key_file
    or croak "chmod failed for TLS private key $private_key_file: $OS_ERROR\n";
  return 1;
}

sub wait_for_ready_details {
  my ($host) = @_;

  my $ready = $host->pump_until(
    timeout_ms => 2_000,
    condition  => sub {
      my ($current_host) = @_;
      for my $notification (@{$current_host->observed_notifications}) {
        my $params = $notification->{params} || {};
        next     if ($notification->{method} || q{}) ne 'program.health';
        next     if ($params->{status}       || q{}) ne 'ready';
        next     if ref($params->{details}) ne 'HASH';
        return 1 if defined $params->{details}{listen_port};
      }
      return 0;
    },
  );
  if (!$ready) {
    return;
  }

  for my $notification (@{$host->observed_notifications}) {
    my $params = $notification->{params} || {};
    next if ($notification->{method} || q{}) ne 'program.health';
    next if ($params->{status}       || q{}) ne 'ready';
    next if ref($params->{details}) ne 'HASH';
    return $params->{details};
  }

  return;
}

sub write_new_notifications {
  my ($host, $cursor, $log_file_path) = @_;
  my $notifications = $host->observed_notifications;

  while ($cursor->[0] < @{$notifications}) {
    my $notification = $notifications->[$cursor->[0]];
    $cursor->[0] += 1;

    my $method = $notification->{method} || q{};
    my $params = $notification->{params} || {};

    if ($method eq 'program.log') {
      _write_program_log_notification($log_file_path, $params);
      next;
    }

    if ($method eq 'program.health') {
      _write_program_health_notification($log_file_path, $params);
    }
  }
  return 1;
}

sub _write_program_log_notification {
  my ($log_file_path, $params) = @_;

  my $level   = $params->{level}   || 'info';
  my $message = $params->{message} || q{};
  append_log($log_file_path, "[program.$level] $message\n");
  return 1;
}

sub _write_program_health_notification {
  my ($log_file_path, $params) = @_;

  my $status  = $params->{status}  || 'unknown';
  my $message = $params->{message} || q{};
  my $suffix  = length($message) ? ": $message" : q{};
  append_log($log_file_path, "[program.health] $status$suffix\n");
  return 1;
}

sub print_new_notifications {
  my ($host, $cursor) = @_;
  my $notifications = $host->observed_notifications;

  while ($cursor->[0] < @{$notifications}) {
    my $notification = $notifications->[$cursor->[0]];
    $cursor->[0] += 1;

    my $method = $notification->{method} || q{};
    my $params = $notification->{params} || {};

    if ($method eq 'program.log') {
      _print_program_log_notification($params);
      next;
    }

    if ($method eq 'program.health') {
      _print_program_health_notification($params);
    }
  }
  return 1;
}

sub _print_program_log_notification {
  my ($params) = @_;

  my $level   = $params->{level}   || 'info';
  my $message = $params->{message} || q{};
  checked_print_stderr("[program.$level] $message\n");
  return 1;
}

sub _print_program_health_notification {
  my ($params) = @_;

  return 1 if ($params->{status} || q{}) eq 'ready';

  my $status  = $params->{status}  || 'unknown';
  my $message = $params->{message} || q{};
  my $suffix  = length($message) ? ": $message" : q{};
  checked_print_stderr("[program.health] $status$suffix\n");
  return 1;
}

sub append_log {
  my ($path, $message) = @_;
  if (!defined $path) {
    return 1;
  }
  if (!length $path) {
    return 1;
  }

  my $directory = dirname($path);
  if (!-d $directory) {
    make_path($directory);
  }

  open my $fh, '>>', $path
    or croak "Can't open log file $path: $OS_ERROR\n";
  checked_print($fh, $message);
  checked_close($fh, "log file $path");
  return 1;
}

sub write_health_file {
  my ($path, $payload) = @_;
  if (!defined $path) {
    return 1;
  }
  if (!length $path) {
    return 1;
  }

  my $directory = dirname($path);
  if (!-d $directory) {
    make_path($directory);
  }

  my $tmp_path = $path . '.tmp.' . $PROCESS_ID;
  open my $fh, '>', $tmp_path
    or croak "Can't open health temp file $tmp_path: $OS_ERROR\n";
  my $json = JSON->new->utf8->canonical;
  checked_print($fh, $json->encode($payload));
  checked_close($fh, "health temp file $tmp_path");
  rename $tmp_path, $path
    or croak "Can't rename health temp file $tmp_path to $path: $OS_ERROR\n";
  return 1;
}

sub hexchat_connect_host {
  my ($listen_host) = @_;
  my $ipv6_any = chr(58) . chr(58);
  if ( !defined $listen_host
    || !length($listen_host)
    || $listen_host eq '0.0.0.0'
    || $listen_host eq $ipv6_any) {
    return '127.0.0.1';
  }
  return $listen_host;
}

sub shell_quote {
  my ($value) = @_;
  if (!defined $value) {
    $value = q{};
  }
  my $single_quote        = chr 39;
  my $double_quote        = chr 34;
  my $quoted_single_quote = $single_quote . $double_quote . $single_quote . $double_quote . $single_quote;
  $value =~ s/$single_quote/$quoted_single_quote/gmxs;
  return $single_quote . $value . $single_quote;
}

1;

=head1 NAME

Overnet::Program::IRC::Script::Util - shared IRC script helpers

=head1 DESCRIPTION

Provides checked IO, state-file, TLS, and notification helpers for the
Overnet IRC command-line scripts.

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Program::IRC::Script::Util qw(checked_print_stdout);

=head1 SUBROUTINES/METHODS

=head2 append_log

=head2 checked_close

=head2 checked_print

=head2 checked_print_stderr

=head2 checked_print_stdout

=head2 default_state_dir

=head2 ensure_signing_key

=head2 ensure_tls_material

=head2 executable_name

=head2 hexchat_connect_host

=head2 shell_quote

=head2 validate_port

=head2 wait_for_ready_details

=head2 write_health_file

=head2 write_new_notifications

=head2 print_new_notifications

=head1 DIAGNOSTICS

Invalid arguments and failed IO operations are reported through exceptions.

=head1 CONFIGURATION AND ENVIRONMENT

The default state directory uses C<XDG_STATE_HOME> when available.

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
