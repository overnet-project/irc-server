#!/usr/bin/env perl
#
# integration-client.pl - prove the Overnet IRC frontend and the authority relay
# communicate over their WebSocket link.
#
# This standalone IRC client connects to the frontend's IRC port, performs the
# full OVERNETAUTH CHALLENGE / AUTH / DELEGATE handshake, and exits 0 only when
# the frontend emits the bare "OVERNETAUTH DELEGATE" success NOTICE. That NOTICE
# is emitted ONLY after the frontend published the kind-14142 delegation grant to
# the authority relay AND the relay returned "accepted" -- so a clean exit proves
# the write crossed the frontend -> relay WebSocket link.
#
# The kind-22242 auth event and kind-14142 grant event are constructed exactly as
# in relay-perl/t/program-irc-server-relay-fault.t (subs
# _build_authoritative_auth_payload / _build_authoritative_delegate_payload).
#
# Usage:
#   integration-client.pl [IRC_HOST IRC_PORT SERVER_NAME NETWORK RELAY_URL]
#
# or via environment:
#   IRC_HOST, IRC_PORT, IRC_SERVER_NAME, IRC_NETWORK, RELAY_URL
#
# Optional: NICK (default "alice"), IRC_TIMEOUT_MS (per-read timeout, default 8000).
#
# Depends only on: core Perl, IO::Socket::INET, IO::Select, JSON, MIME::Base64,
# and Net::Nostr::Key (bundled in the deployed images). No test-only modules.

use strictures 2;
use IO::Socket::INET;
use IO::Select;
use JSON         ();
use MIME::Base64 qw(encode_base64);
use Net::Nostr::Key;

$| = 1;

sub _arg {
  my ($index, $env, $default) = @_;
  return $ARGV[$index]
    if defined $ARGV[$index] && length $ARGV[$index];
  return $ENV{$env}
    if defined $ENV{$env} && length $ENV{$env};
  return $default;
}

my $irc_host    = _arg(0, 'IRC_HOST',        '127.0.0.1');
my $irc_port    = _arg(1, 'IRC_PORT',        undef);
my $server_name = _arg(2, 'IRC_SERVER_NAME', 'irc.overnet.local');
my $network     = _arg(3, 'IRC_NETWORK',     'overnet');
my $relay_url   = _arg(4, 'RELAY_URL',       undef);
my $nick        = defined $ENV{NICK} && length $ENV{NICK} ? $ENV{NICK} : 'alice';
my $timeout_ms  = defined $ENV{IRC_TIMEOUT_MS} && $ENV{IRC_TIMEOUT_MS} =~ /\A\d+\z/mx
  ? $ENV{IRC_TIMEOUT_MS}
  : 8_000;

die "IRC port is required (arg 2 or IRC_PORT)\n"  if !(defined $irc_port  && length $irc_port);
die "relay_url is required (arg 5 or RELAY_URL)\n" if !(defined $relay_url && length $relay_url);

my $scope = sprintf 'irc://%s/%s', $server_name, $network;

sub progress { print {*STDERR} '[integration-client] ', @_, "\n"; return; }

# ---- payload construction: byte-for-byte match with relay-fault.t --------------

sub build_auth_payload {
  my (%args) = @_;
  my $event = $args{key}->create_event(
    kind       => 22242,
    created_at => 1_744_301_000,
    content    => '',
    tags       => [['relay', $args{scope}], ['challenge', $args{challenge}],],
  );
  return encode_base64(JSON::encode_json($event->to_hash), '');
}

sub build_delegate_payload {
  my (%args) = @_;
  my $event = $args{key}->create_event(
    kind       => 14142,
    created_at => 1_744_301_100,
    content    => '',
    tags       => [
      ['relay',      $args{relay_url}],
      ['server',     $args{scope}],
      ['delegate',   $args{delegate_pubkey}],
      ['session',    $args{session_id}],
      ['expires_at', $args{expires_at}],
      (defined($args{nick}) ? (['nick', $args{nick}]) : ()),
    ],
  );
  return encode_base64(JSON::encode_json($event->to_hash), '');
}

# ---- socket I/O ----------------------------------------------------------------

my %conn = (socket => undef, buffer => '');

sub read_line {
  my ($tmo_ms) = @_;
  while ($conn{buffer} !~ /\n/mx) {
    my $sel   = IO::Select->new($conn{socket});
    my @ready = $sel->can_read($tmo_ms / 1000);
    die "timed out waiting for a line from the frontend\n" if !@ready;
    my $bytes = sysread($conn{socket}, my $chunk, 4096);
    die "frontend closed the connection unexpectedly\n" if !(defined $bytes && $bytes > 0);
    $conn{buffer} .= $chunk;
  }
  $conn{buffer} =~ s/\A([^\n]*\n)//mx;
  my $line = $1;
  $line =~ s/\r?\n\z//mx;
  return $line;
}

# Read lines until one matches $re, or die on timeout. Returns the matching line.
sub read_until {
  my ($re, $tmo_ms, $what) = @_;
  my $deadline = time + ($tmo_ms / 1000);
  while (1) {
    my $remaining = $deadline - time;
    $remaining = 0.05 if $remaining < 0.05;
    my $line = read_line($remaining * 1000);
    progress("<< $line");
    return $line if $line =~ $re;

    # Fail fast on an explicit delegation-publish failure NOTICE.
    if ($line =~ /delegation\ relay\ publish\ failed/imx
      || $line =~ /OVERNETAUTH\ DELEGATE\ relay\ publish\ failed/imx) {
      print {*STDERR} $line, "\n";
      die "frontend reported a delegation relay publish failure\n";
    }
    die "timed out waiting for $what\n" if time >= $deadline;
  }
}

sub write_line {
  my ($line) = @_;
  progress(">> $line");
  my $payload = $line . "\r\n";
  my $offset  = 0;
  while ($offset < length $payload) {
    my $written = syswrite($conn{socket}, $payload, length($payload) - $offset, $offset);
    die "failed to write to the frontend: $!\n" if !defined $written;
    $offset += $written;
  }
  return;
}

# ---- handshake -----------------------------------------------------------------

progress("connecting to $irc_host:$irc_port (server_name=$server_name network=$network)");
$conn{socket} = IO::Socket::INET->new(
  PeerHost => $irc_host,
  PeerPort => $irc_port,
  Proto    => 'tcp',
  Timeout  => 5,
) or die "cannot connect to $irc_host:$irc_port: $!\n";
binmode $conn{socket}, ':raw';
$conn{socket}->autoflush(1);

my $alice = Net::Nostr::Key->new;
my $alice_pubkey = $alice->pubkey_hex;
progress("generated alice pubkey $alice_pubkey");

write_line("NICK $nick");
write_line("USER $nick 0 * :Overnet Integration Client");

# Registration prelude (001/005/422) precedes the challenge; drain until CHALLENGE.
write_line('OVERNETAUTH CHALLENGE');
my $challenge_line = read_until(
  qr/:\Q$server_name\E\ NOTICE\ \Q$nick\E\ :OVERNETAUTH\ CHALLENGE\ [0-9a-f]{64}/mx,
  $timeout_ms, 'OVERNETAUTH CHALLENGE',
);
my ($challenge) = $challenge_line =~ /([0-9a-f]{64})\z/mx;
die "could not parse challenge from: $challenge_line\n" if !defined $challenge;
progress("received challenge $challenge");

write_line(
  'OVERNETAUTH AUTH '
    . build_auth_payload(key => $alice, challenge => $challenge, scope => $scope));
my $auth_line = read_until(
  qr/:\Q$server_name\E\ NOTICE\ \Q$nick\E\ :OVERNETAUTH\ AUTH\ /mx,
  $timeout_ms, 'OVERNETAUTH AUTH acknowledgement',
);
if ($auth_line !~ /:OVERNETAUTH\ AUTH\ \Q$alice_pubkey\E\z/mx) {
  print {*STDERR} $auth_line, "\n";
  die "AUTH acknowledgement did not confirm alice's pubkey\n";
}
progress('authenticated authoritative pubkey');

# Request delegation parameters.
write_line('OVERNETAUTH DELEGATE');
my $delegate_line = read_until(
  qr/:\Q$server_name\E\ NOTICE\ \Q$nick\E\ :OVERNETAUTH\ DELEGATE\ [0-9a-f]{64}\ /mx,
  $timeout_ms, 'OVERNETAUTH DELEGATE parameters',
);
my ($delegate_pubkey, $session_id, $offered_relay, $expires_at) =
  $delegate_line =~ /:OVERNETAUTH\ DELEGATE\ ([0-9a-f]{64})\ ([0-9a-f]{64})\ (\S+)\ (\d+)\z/mx;
die "could not parse delegation parameters from: $delegate_line\n"
  if !(defined $delegate_pubkey && defined $session_id && defined $offered_relay && defined $expires_at);
progress("delegation params delegate=$delegate_pubkey session=$session_id relay=$offered_relay expires=$expires_at");

# Sign and submit the kind-14142 grant using the relay_url the frontend offered.
write_line(
  'OVERNETAUTH DELEGATE '
    . build_delegate_payload(
    key             => $alice,
    relay_url       => $offered_relay,
    scope           => $scope,
    delegate_pubkey => $delegate_pubkey,
    session_id      => $session_id,
    expires_at      => $expires_at,
    nick            => $nick,
    ));

# SUCCESS is the bare "OVERNETAUTH DELEGATE" NOTICE with no trailing args.
my $ack = read_until(
  qr/:\Q$server_name\E\ NOTICE\ \Q$nick\E\ :OVERNETAUTH\ DELEGATE\z/mx,
  $timeout_ms, 'OVERNETAUTH DELEGATE success acknowledgement',
);
progress('DELEGATE success acknowledgement received; the kind-14142 grant crossed to the relay');

print {*STDOUT} $alice_pubkey, "\n";

close $conn{socket};
exit 0;
